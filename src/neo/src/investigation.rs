use crate::analysis_cli::{self, TargetOptions};
use crate::{memory, output};
use neo::memory::{InterceptionRequest, interception_packet};
use neo::protocol::memory::*;
use neo::unwind::{self, DynamicTable, UnwindContext};
use neo::user::{self, Module};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::time::{Duration, Instant};

const FORMAT: &str = "neo-investigation-v1";

#[derive(Default, Serialize, Deserialize)]
struct Catalog {
    modules: Vec<Module>,
    dynamic: Vec<DynamicTable>,
    dynamic_list: Option<u64>,
}

#[derive(Deserialize, Serialize)]
struct Segment {
    address: String,
    requested: u16,
    status: u32,
    bytes: String,
}

fn field(value: &Value, key: &str) -> Result<u64, String> {
    memory::number(
        value[key]
            .as_str()
            .ok_or_else(|| format!("missing field {key}"))?,
    )
}

fn kind_name(kind: u64) -> &'static str {
    match kind {
        EVENT_CONTEXT => "context",
        EVENT_WATCH => "watch",
        EVENT_EXCEPTION | EVENT_SOFTWARE_EXCEPTION => "exception",
        EVENT_ENTRY => "entry",
        EVENT_RETURN => "return",
        EVENT_ABANDON => "abandon",
        EVENT_UNMATCHED => "unmatched",
        _ => "unknown",
    }
}

fn decode(record: &[u8]) -> Result<Value, String> {
    if record.len() != EVENT_RECORD_BYTES {
        return Err("invalid event record size".into());
    }
    let context = memory::context_json(record);
    let mut offset = EVENT_RECORD_HEADER;
    let mut segments = Vec::new();
    for capacity in [EVENT_CODE_BYTES, EVENT_STACK_BYTES]
        .into_iter()
        .chain([EVENT_REGION_BYTES; EVENT_REGIONS])
    {
        let segment = &record[offset..offset + EVENT_SEGMENT_HEADER + capacity];
        let requested = u16::from_le_bytes([segment[8], segment[9]]);
        let captured = u16::from_le_bytes([segment[10], segment[11]]);
        if captured > requested || usize::from(requested) > capacity {
            return Err("invalid event segment length".into());
        }
        segments.push(Segment {
            address: output::hex(quad(segment, 0)),
            requested,
            status: word(segment, 12),
            bytes: analysis_cli::hex_bytes(&segment[16..16 + usize::from(captured)]),
        });
        offset += segment.len();
    }
    let metadata = &record[CONTEXT_RECORD_BYTES..];
    let kind = quad(metadata, 0);
    let detail = quad(metadata, 24);
    let auxiliary = quad(metadata, 32);
    let address = quad(metadata, 48);
    let mut data = json!({
        "type": "event", "kind": kind_name(kind), "context": context,
        "invocation": output::hex(quad(metadata, 8)), "parent": output::hex(quad(metadata, 16)),
        "source_sequence": output::hex(quad(metadata, 40)), "address": output::hex(address),
        "detail": output::hex(detail), "auxiliary": output::hex(auxiliary),
        "memory_consistency": "captured_at_vm_exit", "segments": segments,
    });
    if kind == EVENT_SOFTWARE_EXCEPTION {
        data["exception"] = json!({"source": "windows_dispatch", "record_available": detail != u64::MAX,
            "code": (detail != u64::MAX).then(|| output::hex(detail)),
            "flags": (detail != u64::MAX).then(|| output::hex(auxiliary)),
            "address": (detail != u64::MAX).then(|| output::hex(address))});
    } else if kind == EVENT_EXCEPTION {
        data["exception"] = json!({"source": "vmx", "vector": detail & 255, "interruption_type": (detail >> 8) & 7,
            "error_code": (detail & (1 << 11) != 0).then_some(auxiliary),
            "fault_address": (detail & 255 == 14).then(|| output::hex(address))});
    }
    Ok(data)
}

struct Snapshot(Vec<(u64, Vec<u8>)>);

impl Snapshot {
    fn parse(event: &Value) -> Result<Self, String> {
        let segments: Vec<Segment> =
            serde_json::from_value(event["segments"].clone()).map_err(|error| error.to_string())?;
        if segments.len() != 2 + EVENT_REGIONS {
            return Err("invalid snapshot segment count".into());
        }
        let mut regions = Vec::new();
        for (index, segment) in segments.into_iter().enumerate() {
            let capacity = [EVENT_CODE_BYTES, EVENT_STACK_BYTES]
                .get(index)
                .copied()
                .unwrap_or(EVENT_REGION_BYTES);
            let address = memory::number(&segment.address)?;
            if segment.bytes.len() % 2 != 0
                || segment.bytes.len() / 2 > usize::from(segment.requested)
                || usize::from(segment.requested) > capacity
                || address.checked_add(u64::from(segment.requested)).is_none()
            {
                return Err("invalid snapshot byte range".into());
            }
            let bytes = segment
                .bytes
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    std::str::from_utf8(pair)
                        .ok()
                        .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                        .ok_or_else(|| "invalid snapshot hex data".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            regions.push((address, bytes));
        }
        Ok(Self(regions))
    }
}

impl user::MemoryReader for Snapshot {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        while bytes.len() < length {
            let position = address
                .checked_add(bytes.len() as u64)
                .ok_or("snapshot address overflow")?;
            let Some((base, region)) = self
                .0
                .iter()
                .find(|(base, data)| position >= *base && position - *base < data.len() as u64)
            else {
                break;
            };
            let start = (position - base) as usize;
            let count = (length - bytes.len()).min(region.len() - start);
            bytes.extend_from_slice(&region[start..start + count]);
        }
        if length != 0 && bytes.is_empty() {
            return Err(format!(
                "address {address:#x} is outside the captured bytes"
            ));
        }
        Ok(bytes)
    }
}

#[derive(Default)]
pub(crate) struct Analysis {
    disasm: bool,
    unwind: bool,
    frames: usize,
    catalog: Catalog,
}

impl Analysis {
    pub(crate) fn apply(&self, event: &mut Value) -> Result<(), String> {
        if !self.disasm && !self.unwind {
            return Ok(());
        }
        let mut snapshot = Snapshot::parse(event)?;
        let context = &event["context"];
        let rip = field(context, "rip")?;
        let rsp = field(context, "rsp")?;
        let cpl = field(context, "cpl")?;
        let mut registers = [0; 16];
        for (index, name) in [
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15",
        ]
        .into_iter()
        .enumerate()
        {
            registers[index] = field(context, name)?;
        }
        if self.disasm {
            event["instructions"] = analysis_cli::instructions_json(&user::disassemble(
                &self.catalog.modules,
                rip,
                &snapshot.0[0].1,
                8,
            ));
        }
        if self.unwind {
            if cpl != 3 {
                return Err("captured unwind requires a native user-mode context".into());
            }
            let mut tables = self.catalog.dynamic.clone();
            let mut discovery_error = None;
            if let Some(head) = self.catalog.dynamic_list {
                match unwind::dynamic_tables(&mut snapshot, head) {
                    Ok(discovered) => tables.extend(discovered),
                    Err(error) => discovery_error = Some(error),
                }
            }
            let result = unwind::unwind_with_tables(
                &mut snapshot,
                &self.catalog.modules,
                &tables,
                UnwindContext {
                    rip,
                    rsp,
                    registers,
                },
                self.frames,
                true,
            );
            event["unwind"] = json!({"frames": result.frames.iter().map(|frame| json!({
                "rip": output::hex(frame.rip), "rsp": output::hex(frame.rsp), "symbol": frame.symbol,
                "method": frame.method,
            })).collect::<Vec<_>>(), "stop": result.stop, "complete": result.complete,
                "dynamic_list_error": discovery_error,
                "memory_consistency": "captured_at_vm_exit", "module_catalog": "collection_start",
            });
        }
        Ok(())
    }
}

fn take(
    arguments: &mut Vec<String>,
    option: &str,
    count: usize,
) -> Result<Option<Vec<String>>, String> {
    let Some(index) = arguments.iter().position(|value| value == option) else {
        return Ok(None);
    };
    if arguments.len() - index <= count {
        return Err(format!("{option} requires {count} value(s)"));
    }
    Ok(Some(
        arguments.drain(index..=index + count).skip(1).collect(),
    ))
}

fn value(arguments: &mut Vec<String>, option: &str) -> Result<Option<String>, String> {
    Ok(take(arguments, option, 1)?.and_then(|mut values| values.pop()))
}

fn flag(arguments: &mut Vec<String>, option: &str) -> bool {
    arguments
        .iter()
        .position(|value| value == option)
        .is_some_and(|index| {
            arguments.remove(index);
            true
        })
}

fn numeric(arguments: &mut Vec<String>, option: &str) -> Result<Option<u64>, String> {
    value(arguments, option)?
        .as_deref()
        .map(memory::number)
        .transpose()
}

pub(crate) fn analysis(arguments: &mut Vec<String>) -> Result<Analysis, String> {
    let mut analysis = Analysis {
        disasm: flag(arguments, "--disasm"),
        unwind: flag(arguments, "--unwind"),
        frames: numeric(arguments, "--frames")?
            .unwrap_or(32)
            .try_into()
            .map_err(|_| "invalid frame limit")?,
        ..Analysis::default()
    };
    if !(1..=STACK_MAX_FRAMES).contains(&analysis.frames) {
        return Err("--frames must be 1..64".into());
    }
    analysis.catalog.dynamic_list = numeric(arguments, "--dynamic-list")?;
    while let Some(values) = take(arguments, "--table", 5)? {
        let values = values
            .iter()
            .map(|value| memory::number(value))
            .collect::<Result<Vec<_>, _>>()?;
        let table = DynamicTable {
            base: values[0],
            start: values[1],
            end: values[2],
            address: values[3],
            count: values[4].try_into().map_err(|_| "invalid table count")?,
            kind: 0,
        };
        table.validate()?;
        analysis.catalog.dynamic.push(table);
    }
    Ok(analysis)
}

fn request(request: InterceptionRequest) -> Result<Vec<u8>, String> {
    let mut bytes = interception_packet(&request)?;
    for attempt in 0..5 {
        let result = memory::invoke(&mut bytes);
        if result.is_ok() || word(&bytes, 40) != Error::Busy as u32 || attempt == 4 {
            return result.map(|()| bytes);
        }
        std::thread::sleep(Duration::from_millis(1));
        bytes = interception_packet(&request)?;
    }
    unreachable!()
}

pub(crate) fn available() -> Result<bool, String> {
    let mut info = neo::memory::info_packet()?;
    memory::invoke(&mut info)?;
    Ok(word(&info, 72) & EVENT_CAPABILITY != 0)
}

struct Batch {
    next: u64,
    oldest: u64,
    dropped: u64,
    records: Vec<Value>,
}

fn fetch(token: u64, cpu: u32, cursor: u64) -> Result<Batch, String> {
    let probe = request(InterceptionRequest {
        operation: EVENT_FETCH,
        token,
        cpu,
        cursor,
        ..Default::default()
    })?;
    let oldest = quad(&probe, 96);
    let head = quad(&probe, 104);
    let pending = head.saturating_sub(cursor.max(oldest.saturating_sub(1)));
    if pending == 0 {
        return Ok(Batch {
            next: cursor,
            oldest,
            dropped: quad(&probe, 120),
            records: Vec::new(),
        });
    }
    let bytes = request(InterceptionRequest {
        operation: EVENT_FETCH,
        token,
        cpu,
        cursor,
        count: pending.min(EVENT_FETCH_MAX as u64) as usize,
        ..Default::default()
    })?;
    let count = word(&bytes, 32) as usize;
    if count > EVENT_FETCH_MAX {
        return Err("invalid event response count".into());
    }
    let records = bytes[HEADER_BYTES..]
        .chunks_exact(EVENT_RECORD_BYTES)
        .take(count)
        .map(decode)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Batch {
        next: quad(&bytes, 88),
        oldest: quad(&bytes, 96),
        dropped: quad(&bytes, 120),
        records,
    })
}

pub(crate) fn retained(token: u64, cpu: u32, kind: u64) -> Result<Vec<Value>, String> {
    let mut cursor = 0;
    let mut records = Vec::new();
    for _ in 0..EVENT_RING_RECORDS.div_ceil(EVENT_FETCH_MAX) {
        let batch = fetch(token, cpu, cursor)?;
        let full = batch.records.len() == EVENT_FETCH_MAX;
        cursor = batch.next;
        records.extend(
            batch
                .records
                .into_iter()
                .filter(|event| event["kind"] == kind_name(kind)),
        );
        if !full {
            break;
        }
    }
    Ok(records)
}

pub(crate) fn attach(
    bytes: &[u8],
    request: &InterceptionRequest,
    options: &TargetOptions,
    mut analysis: Analysis,
) -> Result<Value, String> {
    let mut data = memory::observation_json(bytes, request.operation)?;
    let records = data["records"]
        .as_array_mut()
        .ok_or("missing observation records")?;
    let captured = retained(
        request.token,
        request.cpu,
        if request.operation == WATCH_FETCH {
            EVENT_WATCH
        } else {
            EVENT_CONTEXT
        },
    )?;
    let process = records
        .first()
        .map(|record| field(record, "cr3"))
        .transpose()?
        .map(|root| analysis.load_catalog(options, root))
        .transpose()?
        .flatten();
    for record in records {
        let Some(mut event) = captured
            .iter()
            .find(|event| {
                event["source_sequence"] == record["sequence"]
                    && event["context"]["tsc"] == record["tsc"]
                    && event["context"]["cr3"] == record["cr3"]
            })
            .cloned()
        else {
            record["analysis_error"] =
                json!("event bytes are outside the retained snapshot window");
            continue;
        };
        let root = field(record, "cr3")?;
        if process.is_some_and(|(kernel, user)| root != kernel && root != user) {
            record["analysis_error"] =
                json!("captured CR3 does not belong to the selected process");
            continue;
        }
        if let Err(error) = analysis.apply(&mut event) {
            event["analysis_error"] = json!(error);
        }
        if process.is_some() {
            record["symbol"] = json!(user::symbolize(
                &analysis.catalog.modules,
                field(record, "rip")?
            ));
        }
        record["snapshot"] = event;
    }
    data["memory_consistency"] = json!("captured_at_vm_exit");
    Ok(data)
}

impl Analysis {
    fn load_catalog(
        &mut self,
        options: &TargetOptions,
        root: u64,
    ) -> Result<Option<(u64, u64)>, String> {
        let Some(selector) = options.selector.as_deref() else {
            return Ok(None);
        };
        let (_, process) = options.load(selector, root)?;
        if root != process.user_root() && root != process.kernel_cr3 {
            return Err("captured CR3 does not belong to the selected process".into());
        }
        self.catalog.modules = analysis_cli::load_modules(&process)?;
        if self.catalog.dynamic_list.is_none() {
            let mut reader = |address, length| {
                Ok(neo::memory::read_ranges(process.user_root(), &[(address, length)])?.remove(0))
            };
            self.catalog.dynamic_list =
                unwind::dynamic_list_head(&mut reader, &self.catalog.modules).ok();
        }
        Ok(Some((process.kernel_cr3, process.user_root())))
    }

    pub(crate) fn captured_stack(
        mut self,
        token: u64,
        cpu: u32,
        sequence: u64,
        count: usize,
        options: &TargetOptions,
    ) -> Result<i32, String> {
        let cached = request(InterceptionRequest {
            operation: CONTEXT_RECORD_GET,
            token,
            cpu,
            cursor: sequence,
            count: 1,
            ..Default::default()
        })?;
        let context = memory::context_json(&cached[HEADER_BYTES..]);
        let mut event = retained(token, cpu, EVENT_CONTEXT)?
            .into_iter()
            .find(|event| {
                event["source_sequence"] == context["sequence"]
                    && event["context"]["tsc"] == context["tsc"]
                    && event["context"]["cr3"] == context["cr3"]
            })
            .ok_or("context memory is outside the retained snapshot window")?;
        self.frames = count;
        self.load_catalog(options, field(&event["context"], "cr3")?)?;
        self.apply(&mut event)?;
        let incomplete = event["unwind"]["complete"] != true;
        if incomplete && output::is_json() {
            output::partial(
                event,
                "UNWIND_PARTIAL",
                "stack walk stopped at the recorded boundary",
            )?;
        } else {
            report(event)?;
        }
        Ok(i32::from(incomplete))
    }

    pub(crate) fn live_tables(
        &self,
        reader: &mut impl user::MemoryReader,
        modules: &[Module],
    ) -> Result<Vec<DynamicTable>, String> {
        let mut tables = self.catalog.dynamic.clone();
        if let Some(head) = self.catalog.dynamic_list {
            tables.extend(unwind::dynamic_tables(reader, head)?);
        } else if let Ok(head) = unwind::dynamic_list_head(reader, modules)
            && let Ok(discovered) = unwind::dynamic_tables(reader, head)
        {
            tables.extend(discovered);
        }
        Ok(tables)
    }
}

fn active(token: u64, bytes: &[u8]) -> Result<(), String> {
    if quad(bytes, 80) != token || word(bytes, 112) != INTERCEPT_ACTIVE {
        return Err(format!(
            "capture session ended or token changed (cause {})",
            word(bytes, 116)
        ));
    }
    Ok(())
}

fn setup(arguments: &mut Vec<String>) -> Result<i32, String> {
    let options = TargetOptions::extract(arguments)?;
    let no_lease = flag(arguments, "--no-lease");
    let mut setup = InterceptionRequest {
        operation: EVENT_SET,
        event_sample: flag(arguments, "--sample"),
        flags: if no_lease { INTERCEPT_NO_LEASE } else { 0 },
        event_exceptions: numeric(arguments, "--exceptions")?.unwrap_or(0),
        alternate_cr3: numeric(arguments, "--alternate-cr3")?.unwrap_or(0),
        lease_ms: numeric(arguments, "--lease-ms")?
            .unwrap_or(0)
            .try_into()
            .map_err(|_| "invalid lease")?,
        ..Default::default()
    };
    let mut regions = Vec::new();
    while let Some(values) = take(arguments, "--region", 2)? {
        regions.push((values[0].clone(), memory::number(&values[1])?));
    }
    let mut probes = Vec::new();
    for (option, kind) in [
        ("--entry", EVENT_ENTRY),
        ("--return", EVENT_RETURN),
        ("--exception-dispatch", EVENT_SOFTWARE_EXCEPTION),
    ] {
        while let Some(address) = value(arguments, option)? {
            probes.push((address, kind));
        }
    }
    let [cr3, token] = arguments.as_slice() else {
        return Err("usage: neo session set CR3 TOKEN [--sample] [--exceptions MASK] [--region ADDRESS SIZE] [--entry ADDRESS --return ADDRESS]".into());
    };
    setup.cr3 = memory::number(cr3)?;
    setup.token = memory::number(token)?;
    if setup.token != 0 {
        let status = request(InterceptionRequest {
            operation: INTERCEPT_STATUS,
            ..Default::default()
        })?;
        active(setup.token, &status)?;
        if setup.alternate_cr3 == 0 {
            setup.alternate_cr3 = quad(&status, 64);
        }
        if !no_lease && setup.lease_ms == 0 {
            setup.lease_ms = word(&status, 132);
            if setup.lease_ms == 0 {
                setup.flags |= INTERCEPT_NO_LEASE;
            }
        }
    }
    let modules = if let Some(selector) = options.selector.as_deref() {
        let (_, process) = options.load(selector, setup.cr3)?;
        analysis_cli::load_modules(&process)?
    } else {
        Vec::new()
    };
    let resolve = |address: String| user::resolve_address(&modules, &address);
    for (address, length) in regions {
        setup.event_regions.push((resolve(address)?, length));
    }
    for (address, kind) in probes {
        setup.event_probes.push((resolve(address)?, kind));
    }
    let bytes = request(setup)?;
    report(memory::interception_json(&bytes)?)
}

fn report(data: Value) -> Result<i32, String> {
    if output::is_json() {
        output::success(data)?;
    } else {
        output::write(&data)?;
    }
    Ok(0)
}

fn write_row(writer: &mut impl Write, value: &Value) -> Result<(), String> {
    serde_json::to_writer(&mut *writer, value).map_err(|error| error.to_string())?;
    writer.write_all(b"\n").map_err(|error| error.to_string())
}

struct RecordingLease {
    stop: std::sync::mpsc::Sender<()>,
    failures: std::sync::mpsc::Receiver<String>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl RecordingLease {
    fn renew(token: u64, lease_ms: u32) -> Result<u32, String> {
        let bytes = request(InterceptionRequest {
            operation: if lease_ms == 0 {
                INTERCEPT_STATUS
            } else {
                INTERCEPT_RENEW
            },
            token,
            ..Default::default()
        })?;
        active(token, &bytes)?;
        Ok(word(&bytes, 132))
    }

    fn start(token: u64, lease_ms: u32) -> Result<Self, String> {
        let mut lease_ms = Self::renew(token, lease_ms)?;
        let (stop, stopped) = std::sync::mpsc::channel();
        let (failure, failures) = std::sync::mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("neo-recording-lease".into())
            .spawn(move || {
                loop {
                    let delay = Duration::from_millis(if lease_ms == 0 {
                        1000
                    } else {
                        u64::from(lease_ms / 3).max(1)
                    });
                    if stopped.recv_timeout(delay)
                        != Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    {
                        break;
                    }
                    match Self::renew(token, lease_ms) {
                        Ok(duration) => lease_ms = duration,
                        Err(error) => {
                            let _ = failure.send(error);
                            break;
                        }
                    }
                }
            })
            .map_err(|error| format!("cannot start lease renewal: {error}"))?;
        Ok(Self {
            stop,
            failures,
            worker: Some(worker),
        })
    }

    fn check(&self) -> Result<(), String> {
        match self.failures.try_recv() {
            Ok(error) => Err(error),
            Err(std::sync::mpsc::TryRecvError::Empty) => Ok(()),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Err("lease renewal stopped".into()),
        }
    }
}

impl Drop for RecordingLease {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn record(mut arguments: Vec<String>, watch: bool) -> Result<i32, String> {
    let mut analysis = analysis(&mut arguments)?;
    let target = TargetOptions::extract(&mut arguments)?;
    let path = value(&mut arguments, "--output")?.ok_or("record requires --output FILE.jsonl")?;
    let seconds = numeric(&mut arguments, "--seconds")?;
    let interval = numeric(&mut arguments, "--interval-ms")?.unwrap_or(25);
    let cpu = numeric(&mut arguments, "--cpu")?;
    let [token] = arguments.as_slice() else {
        return Err("record requires TOKEN".into());
    };
    let token = memory::number(token)?;
    if seconds.is_some_and(|seconds| !(1..=86_400).contains(&seconds))
        || !(1..=1000).contains(&interval)
        || cpu.is_some_and(|cpu| cpu >= 64)
    {
        return Err("invalid recording duration, interval or CPU".into());
    }
    let status = request(InterceptionRequest {
        operation: INTERCEPT_STATUS,
        ..Default::default()
    })?;
    active(token, &status)?;
    let root = quad(&status, 16);
    let alternate = quad(&status, 64);
    let lease = RecordingLease::start(token, word(&status, 132))?;
    analysis.load_catalog(&target, root)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("{path}: {error}"))?;
    let mut writer = BufWriter::new(file);
    write_row(
        &mut writer,
        &json!({"type": "session", "format": FORMAT, "token": output::hex(token),
        "cr3": output::hex(root), "alternate_cr3": output::hex(alternate), "catalog": analysis.catalog,
        "started_unix_ms": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
        "kind": if watch { "watch" } else { "all" }}),
    )?;
    writer.flush().map_err(|error| error.to_string())?;
    let start = Instant::now();
    let mut cursors = [0; 64];
    let mut drops = [0; 64];
    let mut written = 0u64;
    let mut gaps = 0u64;
    let result = (|| -> Result<(), String> {
        loop {
            lease.check()?;
            let final_pass =
                seconds.is_some_and(|seconds| start.elapsed() >= Duration::from_secs(seconds));
            for index in 0..64 {
                if cpu.is_some_and(|cpu| cpu != index as u64) {
                    continue;
                }
                // A bounded drain keeps other CPUs and the lease renewal responsive.
                for _ in 0..EVENT_RING_RECORDS.div_ceil(EVENT_FETCH_MAX) {
                    lease.check()?;
                    let batch = fetch(token, index as u32, cursors[index])?;
                    if batch.oldest > cursors[index].saturating_add(1)
                        || batch.dropped != drops[index]
                    {
                        write_row(
                            &mut writer,
                            &json!({"type": "gap", "cpu": output::hex(index as u64),
                            "after": output::hex(cursors[index]), "oldest": output::hex(batch.oldest),
                            "dropped_total": output::hex(batch.dropped)}),
                        )?;
                        gaps += 1;
                    }
                    drops[index] = batch.dropped;
                    cursors[index] = batch.next;
                    let full = batch.records.len() == EVENT_FETCH_MAX;
                    for mut event in batch.records {
                        if watch && event["kind"] != "watch" {
                            continue;
                        }
                        lease.check()?;
                        if let Err(error) = analysis.apply(&mut event) {
                            event["analysis_error"] = json!(error);
                        }
                        write_row(&mut writer, &event)?;
                        written += 1;
                    }
                    if !full {
                        break;
                    }
                }
            }
            writer.flush().map_err(|error| error.to_string())?;
            if final_pass {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(interval));
        }
    })();
    write_row(
        &mut writer,
        &json!({"type": "end", "events": output::hex(written), "gaps": output::hex(gaps),
        "complete": result.is_ok(), "error": result.as_ref().err()}),
    )?;
    writer.flush().map_err(|error| error.to_string())?;
    result?;
    report(json!({"output": path, "events": output::hex(written), "gaps": output::hex(gaps)}))
}

fn query(mut arguments: Vec<String>, tree: bool) -> Result<i32, String> {
    let mut analysis = analysis(&mut arguments)?;
    let kind = value(&mut arguments, "--kind")?;
    let cpu = numeric(&mut arguments, "--cpu")?;
    let teb = numeric(&mut arguments, "--thread-teb")?;
    let sequence = numeric(&mut arguments, "--sequence")?;
    let invocation = numeric(&mut arguments, "--invocation")?;
    let limit = numeric(&mut arguments, "--limit")?.unwrap_or(u64::MAX);
    let [path] = arguments.as_slice() else {
        return Err("query requires FILE.jsonl".into());
    };
    let file = File::open(Path::new(path)).map_err(|error| format!("{path}: {error}"))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    let header: Value = serde_json::from_str(&line).map_err(|error| error.to_string())?;
    if header["type"] != "session" || header["format"] != FORMAT {
        return Err("unsupported investigation format".into());
    }
    let catalog: Catalog =
        serde_json::from_value(header["catalog"].clone()).map_err(|error| error.to_string())?;
    if catalog.modules.iter().any(|module| {
        module.base == 0
            || module.size == 0
            || module
                .base
                .checked_add(u64::from(module.size))
                .is_none_or(|end| end > 0x8000_0000_0000)
    }) {
        return Err("invalid module range in investigation catalog".into());
    }
    for table in &catalog.dynamic {
        table.validate()?;
    }
    analysis.catalog.modules = catalog.modules;
    if analysis.catalog.dynamic_list.is_none() {
        analysis.catalog.dynamic_list = catalog.dynamic_list;
    }
    if analysis.catalog.dynamic.is_empty() {
        analysis.catalog.dynamic = catalog.dynamic;
    }
    let mut shown = 0;
    let mut calls = std::collections::BTreeMap::new();
    let mut gaps = 0;
    let mut complete = false;
    let mut truncated = false;
    loop {
        line.clear();
        if reader
            .read_line(&mut line)
            .map_err(|error| error.to_string())?
            == 0
        {
            break;
        }
        let mut event: Value = match serde_json::from_str(&line) {
            Ok(event) => event,
            Err(_) if !line.ends_with('\n') => {
                truncated = true;
                break;
            }
            Err(error) => return Err(format!("invalid investigation row: {error}")),
        };
        match event["type"].as_str() {
            Some("gap") => {
                gaps += 1;
            }
            Some("end") => {
                complete = event["complete"] == true;
            }
            Some("event") => {
                let context = &event["context"];
                if shown >= limit
                    || kind
                        .as_ref()
                        .is_some_and(|kind| event["kind"].as_str() != Some(kind))
                    || cpu.is_some_and(|cpu| field(context, "cpu").ok() != Some(cpu))
                    || teb.is_some_and(|teb| field(context, "thread_teb").ok() != Some(teb))
                    || sequence
                        .is_some_and(|sequence| field(context, "sequence").ok() != Some(sequence))
                    || invocation.is_some_and(|id| {
                        field(&event, "invocation").ok() != Some(id)
                            && field(&event, "parent").ok() != Some(id)
                    })
                {
                    continue;
                }
                if tree {
                    if !matches!(event["kind"].as_str(), Some("entry" | "return" | "abandon")) {
                        continue;
                    }
                    let id = field(&event, "invocation")?;
                    let node = calls.entry(id).or_insert_with(|| json!({
                        "id": event["invocation"], "parent": event["parent"], "address": event["address"],
                        "thread_teb": event["context"]["thread_teb"], "status": "open", "children": [],
                    }));
                    if event["kind"] == "entry" {
                        node["entry"] = event["context"].clone();
                    } else {
                        node["end"] = event["context"].clone();
                        node["status"] = json!(if event["kind"] == "return" {
                            "returned"
                        } else {
                            "abandoned"
                        });
                    }
                } else {
                    if let Err(error) = analysis.apply(&mut event) {
                        event["analysis_error"] = json!(error);
                    }
                    report(event)?;
                }
                shown += 1;
            }
            _ => return Err("invalid investigation row type".into()),
        }
    }
    if tree {
        let relationships = calls
            .iter()
            .map(|(id, node)| Ok((*id, field(node, "parent")?)))
            .collect::<Result<Vec<_>, String>>()?;
        let mut roots = Vec::new();
        for (id, parent) in relationships {
            if let Some(node) = calls.get_mut(&parent).filter(|_| parent < id) {
                node["children"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(output::hex(id)));
            } else {
                roots.push(output::hex(id));
            }
        }
        return report(
            json!({"type": "call_tree", "roots": roots, "calls": calls.into_values().collect::<Vec<_>>(),
            "gaps": output::hex(gaps), "complete": complete, "truncated_tail": truncated}),
        );
    }
    report(
        json!({"type": "query_summary", "events": output::hex(shown), "gaps": output::hex(gaps),
        "complete": complete, "truncated_tail": truncated}),
    )
}

pub(crate) fn run(arguments: &[String]) -> Result<i32, String> {
    let watch = arguments[0] == "watch";
    if arguments.len() < 2 {
        return Err("usage: neo session set|clear|record|query".into());
    }
    let mut operands = arguments[2..].to_vec();
    if !watch && matches!(arguments[1].as_str(), "query" | "tree") {
        return query(operands, arguments[1] == "tree");
    }
    if !available()? {
        return Err("event snapshots require an updated MatrixHV EFI".into());
    }
    match arguments[1].as_str() {
        "set" if !watch => setup(&mut operands),
        "clear" if !watch && operands.len() == 1 => {
            let bytes = request(InterceptionRequest {
                operation: EVENT_CLEAR,
                token: memory::number(&operands[0])?,
                ..Default::default()
            })?;
            report(memory::interception_json(&bytes)?)
        }
        "record" => record(operands, watch),
        _ => Err(
            "usage: neo session set|clear|record|query; neo watch record TOKEN --output FILE.jsonl"
                .into(),
        ),
    }
}
