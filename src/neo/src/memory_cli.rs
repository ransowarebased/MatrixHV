#[cfg(test)]
#[path = "../../memory/access.rs"]
pub(crate) mod access;

#[cfg(test)]
#[path = "../../memory/tracking.rs"]
pub(crate) mod tracking;

#[cfg(test)]
#[path = "../../memory/interception.rs"]
pub(crate) mod interception;

#[cfg(test)]
#[path = "../../memory/observation.rs"]
pub(crate) mod observation;

use crate::protocol::memory::{
    AD_CANCEL, AD_ENABLED, AD_LARGE_PAGE, AD_RELEASE, AD_STATUS, AD_STOP, BUFFER_BYTES,
    HEADER_BYTES, ITEM_BYTES, MAX_ITEMS, READ, ROOT_HISTORY_COUNT, TRACK_ACCESSED, TRACK_DIRTY,
    TRACK_DUMP_VALID, TRACK_FETCH_PAGES, TRACK_HASH_CHANGED, TRACK_MAX_PAGES, TRACK_RECORD_BYTES,
    TRACK_REMAPPED, WRITE, quad, word,
};
use neo::memory::{
    InterceptionRequest, Item, bitmap_packet, enumerate_targets, fetch_tracking_packet,
    info_packet, invoke, resolve_process, start_tracking_packet, status_text, tracking_packet,
    transfer,
};
use neo::symbols;

pub(crate) fn number(text: &str) -> Result<u64, String> {
    let value = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        text.parse()
    };
    value.map_err(|_| format!("invalid integer: {text}; use decimal or 0x-prefixed hexadecimal"))
}

pub(crate) fn interception_packet(arguments: &[String]) -> Result<Vec<u8>, String> {
    use crate::protocol::memory::{
        DEBUG_CLEAR, DEBUG_SET, HOOK_ADD, HOOK_DROP, HOOK_INSTALL, HOOK_LIST, HOOK_REMOVE,
        INTERCEPT_CONTEXT_ADD, INTERCEPT_CONTEXT_LIST, INTERCEPT_CONTEXT_REMOVE,
        INTERCEPT_MAX_LEASE_MS, INTERCEPT_RELEASE, INTERCEPT_RENEW, INTERCEPT_STATUS,
    };
    let mut arguments = arguments.to_vec();
    let no_lease = if let Some(index) = arguments.iter().position(|value| value == "--no-lease") {
        arguments.remove(index);
        true
    } else {
        false
    };
    let data_shadow =
        if let Some(index) = arguments.iter().position(|value| value == "--data-shadow") {
            arguments.remove(index);
            true
        } else {
            false
        };
    let mut modes = 0;
    for (option, flag) in [
        (
            "--concurrent-writes",
            crate::protocol::memory::INTERCEPT_CONCURRENT_WRITES,
        ),
        (
            "--persistent-data",
            crate::protocol::memory::INTERCEPT_PERSISTENT_DATA,
        ),
    ] {
        if let Some(index) = arguments.iter().position(|value| value == option) {
            arguments.remove(index);
            modes |= flag;
        }
    }
    let timing = if let Some(index) = arguments.iter().position(|value| value == "--tsc-offset") {
        arguments.remove(index);
        true
    } else {
        false
    };
    let mut lease_ms = 0;
    if let Some(index) = arguments.iter().position(|value| value == "--lease-ms") {
        if index + 1 >= arguments.len() {
            return Err("--lease-ms requires a duration".into());
        }
        lease_ms = number(&arguments[index + 1])?;
        if lease_ms == 0 || lease_ms > u64::from(INTERCEPT_MAX_LEASE_MS) {
            return Err(format!(
                "lease must be 1..={INTERCEPT_MAX_LEASE_MS} milliseconds"
            ));
        }
        arguments.drain(index..index + 2);
    }
    let command = arguments.first().map(String::as_str);
    let action = arguments.get(1).map(String::as_str);
    let operation = match (command, action) {
        (Some("hook"), Some("install")) => HOOK_INSTALL,
        (Some("hook"), Some("add")) => HOOK_ADD,
        (Some("hook"), Some("remove")) if arguments.len() == 4 => HOOK_DROP,
        (Some("hook"), Some("remove")) => HOOK_REMOVE,
        (Some("hook"), Some("list")) => HOOK_LIST,
        (Some("hook"), Some("context-add")) => INTERCEPT_CONTEXT_ADD,
        (Some("hook"), Some("context-remove")) => INTERCEPT_CONTEXT_REMOVE,
        (Some("hook"), Some("context-list")) => INTERCEPT_CONTEXT_LIST,
        (Some("hook" | "debug-registers"), Some("renew")) => INTERCEPT_RENEW,
        (Some("hook" | "debug-registers"), Some("release")) => INTERCEPT_RELEASE,
        (Some("debug-registers"), Some("set")) => DEBUG_SET,
        (Some("debug-registers"), Some("clear")) => DEBUG_CLEAR,
        (Some("hook" | "debug-registers"), Some("status")) => INTERCEPT_STATUS,
        _ => return Err("usage: neo hook install CR3 ADDRESS HEX [...] [--alternate-cr3 CR3] [--vmfunc] [--concurrent-writes] [--persistent-data] [--lease-ms MS | --no-lease] [--tsc-offset] | hook add TOKEN ADDRESS HEX [...] | hook remove TOKEN [ID] | hook list TOKEN | hook context-add TOKEN CR3 [...] | hook context-remove TOKEN CR3 [...] | hook context-list TOKEN | hook renew TOKEN [--lease-ms MS] | hook release TOKEN | hook watch TOKEN [--lease-ms MS] | hook status; neo debug-registers set CR3 ADDRESS REDIRECT_RIP [...] [--alternate-cr3 CR3] [--lease-ms MS | --no-lease] [--tsc-offset] | debug-registers clear TOKEN | debug-registers status".into()),
    };
    if operation == INTERCEPT_STATUS && arguments.len() != 2
        || matches!(
            operation,
            HOOK_REMOVE
                | DEBUG_CLEAR
                | HOOK_LIST
                | INTERCEPT_RENEW
                | INTERCEPT_RELEASE
                | INTERCEPT_CONTEXT_LIST
        ) && arguments.len() != 3
    {
        return Err("status takes no operands; remove/clear requires the token returned by installation or status".into());
    }
    if lease_ms != 0 && !matches!(operation, HOOK_INSTALL | DEBUG_SET | INTERCEPT_RENEW) {
        return Err("--lease-ms applies to installation, debug setup or renewal".into());
    }
    if no_lease && (lease_ms != 0 || !matches!(operation, HOOK_INSTALL | DEBUG_SET)) {
        return Err("--no-lease applies only to installation or debug setup and cannot be combined with --lease-ms".into());
    }
    if timing && !matches!(operation, HOOK_INSTALL | DEBUG_SET) {
        return Err("--tsc-offset applies only to hook installation or debug setup".into());
    }
    if modes != 0 && operation != HOOK_INSTALL {
        return Err("data-view modes apply only to hook installation".into());
    }
    let mut request = InterceptionRequest {
        operation,
        lease_ms: lease_ms as u32,
        flags: modes,
        ..Default::default()
    };
    if data_shadow && !matches!(operation, HOOK_INSTALL | HOOK_ADD) {
        return Err("--data-shadow applies to hook installation or add".into());
    }
    if no_lease {
        request.flags |= crate::protocol::memory::INTERCEPT_NO_LEASE;
    }
    if timing {
        request.flags |= crate::protocol::memory::INTERCEPT_TSC_OFFSET;
    }
    if matches!(operation, INTERCEPT_CONTEXT_ADD | INTERCEPT_CONTEXT_REMOVE) {
        if arguments.len() < 4 || arguments.len() > ROOT_HISTORY_COUNT + 1 {
            return Err("context change requires TOKEN and 1..14 CR3 roots".into());
        }
        request.token = number(&arguments[2])?;
        request.contexts = arguments[3..]
            .iter()
            .map(|value| number(value))
            .collect::<Result<_, _>>()?;
    } else if operation == HOOK_ADD {
        request.token = number(arguments.get(2).ok_or("add requires a session token")?)?;
        request.items = parse_items(WRITE, &arguments[3..])?;
    } else if matches!(operation, HOOK_INSTALL | DEBUG_SET) {
        request.cr3 = number(arguments.get(2).ok_or("installation requires CR3")?)?;
        let mut operands = arguments[3..].to_vec();
        if let Some(index) = operands.iter().position(|value| value == "--vmfunc") {
            if operation != HOOK_INSTALL {
                return Err("--vmfunc applies only to hook installation".into());
            }
            operands.remove(index);
            request.flags |= crate::protocol::memory::INTERCEPT_VMFUNC;
        }
        if let Some(index) = operands.iter().position(|value| value == "--alternate-cr3") {
            let value = operands
                .get(index + 1)
                .ok_or("--alternate-cr3 requires a CR3 root")?;
            request.alternate_cr3 = number(value)?;
            if request.alternate_cr3 & !4095 == 0 {
                return Err("alternate CR3 must contain a nonzero page-table root".into());
            }
            operands.drain(index..index + 2);
        }
        if operation == HOOK_INSTALL {
            request.items = parse_items(WRITE, &operands)?;
        } else {
            if operands.is_empty() || !operands.len().is_multiple_of(2) || operands.len() > 8 {
                return Err("debug-registers requires 1..4 ADDRESS REDIRECT_RIP pairs".into());
            }
            request.redirects = operands
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| Ok((number(&pair[0])?, number(&pair[1])?)))
                .collect::<Result<_, String>>()?;
        }
    } else if matches!(
        operation,
        HOOK_REMOVE
            | HOOK_DROP
            | HOOK_LIST
            | DEBUG_CLEAR
            | INTERCEPT_RENEW
            | INTERCEPT_RELEASE
            | INTERCEPT_CONTEXT_LIST
    ) {
        request.token = number(&arguments[2])?;
        if operation == HOOK_DROP {
            request.patch_id = number(&arguments[3])?;
        }
    }
    if data_shadow {
        request.hook_flags = vec![crate::protocol::memory::HOOK_DATA_SHADOW; request.items.len()];
    }
    neo::memory::interception_packet(&request)
}

pub(crate) fn run_observation(arguments: &[String]) -> Result<i32, String> {
    use crate::protocol::memory::*;
    let mut operands = arguments.to_vec();
    let no_lease = if let Some(index) = operands.iter().position(|value| value == "--no-lease") {
        operands.remove(index);
        true
    } else {
        false
    };
    let mut request = InterceptionRequest::default();
    let command = operands.first().map(String::as_str).unwrap_or("");
    let action = operands.get(1).map(String::as_str).unwrap_or("");
    request.operation = match (command, action) {
        ("watch", "set") => WATCH_SET, ("watch", "fetch") => WATCH_FETCH, ("watch", "clear") => WATCH_CLEAR,
        ("context", "set") => CONTEXT_SET, ("context", "clear") => CONTEXT_CLEAR,
        ("context", "snapshot") => CONTEXT_SNAPSHOT, ("context", "stack") => STACK_WALK,
        ("syscall", "set") => SYSCALL_SET, ("syscall", "clear") => SYSCALL_CLEAR,
        _ => return Err("usage: neo watch set CR3 TOKEN ADDRESS write|rw LENGTH [...] [--no-lease]; watch fetch TOKEN CPU CURSOR COUNT; watch clear TOKEN; context set CR3 TOKEN [--no-lease]; context snapshot TOKEN CPU CURSOR COUNT; context stack TOKEN CPU SEQUENCE COUNT (RBP chain); context clear TOKEN; syscall set CR3 TOKEN CALLBACK LSTAR [--no-lease]; syscall clear TOKEN".into()),
    };
    if no_lease {
        if !matches!(request.operation, WATCH_SET | CONTEXT_SET | SYSCALL_SET) {
            return Err("--no-lease requires set".into());
        }
        request.flags |= INTERCEPT_NO_LEASE;
    }
    let value = |index: usize| number(operands.get(index).ok_or("missing observation operand")?);
    match request.operation {
        WATCH_SET | CONTEXT_SET | SYSCALL_SET => {
            request.cr3 = value(2)?;
            request.token = value(3)?;
            if request.operation == WATCH_SET {
                if operands.len() <= 4 || !(operands.len() - 4).is_multiple_of(3) {
                    return Err("watch set requires ADDRESS write|rw LENGTH triples".into());
                }
                for triple in operands[4..].as_chunks::<3>().0 {
                    let access = match triple[1].as_str() {
                        "write" => 1,
                        "rw" => 3,
                        _ => return Err("watch access must be write or rw".into()),
                    };
                    let length =
                        u32::try_from(number(&triple[2])?).map_err(|_| "invalid watch length")?;
                    request
                        .watchpoints
                        .push((number(&triple[0])?, access, length));
                }
            } else if request.operation == SYSCALL_SET && operands.len() == 6 {
                request.callback = value(4)?;
                request.syscall_entry = value(5)?;
            } else if request.operation != CONTEXT_SET || operands.len() != 4 {
                return Err("invalid setup operands".into());
            }
        }
        WATCH_FETCH | CONTEXT_SNAPSHOT | STACK_WALK => {
            if operands.len() != 6 {
                return Err("fetch requires TOKEN CPU CURSOR COUNT".into());
            }
            request.token = value(2)?;
            request.cpu = u32::try_from(value(3)?).map_err(|_| "invalid CPU")?;
            request.cursor = value(4)?;
            request.count = usize::try_from(value(5)?).map_err(|_| "invalid record count")?;
        }
        _ => {
            if operands.len() != 3 {
                return Err("clear requires TOKEN".into());
            }
            request.token = value(2)?;
        }
    }
    let mut bytes = neo::memory::interception_packet(&request)?;
    invoke(&mut bytes)?;
    if matches!(
        request.operation,
        WATCH_FETCH | CONTEXT_SNAPSHOT | STACK_WALK
    ) {
        let size = match request.operation {
            WATCH_FETCH => WATCH_RECORD_BYTES,
            CONTEXT_SNAPSHOT => CONTEXT_RECORD_BYTES,
            _ => 16,
        };
        println!(
            "records={} next={} oldest={} dropped={} walk_status={}",
            word(&bytes, 32),
            quad(&bytes, 88),
            quad(&bytes, 96),
            quad(&bytes, 120),
            word(&bytes, 72)
        );
        for index in 0..word(&bytes, 32) as usize {
            let record = &bytes[HEADER_BYTES + index * size..HEADER_BYTES + (index + 1) * size];
            if request.operation == STACK_WALK {
                println!("rip={:#x} rsp={:#x}", quad(record, 0), quad(record, 8));
            } else {
                println!(
                    "sequence={} tsc={} cr3={:#x} rip={:#x} rsp={:#x} rbp={:#x} rflags={:#x} gs_base={:#x} thread_teb={:#x} cpu={} cpl={}",
                    quad(record, 0),
                    quad(record, 8),
                    quad(record, 16),
                    quad(record, 24),
                    quad(record, 32),
                    quad(record, 40),
                    quad(record, 48),
                    quad(record, 56),
                    quad(record, 64),
                    quad(record, 192),
                    quad(record, 200)
                );
                for (reg, name) in [
                    "rax", "rcx", "rdx", "rbx", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
                    "r12", "r13", "r14", "r15",
                ]
                .iter()
                .enumerate()
                {
                    print!("{name}={:#x} ", quad(record, 72 + reg * 8));
                }
                println!();
                if request.operation == WATCH_FETCH {
                    println!(
                        "address={:#x} hit_count={} slot={} post_instruction={}",
                        quad(record, 208),
                        quad(record, 216),
                        quad(record, 224),
                        quad(record, 232) & WATCH_POST_INSTRUCTION != 0
                    );
                }
            }
        }
    } else {
        println!("token={} state={}", quad(&bytes, 80), word(&bytes, 112));
    }
    Ok(0)
}

pub(crate) fn run_interception(arguments: &[String]) -> Result<i32, String> {
    if arguments.get(1).is_some_and(|action| action == "watch") {
        let mut renewal = arguments.to_vec();
        renewal[1] = "renew".into();
        let template = interception_packet(&renewal)?;
        println!(
            "Renewing session {} until this process exits; the watchdog remains armed.",
            quad(&template, 80)
        );
        loop {
            let mut bytes = template.clone();
            if let Err(error) = invoke(&mut bytes) {
                if word(&bytes, 40) == crate::protocol::memory::Error::Busy as u32 {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                return Err(error);
            }
            if word(&bytes, 112) != crate::protocol::memory::INTERCEPT_ACTIVE {
                return Err("session is no longer active".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(
                (u64::from(word(&bytes, 132)) / 3).max(1),
            ));
        }
    }
    let mut bytes = interception_packet(arguments)?;
    let operation = word(&bytes, 12);
    invoke(&mut bytes)?;
    let state = match word(&bytes, 112) {
        crate::protocol::memory::INTERCEPT_DISABLED => "disabled",
        crate::protocol::memory::INTERCEPT_ACTIVE => "active",
        crate::protocol::memory::INTERCEPT_REVOKED => "revoked",
        _ => "unknown",
    };
    println!(
        "token={} cr3={:#x} alternate_cr3={:#x} hooks={} debug_targets={} hits={} state={state}",
        quad(&bytes, 80),
        quad(&bytes, 16),
        quad(&bytes, 64),
        word(&bytes, 104),
        word(&bytes, 108),
        quad(&bytes, 88)
    );
    let cause = match word(&bytes, 116) {
        crate::protocol::memory::INTERCEPT_CAUSE_NONE => "none",
        crate::protocol::memory::INTERCEPT_CAUSE_CONTEXT => "nested-or-cache-change",
        crate::protocol::memory::INTERCEPT_CAUSE_MIXED_ACCESS => {
            "instruction-fetch-and-data-on-hooked-code"
        }
        crate::protocol::memory::INTERCEPT_CAUSE_RENDEZVOUS => "cpu-rendezvous-failed",
        crate::protocol::memory::INTERCEPT_CAUSE_LEASE => "lease-expired",
        crate::protocol::memory::INTERCEPT_CAUSE_MERGE => "page-merge-conflict",
        crate::protocol::memory::INTERCEPT_CAUSE_RUNTIME => "profile-runtime-failure",
        crate::protocol::memory::INTERCEPT_CAUSE_PROGRESS => "instruction-progress-failed",
        _ => "unknown",
    };
    println!(
        "mode=dual-eptp-split-view data_exits={} write_windows={} revocation_cause={cause}",
        quad(&bytes, 96),
        quad(&bytes, 120)
    );
    println!(
        "lease_ms={} remaining_ms={} patches={} generation={}",
        word(&bytes, 132),
        quad(&bytes, 136),
        quad(&bytes, 152),
        quad(&bytes, 144)
    );
    if word(&bytes, 128) & crate::protocol::memory::INTERCEPT_NO_LEASE != 0 {
        println!("lease=disabled lifetime=explicit-release");
    }
    if word(&bytes, 128) & crate::protocol::memory::INTERCEPT_TSC_OFFSET != 0 {
        println!(
            "timing=cpu-local-tsc-offset compensated_ticks={} reference_tsc=unsupported",
            quad(&bytes, 72)
        );
    }
    println!(
        "contexts={} concurrent_writes={} persistent_data={}",
        word(&bytes, 44),
        word(&bytes, 128) & crate::protocol::memory::INTERCEPT_CONCURRENT_WRITES != 0,
        word(&bytes, 128) & crate::protocol::memory::INTERCEPT_PERSISTENT_DATA != 0
    );
    if matches!(
        operation,
        crate::protocol::memory::HOOK_INSTALL | crate::protocol::memory::HOOK_ADD
    ) {
        for index in 0..word(&bytes, 32) as usize {
            let descriptor = HEADER_BYTES + index * ITEM_BYTES;
            println!(
                "id={} address={:#x} length={}",
                quad(&bytes, descriptor + 16),
                quad(&bytes, descriptor),
                word(&bytes, descriptor + 12)
            );
        }
    } else if operation == crate::protocol::memory::HOOK_LIST {
        for index in 0..word(&bytes, 32) as usize {
            let descriptor = HEADER_BYTES + index * ITEM_BYTES;
            println!(
                "id={} address={:#x} length={}",
                quad(&bytes, descriptor),
                quad(&bytes, descriptor + 8),
                word(&bytes, descriptor + 16)
            );
        }
    } else if operation == crate::protocol::memory::INTERCEPT_CONTEXT_LIST {
        for index in 0..word(&bytes, 32) as usize {
            println!("context_cr3={:#x}", quad(&bytes, HEADER_BYTES + index * 8));
        }
    }
    if word(&bytes, 128) & crate::protocol::memory::INTERCEPT_VMFUNC != 0 {
        println!(
            "vmfunc=cooperative function=0 execute_slot={} data_slot={} data_writes=mtf",
            crate::protocol::memory::INTERCEPT_EXECUTE_SLOT,
            crate::protocol::memory::INTERCEPT_DATA_SLOT
        );
    }
    Ok(0)
}

pub(crate) fn run_bitmap(arguments: &[String]) -> Result<i32, String> {
    if matches!(
        arguments.get(1).map(String::as_str),
        Some("start" | "stop" | "dump" | "release" | "status" | "cancel")
    ) {
        return run_tracking(&arguments[1..]);
    }
    if arguments.len() != 3 && arguments.len() != 5
        || arguments.len() == 5 && arguments[3] != "--output"
    {
        return Err("usage: neo ad-bitmap GPA PAGE_COUNT [--output FILE]".into());
    }
    let start = number(&arguments[1])?;
    let page_count = usize::try_from(number(&arguments[2])?)
        .map_err(|_| "page count exceeds the host address space".to_string())?;
    let mut bytes = bitmap_packet(start, page_count)?;
    invoke(&mut bytes)?;
    let flags = word(&bytes, 72);
    if flags & AD_ENABLED == 0 {
        return Err("EPT accessed/dirty tracking is unavailable on this CPU".into());
    }
    let bitmap_bytes = page_count.div_ceil(8);
    let accessed = &bytes[HEADER_BYTES..HEADER_BYTES + bitmap_bytes];
    let dirty = &bytes[HEADER_BYTES + bitmap_bytes..];
    println!(
        "gpa={start:#x} pages={page_count} accessed={} dirty={} large_page_coverage={} scope=L1 snapshot=observational",
        accessed.iter().map(|byte| byte.count_ones()).sum::<u32>(),
        dirty.iter().map(|byte| byte.count_ones()).sum::<u32>(),
        flags & AD_LARGE_PAGE != 0,
    );
    if let Some(path) = arguments.get(4) {
        std::fs::write(path, &bytes).map_err(|error| format!("cannot save A/D bitmap: {error}"))?;
        println!("output={path}");
    } else {
        for (name, bitmap) in [("accessed", accessed), ("dirty", dirty)] {
            print!("{name}=");
            for byte in bitmap {
                print!("{byte:02x}");
            }
            println!();
        }
    }
    Ok(0)
}

fn start_tracking(arguments: &[String]) -> Result<i32, String> {
    let mut pid = None;
    let mut cr3 = None;
    let mut gva = None;
    let mut pages = None;
    let mut kernel_cr3 = 0;
    let mut image = None;
    let mut cache = None;
    let mut index = 1;
    while index < arguments.len() {
        let option = &arguments[index];
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{option} requires a value"))?;
        match option.as_str() {
            "--pid" => pid = Some(number(value)?),
            "--cr3" => cr3 = Some(number(value)?),
            "--gva" => gva = Some(number(value)?),
            "--pages" => {
                pages = Some(usize::try_from(number(value)?).map_err(|_| "page count overflow")?)
            }
            "--kernel-cr3" => kernel_cr3 = number(value)?,
            "--kernel-image" => image = Some(std::path::PathBuf::from(value)),
            "--symbols" => cache = Some(std::path::PathBuf::from(value)),
            _ => return Err(format!("unknown tracking option: {option}")),
        }
        index += 2;
    }
    if pid.is_some() == cr3.is_some() || pid == Some(0) || gva.is_some() != pages.is_some() {
        return Err("start requires either --pid PID or --cr3 CR3; supply --gva GVA and --pages COUNT together".into());
    }
    if let (Some(address), Some(count)) = (gva, pages)
        && (address & 4095 != 0
            || count == 0
            || count > TRACK_MAX_PAGES
            || address.checked_add(count as u64 * 4096).is_none())
    {
        return Err(format!(
            "tracking range requires an aligned GVA and 1..={TRACK_MAX_PAGES} pages"
        ));
    }
    let (kernel_root, user_root) = if let Some(pid) = pid {
        let mut info = info_packet()?;
        invoke(&mut info)?;
        let mut roots = vec![kernel_cr3, quad(&info, 64), quad(&info, 48)];
        roots.extend((0..ROOT_HISTORY_COUNT).map(|entry| quad(&info, HEADER_BYTES + entry * 8)));
        roots.retain(|root| root & !4095 != 0);
        roots.sort_unstable();
        roots.dedup();
        let image = image
            .map(Ok)
            .unwrap_or_else(symbols::default_kernel_image)?;
        let cache = cache.map(Ok).unwrap_or_else(symbols::default_cache)?;
        let database = symbols::KernelSymbols::load(&image, &cache)?;
        let process = database.resolve(&pid.to_string(), 0, &roots, quad(&info, 56))?;
        (
            process.kernel_cr3,
            if process.user_cr3 == 0 {
                process.kernel_cr3
            } else {
                process.user_cr3
            },
        )
    } else {
        let root = cr3.ok_or("tracking requires a CR3 root")?;
        if root & !4095 == 0 || gva.is_none() {
            return Err("--cr3 requires a nonzero root, --gva and --pages".into());
        }
        (root, root)
    };
    let targets = if let (Some(address), Some(count)) = (gva, pages) {
        (0..count)
            .map(|page| {
                let address = address + page as u64 * 4096;
                (
                    if address >> 63 != 0 {
                        kernel_root
                    } else {
                        user_root
                    },
                    address,
                )
            })
            .collect()
    } else {
        enumerate_targets(user_root)?
    };
    let mut bytes = start_tracking_packet(pid.unwrap_or(0), &targets)?;
    invoke(&mut bytes)?;
    println!(
        "session={} state=ACTIVE pages={} t0={} scope=L1 precision=4096",
        quad(&bytes, 80),
        word(&bytes, 108),
        quad(&bytes, 88)
    );
    Ok(0)
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn verify_dump(record: &[u8]) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    if record.len() != TRACK_RECORD_BYTES {
        return Err("invalid tracking record size".into());
    }
    if word(record, 48) & TRACK_DUMP_VALID != 0 {
        let digest = Sha256::digest(&record[120..]);
        if digest[..] != record[88..120] {
            return Err("dirty page SHA-256 verification failed".into());
        }
    }
    Ok(())
}

pub(crate) fn dump_tracking(
    session: u64,
    directory: &std::path::Path,
    mut submit: impl FnMut(&mut [u8]) -> Result<(), String>,
) -> Result<i32, String> {
    use std::io::Write;
    let mut status = tracking_packet(AD_STOP, session, 0)?;
    submit(&mut status)?;
    if let Some(parent) = directory
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::create_dir(directory).map_err(|error| {
        format!("dump directory must be new: {error}; frozen session remains available")
    })?;
    let mut manifest = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("pages.jsonl"))
        .map_err(|error| error.to_string())?;
    let total = word(&status, 108) as usize;
    if total == 0 || total > TRACK_MAX_PAGES {
        return Err("invalid stopped session size".into());
    }
    let mut first = 0;
    let mut accessed_bitmap = vec![0u8; total.div_ceil(8)];
    let mut dirty_bitmap = vec![0u8; total.div_ceil(8)];
    let mut dirty = 0;
    let mut remapped = 0;
    let mut failed = false;
    while first < total {
        let requested = (total - first).min(TRACK_FETCH_PAGES);
        let mut bytes = fetch_tracking_packet(session, first, requested)?;
        submit(&mut bytes)?;
        let count = word(&bytes, 32) as usize;
        if count != requested {
            return Err("incomplete frozen session response".into());
        }
        for index in 0..count {
            let offset = HEADER_BYTES + index * TRACK_RECORD_BYTES;
            let record = &bytes[offset..offset + TRACK_RECORD_BYTES];
            verify_dump(record)?;
            let flags = word(record, 48);
            let page_index = first + index;
            if flags & TRACK_ACCESSED != 0 {
                accessed_bitmap[page_index / 8] |= 1 << (page_index & 7);
            }
            if flags & TRACK_DIRTY != 0 {
                dirty_bitmap[page_index / 8] |= 1 << (page_index & 7);
            }
            let status = word(record, 52);
            dirty += usize::from(flags & TRACK_DIRTY != 0);
            remapped += usize::from(flags & TRACK_REMAPPED != 0);
            failed |= status != 0;
            let filename = if flags & TRACK_DUMP_VALID != 0 {
                let name = format!("page-{:04}-{:016x}.bin", first + index, quad(record, 8));
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(directory.join(&name))
                    .map_err(|error| error.to_string())?;
                file.write_all(&record[120..])
                    .map_err(|error| error.to_string())?;
                file.sync_all().map_err(|error| error.to_string())?;
                name
            } else {
                String::new()
            };
            writeln!(manifest,
                "{{\"index\":{},\"cr3\":{},\"gva\":{},\"initial_gpa\":{},\"current_gpa\":{},\"pte_fingerprint\":{},\"current_fingerprint\":{},\"flags\":{},\"status\":{},\"hash_changed\":{},\"initial_sha256\":\"{}\",\"sha256\":\"{}\",\"dump\":\"{}\"}}",
                first + index, quad(record, 0), quad(record, 8), quad(record, 16), quad(record, 24),
                quad(record, 32), quad(record, 40), flags, status, flags & TRACK_HASH_CHANGED != 0,
                hex_bytes(&record[56..88]), hex_bytes(&record[88..120]), filename)
                .map_err(|error| error.to_string())?;
        }
        first += count;
    }
    manifest.sync_all().map_err(|error| error.to_string())?;
    std::fs::write(directory.join("accessed.bin"), accessed_bitmap)
        .map_err(|error| error.to_string())?;
    std::fs::write(directory.join("dirty.bin"), dirty_bitmap).map_err(|error| error.to_string())?;
    std::fs::write(directory.join("session.txt"), format!("session={session}\npid={}\npages={total}\nt0={}\nt1={}\nscope=L1\nprecision=4096\ndirty={dirty}\nremapped={remapped}\n",
        quad(&status, 24), quad(&status, 88), quad(&status, 96))).map_err(|error| error.to_string())?;
    let mut release = tracking_packet(AD_RELEASE, session, 0)?;
    submit(&mut release)?;
    println!(
        "session={session} state=IDLE captured_state=STOPPED pages={total} dirty={dirty} remapped={remapped} output={}",
        directory.display()
    );
    if remapped != 0 {
        eprintln!(
            "tracking warning: {remapped} page mappings changed; their frames were excluded from the dump"
        );
    }
    Ok(i32::from(failed))
}

fn run_tracking(arguments: &[String]) -> Result<i32, String> {
    match arguments[0].as_str() {
        "start" => start_tracking(arguments),
        "status" if arguments.len() == 1 => {
            let mut bytes = tracking_packet(AD_STATUS, 0, 0)?;
            invoke(&mut bytes)?;
            println!("session={} state={} pages={} t0={} t1={} split_tables={}",
                quad(&bytes, 80), word(&bytes, 104), word(&bytes, 108), quad(&bytes, 88), quad(&bytes, 96), word(&bytes, 112));
            Ok(0)
        }
        "release" | "cancel" if arguments.len() == 2 => {
            let operation = if arguments[0] == "cancel" { AD_CANCEL } else { AD_RELEASE };
            let mut bytes = tracking_packet(operation, number(&arguments[1])?, 0)?;
            invoke(&mut bytes)?;
            Ok(0)
        }
        "stop" | "dump" if arguments.len() == 4 && arguments[2] == "--output" => {
            dump_tracking(number(&arguments[1])?, std::path::Path::new(&arguments[3]), invoke)
        }
        "stop" if arguments.len() == 2 => {
            let mut bytes = tracking_packet(AD_STOP, number(&arguments[1])?, 0)?;
            invoke(&mut bytes)?;
            println!("session={} state=STOPPED pages={} t0={} t1={}; use dump SESSION --output DIRECTORY to export",
                quad(&bytes, 80), word(&bytes, 108), quad(&bytes, 88), quad(&bytes, 96));
            Ok(0)
        }
        _ => Err("usage: neo ad-bitmap start (--pid PID [--gva GVA --pages COUNT] | --cr3 CR3 --gva GVA --pages COUNT); stop SESSION [--output DIRECTORY]; dump SESSION --output DIRECTORY; release SESSION; cancel SESSION; status".into()),
    }
}

pub(crate) fn parse_items(operation: u32, arguments: &[String]) -> Result<Vec<Item>, String> {
    if !arguments.len().is_multiple_of(2) {
        return Err("memory items require ADDRESS SIZE or ADDRESS HEX pairs".into());
    }
    if arguments.len() / 2 > MAX_ITEMS {
        return Err(format!("memory batches support at most {MAX_ITEMS} items"));
    }
    let mut total = HEADER_BYTES + arguments.len() / 2 * ITEM_BYTES;
    let mut items = Vec::new();
    for pair in arguments.as_chunks::<2>().0 {
        let address = number(&pair[0])?;
        let bytes = if operation == READ {
            let length =
                usize::try_from(number(&pair[1])?).map_err(|_| "read size is too large")?;
            if length == 0 || length > BUFFER_BYTES {
                return Err("read size must be 1..=65536 bytes".into());
            }
            vec![0; length]
        } else {
            let hex = pair[1].strip_prefix("0x").unwrap_or(&pair[1]);
            if hex.is_empty()
                || !hex.len().is_multiple_of(2)
                || hex.len() > BUFFER_BYTES * 2
                || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(
                    "write data must contain an even, nonzero number of hexadecimal digits".into(),
                );
            }
            hex.as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|digits| {
                    u8::from_str_radix(
                        std::str::from_utf8(digits).map_err(|_| "invalid hexadecimal data")?,
                        16,
                    )
                    .map_err(|_| "invalid hexadecimal byte")
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        total = total
            .checked_add(bytes.len())
            .filter(|size| *size <= BUFFER_BYTES)
            .ok_or_else(|| "memory batch exceeds 65536 bytes including descriptors".to_string())?;
        if address.checked_add(bytes.len() as u64).is_none() {
            return Err("memory address range overflows".into());
        }
        items.push(Item { address, bytes });
    }
    Ok(items)
}

pub fn run(arguments: &[String]) -> Result<i32, String> {
    if arguments.len() < 2 {
        return Err("usage: neo read PID|NAME CR3|auto [ADDRESS SIZE ...] or neo write PID|NAME CR3|auto ADDRESS HEX [...]; options: --kernel-cr3 CR3 --kernel-image PATH --symbols DIRECTORY".into());
    }
    let operation = if arguments[0] == "read" { READ } else { WRITE };
    let selector = &arguments[1];
    let cr3 = match arguments.get(2).map(String::as_str) {
        None | Some("auto") => 0,
        Some(value) => number(value)?,
    };
    if cr3 != 0 && cr3 & !4095 == 0 {
        return Err("CR3 must contain a nonzero page-table root".into());
    }
    let mut kernel_cr3 = 0;
    let mut image = symbols::default_kernel_image()?;
    let mut cache = symbols::default_cache()?;
    let mut operands = Vec::new();
    let mut index = 3;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--kernel-cr3" | "--kernel-image" | "--symbols" => {
                let option = &arguments[index];
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| format!("{option} requires a value"))?;
                match option.as_str() {
                    "--kernel-cr3" => kernel_cr3 = number(value)?,
                    "--kernel-image" => image = value.into(),
                    _ => cache = value.into(),
                }
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown memory option: {value}"));
            }
            value => operands.push(value.to_string()),
        }
        index += 1;
    }
    let items = parse_items(operation, &operands)?;
    if operation == WRITE && items.is_empty() {
        return Err("write requires at least one ADDRESS HEX pair".into());
    }
    let mut info = info_packet()?;
    invoke(&mut info)?;
    let symbols = symbols::KernelSymbols::load(&image, &cache)?;
    let process = resolve_process(
        &symbols,
        selector,
        cr3,
        (kernel_cr3 != 0).then_some(kernel_cr3),
    )?;
    let target_cr3 = if cr3 == 0 { process.kernel_cr3 } else { cr3 };
    println!(
        "pid={} name={} cr3={target_cr3:#x} kernel_cr3={:#x} user_cr3={:#x}",
        process.pid, process.name, process.kernel_cr3, process.user_cr3
    );
    if items.is_empty() {
        return Ok(0);
    }
    let transfers = transfer(
        &symbols,
        &process,
        operation,
        (cr3 != 0).then_some(cr3),
        &items,
    )?;
    let mut failed = false;
    for result in transfers {
        failed |= !result.is_complete();
        print!(
            "address={:#x} status={} transferred={}/{}",
            result.address,
            status_text(result.status),
            result.transferred,
            result.requested
        );
        if operation == READ {
            print!(" data=");
            for byte in &result.bytes {
                print!("{byte:02x}");
            }
        }
        println!();
    }
    Ok(i32::from(failed))
}
