use crate::protocol::{
    MATRIXHV_STATUS_LEAF, MATRIXHV_STATUS_SIGNATURE_EAX, MATRIXHV_STATUS_SIGNATURE_EBX,
    MATRIXHV_STATUS_SIGNATURE_ECX,
};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MATRIXHV_DIAGNOSTIC_MIN_PROTOCOL: u32 = 4;
const MATRIXHV_DIAGNOSTIC_PROTOCOL: u32 = 7;
const TELEMETRY_CONTROL_CAPABILITY: u32 = 1 << 8;
const EXIT_PROFILE_CAPABILITY: u32 = 1 << 10;
const EXIT_REASON_COUNTS_CAPABILITY: u32 = 1 << 11;
const VMX_HARDWARE_CAPABILITY: u32 = 1 << 12;
const EPT_RECYCLING_CAPABILITY: u32 = 1 << 13;
const CONTROL_STAGE_CAPABILITY: u32 = 1 << 14;
const CONTROL_NATIVE_SNAPSHOT_CAPABILITY: u32 = 1 << 15;
const PROFILE_PAIR_NAMES: [[&str; 2]; 9] = [
    ["rdmsr", "wrmsr"],
    ["cpuid", "nested_invvpid_instructions"],
    ["nested_vmread", "nested_vmwrite"],
    ["nested_vmlaunch", "nested_vmresume"],
    ["last_normal_exit_reason", "last_guest_rcx"],
    ["handler_cycles.vmcs", "handler_cycles.nested_entry"],
    ["handler_cycles.other", "handler_cycles.invept"],
    ["last_normal_guest_rip", "profile_tsc_hz"],
    ["ept02_table_pages", "cached_ept02_table_pages"],
];
const PAIR_NAMES: [[&str; 2]; 27] = [
    ["sequence", "phase"],
    ["exits", "handler_returns"],
    ["resume_failures", "nested_l2_entries"],
    ["nested_vmx_failures", "nested_entry_rejections"],
    ["last_exit_reason", "last_guest_rip"],
    ["entry_failure_state", "entry_failure_exit"],
    ["entry_failure_tsc", "violation_read"],
    ["violation_write", "violation_execute"],
    ["cr3_exits", "eptp_switches"],
    ["mtf_exits", "invept"],
    ["preemption_timer_exits", "nested_invept_instructions"],
    ["nested_ept_compositions", "nested_ept02_invalidations"],
    ["nested_l2_exits", "nested_l2_resumes"],
    ["last_before.rip", "last_before.rsp"],
    ["last_before.rflags", "last_before.cr0"],
    ["last_before.cr3", "last_before.cr4"],
    ["last_before.efer", "last_after_handler.rip"],
    ["last_after_handler.rsp", "last_after_handler.rflags"],
    ["last_after_handler.cr0", "last_after_handler.cr3"],
    ["last_after_handler.cr4", "last_after_handler.efer"],
    ["last_resume.rip", "last_resume.rsp"],
    ["last_resume.rflags", "last_resume.cr0"],
    ["last_resume.cr3", "last_resume.cr4"],
    ["last_resume.efer", "entry_failure.rip"],
    ["entry_failure.rsp", "entry_failure.rflags"],
    ["entry_failure.cr0", "entry_failure.cr3"],
    ["entry_failure.cr4", "entry_failure.efer"],
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Mode {
    General = 0,
    Watchdog = 1,
    EptDiagnostics = 2,
}

impl Mode {
    pub fn from_u32(value: u32) -> Result<Self, String> {
        match value {
            0 => Ok(Self::General),
            1 => Ok(Self::Watchdog),
            2 => Ok(Self::EptDiagnostics),
            _ => Err(format!("unknown telemetry mode {value}")),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Watchdog => "watchdog",
            Self::EptDiagnostics => "eptdiag",
        }
    }
}

#[derive(Clone, Copy)]
#[repr(u32)]
pub enum Control {
    Query = 0,
    Start = 1,
    Stop = 2,
    Enable = 3,
    Disable = 4,
}

impl Control {
    pub fn from_u32(value: u32) -> Result<Self, String> {
        match value {
            0 => Ok(Self::Query),
            1 => Ok(Self::Start),
            2 => Ok(Self::Stop),
            3 => Ok(Self::Enable),
            4 => Ok(Self::Disable),
            _ => Err(format!("unknown telemetry control {value}")),
        }
    }
}

pub struct CaptureOptions {
    pub mode: Mode,
    pub seconds: Option<u64>,
    pub interval: Duration,
    pub output: Option<PathBuf>,
}

pub struct ControlTraceOptions {
    pub cpu: u32,
    pub seconds: u64,
    pub output: PathBuf,
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
pub(crate) const NATIVE_SNAPSHOT_FIELDS: [&str; 26] = [
    "stage",
    "rip",
    "rsp",
    "rflags",
    "cr0",
    "cr3",
    "cr4",
    "caller_rsp",
    "stack_limit",
    "stack_base",
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "tsc",
];

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeSnapshotLayout {
    pub(crate) snapshot_bytes: usize,
    pub(crate) stack_offset: usize,
    pub(crate) stack_bytes: usize,
    pub(crate) capacity: u64,
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
impl NativeSnapshotLayout {
    pub(crate) fn from_cpuid(result: std::arch::x86_64::CpuidResult) -> Result<Self, String> {
        let layout = Self {
            snapshot_bytes: result.eax as usize,
            stack_offset: result.ebx as usize,
            stack_bytes: result.ecx as usize,
            capacity: u64::from(result.edx),
        };
        let pairs = layout.snapshot_bytes / 16;
        let leaf_limit = 0x4000u64 + layout.capacity * pairs as u64;
        if layout.stack_offset != NATIVE_SNAPSHOT_FIELDS.len() * 8
            || layout.stack_bytes == 0
            || layout.stack_bytes > 65536
            || layout.snapshot_bytes != layout.stack_offset + layout.stack_bytes
            || layout.snapshot_bytes % 16 != 0
            || layout.capacity == 0
            || leaf_limit > 0x10000
        {
            return Err(format!(
                "unsupported native snapshot layout: bytes={}, stack_offset={}, stack_bytes={}, capacity={}",
                layout.snapshot_bytes, layout.stack_offset, layout.stack_bytes, layout.capacity
            ));
        }
        Ok(layout)
    }

    fn published(
        self,
        query: &mut impl FnMut(u32) -> std::arch::x86_64::CpuidResult,
    ) -> Result<(u64, u64), String> {
        let published = pair(query(51));
        if published.0 > self.capacity {
            return Err(format!(
                "native snapshot count {} exceeds capacity {}",
                published.0, self.capacity
            ));
        }
        Ok(published)
    }

    pub(crate) fn read_frame(
        self,
        frame_index: u64,
        sequence: u64,
        query: &mut impl FnMut(u32) -> std::arch::x86_64::CpuidResult,
    ) -> Result<Option<Vec<u8>>, String> {
        let before = self.published(query)?;
        if before.1 != sequence || frame_index >= before.0 {
            return Ok(None);
        }
        let first_leaf = 0x4000 + frame_index as u32 * (self.snapshot_bytes / 16) as u32;
        let mut bytes = vec![0; self.snapshot_bytes];
        for (index, chunk) in bytes.chunks_exact_mut(16).enumerate() {
            let result = query(first_leaf + index as u32);
            for (word, value) in chunk
                .chunks_exact_mut(4)
                .zip([result.eax, result.ebx, result.ecx, result.edx])
            {
                word.copy_from_slice(&value.to_le_bytes());
            }
        }
        // Published frames are immutable until the next activation resets the count.
        // Recheck both the header and publication state before accepting the stack.
        for (index, chunk) in bytes[..self.stack_offset].chunks_exact(16).enumerate() {
            let result = query(first_leaf + index as u32);
            for (word, value) in chunk
                .chunks_exact(4)
                .zip([result.eax, result.ebx, result.ecx, result.edx])
            {
                if word != value.to_le_bytes() {
                    return Ok(None);
                }
            }
        }
        let after = self.published(query)?;
        if after.1 != sequence || after.0 < before.0 {
            return Ok(None);
        }
        let fields = native_snapshot_fields(&bytes);
        if fields[0] == 0
            || fields[1] == 0
            || fields[9].checked_sub(fields[8]) != Some(self.stack_bytes as u64)
            || !(fields[8]..=fields[9]).contains(&fields[2])
        {
            return Err(format!(
                "invalid native snapshot header at frame {frame_index}"
            ));
        }
        Ok(Some(bytes))
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
pub(crate) fn native_snapshot_fields(bytes: &[u8]) -> [u64; NATIVE_SNAPSHOT_FIELDS.len()] {
    std::array::from_fn(|index| {
        u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap())
    })
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
pub(crate) fn save_native_frame(
    trace_path: &std::path::Path,
    trace: &mut std::fs::File,
    cpu: u32,
    sequence: u64,
    frame_index: u64,
    layout: NativeSnapshotLayout,
    bytes: &[u8],
) -> Result<(), String> {
    let mut frame_name = trace_path
        .file_name()
        .ok_or_else(|| "control trace output requires a file name".to_string())?
        .to_os_string();
    frame_name.push(format!(
        ".cpu{cpu}.seq{sequence:016x}.frame{frame_index:02}.bin"
    ));
    let frame_path = trace_path.with_file_name(frame_name);
    let mut frame_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&frame_path)
        .map_err(|error| format!("failed to create {}: {error}", frame_path.display()))?;
    frame_file
        .write_all(bytes)
        .and_then(|()| frame_file.sync_all())
        .map_err(|error| format!("failed to persist {}: {error}", frame_path.display()))?;
    let fields = native_snapshot_fields(bytes);
    let mut record = format!(
        "native_frame_index={frame_index}\nnative_control_sequence=0x{sequence:016x}\nnative_frame_file={}\nnative_frame_bytes={}\nnative_stack_offset={}\nnative_stack_bytes={}\nnative_stack_scope=runtime_resident_allocation\nnative_rip_kind=checkpoint_return_address\nnative_stage_name={}\n",
        frame_path.display(),
        layout.snapshot_bytes,
        layout.stack_offset,
        layout.stack_bytes,
        control_stage_name(fields[0]),
    );
    for (name, value) in NATIVE_SNAPSHOT_FIELDS.iter().zip(fields) {
        writeln!(record, "native_{name}=0x{value:016x}").unwrap();
    }
    record.push_str("native_frame_complete=true\n\n");
    trace
        .write_all(record.as_bytes())
        .and_then(|()| trace.sync_data())
        .map_err(|error| format!("failed to write {}: {error}", trace_path.display()))
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
pub fn capture_control(options: ControlTraceOptions) -> Result<(), String> {
    if options.cpu >= 64 || !(1..=3600).contains(&options.seconds) {
        return Err("invalid control trace CPU or duration".into());
    }
    let mut affinity = CpuAffinity::current()?;
    let observer_cpu = affinity
        .allowed()
        .iter()
        .copied()
        .find(|cpu| *cpu != options.cpu && *cpu < 64)
        .ok_or_else(|| {
            "control trace requires an observer CPU different from the target".to_string()
        })?;
    affinity.pin(observer_cpu)?;
    verify_cpu(observer_cpu)?;
    let capabilities = diagnostic_cpu(34, options.cpu).eax;
    if capabilities & CONTROL_STAGE_CAPABILITY == 0 {
        return Err("MatrixHV does not support control stage tracing on the target CPU".into());
    }
    let native_layout = if capabilities & CONTROL_NATIVE_SNAPSHOT_CAPABILITY != 0 {
        Some(NativeSnapshotLayout::from_cpuid(diagnostic_cpu(
            52,
            options.cpu,
        ))?)
    } else {
        None
    };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&options.output)
        .map_err(|error| format!("failed to create {}: {error}", options.output.display()))?;
    writeln!(
        file,
        "format=matrixhv-control-trace-v2\nobserver_cpu={observer_cpu}\ntarget_cpu={}\npolling=continuous\nnative_capture_supported={}\nnative_snapshot_encoding=little_endian_u64_header_and_raw_stack\n",
        options.cpu,
        native_layout.is_some(),
    )
    .and_then(|()| file.sync_all())
    .map_err(|error| format!("failed to write {}: {error}", options.output.display()))?;
    let deadline = Instant::now() + Duration::from_secs(options.seconds);
    let mut previous = None;
    let mut previous_native = None;
    let mut native_sequence = None;
    let mut next_native_frame = 0;
    let mut next_heartbeat = Instant::now();
    loop {
        let state = pair(diagnostic_cpu(50, options.cpu));
        let mut query = |subleaf| diagnostic_cpu(subleaf, options.cpu);
        let published = native_layout
            .map(|layout| layout.published(&mut query))
            .transpose()?;
        if let (Some(layout), Some((count, sequence))) = (native_layout, published) {
            if native_sequence != Some(sequence) {
                native_sequence = Some(sequence);
                next_native_frame = 0;
            }
            // Off uses the same control sequence slot and clears the native stage.
            // Its retained bytes must not be relabeled as a new activation.
            if state.0 != 0 {
                while next_native_frame < count {
                    let Some(bytes) = layout.read_frame(next_native_frame, sequence, &mut query)?
                    else {
                        break;
                    };
                    save_native_frame(
                        &options.output,
                        &mut file,
                        options.cpu,
                        sequence,
                        next_native_frame,
                        layout,
                        &bytes,
                    )?;
                    next_native_frame += 1;
                }
            }
        }
        let now = Instant::now();
        if previous != Some(state) || previous_native != published || now >= next_heartbeat {
            let (exits, handler_returns) = pair(diagnostic_cpu(5, options.cpu));
            let resume_failures = pair(diagnostic_cpu(6, options.cpu)).0;
            let (last_exit_reason, last_guest_rip) = pair(diagnostic_cpu(8, options.cpu));
            let (entry_failure_state, entry_failure_exit) = pair(diagnostic_cpu(9, options.cpu));
            let (control_failure_reason, control_failure_qualification) =
                pair(diagnostic_cpu(53, options.cpu));
            let (fault_vector, fault_error) = pair(diagnostic(32));
            let (fault_rip, fault_address) = pair(diagnostic(33));
            let sample_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| format!("system clock is before the Unix epoch: {error}"))?
                .as_millis();
            writeln!(
                file,
                "sample_unix_ms={sample_time}\ncontrol_stage={}\ncontrol_stage_name={}\ncontrol_phase={}\ncontrol_failure_reason=0x{control_failure_reason:016x}\ncontrol_failure_qualification=0x{control_failure_qualification:016x}\nexits={exits}\nhandler_returns={handler_returns}\nresume_failures={resume_failures}\nlast_exit_reason={last_exit_reason}\nlast_guest_rip=0x{last_guest_rip:x}\nentry_failure_state={entry_failure_state}\nentry_failure_exit={entry_failure_exit}\nfault_vector={fault_vector}\nfault_error={fault_error}\nfault_rip=0x{fault_rip:x}\nfault_address=0x{fault_address:x}\n",
                state.0,
                control_stage_name(state.0),
                state.1
            )
            .and_then(|()| {
                if let Some((count, sequence)) = published {
                    writeln!(
                        file,
                        "native_published_count={count}\nnative_control_sequence=0x{sequence:016x}\nnative_saved_count={next_native_frame}\n"
                    )?;
                }
                Ok(())
            })
            .and_then(|()| file.sync_data())
            .map_err(|error| format!("failed to write {}: {error}", options.output.display()))?;
            previous = Some(state);
            previous_native = published;
            next_heartbeat = now + Duration::from_millis(100);
        }
        if now >= deadline {
            return Ok(());
        }
        std::hint::spin_loop();
    }
}

#[cfg(not(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
)))]
pub fn capture_control(_options: ControlTraceOptions) -> Result<(), String> {
    Err("MatrixHV control tracing requires x86-64 Windows or Linux".into())
}

pub fn capture(
    options: CaptureOptions,
    mut request: impl FnMut(Mode, Control) -> Result<String, String>,
) -> Result<(), String> {
    if options.mode == Mode::Watchdog && options.interval > Duration::from_secs(5) {
        return Err("watchdog sampling interval must not exceed 5000 ms".to_string());
    }
    if options.mode == Mode::Watchdog {
        request(options.mode, Control::Start)?;
        std::thread::sleep(Duration::from_millis(200));
    }
    let result = capture_samples(&options, &mut request);
    if options.mode == Mode::Watchdog {
        let stopped = request(options.mode, Control::Stop);
        result.and(stopped.map(|_| ()))
    } else {
        result
    }
}

fn capture_samples(
    options: &CaptureOptions,
    request: &mut impl FnMut(Mode, Control) -> Result<String, String>,
) -> Result<(), String> {
    let mut output_file = None;
    let mut stdout = std::io::stdout();
    let deadline = options
        .seconds
        .map(|seconds| Instant::now() + Duration::from_secs(seconds));
    loop {
        if options.mode == Mode::Watchdog {
            request(options.mode, Control::Start)?;
        }
        let sample_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock is before the Unix epoch: {error}"))?
            .as_millis();
        let sample = request(options.mode, Control::Query)?;
        if let Some(path) = options.output.as_ref() {
            if output_file.is_none() {
                output_file = Some(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(path)
                        .map_err(|error| format!("failed to create {}: {error}", path.display()))?,
                );
            }
            let file = output_file.as_mut().unwrap();
            write!(file, "sample_unix_ms={sample_time}\n{sample}\n")
                .and_then(|()| file.sync_data())
                .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
        } else {
            write!(stdout, "sample_unix_ms={sample_time}\n{sample}\n")
                .and_then(|()| stdout.flush())
                .map_err(|error| format!("failed to write telemetry: {error}"))?;
        }
        let Some(deadline) = deadline else {
            return Ok(());
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        std::thread::sleep(options.interval.min(remaining));
        if Instant::now() >= deadline {
            return Ok(());
        }
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
fn diagnostic(subleaf: u32) -> std::arch::x86_64::CpuidResult {
    std::arch::x86_64::__cpuid_count(MATRIXHV_STATUS_LEAF, subleaf)
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
fn diagnostic_cpu(subleaf: u32, cpu: u32) -> std::arch::x86_64::CpuidResult {
    diagnostic(subleaf | ((cpu + 1) << 16))
}
#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
fn pair(result: std::arch::x86_64::CpuidResult) -> (u64, u64) {
    (
        u64::from(result.eax) | (u64::from(result.ebx) << 32),
        u64::from(result.ecx) | (u64::from(result.edx) << 32),
    )
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
pub(crate) fn control_stage_name(stage: u64) -> &'static str {
    match stage {
        0 => "idle",
        1 => "requested",
        2 => "preflight_complete",
        3 => "vmxe_enabled",
        4 => "vmxon_complete",
        5 => "vmcs_loaded",
        6 => "host_fields_restored",
        7 => "guest_fields_written",
        8 => "invalidation_complete",
        9 => "guest_entered",
        10 => "vmcs_cleared",
        11 => "before_invept",
        12 => "before_invvpid",
        128 => "preflight_failed",
        129 => "vmx_busy",
        130 => "vmxon_failed",
        131 => "root_setup_failed",
        132 => "invalidation_failed",
        133 => "vm_entry_failed",
        134 => "vmcs_preservation_failed",
        _ => "unknown",
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
fn nested_vmx_instruction(exit_reason: u64) -> &'static str {
    match exit_reason & 0xffff {
        19 => "VMCLEAR",
        20 => "VMLAUNCH",
        21 => "VMPTRLD",
        22 => "VMPTRST",
        23 => "VMREAD",
        24 => "VMRESUME",
        25 => "VMWRITE",
        26 => "VMXOFF",
        27 => "VMXON",
        50 => "INVEPT",
        53 => "INVVPID",
        _ => "unknown",
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
fn nested_vmx_failure_reason(kind: u64, code: u64) -> String {
    match kind {
        1 => match code {
            2 => "VMCLEAR invalid physical address".to_string(),
            3 => "VMCLEAR points to the VMXON region".to_string(),
            4 => "VMLAUNCH requires a clear VMCS".to_string(),
            5 => "VMRESUME requires a launched VMCS".to_string(),
            7 => "invalid VM-entry control fields".to_string(),
            8 => "invalid VM-entry host state".to_string(),
            9 => "VMPTRLD invalid physical address".to_string(),
            10 => "VMPTRLD points to the VMXON region".to_string(),
            11 => "VMPTRLD incorrect VMCS revision".to_string(),
            12 => "unsupported VMCS component".to_string(),
            13 => "VMWRITE to a read-only VMCS component".to_string(),
            15 => "VMXON while already in VMX operation".to_string(),
            26 => "VM entry blocked by MOV SS".to_string(),
            28 => "invalid INVEPT or INVVPID operand".to_string(),
            _ => format!("VM-instruction error {code}"),
        },
        2 => match code {
            1 => "no current VMCS".to_string(),
            2 => "invalid VMXON physical address".to_string(),
            3 => "incorrect VMXON region revision".to_string(),
            4 => "hardware VMfailInvalid on L2 entry".to_string(),
            _ => format!("VMfailInvalid detail {code}"),
        },
        3 => format!("page fault with error code {code}"),
        4 => "VMX instruction unavailable in the current mode".to_string(),
        5 => "VMX instruction privilege or feature-control violation".to_string(),
        6 => format!("no current VMCS; attempted VM-instruction error {code}"),
        _ => format!("unknown failure kind {kind}, detail {code}"),
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
fn nested_vmx_failure_outcome(kind: u64) -> &'static str {
    match kind {
        1 => "VMfailValid",
        2 | 6 => "VMfailInvalid",
        3 => "#PF",
        4 => "#UD",
        5 => "#GP",
        _ => "unknown",
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
fn nested_vmcs_field_details(field: u64) -> Option<(&'static str, Option<&'static str>)> {
    match field & !1 {
        0x200c => Some(("executive VMCS pointer", None)),
        0x2016 => Some((
            "posted-interrupt descriptor address",
            Some("process posted interrupts"),
        )),
        0x2024 => Some(("EPTP-list address", Some("EPTP switching VM function"))),
        0x2026 => Some(("VMREAD-bitmap address", Some("VMCS shadowing"))),
        0x2028 => Some(("VMWRITE-bitmap address", Some("VMCS shadowing"))),
        0x202a => Some((
            "virtualization-exception information address",
            Some("EPT-violation #VE"),
        )),
        _ => None,
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
mod nested_failure_tests {
    use super::nested_vmcs_field_details;

    #[test]
    fn executive_pointer_is_unconditional_and_optional_fields_require_controls() {
        assert_eq!(
            nested_vmcs_field_details(0x200c),
            Some(("executive VMCS pointer", None))
        );
        for field in [0x2016, 0x2024, 0x2026, 0x2028, 0x202a] {
            assert!(nested_vmcs_field_details(field).unwrap().1.is_some());
        }
        assert_eq!(
            nested_vmcs_field_details(0x202b),
            nested_vmcs_field_details(0x202a)
        );
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
fn append_nested_failure_trace(text: &mut String, cpu: u32, extended_invept: bool) {
    let prefix = format!("cpu.{cpu}");
    let metadata = diagnostic_cpu(0x100, cpu);
    let count = u64::from(metadata.eax) | (u64::from(metadata.ebx) << 32);
    let capacity = metadata.ecx.min(32);
    writeln!(text, "{prefix}.nested_failure_trace_count={count}").unwrap();
    writeln!(text, "{prefix}.nested_failure_trace_capacity={capacity}").unwrap();
    writeln!(
        text,
        "{prefix}.nested_failure_trace_truncated={}",
        u8::from(count > u64::from(capacity))
    )
    .unwrap();
    let mut unsupported_capability_fields = 0;
    let mut other_failures = 0;
    for index in 0..count.min(u64::from(capacity)) as u32 {
        let subleaf = 0x101 + index * 3;
        let (rip, exit_reason) = pair(diagnostic_cpu(subleaf, cpu));
        let (kind, code) = pair(diagnostic_cpu(subleaf + 1, cpu));
        let (vmcs_field, operand) = pair(diagnostic_cpu(subleaf + 2, cpu));
        let entry = format!("{prefix}.nested_failure.{index}");
        writeln!(text, "{entry}.rip=0x{rip:x}").unwrap();
        writeln!(
            text,
            "{entry}.instruction={}",
            nested_vmx_instruction(exit_reason)
        )
        .unwrap();
        writeln!(text, "{entry}.outcome={}", nested_vmx_failure_outcome(kind)).unwrap();
        writeln!(
            text,
            "{entry}.reason={}",
            nested_vmx_failure_reason(kind, code)
        )
        .unwrap();
        writeln!(text, "{entry}.code={code}").unwrap();
        if matches!(exit_reason & 0xffff, 23 | 25) {
            writeln!(text, "{entry}.vmcs_field=0x{vmcs_field:x}").unwrap();
        }
        if extended_invept && exit_reason & 0xffff == 50 {
            writeln!(text, "{entry}.invalidation_type={vmcs_field}").unwrap();
            if matches!(vmcs_field, 1 | 2) {
                writeln!(text, "{entry}.descriptor_eptp=0x{operand:x}").unwrap();
            }
        }
        let capability_field = if kind == 1 && code == 12 && matches!(exit_reason & 0xffff, 23 | 25)
        {
            nested_vmcs_field_details(vmcs_field).and_then(|(_, required_control)| required_control)
        } else {
            None
        };
        if let Some((name, required_control)) = nested_vmcs_field_details(vmcs_field) {
            if matches!(exit_reason & 0xffff, 23 | 25) {
                writeln!(text, "{entry}.vmcs_field_name={name}").unwrap();
                if let Some(required_control) = required_control {
                    writeln!(text, "{entry}.required_control={required_control}").unwrap();
                }
            }
        }
        if capability_field.is_some() {
            unsupported_capability_fields += 1;
            writeln!(text, "{entry}.classification=unsupported_capability_field").unwrap();
        } else {
            other_failures += 1;
            writeln!(text, "{entry}.classification=other_failure").unwrap();
        }
        if kind == 3 || matches!(exit_reason & 0xffff, 19 | 21 | 22 | 27) {
            writeln!(text, "{entry}.operand=0x{operand:x}").unwrap();
        }
    }
    writeln!(
        text,
        "{prefix}.nested_failure_trace_unsupported_capability_fields={unsupported_capability_fields}"
    )
    .unwrap();
    writeln!(
        text,
        "{prefix}.nested_failure_trace_other_failures={other_failures}"
    )
    .unwrap();
}
#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
fn verify_cpu(cpu: u32) -> Result<(), String> {
    let status = diagnostic(0);
    if status.eax != MATRIXHV_STATUS_SIGNATURE_EAX
        || status.ebx != MATRIXHV_STATUS_SIGNATURE_EBX
        || status.ecx != MATRIXHV_STATUS_SIGNATURE_ECX
    {
        return Err(format!("MatrixHV is not present on logical CPU {cpu}"));
    }
    if !(MATRIXHV_DIAGNOSTIC_MIN_PROTOCOL..=MATRIXHV_DIAGNOSTIC_PROTOCOL).contains(&status.edx) {
        return Err(format!(
            "unsupported MatrixHV diagnostic protocol {} on logical CPU {cpu}",
            status.edx
        ));
    }
    Ok(())
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
pub fn request_text(mode: u32, control: u32) -> Result<String, String> {
    let mode = Mode::from_u32(mode)?;
    let control = Control::from_u32(control)?;
    if matches!(control, Control::Query) {
        return snapshot_text(mode);
    }
    if matches!(control, Control::Enable | Control::Disable) && mode != Mode::General {
        return Err("telemetry enable/disable requires general telemetry mode".to_string());
    }
    if matches!(control, Control::Start | Control::Stop) && mode != Mode::Watchdog {
        return Err("watchdog control requires watchdog telemetry mode".to_string());
    }
    let mut affinity = CpuAffinity::current()?;
    let observer_cpu = affinity.allowed()[0];
    affinity.pin(observer_cpu)?;
    verify_cpu(observer_cpu)?;
    let supports_control = diagnostic(34).eax & TELEMETRY_CONTROL_CAPABILITY != 0;
    if matches!(control, Control::Enable | Control::Disable) && !supports_control {
        return Err(
            "MatrixHV does not support telemetry enable/disable; update the hypervisor".to_string(),
        );
    }
    let mask = pair(diagnostic(36)).0;
    if mask == 0 {
        return Err("MatrixHV reported no registered vCPUs".to_string());
    }
    if matches!(control, Control::Start) && supports_control {
        for cpu in (0..64).filter(|cpu| mask & (1u64 << cpu) != 0) {
            if diagnostic_cpu(37, cpu).eax == 0 {
                return Err(
                    "telemetry is disabled; run neo telemetry enable before watchdog capture"
                        .to_string(),
                );
            }
        }
    }
    for cpu in (0..64).filter(|cpu| mask & (1u64 << cpu) != 0) {
        let result = diagnostic_cpu(
            match control {
                Control::Start => 0x200,
                Control::Stop => 0x201,
                Control::Enable => 0x202,
                Control::Disable => 0x203,
                Control::Query => unreachable!(),
            },
            cpu,
        );
        if matches!(control, Control::Enable | Control::Start) && result.eax != 1 {
            return Err(format!(
                "MatrixHV rejected telemetry control on logical CPU {cpu}"
            ));
        }
    }
    match control {
        Control::Enable | Control::Disable => snapshot_text(mode),
        _ => Ok(String::new()),
    }
}
#[cfg(not(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
)))]
pub fn request_text(_mode: u32, _control: u32) -> Result<String, String> {
    Err("MatrixHV telemetry requires x86-64 Windows or Linux".to_string())
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
pub fn snapshot_text(mode: Mode) -> Result<String, String> {
    let mut affinity = CpuAffinity::current()?;
    let observer_cpu = affinity.allowed()[0];
    affinity.pin(observer_cpu)?;
    verify_cpu(observer_cpu)?;
    let protocol = diagnostic(0).edx;
    let registered_mask = pair(diagnostic(36)).0;
    let cpus: Vec<u32> = (0..64)
        .filter(|cpu| registered_mask & (1u64 << cpu) != 0)
        .collect();
    if cpus.is_empty() {
        return Err("MatrixHV reported no registered vCPUs".to_string());
    }
    let format_version = if protocol >= 5 { 3 } else { 2 };
    let mut text = format!(
        "format=matrixhv-telemetry-v{format_version}\nmode={}\nscope=registered_vcpus\n",
        mode.name()
    );
    if mode != Mode::EptDiagnostics {
        text.push_str("guest_state_fields=rip,rsp,rflags,cr0,cr3,cr4,efer\nguest_state_capture=watchdog_lease\nfault_scope=host_exception\n");
    }
    writeln!(text, "cpu_count={}", cpus.len()).unwrap();
    writeln!(text, "observer_cpu={observer_cpu}").unwrap();
    for cpu in cpus.iter().copied() {
        let prefix = format!("cpu.{cpu}");
        let mut sample = String::new();
        let mut coherent = false;
        for _ in 0..3 {
            sample.clear();
            let before = pair(diagnostic_cpu(4, cpu)).0;
            let caps = diagnostic_cpu(34, cpu);
            writeln!(sample, "{prefix}.processor_number={}", caps.ebx).unwrap();
            writeln!(sample, "{prefix}.capabilities=0x{:x}", caps.eax).unwrap();
            writeln!(sample, "{prefix}.watchdog_active={}", caps.ecx).unwrap();
            if caps.eax & CONTROL_STAGE_CAPABILITY != 0 {
                let (stage, phase) = pair(diagnostic_cpu(50, cpu));
                writeln!(sample, "{prefix}.control_stage={stage}").unwrap();
                writeln!(
                    sample,
                    "{prefix}.control_stage_name={}",
                    control_stage_name(stage)
                )
                .unwrap();
                writeln!(sample, "{prefix}.control_phase={phase}").unwrap();
                let (reason, qualification) = pair(diagnostic_cpu(53, cpu));
                writeln!(sample, "{prefix}.control_failure_reason=0x{reason:016x}").unwrap();
                writeln!(
                    sample,
                    "{prefix}.control_failure_qualification=0x{qualification:016x}"
                )
                .unwrap();
            }
            if caps.eax & TELEMETRY_CONTROL_CAPABILITY != 0 {
                writeln!(
                    sample,
                    "{prefix}.telemetry_enabled={}",
                    diagnostic_cpu(37, cpu).eax
                )
                .unwrap();
            }
            for (index, names) in PAIR_NAMES.iter().enumerate() {
                let selected = match mode {
                    Mode::General => true,
                    Mode::Watchdog => index <= 6 || index >= 12,
                    Mode::EptDiagnostics => (6..=12).contains(&index),
                };
                if selected {
                    let (first, second) = pair(diagnostic_cpu(index as u32 + 4, cpu));
                    writeln!(sample, "{prefix}.{}={first}", names[0]).unwrap();
                    writeln!(sample, "{prefix}.{}={second}", names[1]).unwrap();
                }
            }
            if caps.eax & EXIT_PROFILE_CAPABILITY != 0 && mode == Mode::General {
                writeln!(
                    sample,
                    "{prefix}.vmcs_instruction_counter_scope={}",
                    if caps.eax & EXIT_REASON_COUNTS_CAPABILITY != 0 {
                        "vcpu_cumulative"
                    } else {
                        "current_vmcs_snapshot"
                    }
                )
                .unwrap();
                for (index, names) in PROFILE_PAIR_NAMES.iter().enumerate() {
                    let (first, second) = pair(diagnostic_cpu(index as u32 + 38, cpu));
                    writeln!(sample, "{prefix}.{}={first}", names[0]).unwrap();
                    writeln!(sample, "{prefix}.{}={second}", names[1]).unwrap();
                }
            }
            if caps.eax & EPT_RECYCLING_CAPABILITY != 0 && mode != Mode::Watchdog {
                let (resets, table_evictions) = pair(diagnostic_cpu(49, cpu));
                writeln!(sample, "{prefix}.nested_ept02_full_recycles={resets}").unwrap();
                writeln!(
                    sample,
                    "{prefix}.nested_ept02_table_evictions={table_evictions}"
                )
                .unwrap();
            }
            if caps.eax & EXIT_REASON_COUNTS_CAPABILITY != 0 && mode == Mode::General {
                for index in 0..64 {
                    let (first, second) = pair(diagnostic_cpu(0x300 + index, cpu));
                    writeln!(sample, "{prefix}.exit_reason.{}={first}", index * 2).unwrap();
                    writeln!(sample, "{prefix}.exit_reason.{}={second}", index * 2 + 1).unwrap();
                }
            }
            if mode != Mode::EptDiagnostics {
                let nested = diagnostic_cpu(31, cpu);
                writeln!(sample, "{prefix}.nested_active={}", nested.eax).unwrap();
                writeln!(sample, "{prefix}.nested_l2_active={}", nested.ebx).unwrap();
                writeln!(sample, "{prefix}.nested_last_exit_reason={}", nested.ecx).unwrap();
                writeln!(sample, "{prefix}.nested_instruction_error={}", nested.edx).unwrap();
            }
            coherent = before & 1 == 0 && before == pair(diagnostic_cpu(4, cpu)).0;
            if coherent {
                break;
            }
        }
        writeln!(text, "{prefix}.coherent={}", u8::from(coherent)).unwrap();
        text.push_str(&sample);
        if protocol >= 5 && mode == Mode::General {
            append_nested_failure_trace(
                &mut text,
                cpu,
                diagnostic_cpu(34, cpu).eax & VMX_HARDWARE_CAPABILITY != 0,
            );
        }
        if cpu == cpus[0] {
            let low = diagnostic(1);
            let high = diagnostic(2);
            let active_mask = (u64::from(low.ecx) | (u64::from(high.ecx) << 32))
                & !(u64::from(low.edx) | (u64::from(high.edx) << 32));
            writeln!(
                text,
                "global.logical_processor_count={}",
                if active_mask == 0 {
                    "unavailable".to_string()
                } else {
                    active_mask.count_ones().to_string()
                }
            )
            .unwrap();
            let failure = diagnostic(3);
            writeln!(text, "global.failed_processor={}", failure.eax).unwrap();
            writeln!(text, "global.failed_exit_reason={}", failure.ebx).unwrap();
            if mode != Mode::EptDiagnostics {
                let (vector, error) = pair(diagnostic(32));
                let (rip, address) = pair(diagnostic(33));
                writeln!(
                    text,
                    "global.fault_state={}",
                    if vector == u64::MAX { 0 } else { 2 }
                )
                .unwrap();
                writeln!(
                    text,
                    "global.fault_vector={}",
                    if vector == u64::MAX { 0 } else { vector }
                )
                .unwrap();
                writeln!(text, "global.fault_error={error}").unwrap();
                writeln!(text, "global.fault_rip={rip}").unwrap();
                writeln!(text, "global.fault_cr2={address}").unwrap();
            }
        }
    }
    if mode != Mode::Watchdog {
        text.push_str("ept.cr3_cache_hits=unavailable\nept.cr3_cache_misses=unavailable\nept.rendezvous_timeouts=unavailable\nept.last_pending_vcpu=unavailable\n");
    }
    Ok(text)
}
#[cfg(not(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
)))]
pub fn snapshot_text(_mode: Mode) -> Result<String, String> {
    Err("MatrixHV telemetry requires x86-64 Windows or Linux".to_string())
}

pub fn capability_status(matrixhv_present: bool, protocol: u32) -> String {
    #[cfg(all(
        target_arch = "x86_64",
        any(target_os = "windows", target_os = "linux")
    ))]
    if matrixhv_present
        && (MATRIXHV_DIAGNOSTIC_MIN_PROTOCOL..=MATRIXHV_DIAGNOSTIC_PROTOCOL).contains(&protocol)
    {
        let caps = diagnostic(34);
        let low = diagnostic(1);
        let high = diagnostic(2);
        let mask = (u64::from(low.ecx) | (u64::from(high.ecx) << 32))
            & !(u64::from(low.edx) | (u64::from(high.edx) << 32));
        let count = if mask == 0 {
            "unavailable".to_string()
        } else {
            mask.count_ones().to_string()
        };
        let format_version = if protocol >= 5 { 3 } else { 2 };
        let mut text = format!(
            "capabilities=0x{:x}\n[TELEMETRY v{format_version}]\nlogical_processor_count={count}\n",
            caps.eax,
        );
        if caps.eax & TELEMETRY_CONTROL_CAPABILITY != 0 {
            writeln!(
                text,
                "telemetry_control=true\ntelemetry_enabled={}",
                diagnostic(37).eax
            )
            .unwrap();
        }
        if caps.eax & VMX_HARDWARE_CAPABILITY != 0 {
            let (host_secondary, nested_secondary) = pair(diagnostic(47));
            let (host_misc, nested_misc) = pair(diagnostic(48));
            text.push_str(&format_vmx_support(
                host_secondary,
                nested_secondary,
                host_misc,
                nested_misc,
            ));
        } else {
            text.push_str("vmcs_shadowing_host_supported=unknown\nvmcs_shadowing_query=requires_updated_matrixhv\n");
        }
        return text;
    }
    let _ = (matrixhv_present, protocol);
    "capabilities=none\nlogical_processor_count=unavailable\nvmcs_shadowing_host_supported=unknown\nvmcs_shadowing_query=requires_matrixhv_msr_telemetry\n".to_string()
}

fn format_vmx_support(
    host_secondary: u64,
    nested_secondary: u64,
    host_misc: u64,
    nested_misc: u64,
) -> String {
    format!(
        "vmx_capability_source=matrixhv_root_msr_snapshot\nvmx_host_secondary_controls=0x{host_secondary:x}\nvmx_nested_secondary_controls=0x{nested_secondary:x}\nvmcs_shadowing_host_supported={}\nvmcs_shadowing_nested_exposed={}\nvmx_host_vmwrite_read_only_supported={}\nvmx_nested_vmwrite_read_only_supported={}\n",
        host_secondary & (1 << 46) != 0,
        nested_secondary & (1 << 46) != 0,
        host_misc & (1 << 29) != 0,
        nested_misc & (1 << 29) != 0,
    )
}

#[cfg(test)]
mod vmx_support_tests {
    #[test]
    fn shadowing_uses_the_allowed_one_bit_and_reports_nested_filtering() {
        let text = super::format_vmx_support(1 << 46, 1 << 14, 1 << 29, 0);
        assert!(text.contains("vmcs_shadowing_host_supported=true\n"));
        assert!(text.contains("vmcs_shadowing_nested_exposed=false\n"));
        assert!(text.contains("vmx_host_vmwrite_read_only_supported=true\n"));
        assert!(text.contains("vmx_nested_vmwrite_read_only_supported=false\n"));
        let text = super::format_vmx_support(1 << 14, 1 << 46, 0, 1 << 29);
        assert!(text.contains("vmcs_shadowing_host_supported=false\n"));
        assert!(text.contains("vmcs_shadowing_nested_exposed=true\n"));
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut core::ffi::c_void;
    fn GetCurrentThread() -> *mut core::ffi::c_void;
    fn GetProcessAffinityMask(
        process: *mut core::ffi::c_void,
        process_mask: *mut usize,
        system_mask: *mut usize,
    ) -> i32;
    fn SetThreadAffinityMask(thread: *mut core::ffi::c_void, mask: usize) -> usize;
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn sched_getaffinity(pid: i32, cpusetsize: usize, mask: *mut u8) -> i32;
    fn sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const u8) -> i32;
}

#[cfg(target_os = "windows")]
struct CpuAffinity {
    thread: *mut core::ffi::c_void,
    allowed: Vec<u32>,
    original_mask: Option<usize>,
}

#[cfg(target_os = "windows")]
impl CpuAffinity {
    fn current() -> Result<Self, String> {
        let mut process_mask = 0usize;
        let mut system_mask = 0usize;
        if unsafe {
            GetProcessAffinityMask(GetCurrentProcess(), &mut process_mask, &mut system_mask)
        } == 0
            || process_mask == 0
        {
            return Err(format!(
                "failed to read process CPU affinity: {}",
                std::io::Error::last_os_error()
            ));
        }
        let allowed = (0..usize::BITS)
            .filter(|cpu| process_mask & (1usize << cpu) != 0)
            .collect();
        Ok(Self {
            thread: unsafe { GetCurrentThread() },
            allowed,
            original_mask: None,
        })
    }

    fn allowed(&self) -> &[u32] {
        &self.allowed
    }

    fn pin(&mut self, cpu: u32) -> Result<(), String> {
        let previous = unsafe { SetThreadAffinityMask(self.thread, 1usize << cpu) };
        if previous == 0 {
            return Err(format!(
                "failed to pin telemetry to logical CPU {cpu}: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.original_mask.get_or_insert(previous);
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl Drop for CpuAffinity {
    fn drop(&mut self) {
        if let Some(mask) = self.original_mask {
            unsafe { SetThreadAffinityMask(self.thread, mask) };
        }
    }
}

#[cfg(target_os = "linux")]
struct CpuAffinity {
    allowed: Vec<u32>,
    original_mask: [u8; 128],
}

#[cfg(target_os = "linux")]
impl CpuAffinity {
    fn current() -> Result<Self, String> {
        let mut original_mask = [0u8; 128];
        if unsafe { sched_getaffinity(0, original_mask.len(), original_mask.as_mut_ptr()) } != 0 {
            return Err(format!(
                "failed to read process CPU affinity: {}",
                std::io::Error::last_os_error()
            ));
        }
        let allowed: Vec<u32> = original_mask
            .iter()
            .enumerate()
            .flat_map(|(byte, value)| {
                (0..8).filter_map(move |bit| {
                    (value & (1 << bit) != 0).then_some((byte * 8 + bit) as u32)
                })
            })
            .collect();
        if allowed.is_empty() {
            return Err("process CPU affinity has no available processors".to_string());
        }
        Ok(Self {
            allowed,
            original_mask,
        })
    }

    fn allowed(&self) -> &[u32] {
        &self.allowed
    }

    fn pin(&mut self, cpu: u32) -> Result<(), String> {
        let mut mask = [0u8; 128];
        mask[cpu as usize / 8] = 1 << (cpu % 8);
        if unsafe { sched_setaffinity(0, mask.len(), mask.as_ptr()) } != 0 {
            return Err(format!(
                "failed to pin telemetry to logical CPU {cpu}: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for CpuAffinity {
    fn drop(&mut self) {
        unsafe { sched_setaffinity(0, self.original_mask.len(), self.original_mask.as_ptr()) };
    }
}
