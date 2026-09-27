use crate::server::hypervisor::MATRIXHV_STATUS_LEAF;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MATRIXHV_DIAGNOSTIC_MIN_PROTOCOL: u32 = 4;
const MATRIXHV_DIAGNOSTIC_PROTOCOL: u32 = 5;
const TELEMETRY_CONTROL_CAPABILITY: u32 = 1 << 8;
const NESTED_FAILURE_TRACE_CAPABILITY: u32 = 1 << 9;
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
fn append_nested_failure_trace(text: &mut String, cpu: u32) {
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
    if status.eax != 0x4d48_5631
        || status.ebx != u32::from_le_bytes(*b"MATR")
        || status.ecx != u32::from_le_bytes(*b"IXHV")
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
            append_nested_failure_trace(&mut text, cpu);
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
        let mut text = format!(
            "capabilities=0x{:x}\ncapability_names=vcpu_counters,watchdog_sequence_phase,guest_triad,entry_failure_slot,host_exception_slot,ept_diagnostics,watchdog_lease,remote_vcpu_query{}{}\nlogical_processor_count={count}\n",
            caps.eax,
            if caps.eax & TELEMETRY_CONTROL_CAPABILITY != 0 {
                ",telemetry_control"
            } else {
                ""
            },
            if caps.eax & NESTED_FAILURE_TRACE_CAPABILITY != 0 {
                ",nested_failure_trace"
            } else {
                ""
            },
        );
        if caps.eax & TELEMETRY_CONTROL_CAPABILITY != 0 {
            writeln!(
                text,
                "telemetry_control=true\ntelemetry_enabled={}",
                diagnostic(37).eax
            )
            .unwrap();
        }
        return text;
    }
    let _ = (matrixhv_present, protocol);
    "capabilities=none\nlogical_processor_count=unavailable\n".to_string()
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
