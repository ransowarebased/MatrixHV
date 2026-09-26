use crate::server::hypervisor::MATRIXHV_STATUS_LEAF;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MATRIXHV_DIAGNOSTIC_PROTOCOL: u32 = 4;
const TELEMETRY_CONTROL_CAPABILITY: u32 = 1 << 8;
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
fn verify_cpu(cpu: u32) -> Result<(), String> {
    let status = diagnostic(0);
    if status.eax != 0x4d48_5631
        || status.ebx != u32::from_le_bytes(*b"MATR")
        || status.ecx != u32::from_le_bytes(*b"IXHV")
    {
        return Err(format!("MatrixHV is not present on logical CPU {cpu}"));
    }
    if status.edx != MATRIXHV_DIAGNOSTIC_PROTOCOL {
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
    let registered_mask = pair(diagnostic(36)).0;
    let cpus: Vec<u32> = (0..64)
        .filter(|cpu| registered_mask & (1u64 << cpu) != 0)
        .collect();
    if cpus.is_empty() {
        return Err("MatrixHV reported no registered vCPUs".to_string());
    }
    let mut text = format!(
        "format=matrixhv-telemetry-v2\nmode={}\nscope=registered_vcpus\n",
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
    if matrixhv_present && protocol == MATRIXHV_DIAGNOSTIC_PROTOCOL {
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
            "capabilities=0x{:x}\ncapability_names=vcpu_counters,watchdog_sequence_phase,guest_triad,entry_failure_slot,host_exception_slot,ept_diagnostics,watchdog_lease,remote_vcpu_query{}\nlogical_processor_count={count}\n",
            caps.eax,
            if caps.eax & TELEMETRY_CONTROL_CAPABILITY != 0 {
                ",telemetry_control"
            } else {
                ""
            }
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
struct CpuAffinity {
    thread: *mut core::ffi::c_void,
    allowed: Vec<u32>,
    original_mask: Option<usize>,
}

#[cfg(target_os = "windows")]
impl CpuAffinity {
    fn current() -> Result<Self, String> {
        unsafe extern "system" {
            fn GetCurrentProcess() -> *mut core::ffi::c_void;
            fn GetCurrentThread() -> *mut core::ffi::c_void;
            fn GetProcessAffinityMask(
                process: *mut core::ffi::c_void,
                process_mask: *mut usize,
                system_mask: *mut usize,
            ) -> i32;
        }
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
        unsafe extern "system" {
            fn SetThreadAffinityMask(thread: *mut core::ffi::c_void, mask: usize) -> usize;
        }
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
        unsafe extern "system" {
            fn SetThreadAffinityMask(thread: *mut core::ffi::c_void, mask: usize) -> usize;
        }
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
        unsafe extern "C" {
            fn sched_getaffinity(pid: i32, cpusetsize: usize, mask: *mut u8) -> i32;
        }
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
        unsafe extern "C" {
            fn sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const u8) -> i32;
        }
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
        unsafe extern "C" {
            fn sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const u8) -> i32;
        }
        unsafe { sched_setaffinity(0, self.original_mask.len(), self.original_mask.as_ptr()) };
    }
}
