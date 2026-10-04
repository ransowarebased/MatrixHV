#[repr(C)]
#[derive(Clone, Copy)]
pub struct WatchdogGuestState {
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
}

pub const CONTEXT_CANARY_END: u64 = 0x4856_5245_5349_4432;
pub const CONTEXT_CANARY_START: u64 = 0x4856_5245_5349_4431;
pub const BOOT_CONTEXT_CANARY_END: u64 = 0x4856_424f_4f54_4332;
pub const BOOT_CONTEXT_CANARY_START: u64 = 0x4856_424f_4f54_4331;
pub const FLIGHT_RECORDER_CAPACITY: usize = 2048;
pub const FLIGHT_RECORDER_RECORD_BYTES: usize = 80;
pub const FLIGHT_RECORDER_WORD_COUNT: usize = 20480;
use crate::memory::host::PAGE_SIZE;
use crate::protocol::ControlProbeSnapshot;
use crate::vmx::bridge::ControlCpuState;
use crate::vmx::nested::NestedVmxState;
use crate::vmx::vmcs12::NestedVmcs12State;
use core::mem::size_of;
use core::sync::atomic::AtomicU64;

#[repr(C, align(16))]
pub struct ResidentEventContext {
    pub magic: u64,
    pub exit_boot_services_seen: AtomicU64,
    pub virtual_address_change_seen: u64,
    pub canary: u64,
    pub serial_lock: AtomicU64,
    pub visual_base: u64,
    pub visual_stride_bytes: u64,
    pub post_ebs_cpu_mask: AtomicU64,
    pub diagnostic_halted: AtomicU64,
    pub host_fault_vector: u64,
    pub host_fault_rip: u64,
    pub host_fault_error_code: u64,
    pub host_fault_address: u64,
    pub init_cpu_mask: AtomicU64,
    pub sipi_cpu_mask: AtomicU64,
    pub halted_cpu_mask: AtomicU64,
    pub failed_processor: u64,
    pub failed_exit_reason: u64,
    pub failed_qualification: u64,
    pub failed_stop_result: u64,
    pub watchdog_tsc_hz: u64,
    pub cpu_contexts: [u64; 64],
    pub visual_deadline_tsc: u64,
    pub control_expected_mask: AtomicU64,
    pub control_active_mask: AtomicU64,
    pub control_stopped_mask: AtomicU64,
    pub control_failed_mask: AtomicU64,
    pub control_processor_count: u64,
    pub control_va_error: u64,
    pub control_completion_sequences: [AtomicU64; 64],
    pub control_rearm_mask: AtomicU64,
    pub runtime_get_variable: u64,
    pub runtime_set_variable: u64,
    pub runtime_context: u64,
    pub control_apic_ids: [u32; 64],
    pub control_probe_states: [ControlProbeSnapshot; 64],
    pub control_cpu_states: [ControlCpuState; 64],
    pub hyperv_tsc_scale: u64,
    pub hyperv_tsc_offset: u64,
    pub hyperv_reference_tsc_msr: AtomicU64,
    pub hyperv_reference_tsc_lock: AtomicU64,
    pub hyperv_reference_tsc_sequence: AtomicU64,
    pub hyperv_guest_os_id: AtomicU64,
    pub hyperv_hypercall_msr: AtomicU64,
    pub hyperv_hypercall_lock: AtomicU64,
    pub hyperv_tsc_invariant_supported: u64,
    pub hyperv_tsc_invariant_control: AtomicU64,
    pub control_off_native_rip: u64,
    pub control_recovery_physical: u64,
    pub control_recovery_runtime: u64,
    pub update_loader_physical: u64,
    pub update_loader_runtime: u64,
    pub update_context_physical: u64,
    pub update_context_runtime: u64,
    pub update_status: [u64; 48],
    pub update_public_key: [u8; 32],
    pub update_abi: [u32; 6],
    pub update_image_physical: u64,
    pub update_image_runtime: u64,
    pub update_image_bytes: u64,
    pub update_relocations_start: u64,
    pub update_relocations_end: u64,
    pub memory_entry_physical: u64,
    pub memory_kernel_cr3: AtomicU64,
    pub memory_root_sequence: AtomicU64,
    pub memory_root_history: [AtomicU64; crate::protocol::memory::ROOT_HISTORY_COUNT],
    pub tracking_context_physical: u64,
    pub interception_context_physical: u64,
    pub interception_entry_physical: u64,
}

#[repr(C, align(16))]
pub struct RootFxState(pub [u8; 512]);

#[repr(C)]
#[derive(Default)]
pub struct InterceptionCpuState {
    pub controls_saved: u64,
    pub primary_bits: u64,
    pub exception_bit: u64,
    pub debug_armed: u64,
    pub guest_debug: [u64; 6],
    pub applied_ept: u64,
    pub debug_targets: [[u64; 2]; 4],
    pub debug_count: usize,
    pub debug_token: u64,
    pub debug_generation: u64,
    pub exit_ept: u64,
    pub hook_pages: [u64; crate::protocol::memory::HOOK_MAX_PAGES],
    pub hook_count: usize,
    pub hook_token: u64,
    pub step_active: u64,
    pub step_cr3: u64,
    pub exit_step: u64,
    pub vmfunc_armed: u64,
    pub vmfunc_saved: u64,
    pub vmfunc_secondary: u64,
    pub vmfunc_control: u64,
    pub vmfunc_list: u64,
    pub cooperative_data: u64,
    pub cooperative_cr3: u64,
    pub exit_vmfunc: u64,
    pub cr3_target_count: u64,
    pub timer_saved: u64,
    pub timer_pin: u64,
    pub timer_value: u64,
    pub timer_armed: u64,
    pub exit_timer: u64,
    pub data_address: u64,
    pub data_linear: u64,
    pub data_qualification: u64,
    pub hook_generation: u64,
    pub timing_saved: u64,
    pub timing_offset: u64,
    pub timing_start: u64,
    pub data_pending: u64,
    pub data_rip: u64,
    pub refresh_owned: u64,
    pub split_flush_epoch: AtomicU64,
    pub runtime_diagnostics: [u64; crate::protocol::memory::INTERCEPT_DIAGNOSTIC_WORDS],
    pub sync_diagnostics: [u64; crate::protocol::memory::EPT_SYNC_DIAGNOSTIC_WORDS],
}

#[repr(C, align(16))]
pub struct ResidentBootContext {
    pub serial_lock: u64,
    pub root_rsp: u64,
    pub return_rip: u64,
    pub expected_host_cr3: u64,
    pub initial_guest_cr3: u64,
    pub event_context: u64,
    pub ept_test_gpa: u64,
    pub ept_probe_fault_rip: u64,
    pub ept_probe_resume_rip: u64,
    pub ept_test_violation_seen: u64,
    pub exit_count: u64,
    pub cpuid_count: u64,
    pub rdmsr_count: u64,
    pub wrmsr_count: u64,
    pub xsetbv_count: u64,
    pub vmcall_count: u64,
    pub start_checkpoint_seen: u64,
    pub visual_first_exit_seen: u64,
    pub post_start_exit_count: u64,
    pub post_ebs_exit_count: u64,
    pub post_va_exit_count: u64,
    pub msr_gp_count: u64,
    pub last_gp_msr: u64,
    pub diagnostic_interval_tsc: u64,
    pub diagnostic_timer_rate: u64,
    pub diagnostic_deadline_tsc: u64,
    pub diagnostic_sample_count: u64,
    pub diagnostic_expired: u64,
    pub last_normal_reason: u64,
    pub last_normal_rip: u64,
    pub last_efer_write: u64,
    pub last_reason: u64,
    pub last_instruction_len: u64,
    pub last_qualification: u64,
    pub last_guest_physical_address: u64,
    pub last_guest_rax: u64,
    pub last_guest_rcx: u64,
    pub last_guest_rdx: u64,
    pub last_guest_rip: u64,
    pub last_guest_cr3: u64,
    pub last_host_cr3: u64,
    pub stop_result: u64,
    pub canary_start: u64,
    pub canary_end: u64,
    pub processor_number: u64,
    pub ap_started: u64,
    pub init_count: u64,
    pub sipi_count: u64,
    pub cpuid_presence: u64,
    pub hyperv_timing_supported: u64,
    pub cpuid_leaf1_count: u64,
    pub cpuid_hypervisor_count: u64,
    pub cpuid_leaf1_ecx: u64,
    pub cpuid_hypervisor_eax: u64,
    pub cache_ept_pointer: u64,
    pub cache_generation: u64,
    pub mtrr_dirty: u64,
    pub mtrr_updates: u64,
    pub nmi_pending: u64,
    pub nmi_count: u64,
    pub telemetry_enabled: u64,
    pub telemetry_active: u64,
    pub telemetry_probe_active: u64,
    pub watchdog_tsc_hz: u64,
    pub watchdog_deadline_tsc: u64,
    pub watchdog_sequence: u64,
    pub watchdog_exit_count: u64,
    pub watchdog_phase: u64,
    pub watchdog_handler_returns: u64,
    pub watchdog_resume_failures: u64,
    pub watchdog_last_reason: u64,
    pub watchdog_last_rip: u64,
    pub entry_failure_state: u64,
    pub entry_failure_exit: u64,
    pub entry_failure_tsc: u64,
    pub vmresume_status_flags: u64,
    pub entry_failure: WatchdogGuestState,
    pub last_before: WatchdogGuestState,
    pub last_after_handler: WatchdogGuestState,
    pub last_resume: WatchdogGuestState,
    pub ept_violation_read: u64,
    pub ept_violation_write: u64,
    pub ept_violation_execute: u64,
    pub cr3_exits: u64,
    pub eptp_switches: u64,
    pub mtf_exits: u64,
    pub invept_exits: u64,
    pub preemption_timer_exits: u64,
    pub flight_recorder_sequence: u64,
    pub flight_recorder_frozen: u64,
    pub flight_recorder_records: [u64; FLIGHT_RECORDER_WORD_COUNT],
    pub nested: NestedVmxState,
    pub original_gdtr: [u8; 10],
    pub original_idtr: [u8; 10],
    pub root_fx_state: RootFxState,
    pub root_vmx_active: u64,
    pub cpuid_leaf0: [u32; 4],
    pub memory_scratch: [u8; crate::protocol::memory::BUFFER_BYTES],
    pub interception: InterceptionCpuState,
}

pub const RESIDENT_BOOT_CONTEXT_PAGES: usize = size_of::<ResidentBootContext>().div_ceil(PAGE_SIZE);

impl ResidentBootContext {
    pub fn new(
        expected_host_cr3: u64,
        initial_guest_cr3: u64,
        event_context: u64,
        ept_test_gpa: u64,
        (ept_probe_fault_rip, ept_probe_resume_rip): (u64, u64),
        nested: NestedVmxState,
        cpuid_presence: bool,
    ) -> Self {
        // Both BSP and AP callers construct this context on its owning processor.
        let cpuid_leaf0 = core::arch::x86_64::__cpuid_count(0, 0);
        Self {
            serial_lock: event_context + EVENT_CTX_SERIAL_LOCK as u64,
            root_rsp: 0,
            return_rip: 0,
            expected_host_cr3,
            initial_guest_cr3,
            event_context,
            ept_test_gpa,
            ept_probe_fault_rip,
            ept_probe_resume_rip,
            ept_test_violation_seen: 0,
            exit_count: 0,
            cpuid_count: 0,
            rdmsr_count: 0,
            wrmsr_count: 0,
            xsetbv_count: 0,
            vmcall_count: 0,
            start_checkpoint_seen: 0,
            visual_first_exit_seen: 0,
            post_start_exit_count: 0,
            post_ebs_exit_count: 0,
            post_va_exit_count: 0,
            msr_gp_count: 0,
            last_gp_msr: 0,
            diagnostic_interval_tsc: 0,
            diagnostic_timer_rate: 0,
            diagnostic_deadline_tsc: 0,
            diagnostic_sample_count: 0,
            diagnostic_expired: 0,
            last_normal_reason: 0,
            last_normal_rip: 0,
            last_efer_write: 0,
            last_reason: 0,
            last_instruction_len: 0,
            last_qualification: 0,
            last_guest_physical_address: 0,
            last_guest_rax: 0,
            last_guest_rcx: 0,
            last_guest_rdx: 0,
            last_guest_rip: 0,
            last_guest_cr3: 0,
            last_host_cr3: 0,
            stop_result: 0,
            canary_start: BOOT_CONTEXT_CANARY_START,
            canary_end: BOOT_CONTEXT_CANARY_END,
            processor_number: 0,
            ap_started: 0,
            init_count: 0,
            sipi_count: 0,
            cpuid_presence: u64::from(cpuid_presence),
            hyperv_timing_supported: 0,
            cpuid_leaf1_count: 0,
            cpuid_hypervisor_count: 0,
            cpuid_leaf1_ecx: 0,
            cpuid_hypervisor_eax: 0,
            cache_ept_pointer: 0,
            cache_generation: 0,
            mtrr_dirty: 0,
            mtrr_updates: 0,
            nmi_pending: 0,
            nmi_count: 0,
            telemetry_enabled: 0,
            telemetry_active: 0,
            telemetry_probe_active: 0,
            watchdog_tsc_hz: 0,
            watchdog_deadline_tsc: 0,
            watchdog_sequence: 0,
            watchdog_exit_count: 0,
            watchdog_phase: 1,
            watchdog_handler_returns: 0,
            watchdog_resume_failures: 0,
            watchdog_last_reason: 0,
            watchdog_last_rip: 0,
            entry_failure_state: 0,
            entry_failure_exit: 0,
            entry_failure_tsc: 0,
            vmresume_status_flags: 0,
            entry_failure: WatchdogGuestState {
                rip: 0,
                rsp: 0,
                rflags: 0,
                cr0: 0,
                cr3: 0,
                cr4: 0,
                efer: 0,
            },
            last_before: WatchdogGuestState {
                rip: 0,
                rsp: 0,
                rflags: 0,
                cr0: 0,
                cr3: 0,
                cr4: 0,
                efer: 0,
            },
            last_after_handler: WatchdogGuestState {
                rip: 0,
                rsp: 0,
                rflags: 0,
                cr0: 0,
                cr3: 0,
                cr4: 0,
                efer: 0,
            },
            last_resume: WatchdogGuestState {
                rip: 0,
                rsp: 0,
                rflags: 0,
                cr0: 0,
                cr3: 0,
                cr4: 0,
                efer: 0,
            },
            ept_violation_read: 0,
            ept_violation_write: 0,
            ept_violation_execute: 0,
            cr3_exits: 0,
            eptp_switches: 0,
            mtf_exits: 0,
            invept_exits: 0,
            preemption_timer_exits: 0,
            flight_recorder_sequence: 0,
            flight_recorder_frozen: 0,
            flight_recorder_records: [0; FLIGHT_RECORDER_WORD_COUNT],
            nested,
            original_gdtr: [0; 10],
            original_idtr: [0; 10],
            root_fx_state: RootFxState([0; 512]),
            root_vmx_active: 0,
            memory_scratch: [0; crate::protocol::memory::BUFFER_BYTES],
            interception: InterceptionCpuState::default(),
            cpuid_leaf0: [
                cpuid_leaf0.eax,
                cpuid_leaf0.ebx,
                cpuid_leaf0.ecx,
                cpuid_leaf0.edx,
            ],
        }
    }
}

pub const BCTX_SERIAL_LOCK: usize = core::mem::offset_of!(ResidentBootContext, serial_lock);
pub const BCTX_ROOT_RSP: usize = core::mem::offset_of!(ResidentBootContext, root_rsp);
pub const BCTX_RETURN_RIP: usize = core::mem::offset_of!(ResidentBootContext, return_rip);
pub const BCTX_EXPECTED_HOST_CR3: usize =
    core::mem::offset_of!(ResidentBootContext, expected_host_cr3);
pub const BCTX_EVENT_CONTEXT: usize = core::mem::offset_of!(ResidentBootContext, event_context);
pub const BCTX_EPT_TEST_GPA: usize = core::mem::offset_of!(ResidentBootContext, ept_test_gpa);
pub const BCTX_EPT_PROBE_FAULT_RIP: usize =
    core::mem::offset_of!(ResidentBootContext, ept_probe_fault_rip);
pub const BCTX_EPT_PROBE_RESUME_RIP: usize =
    core::mem::offset_of!(ResidentBootContext, ept_probe_resume_rip);
pub const BCTX_EPT_TEST_VIOLATION_SEEN: usize =
    core::mem::offset_of!(ResidentBootContext, ept_test_violation_seen);
pub const BCTX_EXIT_COUNT: usize = core::mem::offset_of!(ResidentBootContext, exit_count);
pub const BCTX_CPUID_COUNT: usize = core::mem::offset_of!(ResidentBootContext, cpuid_count);
pub const BCTX_RDMSR_COUNT: usize = core::mem::offset_of!(ResidentBootContext, rdmsr_count);
pub const BCTX_WRMSR_COUNT: usize = core::mem::offset_of!(ResidentBootContext, wrmsr_count);
pub const BCTX_XSETBV_COUNT: usize = core::mem::offset_of!(ResidentBootContext, xsetbv_count);
pub const BCTX_VMCALL_COUNT: usize = core::mem::offset_of!(ResidentBootContext, vmcall_count);
pub const BCTX_START_CHECKPOINT_SEEN: usize =
    core::mem::offset_of!(ResidentBootContext, start_checkpoint_seen);
pub const BCTX_VISUAL_FIRST_EXIT_SEEN: usize =
    core::mem::offset_of!(ResidentBootContext, visual_first_exit_seen);
pub const BCTX_POST_START_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, post_start_exit_count);
pub const BCTX_POST_EBS_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, post_ebs_exit_count);
pub const BCTX_POST_VA_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, post_va_exit_count);
pub const BCTX_MSR_GP_COUNT: usize = core::mem::offset_of!(ResidentBootContext, msr_gp_count);
pub const BCTX_LAST_GP_MSR: usize = core::mem::offset_of!(ResidentBootContext, last_gp_msr);
pub const BCTX_DIAGNOSTIC_INTERVAL: usize =
    core::mem::offset_of!(ResidentBootContext, diagnostic_interval_tsc);
pub const BCTX_DIAGNOSTIC_RATE: usize =
    core::mem::offset_of!(ResidentBootContext, diagnostic_timer_rate);
pub const BCTX_DIAGNOSTIC_DEADLINE: usize =
    core::mem::offset_of!(ResidentBootContext, diagnostic_deadline_tsc);
pub const BCTX_DIAGNOSTIC_SAMPLES: usize =
    core::mem::offset_of!(ResidentBootContext, diagnostic_sample_count);
pub const BCTX_DIAGNOSTIC_EXPIRED: usize =
    core::mem::offset_of!(ResidentBootContext, diagnostic_expired);
pub const BCTX_LAST_NORMAL_REASON: usize =
    core::mem::offset_of!(ResidentBootContext, last_normal_reason);
pub const BCTX_LAST_NORMAL_RIP: usize = core::mem::offset_of!(ResidentBootContext, last_normal_rip);
pub const BCTX_LAST_EFER_WRITE: usize = core::mem::offset_of!(ResidentBootContext, last_efer_write);
pub const BCTX_LAST_REASON: usize = core::mem::offset_of!(ResidentBootContext, last_reason);
pub const BCTX_LAST_INSTRUCTION_LEN: usize =
    core::mem::offset_of!(ResidentBootContext, last_instruction_len);
pub const BCTX_LAST_QUALIFICATION: usize =
    core::mem::offset_of!(ResidentBootContext, last_qualification);
pub const BCTX_LAST_GUEST_PHYSICAL_ADDRESS: usize =
    core::mem::offset_of!(ResidentBootContext, last_guest_physical_address);
pub const BCTX_LAST_GUEST_RAX: usize = core::mem::offset_of!(ResidentBootContext, last_guest_rax);
pub const BCTX_LAST_GUEST_RCX: usize = core::mem::offset_of!(ResidentBootContext, last_guest_rcx);
pub const BCTX_LAST_GUEST_RDX: usize = core::mem::offset_of!(ResidentBootContext, last_guest_rdx);
pub const BCTX_LAST_GUEST_RIP: usize = core::mem::offset_of!(ResidentBootContext, last_guest_rip);
pub const BCTX_LAST_GUEST_CR3: usize = core::mem::offset_of!(ResidentBootContext, last_guest_cr3);
pub const BCTX_LAST_HOST_CR3: usize = core::mem::offset_of!(ResidentBootContext, last_host_cr3);
pub const BCTX_STOP_RESULT: usize = core::mem::offset_of!(ResidentBootContext, stop_result);
pub const BCTX_CANARY_START: usize = core::mem::offset_of!(ResidentBootContext, canary_start);
pub const BCTX_CANARY_END: usize = core::mem::offset_of!(ResidentBootContext, canary_end);
pub const BCTX_CPUID_PRESENCE: usize = core::mem::offset_of!(ResidentBootContext, cpuid_presence);
pub const BCTX_CPUID_LEAF1_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, cpuid_leaf1_count);
pub const BCTX_CPUID_HYPERVISOR_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, cpuid_hypervisor_count);
pub const BCTX_CPUID_LEAF1_ECX: usize = core::mem::offset_of!(ResidentBootContext, cpuid_leaf1_ecx);
pub const BCTX_CPUID_HYPERVISOR_EAX: usize =
    core::mem::offset_of!(ResidentBootContext, cpuid_hypervisor_eax);
pub const BCTX_NESTED_FEATURE_CONTROL: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, feature_control);
pub const BCTX_NESTED_VMX_BASIC: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_basic);
pub const BCTX_NESTED_VMX_PINBASED_CTLS: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_pinbased_ctls);
pub const BCTX_NESTED_VMX_PROCBASED_CTLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmx_procbased_ctls);
pub const BCTX_NESTED_VMX_EXIT_CTLS: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_exit_ctls);
pub const BCTX_NESTED_VMX_ENTRY_CTLS: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_entry_ctls);
pub const BCTX_NESTED_VMX_MISC: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_misc);
pub const BCTX_NESTED_HOST_PROCBASED_CTLS2: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, host_procbased_ctls2);
pub const BCTX_NESTED_HOST_MISC: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, host_misc);
pub const BCTX_NESTED_VMX_CR0_FIXED0: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_cr0_fixed0);
pub const BCTX_NESTED_VMX_CR0_FIXED1: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_cr0_fixed1);
pub const BCTX_NESTED_VMX_CR4_FIXED0: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_cr4_fixed0);
pub const BCTX_NESTED_VMX_CR4_FIXED1: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_cr4_fixed1);
pub const BCTX_NESTED_VMX_VMCS_ENUM: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_vmcs_enum);
pub const BCTX_NESTED_VMX_PROCBASED_CTLS2: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmx_procbased_ctls2);
pub const BCTX_NESTED_VMX_EPT_VPID_CAP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_ept_vpid_cap);
pub const BCTX_NESTED_VMX_TRUE_PINBASED_CTLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmx_true_pinbased_ctls);
pub const BCTX_NESTED_VMX_TRUE_PROCBASED_CTLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmx_true_procbased_ctls);
pub const BCTX_NESTED_VMX_TRUE_EXIT_CTLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmx_true_exit_ctls);
pub const BCTX_NESTED_VMX_TRUE_ENTRY_CTLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmx_true_entry_ctls);
pub const BCTX_NESTED_EXPOSE_VMX: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, expose_vmx);
pub const BCTX_NESTED_L1_CR4: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l1_cr4);
pub const BCTX_NESTED_VMXON_OPERAND: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmxon_operand);
pub const BCTX_NESTED_VMXON_REGION: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmxon_region);
pub const BCTX_NESTED_CURRENT_VMCS: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, current_vmcs);
pub const BCTX_NESTED_LAST_OPERAND: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, last_operand);
pub const BCTX_NESTED_LAST_VMCS_FIELD: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, last_vmcs_field);
pub const BCTX_NESTED_INSTRUCTION_ERROR: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, instruction_error);
pub const BCTX_NESTED_VMXON_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmxon_count);
pub const BCTX_NESTED_VMXOFF_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmxoff_count);
pub const BCTX_NESTED_FAILURE_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, failure_count);
pub const BCTX_NESTED_ACTIVE: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, active);
pub const BCTX_NESTED_PROBE_COMPLETE: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, probe_complete);
pub const BCTX_NESTED_VMCS12_OPERAND: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, operand);
pub const BCTX_NESTED_VMCS12_REGION: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, region);
pub const BCTX_NESTED_VMPTRST_DESTINATION: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, vmptrst_destination);
pub const BCTX_NESTED_LAST_STORED_POINTER: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, last_stored_pointer);
pub const BCTX_NESTED_VMCS12_REVISION_ID: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, revision_id);
pub const BCTX_NESTED_VMCS12_LAUNCH_STATE: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, launch_state);
pub const BCTX_NESTED_VMCS12_GUEST_RIP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, guest_rip);
pub const BCTX_NESTED_VMCS12_GUEST_RSP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, guest_rsp);
pub const BCTX_NESTED_VMCS12_GUEST_RFLAGS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, guest_rflags);
pub const BCTX_NESTED_VMCS12_HOST_RSP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, host_rsp);
pub const BCTX_NESTED_VMCS12_HOST_RIP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, host_rip);
pub const BCTX_NESTED_VMCS12_EXIT_INSTRUCTION_LEN: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, exit_instruction_len);
pub const BCTX_NESTED_VMCS12_EXIT_QUALIFICATION: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, exit_qualification);
pub const BCTX_NESTED_VMCS12_EXTENDED_FIELDS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, extended_fields);
pub const BCTX_NESTED_VMCS12_VPID: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS;
pub const BCTX_NESTED_VMCS12_PIN_BASED_CONTROL: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 8;
pub const BCTX_NESTED_VMCS12_PRIMARY_CONTROL: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 16;
pub const BCTX_NESTED_VMCS12_SECONDARY_CONTROL: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 24;
pub const BCTX_NESTED_VMCS12_EXCEPTION_BITMAP: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 32;
pub const BCTX_NESTED_VMCS12_PF_ERROR_MASK: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 40;
pub const BCTX_NESTED_VMCS12_PF_ERROR_MATCH: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 48;
pub const BCTX_NESTED_VMCS12_CR3_TARGET_COUNT: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 56;
pub const BCTX_NESTED_VMCS12_VM_EXIT_CONTROLS: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 64;
pub const BCTX_NESTED_VMCS12_VM_EXIT_MSR_STORE_COUNT: usize =
    BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 72;
pub const BCTX_NESTED_VMCS12_VM_EXIT_MSR_LOAD_COUNT: usize =
    BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 80;
pub const BCTX_NESTED_VMCS12_VM_ENTRY_CONTROLS: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 88;
pub const BCTX_NESTED_VMCS12_VM_ENTRY_MSR_LOAD_COUNT: usize =
    BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 96;
pub const BCTX_NESTED_VMCS12_VM_ENTRY_INTR_INFO: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 104;
pub const BCTX_NESTED_VMCS12_VM_ENTRY_EXCEPTION_ERROR: usize =
    BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 112;
pub const BCTX_NESTED_VMCS12_VM_ENTRY_INSTRUCTION_LEN: usize =
    BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 120;
pub const BCTX_NESTED_VMCS12_EPT_POINTER: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 128;
pub const BCTX_NESTED_VMCS12_TSC_OFFSET: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 136;
pub const BCTX_NESTED_VMCS12_GUEST_PHYSICAL_ADDRESS: usize =
    BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 110 * size_of::<u64>();
pub const BCTX_NESTED_VMCS12_CR0_MASK: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 152;
pub const BCTX_NESTED_VMCS12_CR4_MASK: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 160;
pub const BCTX_NESTED_VMCS12_CR0_SHADOW: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 168;
pub const BCTX_NESTED_VMCS12_CR4_SHADOW: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 176;
pub const BCTX_NESTED_VMCS12_MSR_BITMAP: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 144;
pub const BCTX_NESTED_VMCS12_IO_BITMAP_A: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 744;
pub const BCTX_NESTED_VMCS12_IO_BITMAP_B: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 752;
pub const BCTX_NESTED_VMCS12_TPR_THRESHOLD: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 800;
pub const BCTX_NESTED_VMCS12_VIRTUAL_APIC_PAGE: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 808;
pub const BCTX_NESTED_VMCS12_XSS_EXITING_BITMAP: usize =
    BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 95 * size_of::<u64>();
pub const BCTX_NESTED_VMCS12_VM_EXIT_MSR_STORE_ADDR: usize =
    BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 824;
pub const BCTX_NESTED_VMCS12_VM_EXIT_MSR_LOAD_ADDR: usize =
    BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 832;
pub const BCTX_NESTED_VMCS12_VM_ENTRY_MSR_LOAD_ADDR: usize =
    BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 840;
pub const BCTX_NESTED_VMCS12_VM_EXIT_INTR_INFO: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 848;
pub const BCTX_NESTED_VMCS12_VM_EXIT_INTR_ERROR: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 856;
pub const BCTX_NESTED_VMCS12_IDT_VECTORING_INFO: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 864;
pub const BCTX_NESTED_VMCS12_IDT_VECTORING_ERROR: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 872;
pub const BCTX_NESTED_VMCS12_EXIT_INSTRUCTION_INFO: usize =
    BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 115 * size_of::<u64>();
pub const BCTX_NESTED_VMCS12_GUEST_CR0: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 232;
pub const BCTX_NESTED_VMCS12_GUEST_CR3: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 240;
pub const BCTX_NESTED_VMCS12_GUEST_CR4: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 248;
pub const BCTX_NESTED_VMCS12_HOST_CR0: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 256;
pub const BCTX_NESTED_VMCS12_HOST_CR3: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 264;
pub const BCTX_NESTED_VMCS12_HOST_CR4: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 272;
pub const BCTX_NESTED_VMCS12_GUEST_SYSENTER_EIP: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 696;
pub const BCTX_NESTED_VMCS12_HOST_SYSENTER_ESP: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 712;
pub const BCTX_NESTED_VMCS12_HOST_SYSENTER_EIP: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 720;
pub const BCTX_NESTED_VMCS12_CONTROL_VALIDATION_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, control_validation_count);
pub const BCTX_NESTED_VMCLEAR_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmclear_count);
pub const BCTX_NESTED_VMPTRLD_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmptrld_count);
pub const BCTX_NESTED_VMPTRST_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmptrst_count);
pub const BCTX_NESTED_VMWRITE_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmwrite_count);
pub const BCTX_NESTED_VMREAD_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmread_count);
pub const BCTX_NESTED_VMCS12_PROBE_COMPLETE: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, probe_complete);
pub const BCTX_NESTED_VMLAUNCH_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmlaunch_count);
pub const BCTX_NESTED_VMRESUME_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmresume_count);
pub const BCTX_NESTED_ENTRY_REJECTION_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, entry_rejection_count);
pub const BCTX_NESTED_VMCS01_REGION: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs01_region);
pub const BCTX_NESTED_VMCS02_REGION: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs02_region);
pub const BCTX_NESTED_SHADOW_VMCS_REGION: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, shadow_vmcs_region);
pub const BCTX_NESTED_SHADOW_VMREAD_BITMAP: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, shadow_vmread_bitmap);
pub const BCTX_NESTED_L2_ACTIVE: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_active);
pub const BCTX_NESTED_L2_ENTRY_WAS_RESUME: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, l2_entry_was_resume);
pub const BCTX_NESTED_L2_ENTRY_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_entry_count);
pub const BCTX_NESTED_L2_EXIT_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_exit_count);
pub const BCTX_NESTED_L2_LAST_EXIT_RIP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_last_exit_rip);
pub const BCTX_NESTED_L2_LAST_EXIT_RSP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_last_exit_rsp);
pub const BCTX_NESTED_L1_REFLECTION_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, l1_reflection_count);
pub const BCTX_NESTED_L2_RESUME_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_resume_count);
pub const BCTX_NESTED_L2_RESUME_EXIT_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, l2_resume_exit_count);
pub const BCTX_NESTED_EPT12_POINTER: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept12_pointer);
pub const BCTX_NESTED_EPT_TARGET_GPA: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept_target_gpa);
pub const BCTX_NESTED_EPT_COMPOSITION_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept_composition_count);
pub const BCTX_NESTED_EPT_PROBE_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept_probe_count);
pub const BCTX_NESTED_EPT_OBSERVED_VALUE: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept_observed_value);
pub const BCTX_NESTED_EPT02_POINTER: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept02_pointer);
pub const BCTX_NESTED_EPT02_ALTERNATE_POINTER: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_alternate_pointer);
pub const BCTX_NESTED_EPT_SECOND_TARGET_GPA: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept_second_target_gpa);
pub const BCTX_NESTED_EPT12_SOURCE_LEAF: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept12_source_leaf);
pub const BCTX_NESTED_EPT12_SOURCE_LEAF_ATTRIBUTES: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept12_source_leaf_attributes);
pub const BCTX_NESTED_INVEPT_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, invept_count);
pub const BCTX_NESTED_INVEPT_SOFTWARE_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, invept_software_count);
pub const BCTX_NESTED_INVVPID_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, invvpid_count);
pub const BCTX_NESTED_INVVPID_SOFTWARE_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, invvpid_software_count);
pub const BCTX_NESTED_EPT_OBSERVED_VALUE_AFTER_INVEPT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept_observed_value_after_invept);
pub const BCTX_NESTED_EPT02_INITIAL_POINTER: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_initial_pointer);
pub const BCTX_NESTED_EPT02_TABLE_POOL: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept02_table_pool);
pub const BCTX_NESTED_EPT02_TABLE_POOL_PAGES: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_table_pool_pages);
pub const BCTX_NESTED_EPT02_TABLE_POOL_USED: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_table_pool_used);
pub const BCTX_NESTED_EPT01_POINTER: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept01_pointer);
pub const BCTX_NESTED_EPT02_INVALIDATION_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_invalidation_count);
pub const BCTX_NESTED_EPT_OBSERVED_VALUE_BEFORE_INVEPT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept_observed_value_before_invept);
pub const BCTX_NESTED_CONTROL_MERGE_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, control_merge_count);
pub const BCTX_NESTED_GUEST_STATE_SYNC_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, guest_state_sync_count);
pub const BCTX_NESTED_L1_HOST_RESTORE_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, l1_host_restore_count);
pub const BCTX_NESTED_LAST_SYNCED_GUEST_CR0: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_synced_guest_cr0);
pub const BCTX_NESTED_LAST_SYNCED_GUEST_CR3: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_synced_guest_cr3);
pub const BCTX_NESTED_LAST_SYNCED_GUEST_CR4: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_synced_guest_cr4);
pub const BCTX_NESTED_LAST_RESTORED_HOST_CR0: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_restored_host_cr0);
pub const BCTX_NESTED_LAST_RESTORED_HOST_CR3: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_restored_host_cr3);
pub const BCTX_NESTED_LAST_RESTORED_HOST_CR4: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_restored_host_cr4);
pub const BCTX_NESTED_LAST_SYNCED_GUEST_SYSENTER_EIP: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_synced_guest_sysenter_eip);
pub const BCTX_NESTED_LAST_RESTORED_HOST_SYSENTER_EIP: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_restored_host_sysenter_eip);
pub const BCTX_NESTED_INHERITED_L1_PAT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, inherited_l1_pat);
pub const BCTX_NESTED_INHERITED_L1_EFER: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, inherited_l1_efer);
pub const BCTX_NESTED_INHERITED_L1_TSC_OFFSET: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, inherited_l1_tsc_offset);
pub const BCTX_NESTED_VMCS01_PIN_BASED_CONTROLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs01_pin_based_controls);
pub const BCTX_NESTED_VMCS01_PRIMARY_CONTROLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs01_primary_controls);
pub const BCTX_NESTED_VMCS01_SECONDARY_CONTROLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs01_secondary_controls);
pub const BCTX_NESTED_VMCS01_EXIT_CONTROLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs01_exit_controls);
pub const BCTX_NESTED_VMCS01_ENTRY_CONTROLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs01_entry_controls);
pub const BCTX_NESTED_L2_SAVED_PAT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_saved_pat);
pub const BCTX_NESTED_L2_SAVED_EFER: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_saved_efer);
pub const BCTX_NESTED_LAST_MERGED_SECONDARY_CONTROLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_merged_secondary_controls);
pub const BCTX_NESTED_LAST_SYNCED_GUEST_GS_BASE: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_synced_guest_gs_base);
pub const BCTX_NESTED_LAST_CAPTURED_GUEST_GS_BASE: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_captured_guest_gs_base);
pub const BCTX_NESTED_LAST_RESTORED_HOST_GS_BASE: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_restored_host_gs_base);
pub const BCTX_NESTED_LAST_RESTORED_HOST_CS_AR: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_restored_host_cs_ar);
pub const BCTX_NESTED_L0_MSR_BITMAP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l0_msr_bitmap);
pub const BCTX_NESTED_COMPOSED_MSR_BITMAP: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, composed_msr_bitmap);
pub const BCTX_NESTED_L0_MSR_GUEST_LIST: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l0_msr_guest_list);
pub const BCTX_NESTED_L0_MSR_HOST_LIST: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l0_msr_host_list);
pub const BCTX_NESTED_VMCS02_ENTRY_MSR_LIST: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs02_entry_msr_list);
pub const BCTX_NESTED_VMCS02_EXIT_STORE_MSR_LIST: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs02_exit_store_msr_list);
pub const BCTX_NESTED_VMCS01_ENTRY_MSR_LIST: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs01_entry_msr_list);
pub const BCTX_NESTED_VMCS01_MSR_ENTRY_COMPOSED: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs01_msr_entry_composed);
pub const BCTX_ORIGINAL_GDTR: usize = core::mem::offset_of!(ResidentBootContext, original_gdtr);
pub const BCTX_ORIGINAL_IDTR: usize = core::mem::offset_of!(ResidentBootContext, original_idtr);
pub const BCTX_ROOT_FX_STATE: usize = core::mem::offset_of!(ResidentBootContext, root_fx_state);
const _: () = assert!(BCTX_ROOT_FX_STATE & 0xf == 0);

pub const EVENT_CTX_MAGIC: usize = core::mem::offset_of!(ResidentEventContext, magic);
pub const EVENT_CTX_EBS_SEEN: usize =
    core::mem::offset_of!(ResidentEventContext, exit_boot_services_seen);
pub const EVENT_CTX_VA_SEEN: usize =
    core::mem::offset_of!(ResidentEventContext, virtual_address_change_seen);
pub const EVENT_CTX_CANARY: usize = core::mem::offset_of!(ResidentEventContext, canary);
pub const EVENT_CTX_SERIAL_LOCK: usize = core::mem::offset_of!(ResidentEventContext, serial_lock);
pub const EVENT_CTX_VISUAL_BASE: usize = core::mem::offset_of!(ResidentEventContext, visual_base);
pub const EVENT_CTX_VISUAL_STRIDE_BYTES: usize =
    core::mem::offset_of!(ResidentEventContext, visual_stride_bytes);
pub const EVENT_CTX_POST_EBS_CPU_MASK: usize =
    core::mem::offset_of!(ResidentEventContext, post_ebs_cpu_mask);
pub const EVENT_CTX_DIAGNOSTIC_HALTED: usize =
    core::mem::offset_of!(ResidentEventContext, diagnostic_halted);
pub const EVENT_CTX_HOST_FAULT_VECTOR: usize =
    core::mem::offset_of!(ResidentEventContext, host_fault_vector);
pub const EVENT_CTX_HOST_FAULT_RIP: usize =
    core::mem::offset_of!(ResidentEventContext, host_fault_rip);
pub const EVENT_CTX_HOST_FAULT_ERROR_CODE: usize =
    core::mem::offset_of!(ResidentEventContext, host_fault_error_code);
pub const EVENT_CTX_HOST_FAULT_ADDRESS: usize =
    core::mem::offset_of!(ResidentEventContext, host_fault_address);

#[repr(C, align(16))]
pub struct ResidentContext {
    pub root_rsp: u64,
    pub return_rip: u64,
    pub source_cr3: u64,
    pub expected_host_cr3: u64,
    pub observed_host_cr3: u64,
    pub observed_guest_cr3: u64,
    pub exit_reason: u64,
    pub guest_rip: u64,
    pub canary_start: u64,
    pub completed: u64,
    pub canary_end: u64,
    pub original_gdtr: [u8; 10],
    pub original_idtr: [u8; 10],
}

impl ResidentContext {
    pub fn new(source_cr3: u64, expected_host_cr3: u64) -> Self {
        Self {
            root_rsp: 0,
            return_rip: 0,
            source_cr3,
            expected_host_cr3,
            observed_host_cr3: 0,
            observed_guest_cr3: 0,
            exit_reason: 0,
            guest_rip: 0,
            canary_start: CONTEXT_CANARY_START,
            completed: 0,
            canary_end: CONTEXT_CANARY_END,
            original_gdtr: [0; 10],
            original_idtr: [0; 10],
        }
    }
}

pub const BCTX_NESTED_VMCS12_EXIT_REASON: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, exit_reason);

pub const BCTX_NESTED_L2_LAST_EXIT_REASON: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, l2_last_exit_reason);
