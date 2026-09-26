use core::arch::global_asm;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use uefi::Status;
use uefi::boot::{self, EventNotifyFn, EventType, Tpl};

use super::vmcs;
use super::vmcs::*;
use super::vt_controls::{self, VmxControlsError};
use super::vt_ept::{self, EptError};
use super::vt_state;
use super::vt_vmxon::{self, VmxInstructionResult, VmxonError};
use crate::arch;
use crate::memory::{
    AddressConstraint, HostAddressSpace, HostPagingError, PAGE_SIZE, RESIDENT_CODE_MEMORY_TYPE,
    RESIDENT_EVENT_MEMORY_TYPE, RESIDENT_MEMORY_TYPE, ResidentPages,
};
use crate::nested::{
    CPUID_HYPERVISOR_PRESENT_BIT, CPUID_OSXSAVE_BIT, CPUID_VMX_BIT, HYPERV_FEATURES_LEAF,
    HYPERVISOR_LEAF_END, HYPERVISOR_LEAF_START, HostVmxCapabilities, IA32_VMX_BASIC_MSR,
    IA32_VMX_CR0_FIXED0_MSR, IA32_VMX_CR0_FIXED1_MSR, IA32_VMX_CR4_FIXED0_MSR,
    IA32_VMX_CR4_FIXED1_MSR, IA32_VMX_ENTRY_CTLS_MSR, IA32_VMX_EPT_VPID_CAP_MSR,
    IA32_VMX_EXIT_CTLS_MSR, IA32_VMX_MISC_MSR, IA32_VMX_PINBASED_CTLS_MSR,
    IA32_VMX_PROCBASED_CTLS_MSR, IA32_VMX_PROCBASED_CTLS2_MSR, IA32_VMX_TRUE_ENTRY_CTLS_MSR,
    IA32_VMX_TRUE_EXIT_CTLS_MSR, IA32_VMX_TRUE_PINBASED_CTLS_MSR, IA32_VMX_TRUE_PROCBASED_CTLS_MSR,
    IA32_VMX_VMCS_ENUM_MSR, INVALID_OPERAND_TO_INVEPT_INVVPID_ERROR, INVEPT_EXIT_REASON,
    INVVPID_EXIT_REASON, MATRIXHV_STATUS_LEAF, MATRIXHV_STATUS_PROTOCOL,
    MATRIXHV_STATUS_SIGNATURE_EAX, MATRIXHV_STATUS_SIGNATURE_EBX, MATRIXHV_STATUS_SIGNATURE_ECX,
    NestedEptConfiguration, NestedMsrComposition, NestedVmcs12State, NestedVmxCapabilities,
    NestedVmxState, VM_ENTRY_BLOCKED_BY_MOV_SS_ERROR, VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR,
    VM_ENTRY_INVALID_HOST_STATE_FIELD_ERROR, VMCLEAR_EXIT_REASON,
    VMCLEAR_INVALID_PHYSICAL_ADDRESS_ERROR, VMCLEAR_VMXON_POINTER_ERROR,
    VMCS_FIELD_EXIT_QUALIFICATION, VMCS_FIELD_GUEST_LINEAR_ADDRESS,
    VMCS_FIELD_GUEST_PHYSICAL_ADDRESS, VMCS_FIELD_GUEST_RFLAGS, VMCS_FIELD_GUEST_RIP,
    VMCS_FIELD_GUEST_RSP, VMCS_FIELD_HOST_RIP, VMCS_FIELD_HOST_RSP,
    VMCS_FIELD_IDT_VECTORING_ERROR_CODE, VMCS_FIELD_IDT_VECTORING_INFO_FIELD,
    VMCS_FIELD_VM_EXIT_INSTRUCTION_INFO, VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN,
    VMCS_FIELD_VM_EXIT_INTR_ERROR_CODE, VMCS_FIELD_VM_EXIT_INTR_INFO, VMCS_FIELD_VM_EXIT_REASON,
    VMCS_FIELD_VM_INSTRUCTION_ERROR, VMCS_UNSUPPORTED_COMPONENT_ERROR, VMCS12_BACKING_MAGIC,
    VMCS12_BACKING_MAGIC_OFFSET, VMCS12_BACKING_QWORD_COUNT, VMCS12_BACKING_STATE_OFFSET,
    VMCS12_EXTENDED_FIELD_COUNT, VMCS12_EXTENDED_FIELDS, VMCS12_LAUNCH_STATE_CLEAR,
    VMCS12_LAUNCH_STATE_LAUNCHED, VMFAIL_INVALID_STATUS, VMFAIL_VALID_STATUS, VMLAUNCH_EXIT_REASON,
    VMLAUNCH_NON_CLEAR_VMCS_ERROR, VMPTRLD_EXIT_REASON, VMPTRLD_INCORRECT_REVISION_ERROR,
    VMPTRLD_INVALID_PHYSICAL_ADDRESS_ERROR, VMPTRLD_VMXON_POINTER_ERROR, VMPTRST_EXIT_REASON,
    VMREAD_EXIT_REASON, VMRESUME_EXIT_REASON, VMRESUME_NON_LAUNCHED_VMCS_ERROR,
    VMWRITE_EXIT_REASON, VMWRITE_READ_ONLY_COMPONENT_ERROR, VMX_BASIC_TRUE_CONTROLS,
    VMX_SECONDARY_ENABLE_EPT, VMX_SECONDARY_ENABLE_VPID, VMX_STATUS_FLAGS_CLEAR_MASK,
    VMXOFF_EXIT_REASON, VMXON_EXIT_REASON, VMXON_IN_VMX_ROOT_ERROR,
};
use crate::smp::ResidentCpuResources;

const GUEST_STACK_PAGES: usize = 4;
pub(crate) const BOOT_GUEST_STACK_PAGES: usize = 64;
pub(crate) const HOST_STACK_PAGES: usize = 4;
const HOST_TABLE_PAGES: usize = 4;
const MSR_BITMAP_PAGES: usize = 1;
const MSR_BITMAP_READ_HIGH_OFFSET: usize = 1024;
const MSR_BITMAP_WRITE_LOW_OFFSET: usize = 2048;
const MSR_BITMAP_WRITE_HIGH_OFFSET: usize = 3072;
const CONTEXT_CANARY_START: u64 = 0x4856_5245_5349_4431;
const CONTEXT_CANARY_END: u64 = 0x4856_5245_5349_4432;
const CONTEXT_COMPLETE: u64 = 0x4856_5245_534f_4b21;
const EVENT_CONTEXT_MAGIC: u64 = 0x4856_4556_454e_5431;
const EVENT_CONTEXT_CANARY: u64 = 0x4856_4556_4341_4e59;
const VMCALL_EXIT_REASON: u64 = 18;
const CPUID_EXIT_REASON: u64 = 10;
const RDMSR_EXIT_REASON: u64 = 31;
const WRMSR_EXIT_REASON: u64 = 32;
const XSETBV_EXIT_REASON: u64 = 55;
const EPT_VIOLATION_EXIT_REASON: u64 = 48;
const VMX_PREEMPTION_TIMER_EXIT_REASON: u64 = 52;
const VM_ENTRY_FAILURE_MSR_LOADING_EXIT_REASON: u64 = 34;
const EPT_TEST_READ_ACCESS: u64 = 1;
const VMWARE_HYPERVISOR_MAGIC: u32 = 0x564d_5868;
const VMWARE_HYPERVISOR_PORT: u16 = 0x5658;
const IA32_TSC_MSR: u32 = 0x10;
const IA32_TSC_ADJUST_MSR: u32 = 0x3b;
const IA32_PLATFORM_ID_MSR: u32 = 0x17;
const IA32_APIC_BASE_MSR: u32 = 0x1b;
const IA32_FEATURE_CONTROL_MSR: u32 = 0x3a;
const IA32_SPEC_CTRL_MSR: u32 = 0x48;
const IA32_PRED_CMD_MSR: u32 = 0x49;
const IA32_BIOS_SIGN_ID_MSR: u32 = 0x8b;
const IA32_MTRRCAP_MSR: u32 = 0xfe;
const IA32_ARCH_CAPABILITIES_MSR: u32 = 0x10a;
const IA32_MCG_CAP_MSR: u32 = 0x179;
const IA32_MCG_STATUS_MSR: u32 = 0x17a;
const IA32_MCG_CTL_MSR: u32 = 0x17b;
const IA32_SYSENTER_CS_MSR: u32 = 0x174;
const IA32_SYSENTER_ESP_MSR: u32 = 0x175;
const IA32_SYSENTER_EIP_MSR: u32 = 0x176;
const IA32_MISC_ENABLE_MSR: u32 = 0x1a0;
const IA32_MTRR_PHYSBASE0_MSR: u32 = 0x200;
const IA32_MTRR_FIX64K_00000_MSR: u32 = 0x250;
const IA32_MTRR_FIX16K_80000_MSR: u32 = 0x258;
const IA32_MTRR_FIX16K_A0000_MSR: u32 = 0x259;
const IA32_MTRR_FIX4K_C0000_MSR: u32 = 0x268;
const IA32_MTRR_FIX4K_F8000_MSR: u32 = 0x26f;
const IA32_MC0_CTL2_MSR: u32 = 0x280;
const IA32_MTRR_DEF_TYPE_MSR: u32 = 0x2ff;
const IA32_MC0_CTL_MSR: u32 = 0x400;
const IA32_MC0_STATUS_MSR: u32 = 0x401;
const IA32_X2APIC_MSR_BASE: u32 = 0x800;
const IA32_X2APIC_MSR_END: u32 = 0x8ff;
const MSR_PKG_ENERGY_STATUS: u32 = 0x611;
const MSR_RAPL_POWER_UNIT: u32 = 0x606;
const MSR_DRAM_ENERGY_STATUS: u32 = 0x619;
const MSR_PP0_ENERGY_STATUS: u32 = 0x639;
const MSR_PP1_ENERGY_STATUS: u32 = 0x641;
const IA32_TSC_DEADLINE_MSR: u32 = 0x6e0;
const IA32_XSS_MSR: u32 = 0xda0;
const AMD_SEV_STATUS_MSR: u32 = 0xc001_0131;
const MACHINE_CHECK_BANK_MSR_STRIDE: u32 = 4;
const HYPERV_GUEST_IDLE_ACCESS_MASK: u32 = !(1 << 10);
const HYPERV_GUEST_IDLE_FEATURE_MASK: u32 = !(1 << 5);
const HYPERV_GUEST_OS_ID_MSR: u32 = 0x4000_0000;
const HYPERV_HYPERCALL_MSR: u32 = 0x4000_0001;
const HYPERV_VP_INDEX_MSR: u32 = 0x4000_0002;
const HYPERV_REFERENCE_TSC_MSR: u32 = 0x4000_0021;
const HYPERV_APIC_FREQUENCY_MSR: u32 = 0x4000_0023;
const HYPERV_REFERENCE_TIME_MSR_SPAN: u32 = HYPERV_APIC_FREQUENCY_MSR - HYPERV_REFERENCE_TSC_MSR;
const HYPERV_VP_ASSIST_MSR: u32 = 0x4000_0073;
const HYPERV_SIMP_MSR: u32 = 0x4000_0083;
const HYPERV_SINT3_MSR: u32 = 0x4000_0093;
const HYPERV_STIMER0_CONFIG_MSR: u32 = 0x4000_00b0;
const HYPERV_STIMER0_COUNT_MSR: u32 = 0x4000_00b1;
const IA32_EFER_MSR: u32 = 0xc000_0080;
const IA32_STAR_MSR: u32 = 0xc000_0081;
const IA32_LSTAR_MSR: u32 = 0xc000_0082;
const IA32_CSTAR_MSR: u32 = 0xc000_0083;
const IA32_FMASK_MSR: u32 = 0xc000_0084;
const IA32_FS_BASE_MSR: u32 = 0xc000_0100;
const IA32_GS_BASE_MSR: u32 = 0xc000_0101;
const IA32_KERNEL_GS_BASE_MSR: u32 = 0xc000_0102;
const IA32_TSC_AUX_MSR: u32 = 0xc000_0103;
const RESIDENT_MSR_SWITCH_CAPACITY: usize = 1;
const NESTED_MSR_BITMAP_OFFSET: u64 = 0;
const NESTED_VMCS02_ENTRY_MSR_LIST_OFFSET: u64 = PAGE_SIZE as u64;
const NESTED_VMCS02_EXIT_STORE_MSR_LIST_OFFSET: u64 = (PAGE_SIZE * 3) as u64;
const NESTED_VMCS01_ENTRY_MSR_LIST_OFFSET: u64 = (PAGE_SIZE * 5) as u64;
const NESTED_MSR_LIST_CAPACITY: usize = (PAGE_SIZE * 2) / size_of::<VmxMsrEntry>();
const NESTED_GUEST_MSR_LIST_CAPACITY: usize =
    NESTED_MSR_LIST_CAPACITY - RESIDENT_MSR_SWITCH_CAPACITY;
const NESTED_MSR_BITMAP_QWORD_COUNT: usize = PAGE_SIZE / size_of::<u64>();
const HOST_PAGE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

#[repr(C)]
#[derive(Clone, Copy)]
struct VmxMsrEntry {
    index: u32,
    reserved: u32,
    value: u64,
}
const HOST_CODE_SELECTOR: u16 = 0x08;
const HOST_DATA_SELECTOR: u16 = 0x10;
const HOST_TSS_SELECTOR: u16 = 0x40;
const TSS_OFFSET: usize = 0x100;
const TSS_LIMIT: u32 = 0x67;
const IDT_ENTRY_COUNT: usize = 256;
const BOOT_CONTEXT_CANARY_START: u64 = 0x4856_424f_4f54_4331;
const BOOT_CONTEXT_CANARY_END: u64 = 0x4856_424f_4f54_4332;
const POST_EBS_EXIT_MESSAGE_LEN: usize = b"[MATRIXHV][RESIDENT] HV:POST_EBS_VMEXIT".len();
const POST_VA_EXIT_MESSAGE_LEN: usize = b"[MATRIXHV][RESIDENT] HV:POST_VA_VMEXIT".len();
const FIRST_START_EXIT_MESSAGE_LEN: usize = b"[MATRIXHV][RESIDENT] HV:START_IMAGE_FIRST_EXIT".len();
const START_CHECKPOINT_MESSAGE_LEN: usize =
    b"[MATRIXHV][RESIDENT] HV:START_IMAGE_CHECKPOINT_RESUME".len();
const START_RETURNED_MESSAGE_LEN: usize = b"[MATRIXHV][RESIDENT] HV:START_IMAGE_RETURNED".len();
const POST_EBS_STOP_MESSAGE_LEN: usize = b"[MATRIXHV][RESIDENT] HV:POST_EBS_TERMINAL_VMCALL".len();
const UNSUPPORTED_EXIT_MESSAGE_LEN: usize = b"[MATRIXHV][RESIDENT] HV:UNSUPPORTED_EXIT".len();
const HOST_CR3_MISMATCH_MESSAGE_LEN: usize = b"[MATRIXHV][RESIDENT] HV:HOST_CR3_MISMATCH".len();
const EVENT_CORRUPT_MESSAGE_LEN: usize = b"[MATRIXHV][RESIDENT] HV:EVENT_CONTEXT_CORRUPT".len();
const VMREAD_FAILED_MESSAGE_LEN: usize = b"[MATRIXHV][RESIDENT] HV:VMREAD_FAILED\r\n".len();
const VMWRITE_FAILED_MESSAGE_LEN: usize = b"[MATRIXHV][RESIDENT] HV:VMWRITE_FAILED".len();
const VMRESUME_FAILED_MESSAGE_LEN: usize =
    b"[MATRIXHV][RESIDENT] HV:VMRESUME_FAILED error=0x".len();
const EPT_TEST_VIOLATION_MESSAGE_LEN: usize =
    b"[MATRIXHV][RESIDENT] HV:EPT_VIOLATION_TEST gpa=0x".len();
const EPT_UNEXPECTED_VIOLATION_MESSAGE_LEN: usize =
    b"[MATRIXHV][RESIDENT] HV:EPT_VIOLATION_UNEXPECTED gpa=0x".len();
const EPT_VIOLATION_RIP_LEN: usize = b" rip=0x".len();
const EPT_VIOLATION_READ_LEN: usize = b" access=read qual=0x".len();
const STATE_REASON_LEN: usize = b" reason=0x".len();
const STATE_RIP_LEN: usize = b" rip=0x".len();
const STATE_NEWLINE_LEN: usize = b"\r\n".len();
const NESTED_VMXON_MESSAGE_LEN: usize = b"[MATRIXHV][NESTED] VMXON cpu=0x".len();
const NESTED_VMXOFF_MESSAGE_LEN: usize = b"[MATRIXHV][NESTED] VMXOFF cpu=0x".len();
const NESTED_POINTER_MESSAGE_LEN: usize = b" pointer=0x".len();
const NESTED_FAILURE_MESSAGE_LEN: usize = b"[MATRIXHV][NESTED] PROBE_FAILED".len();
const NESTED_VMCS12_MESSAGE_LEN: usize = b"[MATRIXHV][NESTED] VMCS12 cpu=0x".len();
const NESTED_REGION_MESSAGE_LEN: usize = b" region=0x".len();
const NESTED_VALUE_MESSAGE_LEN: usize = b" value=0x".len();
const NESTED_L2_EXIT_MESSAGE_LEN: usize = b"[MATRIXHV][NESTED] L2_EXIT cpu=0x".len();

pub const RESIDENT_VMCALL_START_CHECKPOINT: u64 = 0x4856_5354_4152_5421;
pub const RESIDENT_VMCALL_STOP: u64 = 0x4856_5354_4f50_2121;
pub const RESIDENT_VMCALL_NESTED_PROBE_FAILED: u64 = 0x4856_4e56_4d46_4149;
pub const NESTED_VMCS12_TEST_VALUE: u64 = 0x1122_3344_5566_7788;
pub const NESTED_L2_VMCALL_MAGIC: u64 = 0x4c32_564d_4341_4c4c;
pub const NESTED_L2_VMRESUME_MAGIC: u64 = 0x4c32_5245_5355_4d45;
pub const NESTED_L2_POST_INVEPT_MAGIC: u64 = 0x4c32_494e_5645_5054;
const RESIDENT_STOP_UNSUPPORTED_EXIT: u64 = 0x4856_554e_5355_5050;
static EPT_TEST_PAGE_GPA: AtomicU64 = AtomicU64::new(0);
static EVENT_CONTEXT_ADDRESS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentProbeError {
    Allocation(Status),
    Vmxon(VmxonError),
    Vmcs(VmcsError),
    Controls(VmxControlsError),
    Ept(EptError),
    Paging(HostPagingError),
    InvalidCodeLayout,
    HostRspVmwrite,
    HostRipVmwrite,
    VmlaunchVmFailInvalid,
    VmlaunchVmFailValid(u64),
    UnexpectedRunPath(u64),
    Vmclear(VmxInstructionResult),
    Incomplete(u64),
    CanaryCorrupted,
    UnexpectedExitReason(u64),
    HostCr3Mismatch { expected: u64, observed: u64 },
    GuestCr3Mismatch { expected: u64, observed: u64 },
    EventRegistration(Status),
}

impl From<VmcsError> for ResidentProbeError {
    fn from(value: VmcsError) -> Self {
        Self::Vmcs(value)
    }
}

impl From<VmxControlsError> for ResidentProbeError {
    fn from(value: VmxControlsError) -> Self {
        Self::Controls(value)
    }
}

impl From<EptError> for ResidentProbeError {
    fn from(value: EptError) -> Self {
        Self::Ept(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentProbeReport {
    pub code_physical_address: u64,
    pub code_pages: usize,
    pub host_table_pages: usize,
    pub host_table_capacity: usize,
    pub data_memory_type: u32,
    pub code_memory_type: u32,
    pub host_cr3: u64,
    pub guest_cr3: u64,
    pub observed_host_cr3: u64,
    pub observed_guest_cr3: u64,
    pub exit_reason: u64,
    pub guest_rip: u64,
    pub host_gdt: u64,
    pub host_idt: u64,
    pub host_tss: u64,
    pub host_stack: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentEventReport {
    pub code_physical_address: u64,
    pub context_physical_address: u64,
    pub code_memory_type: u32,
    pub data_memory_type: u32,
    pub exit_boot_services_event: u64,
    pub virtual_address_change_event: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentBootReport {
    pub raw_path: u64,
    pub vm_instruction_error: u64,
    pub host_cr3: u64,
    pub initial_guest_cr3: u64,
    pub exit_count: u64,
    pub cpuid_count: u64,
    pub rdmsr_count: u64,
    pub wrmsr_count: u64,
    pub xsetbv_count: u64,
    pub vmcall_count: u64,
    pub start_checkpoint_seen: u64,
    pub post_start_exit_count: u64,
    pub post_ebs_exit_count: u64,
    pub post_va_exit_count: u64,
    pub ept_test_violation_seen: u64,
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
    pub cpuid_presence: u64,
    pub cpuid_leaf1_count: u64,
    pub cpuid_hypervisor_count: u64,
    pub cpuid_leaf1_ecx: u64,
    pub cpuid_hypervisor_eax: u64,
    pub nested: NestedVmxState,
}

#[repr(C, align(16))]
struct ResidentEventContext {
    magic: u64,
    exit_boot_services_seen: AtomicU64,
    virtual_address_change_seen: u64,
    canary: u64,
    serial_lock: AtomicU64,
    visual_base: u64,
    visual_stride_bytes: u64,
    post_ebs_cpu_mask: AtomicU64,
    diagnostic_halted: AtomicU64,
    host_fault_vector: u64,
    host_fault_rip: u64,
    host_fault_error_code: u64,
    host_fault_address: u64,
    init_cpu_mask: AtomicU64,
    sipi_cpu_mask: AtomicU64,
    halted_cpu_mask: AtomicU64,
    failed_processor: u64,
    failed_exit_reason: u64,
    failed_qualification: u64,
    failed_stop_result: u64,
    watchdog_tsc_hz: u64,
    cpu_contexts: [u64; 64],
}

#[repr(C, align(16))]
struct RootFxState([u8; 512]);

#[repr(C)]
#[derive(Clone, Copy)]
struct WatchdogGuestState {
    rip: u64,
    rsp: u64,
    rflags: u64,
    cr0: u64,
    cr3: u64,
    cr4: u64,
    efer: u64,
}

#[repr(C, align(16))]
struct ResidentBootContext {
    serial_lock: u64,
    root_rsp: u64,
    return_rip: u64,
    expected_host_cr3: u64,
    initial_guest_cr3: u64,
    event_context: u64,
    ept_test_gpa: u64,
    ept_probe_fault_rip: u64,
    ept_probe_resume_rip: u64,
    ept_test_violation_seen: u64,
    exit_count: u64,
    cpuid_count: u64,
    rdmsr_count: u64,
    wrmsr_count: u64,
    xsetbv_count: u64,
    vmcall_count: u64,
    start_checkpoint_seen: u64,
    visual_first_exit_seen: u64,
    post_start_exit_count: u64,
    post_ebs_exit_count: u64,
    post_va_exit_count: u64,
    msr_gp_count: u64,
    last_gp_msr: u64,
    diagnostic_interval_tsc: u64,
    diagnostic_timer_rate: u64,
    diagnostic_deadline_tsc: u64,
    diagnostic_sample_count: u64,
    diagnostic_expired: u64,
    last_normal_reason: u64,
    last_normal_rip: u64,
    last_efer_write: u64,
    last_reason: u64,
    last_instruction_len: u64,
    last_qualification: u64,
    last_guest_physical_address: u64,
    last_guest_rax: u64,
    last_guest_rcx: u64,
    last_guest_rdx: u64,
    last_guest_rip: u64,
    last_guest_cr3: u64,
    last_host_cr3: u64,
    stop_result: u64,
    canary_start: u64,
    canary_end: u64,
    processor_number: u64,
    ap_started: u64,
    init_count: u64,
    sipi_count: u64,
    cpuid_presence: u64,
    cpuid_leaf1_count: u64,
    cpuid_hypervisor_count: u64,
    cpuid_leaf1_ecx: u64,
    cpuid_hypervisor_eax: u64,
    cache_ept_pointer: u64,
    cache_generation: u64,
    mtrr_dirty: u64,
    mtrr_updates: u64,
    nmi_pending: u64,
    nmi_count: u64,
    telemetry_enabled: u64,
    telemetry_active: u64,
    telemetry_probe_active: u64,
    watchdog_tsc_hz: u64,
    watchdog_deadline_tsc: u64,
    watchdog_sequence: u64,
    watchdog_exit_count: u64,
    watchdog_phase: u64,
    watchdog_handler_returns: u64,
    watchdog_resume_failures: u64,
    watchdog_last_reason: u64,
    watchdog_last_rip: u64,
    entry_failure_state: u64,
    entry_failure_exit: u64,
    entry_failure_tsc: u64,
    entry_failure: WatchdogGuestState,
    last_before: WatchdogGuestState,
    last_after_handler: WatchdogGuestState,
    last_resume: WatchdogGuestState,
    ept_violation_read: u64,
    ept_violation_write: u64,
    ept_violation_execute: u64,
    cr3_exits: u64,
    eptp_switches: u64,
    mtf_exits: u64,
    invept_exits: u64,
    preemption_timer_exits: u64,
    nested: NestedVmxState,
    original_gdtr: [u8; 10],
    original_idtr: [u8; 10],
    root_fx_state: RootFxState,
}

pub(crate) const RESIDENT_BOOT_CONTEXT_PAGES: usize =
    size_of::<ResidentBootContext>().div_ceil(PAGE_SIZE);

impl ResidentBootContext {
    fn new(
        expected_host_cr3: u64,
        initial_guest_cr3: u64,
        event_context: u64,
        ept_test_gpa: u64,
        ept_probe_fault_rip: u64,
        ept_probe_resume_rip: u64,
        nested: NestedVmxState,
    ) -> Self {
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
            cpuid_presence: u64::from(crate::boot::current().cpuid_presence),
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
            nested,
            original_gdtr: [0; 10],
            original_idtr: [0; 10],
            root_fx_state: RootFxState([0; 512]),
        }
    }
}

const BCTX_SERIAL_LOCK: usize = core::mem::offset_of!(ResidentBootContext, serial_lock);
const BCTX_ROOT_RSP: usize = core::mem::offset_of!(ResidentBootContext, root_rsp);
const BCTX_RETURN_RIP: usize = core::mem::offset_of!(ResidentBootContext, return_rip);
const BCTX_EXPECTED_HOST_CR3: usize = core::mem::offset_of!(ResidentBootContext, expected_host_cr3);
const BCTX_EVENT_CONTEXT: usize = core::mem::offset_of!(ResidentBootContext, event_context);
const BCTX_EPT_TEST_GPA: usize = core::mem::offset_of!(ResidentBootContext, ept_test_gpa);
const BCTX_EPT_PROBE_FAULT_RIP: usize =
    core::mem::offset_of!(ResidentBootContext, ept_probe_fault_rip);
const BCTX_EPT_PROBE_RESUME_RIP: usize =
    core::mem::offset_of!(ResidentBootContext, ept_probe_resume_rip);
const BCTX_EPT_TEST_VIOLATION_SEEN: usize =
    core::mem::offset_of!(ResidentBootContext, ept_test_violation_seen);
const BCTX_EXIT_COUNT: usize = core::mem::offset_of!(ResidentBootContext, exit_count);
const BCTX_CPUID_COUNT: usize = core::mem::offset_of!(ResidentBootContext, cpuid_count);
const BCTX_RDMSR_COUNT: usize = core::mem::offset_of!(ResidentBootContext, rdmsr_count);
const BCTX_WRMSR_COUNT: usize = core::mem::offset_of!(ResidentBootContext, wrmsr_count);
const BCTX_XSETBV_COUNT: usize = core::mem::offset_of!(ResidentBootContext, xsetbv_count);
const BCTX_VMCALL_COUNT: usize = core::mem::offset_of!(ResidentBootContext, vmcall_count);
const BCTX_START_CHECKPOINT_SEEN: usize =
    core::mem::offset_of!(ResidentBootContext, start_checkpoint_seen);
const BCTX_VISUAL_FIRST_EXIT_SEEN: usize =
    core::mem::offset_of!(ResidentBootContext, visual_first_exit_seen);
const BCTX_POST_START_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, post_start_exit_count);
const BCTX_POST_EBS_COUNT: usize = core::mem::offset_of!(ResidentBootContext, post_ebs_exit_count);
const BCTX_POST_VA_COUNT: usize = core::mem::offset_of!(ResidentBootContext, post_va_exit_count);
const BCTX_MSR_GP_COUNT: usize = core::mem::offset_of!(ResidentBootContext, msr_gp_count);
const BCTX_LAST_GP_MSR: usize = core::mem::offset_of!(ResidentBootContext, last_gp_msr);
const BCTX_DIAGNOSTIC_INTERVAL: usize =
    core::mem::offset_of!(ResidentBootContext, diagnostic_interval_tsc);
const BCTX_DIAGNOSTIC_RATE: usize =
    core::mem::offset_of!(ResidentBootContext, diagnostic_timer_rate);
const BCTX_DIAGNOSTIC_DEADLINE: usize =
    core::mem::offset_of!(ResidentBootContext, diagnostic_deadline_tsc);
const BCTX_DIAGNOSTIC_SAMPLES: usize =
    core::mem::offset_of!(ResidentBootContext, diagnostic_sample_count);
const BCTX_DIAGNOSTIC_EXPIRED: usize =
    core::mem::offset_of!(ResidentBootContext, diagnostic_expired);
const BCTX_LAST_NORMAL_REASON: usize =
    core::mem::offset_of!(ResidentBootContext, last_normal_reason);
const BCTX_LAST_NORMAL_RIP: usize = core::mem::offset_of!(ResidentBootContext, last_normal_rip);
const BCTX_LAST_EFER_WRITE: usize = core::mem::offset_of!(ResidentBootContext, last_efer_write);
const BCTX_LAST_REASON: usize = core::mem::offset_of!(ResidentBootContext, last_reason);
const BCTX_LAST_INSTRUCTION_LEN: usize =
    core::mem::offset_of!(ResidentBootContext, last_instruction_len);
const BCTX_LAST_QUALIFICATION: usize =
    core::mem::offset_of!(ResidentBootContext, last_qualification);
const BCTX_LAST_GUEST_PHYSICAL_ADDRESS: usize =
    core::mem::offset_of!(ResidentBootContext, last_guest_physical_address);
const BCTX_LAST_GUEST_RAX: usize = core::mem::offset_of!(ResidentBootContext, last_guest_rax);
const BCTX_LAST_GUEST_RCX: usize = core::mem::offset_of!(ResidentBootContext, last_guest_rcx);
const BCTX_LAST_GUEST_RDX: usize = core::mem::offset_of!(ResidentBootContext, last_guest_rdx);
const BCTX_LAST_GUEST_RIP: usize = core::mem::offset_of!(ResidentBootContext, last_guest_rip);
const BCTX_LAST_GUEST_CR3: usize = core::mem::offset_of!(ResidentBootContext, last_guest_cr3);
const BCTX_LAST_HOST_CR3: usize = core::mem::offset_of!(ResidentBootContext, last_host_cr3);
const BCTX_STOP_RESULT: usize = core::mem::offset_of!(ResidentBootContext, stop_result);
const BCTX_CANARY_START: usize = core::mem::offset_of!(ResidentBootContext, canary_start);
const BCTX_CANARY_END: usize = core::mem::offset_of!(ResidentBootContext, canary_end);
const BCTX_CPUID_PRESENCE: usize = core::mem::offset_of!(ResidentBootContext, cpuid_presence);
const BCTX_CPUID_LEAF1_COUNT: usize = core::mem::offset_of!(ResidentBootContext, cpuid_leaf1_count);
const BCTX_CPUID_HYPERVISOR_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, cpuid_hypervisor_count);
const BCTX_CPUID_LEAF1_ECX: usize = core::mem::offset_of!(ResidentBootContext, cpuid_leaf1_ecx);
const BCTX_CPUID_HYPERVISOR_EAX: usize =
    core::mem::offset_of!(ResidentBootContext, cpuid_hypervisor_eax);
const BCTX_NESTED_FEATURE_CONTROL: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, feature_control);
const BCTX_NESTED_VMX_BASIC: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_basic);
const BCTX_NESTED_VMX_PINBASED_CTLS: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_pinbased_ctls);
const BCTX_NESTED_VMX_PROCBASED_CTLS: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_procbased_ctls);
const BCTX_NESTED_VMX_EXIT_CTLS: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_exit_ctls);
const BCTX_NESTED_VMX_ENTRY_CTLS: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_entry_ctls);
const BCTX_NESTED_VMX_MISC: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_misc);
const BCTX_NESTED_VMX_CR0_FIXED0: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_cr0_fixed0);
const BCTX_NESTED_VMX_CR0_FIXED1: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_cr0_fixed1);
const BCTX_NESTED_VMX_CR4_FIXED0: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_cr4_fixed0);
const BCTX_NESTED_VMX_CR4_FIXED1: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_cr4_fixed1);
const BCTX_NESTED_VMX_VMCS_ENUM: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_vmcs_enum);
const BCTX_NESTED_VMX_PROCBASED_CTLS2: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_procbased_ctls2);
const BCTX_NESTED_VMX_EPT_VPID_CAP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_ept_vpid_cap);
const BCTX_NESTED_VMX_TRUE_PINBASED_CTLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmx_true_pinbased_ctls);
const BCTX_NESTED_VMX_TRUE_PROCBASED_CTLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmx_true_procbased_ctls);
const BCTX_NESTED_VMX_TRUE_EXIT_CTLS: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_true_exit_ctls);
const BCTX_NESTED_VMX_TRUE_ENTRY_CTLS: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmx_true_entry_ctls);
const BCTX_NESTED_EXPOSE_VMX: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, expose_vmx);
const BCTX_NESTED_L1_CR4: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l1_cr4);
const BCTX_NESTED_VMXON_OPERAND: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmxon_operand);
const BCTX_NESTED_VMXON_REGION: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmxon_region);
const BCTX_NESTED_CURRENT_VMCS: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, current_vmcs);
const BCTX_NESTED_LAST_OPERAND: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, last_operand);
const BCTX_NESTED_INSTRUCTION_ERROR: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, instruction_error);
const BCTX_NESTED_VMXON_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmxon_count);
const BCTX_NESTED_VMXOFF_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmxoff_count);
const BCTX_NESTED_FAILURE_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, failure_count);
const BCTX_NESTED_ACTIVE: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, active);
const BCTX_NESTED_PROBE_COMPLETE: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, probe_complete);
const BCTX_NESTED_VMCS12_OPERAND: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, operand);
const BCTX_NESTED_VMCS12_REGION: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, region);
const BCTX_NESTED_VMPTRST_DESTINATION: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmptrst_destination);
const BCTX_NESTED_LAST_STORED_POINTER: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, last_stored_pointer);
const BCTX_NESTED_VMCS12_REVISION_ID: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, revision_id);
const BCTX_NESTED_VMCS12_LAUNCH_STATE: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, launch_state);
const BCTX_NESTED_VMCS12_GUEST_RIP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, guest_rip);
const BCTX_NESTED_VMCS12_GUEST_RSP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, guest_rsp);
const BCTX_NESTED_VMCS12_GUEST_RFLAGS: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, guest_rflags);
const BCTX_NESTED_VMCS12_HOST_RSP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, host_rsp);
const BCTX_NESTED_VMCS12_HOST_RIP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, host_rip);
const BCTX_NESTED_VMCS12_EXIT_REASON: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, exit_reason);
const BCTX_NESTED_VMCS12_EXIT_INSTRUCTION_LEN: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, exit_instruction_len);
const BCTX_NESTED_VMCS12_EXIT_QUALIFICATION: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, exit_qualification);
const BCTX_NESTED_VMCS12_EXTENDED_FIELDS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, extended_fields);
const BCTX_NESTED_VMCS12_VPID: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS;
const BCTX_NESTED_VMCS12_PIN_BASED_CONTROL: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 8;
const BCTX_NESTED_VMCS12_PRIMARY_CONTROL: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 16;
const BCTX_NESTED_VMCS12_SECONDARY_CONTROL: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 24;
const BCTX_NESTED_VMCS12_EXCEPTION_BITMAP: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 32;
const BCTX_NESTED_VMCS12_PF_ERROR_MASK: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 40;
const BCTX_NESTED_VMCS12_PF_ERROR_MATCH: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 48;
const BCTX_NESTED_VMCS12_CR3_TARGET_COUNT: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 56;
const BCTX_NESTED_VMCS12_VM_EXIT_CONTROLS: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 64;
const BCTX_NESTED_VMCS12_VM_EXIT_MSR_STORE_COUNT: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 72;
const BCTX_NESTED_VMCS12_VM_EXIT_MSR_LOAD_COUNT: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 80;
const BCTX_NESTED_VMCS12_VM_ENTRY_CONTROLS: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 88;
const BCTX_NESTED_VMCS12_VM_ENTRY_MSR_LOAD_COUNT: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 96;
const BCTX_NESTED_VMCS12_VM_ENTRY_INTR_INFO: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 104;
const BCTX_NESTED_VMCS12_VM_ENTRY_EXCEPTION_ERROR: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 112;
const BCTX_NESTED_VMCS12_VM_ENTRY_INSTRUCTION_LEN: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 120;
const BCTX_NESTED_VMCS12_EPT_POINTER: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 128;
const BCTX_NESTED_VMCS12_TSC_OFFSET: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 136;
const BCTX_NESTED_VMCS12_GUEST_PHYSICAL_ADDRESS: usize =
    BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 110 * size_of::<u64>();
const BCTX_NESTED_VMCS12_CR0_MASK: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 152;
const BCTX_NESTED_VMCS12_CR4_MASK: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 160;
const BCTX_NESTED_VMCS12_CR0_SHADOW: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 168;
const BCTX_NESTED_VMCS12_CR4_SHADOW: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 176;
const BCTX_NESTED_VMCS12_MSR_BITMAP: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 144;
const BCTX_NESTED_VMCS12_IO_BITMAP_A: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 744;
const BCTX_NESTED_VMCS12_IO_BITMAP_B: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 752;
const BCTX_NESTED_VMCS12_TPR_THRESHOLD: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 800;
const BCTX_NESTED_VMCS12_VIRTUAL_APIC_PAGE: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 808;
const BCTX_NESTED_VMCS12_XSS_EXITING_BITMAP: usize =
    BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 95 * size_of::<u64>();
const BCTX_NESTED_VMCS12_VM_EXIT_MSR_STORE_ADDR: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 824;
const BCTX_NESTED_VMCS12_VM_EXIT_MSR_LOAD_ADDR: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 832;
const BCTX_NESTED_VMCS12_VM_ENTRY_MSR_LOAD_ADDR: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 840;
const BCTX_NESTED_VMCS12_VM_EXIT_INTR_INFO: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 848;
const BCTX_NESTED_VMCS12_VM_EXIT_INTR_ERROR: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 856;
const BCTX_NESTED_VMCS12_IDT_VECTORING_INFO: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 864;
const BCTX_NESTED_VMCS12_IDT_VECTORING_ERROR: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 872;
const BCTX_NESTED_VMCS12_EXIT_INSTRUCTION_INFO: usize =
    BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 115 * size_of::<u64>();
const BCTX_NESTED_VMCS12_GUEST_CR0: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 232;
const BCTX_NESTED_VMCS12_GUEST_CR3: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 240;
const BCTX_NESTED_VMCS12_GUEST_CR4: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 248;
const BCTX_NESTED_VMCS12_HOST_CR0: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 256;
const BCTX_NESTED_VMCS12_HOST_CR3: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 264;
const BCTX_NESTED_VMCS12_HOST_CR4: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 272;
const BCTX_NESTED_VMCS12_GUEST_SYSENTER_EIP: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 696;
const BCTX_NESTED_VMCS12_HOST_SYSENTER_ESP: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 712;
const BCTX_NESTED_VMCS12_HOST_SYSENTER_EIP: usize = BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 720;
const BCTX_NESTED_VMCS12_CONTROL_VALIDATION_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs12)
        + core::mem::offset_of!(NestedVmcs12State, control_validation_count);
const BCTX_NESTED_VMCLEAR_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmclear_count);
const BCTX_NESTED_VMPTRLD_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmptrld_count);
const BCTX_NESTED_VMPTRST_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmptrst_count);
const BCTX_NESTED_VMWRITE_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmwrite_count);
const BCTX_NESTED_VMREAD_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmread_count);
const BCTX_NESTED_VMCS12_PROBE_COMPLETE: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, probe_complete);
const BCTX_NESTED_VMLAUNCH_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmlaunch_count);
const BCTX_NESTED_VMRESUME_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, vmresume_count);
const BCTX_NESTED_ENTRY_REJECTION_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs12)
    + core::mem::offset_of!(NestedVmcs12State, entry_rejection_count);
const BCTX_NESTED_VMCS01_REGION: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs01_region);
const BCTX_NESTED_VMCS02_REGION: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs02_region);
const BCTX_NESTED_L2_ACTIVE: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_active);
const BCTX_NESTED_L2_ENTRY_WAS_RESUME: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_entry_was_resume);
const BCTX_NESTED_L2_ENTRY_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_entry_count);
const BCTX_NESTED_L2_EXIT_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_exit_count);
const BCTX_NESTED_L2_LAST_EXIT_REASON: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_last_exit_reason);
const BCTX_NESTED_L2_LAST_EXIT_RIP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_last_exit_rip);
const BCTX_NESTED_L2_LAST_EXIT_RSP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_last_exit_rsp);
const BCTX_NESTED_L1_REFLECTION_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l1_reflection_count);
const BCTX_NESTED_L2_RESUME_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_resume_count);
const BCTX_NESTED_L2_RESUME_EXIT_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_resume_exit_count);
const BCTX_NESTED_EPT12_POINTER: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept12_pointer);
const BCTX_NESTED_EPT_TARGET_GPA: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept_target_gpa);
const BCTX_NESTED_EPT_COMPOSITION_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept_composition_count);
const BCTX_NESTED_EPT_PROBE_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept_probe_count);
const BCTX_NESTED_EPT_OBSERVED_VALUE: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept_observed_value);
const BCTX_NESTED_EPT02_POINTER: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept02_pointer);
const BCTX_NESTED_EPT02_ALTERNATE_POINTER: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_alternate_pointer);
const BCTX_NESTED_EPT_SECOND_TARGET_GPA: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept_second_target_gpa);
const BCTX_NESTED_EPT12_SOURCE_LEAF: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept12_source_leaf);
const BCTX_NESTED_EPT12_SOURCE_LEAF_ATTRIBUTES: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept12_source_leaf_attributes);
const BCTX_NESTED_INVEPT_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, invept_count);
const BCTX_NESTED_INVEPT_SOFTWARE_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, invept_software_count);
const BCTX_NESTED_INVVPID_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, invvpid_count);
const BCTX_NESTED_INVVPID_SOFTWARE_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, invvpid_software_count);
const BCTX_NESTED_EPT_OBSERVED_VALUE_AFTER_INVEPT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept_observed_value_after_invept);
const BCTX_NESTED_EPT02_INITIAL_POINTER: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept02_initial_pointer);
const BCTX_NESTED_EPT02_TABLE_POOL: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept02_table_pool);
const BCTX_NESTED_EPT02_TABLE_POOL_PAGES: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_table_pool_pages);
const BCTX_NESTED_EPT02_TABLE_POOL_USED: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept02_table_pool_used);
const BCTX_NESTED_EPT01_POINTER: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, ept01_pointer);
const BCTX_NESTED_EPT02_INVALIDATION_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_invalidation_count);
const BCTX_NESTED_EPT_OBSERVED_VALUE_BEFORE_INVEPT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept_observed_value_before_invept);
const BCTX_NESTED_CONTROL_MERGE_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, control_merge_count);
const BCTX_NESTED_GUEST_STATE_SYNC_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, guest_state_sync_count);
const BCTX_NESTED_L1_HOST_RESTORE_COUNT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l1_host_restore_count);
const BCTX_NESTED_LAST_SYNCED_GUEST_CR0: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, last_synced_guest_cr0);
const BCTX_NESTED_LAST_SYNCED_GUEST_CR3: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, last_synced_guest_cr3);
const BCTX_NESTED_LAST_SYNCED_GUEST_CR4: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, last_synced_guest_cr4);
const BCTX_NESTED_LAST_RESTORED_HOST_CR0: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_restored_host_cr0);
const BCTX_NESTED_LAST_RESTORED_HOST_CR3: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_restored_host_cr3);
const BCTX_NESTED_LAST_RESTORED_HOST_CR4: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_restored_host_cr4);
const BCTX_NESTED_LAST_SYNCED_GUEST_SYSENTER_EIP: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_synced_guest_sysenter_eip);
const BCTX_NESTED_LAST_RESTORED_HOST_SYSENTER_EIP: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_restored_host_sysenter_eip);
const BCTX_NESTED_INHERITED_L1_PAT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, inherited_l1_pat);
const BCTX_NESTED_INHERITED_L1_EFER: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, inherited_l1_efer);
const BCTX_NESTED_INHERITED_L1_TSC_OFFSET: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, inherited_l1_tsc_offset);
const BCTX_NESTED_VMCS01_PIN_BASED_CONTROLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs01_pin_based_controls);
const BCTX_NESTED_VMCS01_PRIMARY_CONTROLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs01_primary_controls);
const BCTX_NESTED_VMCS01_SECONDARY_CONTROLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs01_secondary_controls);
const BCTX_NESTED_VMCS01_EXIT_CONTROLS: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs01_exit_controls);
const BCTX_NESTED_VMCS01_ENTRY_CONTROLS: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs01_entry_controls);
const BCTX_NESTED_L2_SAVED_PAT: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_saved_pat);
const BCTX_NESTED_L2_SAVED_EFER: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l2_saved_efer);
const BCTX_NESTED_LAST_MERGED_SECONDARY_CONTROLS: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_merged_secondary_controls);
const BCTX_NESTED_LAST_SYNCED_GUEST_GS_BASE: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_synced_guest_gs_base);
const BCTX_NESTED_LAST_CAPTURED_GUEST_GS_BASE: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_captured_guest_gs_base);
const BCTX_NESTED_LAST_RESTORED_HOST_GS_BASE: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_restored_host_gs_base);
const BCTX_NESTED_LAST_RESTORED_HOST_CS_AR: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, last_restored_host_cs_ar);
const BCTX_NESTED_L0_MSR_BITMAP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l0_msr_bitmap);
const BCTX_NESTED_COMPOSED_MSR_BITMAP: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, composed_msr_bitmap);
const BCTX_NESTED_L0_MSR_GUEST_LIST: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l0_msr_guest_list);
const BCTX_NESTED_L0_MSR_HOST_LIST: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, l0_msr_host_list);
const BCTX_NESTED_VMCS02_ENTRY_MSR_LIST: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs02_entry_msr_list);
const BCTX_NESTED_VMCS02_EXIT_STORE_MSR_LIST: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs02_exit_store_msr_list);
const BCTX_NESTED_VMCS01_ENTRY_MSR_LIST: usize = core::mem::offset_of!(ResidentBootContext, nested)
    + core::mem::offset_of!(NestedVmxState, vmcs01_entry_msr_list);
const BCTX_NESTED_VMCS01_MSR_ENTRY_COMPOSED: usize =
    core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs01_msr_entry_composed);
const BCTX_ORIGINAL_GDTR: usize = core::mem::offset_of!(ResidentBootContext, original_gdtr);
const BCTX_ORIGINAL_IDTR: usize = core::mem::offset_of!(ResidentBootContext, original_idtr);
const BCTX_ROOT_FX_STATE: usize = core::mem::offset_of!(ResidentBootContext, root_fx_state);
const _: () = assert!(BCTX_ROOT_FX_STATE & 0xf == 0);

const EVENT_CTX_MAGIC: usize = core::mem::offset_of!(ResidentEventContext, magic);
const EVENT_CTX_EBS_SEEN: usize =
    core::mem::offset_of!(ResidentEventContext, exit_boot_services_seen);
const EVENT_CTX_VA_SEEN: usize =
    core::mem::offset_of!(ResidentEventContext, virtual_address_change_seen);
const EVENT_CTX_CANARY: usize = core::mem::offset_of!(ResidentEventContext, canary);
const EVENT_CTX_SERIAL_LOCK: usize = core::mem::offset_of!(ResidentEventContext, serial_lock);
const EVENT_CTX_VISUAL_BASE: usize = core::mem::offset_of!(ResidentEventContext, visual_base);
const EVENT_CTX_VISUAL_STRIDE_BYTES: usize =
    core::mem::offset_of!(ResidentEventContext, visual_stride_bytes);
const EVENT_CTX_POST_EBS_CPU_MASK: usize =
    core::mem::offset_of!(ResidentEventContext, post_ebs_cpu_mask);
const EVENT_CTX_DIAGNOSTIC_HALTED: usize =
    core::mem::offset_of!(ResidentEventContext, diagnostic_halted);
const EVENT_CTX_HOST_FAULT_VECTOR: usize =
    core::mem::offset_of!(ResidentEventContext, host_fault_vector);
const EVENT_CTX_HOST_FAULT_RIP: usize = core::mem::offset_of!(ResidentEventContext, host_fault_rip);
const EVENT_CTX_HOST_FAULT_ERROR_CODE: usize =
    core::mem::offset_of!(ResidentEventContext, host_fault_error_code);
const EVENT_CTX_HOST_FAULT_ADDRESS: usize =
    core::mem::offset_of!(ResidentEventContext, host_fault_address);

#[repr(C, align(16))]
struct ResidentContext {
    root_rsp: u64,
    return_rip: u64,
    source_cr3: u64,
    expected_host_cr3: u64,
    observed_host_cr3: u64,
    observed_guest_cr3: u64,
    exit_reason: u64,
    guest_rip: u64,
    canary_start: u64,
    completed: u64,
    canary_end: u64,
    original_gdtr: [u8; 10],
    original_idtr: [u8; 10],
}

impl ResidentContext {
    fn new(source_cr3: u64, expected_host_cr3: u64) -> Self {
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

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    fn interrupt_gate(address: u64, code_selector: u16) -> Self {
        Self {
            offset_low: address as u16,
            selector: code_selector,
            ist: 0,
            attributes: 0x8e,
            offset_mid: (address >> 16) as u16,
            offset_high: (address >> 32) as u32,
            reserved: 0,
        }
    }
}

struct ResidentCode {
    pages: ResidentPages,
    entry: u64,
    fatal: u64,
    gp_handler: u64,
    exception_stubs: u64,
    exit_boot_services_callback: u64,
    virtual_address_change_callback: u64,
    dispatch_entry: u64,
}

impl ResidentCode {
    fn allocate(event_context: u64) -> Result<Self, ResidentProbeError> {
        let start = core::ptr::addr_of!(matrixhv_resident_island_start) as u64;
        let entry = core::ptr::addr_of!(matrixhv_resident_island_entry) as u64;
        let fatal = core::ptr::addr_of!(matrixhv_resident_island_fatal) as u64;
        let gp_handler = core::ptr::addr_of!(matrixhv_resident_island_gp) as u64;
        let exception_stubs = core::ptr::addr_of!(matrixhv_resident_exception_stubs) as u64;
        let event_context_slot = core::ptr::addr_of!(matrixhv_resident_island_event_context) as u64;
        let log_backend = core::ptr::addr_of!(matrixhv_resident_island_log_backend) as u64;
        let msr_count = core::ptr::addr_of!(matrixhv_resident_island_msr_switch_count) as u64;
        let visual_callback = core::ptr::addr_of!(matrixhv_resident_island_visual_callback) as u64;
        let exit_boot_services_callback =
            core::ptr::addr_of!(matrixhv_resident_ebs_callback) as u64;
        let virtual_address_change_callback =
            core::ptr::addr_of!(matrixhv_resident_va_callback) as u64;
        let dispatch_entry = core::ptr::addr_of!(matrixhv_resident_dispatch_entry) as u64;
        let end = core::ptr::addr_of!(matrixhv_resident_island_end) as u64;
        if entry < start
            || fatal < start
            || gp_handler < start
            || exception_stubs < start
            || event_context_slot < start
            || log_backend < start
            || msr_count < start
            || visual_callback < start
            || exit_boot_services_callback < start
            || virtual_address_change_callback < start
            || dispatch_entry < start
            || end <= start
            || entry >= end
            || fatal >= end
            || gp_handler >= end
            || exception_stubs >= end
            || event_context_slot >= end
            || log_backend >= end
            || msr_count + 8 > end
            || visual_callback >= end
            || exit_boot_services_callback >= end
            || virtual_address_change_callback >= end
            || dispatch_entry >= end
        {
            return Err(ResidentProbeError::InvalidCodeLayout);
        }
        let length =
            usize::try_from(end - start).map_err(|_| ResidentProbeError::InvalidCodeLayout)?;
        let pages = ResidentPages::allocate_typed(
            length.div_ceil(PAGE_SIZE),
            AddressConstraint::Any,
            RESIDENT_CODE_MEMORY_TYPE,
        )
        .map_err(ResidentProbeError::Allocation)?;
        unsafe {
            core::ptr::copy_nonoverlapping(start as *const u8, pages.pointer().as_ptr(), length);
            pages
                .pointer()
                .as_ptr()
                .add((msr_count - start) as usize)
                .cast::<u64>()
                .write_unaligned(resident_msr_switch_count());
            pages
                .pointer()
                .as_ptr()
                .add((log_backend - start) as usize)
                .write(crate::runtime::backend() as u8);
            pages
                .pointer()
                .as_ptr()
                .add((visual_callback - start) as usize)
                .cast::<u64>()
                .write_unaligned(
                    crate::boot::screen::vmexit_diagnostic as *const () as usize as u64,
                );
            pages
                .pointer()
                .as_ptr()
                .add((event_context_slot - start) as usize)
                .cast::<u64>()
                .write_unaligned(event_context);
        }
        let base = pages.physical_address();
        Ok(Self {
            entry: base + (entry - start),
            fatal: base + (fatal - start),
            gp_handler: base + (gp_handler - start),
            exception_stubs: base + (exception_stubs - start),
            exit_boot_services_callback: base + (exit_boot_services_callback - start),
            virtual_address_change_callback: base + (virtual_address_change_callback - start),
            dispatch_entry: base + (dispatch_entry - start),
            pages,
        })
    }
}

pub(crate) struct ResidentHostTables {
    pub(crate) pages: ResidentPages,
    gdt: u64,
    tss: u64,
    idt: u64,
    selectors: ResidentHostSelectors,
}

#[derive(Clone, Copy)]
pub(crate) struct ResidentHostSelectors {
    es: u16,
    cs: u16,
    ss: u16,
    ds: u16,
    fs: u16,
    gs: u16,
}

impl ResidentHostSelectors {
    fn inherited(segments: arch::SegmentationState) -> Result<Self, ResidentProbeError> {
        let selectors = Self {
            es: host_selector(segments.es.selector),
            cs: host_selector(segments.cs.selector),
            ss: host_selector(segments.ss.selector),
            ds: host_selector(segments.ds.selector),
            fs: host_selector(segments.fs.selector),
            gs: host_selector(segments.gs.selector),
        };
        if selectors.cs == 0 || !selectors.fit_before_tss() {
            return Err(ResidentProbeError::InvalidCodeLayout);
        }
        Ok(selectors)
    }

    pub(crate) fn fixed() -> Self {
        Self {
            es: HOST_DATA_SELECTOR,
            cs: HOST_CODE_SELECTOR,
            ss: HOST_DATA_SELECTOR,
            ds: HOST_DATA_SELECTOR,
            fs: HOST_DATA_SELECTOR,
            gs: HOST_DATA_SELECTOR,
        }
    }

    fn fit_before_tss(self) -> bool {
        [self.es, self.cs, self.ss, self.ds, self.fs, self.gs]
            .into_iter()
            .all(|selector| selector == 0 || usize::from(selector >> 3) < TSS_OFFSET / 8)
    }
}

impl ResidentHostTables {
    pub(crate) fn allocate(
        fatal_handler: u64,
        gp_handler: u64,
        exception_stubs: u64,
        selectors: ResidentHostSelectors,
    ) -> Result<Self, ResidentProbeError> {
        let pages = ResidentPages::allocate(HOST_TABLE_PAGES, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let base = pages.physical_address();
        let gdt = base;
        let tss = base + TSS_OFFSET as u64;
        let idt = base + PAGE_SIZE as u64;

        unsafe {
            let gdt_pointer = gdt as *mut u64;
            gdt_pointer
                .add(usize::from(selectors.cs >> 3))
                .write(0x00af_9a00_0000_ffff);
            for selector in [
                selectors.es,
                selectors.ss,
                selectors.ds,
                selectors.fs,
                selectors.gs,
            ] {
                if selector != 0 && selector != selectors.cs {
                    gdt_pointer
                        .add(usize::from(selector >> 3))
                        .write(0x00cf_9200_0000_ffff);
                }
            }
            let (tss_low, tss_high) = tss_descriptor(tss);
            let tss_index = usize::from(HOST_TSS_SELECTOR >> 3);
            gdt_pointer.add(tss_index).write(tss_low);
            gdt_pointer.add(tss_index + 1).write(tss_high);

            (tss as *mut u8).write_bytes(0, (TSS_LIMIT + 1) as usize);
            ((tss + 36) as *mut u64).write_unaligned(base + 3 * PAGE_SIZE as u64);
            ((tss + 44) as *mut u64).write_unaligned(base + 4 * PAGE_SIZE as u64);
            ((tss + 102) as *mut u16).write_unaligned((TSS_LIMIT + 1) as u16);

            let idt_pointer = idt as *mut IdtEntry;
            for index in 0..IDT_ENTRY_COUNT {
                let mut entry = IdtEntry::interrupt_gate(
                    if index == 13 {
                        gp_handler
                    } else if index < 32 {
                        exception_stubs + (index * 16) as u64
                    } else {
                        fatal_handler
                    },
                    selectors.cs,
                );
                entry.ist = match index {
                    2 => 1,
                    8 => 2,
                    _ => 0,
                };
                idt_pointer.add(index).write(entry);
            }
        }

        Ok(Self {
            pages,
            gdt,
            tss,
            idt,
            selectors,
        })
    }
}

pub fn probe() -> Result<ResidentProbeReport, ResidentProbeError> {
    if size_of::<ResidentContext>() > PAGE_SIZE {
        return Err(ResidentProbeError::Allocation(Status::OUT_OF_RESOURCES));
    }

    let code = ResidentCode::allocate(0)?;
    let root_segments = arch::capture();
    let selectors = ResidentHostSelectors::inherited(root_segments)?;
    let mut tables =
        ResidentHostTables::allocate(code.fatal, code.gp_handler, code.exception_stubs, selectors)?;
    let context_pages = ResidentPages::allocate(1, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let guest_stack = ResidentPages::allocate(GUEST_STACK_PAGES, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let host_stack = ResidentPages::allocate(HOST_STACK_PAGES, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let mut host_address_space = HostAddressSpace::reserve().map_err(ResidentProbeError::Paging)?;

    let vmx_basic = vt_vmxon::vmx_basic();
    let revision_id = vt_vmxon::revision_id(vmx_basic);
    let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
    vmcs_region.write_revision_id(revision_id);
    let vmcs_physical_address = vmcs_region.physical_address();
    let host_space = host_address_space
        .clone_current()
        .map_err(ResidentProbeError::Paging)?;
    let session = vt_vmxon::enter_vmx_root().map_err(ResidentProbeError::Vmxon)?;
    let source_cr3 = host_space.source_cr3;
    let context = context_pages.pointer().as_ptr().cast::<ResidentContext>();
    unsafe {
        context.write(ResidentContext::new(source_cr3, host_space.host_cr3));
    }

    let clear_result = unsafe { vmcs::vmclear(vmcs_physical_address) };
    if clear_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(ResidentProbeError::Vmclear(clear_result));
    }
    let load_result = unsafe { vmcs::vmptrld(vmcs_physical_address) };
    if load_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(ResidentProbeError::Vmcs(VmcsError::Vmptrld(load_result)));
    }

    let _controls = vt_controls::configure()?;
    configure_resident_host(host_space.host_cr3, &tables, root_segments)?;
    let guest_rsp = guest_stack.physical_address() + guest_stack.byte_len() as u64;
    let guest = vt_state::configure_guest(guest_probe_address(), guest_rsp & !0xf)?;

    let host_rsp = (host_stack.physical_address() + host_stack.byte_len() as u64 - 8) & !0xf;
    unsafe {
        (host_rsp as *mut u64).write(context as u64);
    }

    let raw_path = unsafe { matrixhv_resident_probe_run_asm(context, host_rsp, code.entry) };
    if raw_path == 0 {
        tables.pages.preserve();
    }
    let vm_instruction_error = vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
    let final_clear = unsafe { vmcs::vmclear(vmcs_physical_address) };
    host_address_space.restore_source_cr3();
    drop(session);
    if final_clear != VmxInstructionResult::Succeeded {
        return Err(ResidentProbeError::Vmclear(final_clear));
    }
    validate_run_path(raw_path, vm_instruction_error)?;

    let result = unsafe { &*context };
    if result.completed != CONTEXT_COMPLETE {
        return Err(ResidentProbeError::Incomplete(result.completed));
    }
    if result.canary_start != CONTEXT_CANARY_START || result.canary_end != CONTEXT_CANARY_END {
        return Err(ResidentProbeError::CanaryCorrupted);
    }
    if result.exit_reason & 0xffff != VMCALL_EXIT_REASON {
        return Err(ResidentProbeError::UnexpectedExitReason(result.exit_reason));
    }
    if result.observed_host_cr3 != host_space.host_cr3 {
        return Err(ResidentProbeError::HostCr3Mismatch {
            expected: host_space.host_cr3,
            observed: result.observed_host_cr3,
        });
    }
    if result.observed_guest_cr3 != guest.cr3 {
        return Err(ResidentProbeError::GuestCr3Mismatch {
            expected: guest.cr3,
            observed: result.observed_guest_cr3,
        });
    }

    let report = ResidentProbeReport {
        code_physical_address: code.pages.physical_address(),
        code_pages: code.pages.pages(),
        host_table_pages: host_space.table_pages,
        host_table_capacity: host_space.arena_pages,
        data_memory_type: RESIDENT_MEMORY_TYPE.0,
        code_memory_type: RESIDENT_CODE_MEMORY_TYPE.0,
        host_cr3: host_space.host_cr3,
        guest_cr3: guest.cr3,
        observed_host_cr3: result.observed_host_cr3,
        observed_guest_cr3: result.observed_guest_cr3,
        exit_reason: result.exit_reason,
        guest_rip: result.guest_rip,
        host_gdt: tables.gdt,
        host_idt: tables.idt,
        host_tss: tables.tss,
        host_stack: host_rsp,
    };

    let _ = &tables.pages;
    Ok(report)
}

pub fn status_from_error(error: &ResidentProbeError) -> Status {
    match error {
        ResidentProbeError::Allocation(status)
        | ResidentProbeError::Ept(EptError::Allocation(status))
        | ResidentProbeError::Vmxon(VmxonError::Allocation(status))
        | ResidentProbeError::Vmcs(VmcsError::Allocation(status))
        | ResidentProbeError::Paging(HostPagingError::Allocation(status))
        | ResidentProbeError::EventRegistration(status) => *status,
        _ => Status::DEVICE_ERROR,
    }
}

pub fn ept_test_page_gpa() -> u64 {
    EPT_TEST_PAGE_GPA.load(Ordering::Acquire)
}

pub(crate) fn boot_services_exited() -> bool {
    let address = EVENT_CONTEXT_ADDRESS.load(Ordering::Acquire);
    if address == 0 {
        return false;
    }
    // The event context is retained runtime memory and is also mapped in L0.
    let context = unsafe { &*(address as *const ResidentEventContext) };
    context.exit_boot_services_seen.load(Ordering::Acquire) != 0
}

pub fn arm_residency_events() -> Result<ResidentEventReport, ResidentProbeError> {
    let mut code = ResidentCode::allocate(0)?;
    let mut context_pages =
        ResidentPages::allocate_typed(1, AddressConstraint::Any, RESIDENT_EVENT_MEMORY_TYPE)
            .map_err(ResidentProbeError::Allocation)?;
    let context = context_pages
        .pointer()
        .as_ptr()
        .cast::<ResidentEventContext>();
    unsafe {
        context.write(ResidentEventContext {
            magic: EVENT_CONTEXT_MAGIC,
            exit_boot_services_seen: AtomicU64::new(0),
            virtual_address_change_seen: 0,
            canary: EVENT_CONTEXT_CANARY,
            serial_lock: AtomicU64::new(0),
            visual_base: 0,
            visual_stride_bytes: 0,
            post_ebs_cpu_mask: AtomicU64::new(0),
            diagnostic_halted: AtomicU64::new(0),
            host_fault_vector: u64::MAX,
            host_fault_rip: 0,
            host_fault_error_code: 0,
            host_fault_address: 0,
            init_cpu_mask: AtomicU64::new(0),
            sipi_cpu_mask: AtomicU64::new(0),
            halted_cpu_mask: AtomicU64::new(0),
            failed_processor: u64::MAX,
            failed_exit_reason: 0,
            failed_qualification: 0,
            failed_stop_result: 0,
            watchdog_tsc_hz: 0,
            cpu_contexts: [0; 64],
        });
    }
    let serial_lock_address = context_pages.physical_address() + EVENT_CTX_SERIAL_LOCK as u64;
    let notify_context = NonNull::new(context.cast::<c_void>())
        .ok_or(ResidentProbeError::Allocation(Status::OUT_OF_RESOURCES))?;
    let ebs_callback = unsafe {
        core::mem::transmute::<usize, EventNotifyFn>(code.exit_boot_services_callback as usize)
    };
    let va_callback = unsafe {
        core::mem::transmute::<usize, EventNotifyFn>(code.virtual_address_change_callback as usize)
    };

    let ebs_event = unsafe {
        boot::create_event(
            EventType::SIGNAL_EXIT_BOOT_SERVICES,
            Tpl::NOTIFY,
            Some(ebs_callback),
            Some(notify_context),
        )
    }
    .map_err(|error| ResidentProbeError::EventRegistration(error.status()))?;

    let va_event = match unsafe {
        boot::create_event(
            EventType::SIGNAL_VIRTUAL_ADDRESS_CHANGE,
            Tpl::NOTIFY,
            Some(va_callback),
            Some(notify_context),
        )
    } {
        Ok(event) => event,
        Err(error) => {
            let _ = boot::close_event(ebs_event);
            return Err(ResidentProbeError::EventRegistration(error.status()));
        }
    };

    let report = ResidentEventReport {
        code_physical_address: code.pages.physical_address(),
        context_physical_address: context_pages.physical_address(),
        code_memory_type: RESIDENT_CODE_MEMORY_TYPE.0,
        data_memory_type: RESIDENT_EVENT_MEMORY_TYPE.0,
        exit_boot_services_event: ebs_event.as_ptr() as usize as u64,
        virtual_address_change_event: va_event.as_ptr() as usize as u64,
    };
    code.pages.preserve();
    context_pages.preserve();
    EVENT_CONTEXT_ADDRESS.store(report.context_physical_address, Ordering::Release);
    crate::runtime::install_shared_lock(serial_lock_address);
    Ok(report)
}

fn allow_low_msr_passthrough(bitmap: &ResidentPages, index: u32) {
    debug_assert!(index <= 0x1fff);
    let byte_index = (index >> 3) as usize;
    let bit_mask = !(1_u8 << (index & 7));
    unsafe {
        let read_byte = bitmap.pointer().as_ptr().add(byte_index);
        read_byte.write(read_byte.read() & bit_mask);
        let write_byte = bitmap
            .pointer()
            .as_ptr()
            .add(MSR_BITMAP_WRITE_LOW_OFFSET + byte_index);
        write_byte.write(write_byte.read() & bit_mask);
    }
}

fn allow_low_msr_read_passthrough(bitmap: &ResidentPages, index: u32) {
    debug_assert!(index <= 0x1fff);
    let byte_index = (index >> 3) as usize;
    let bit_mask = !(1_u8 << (index & 7));
    unsafe {
        let read_byte = bitmap.pointer().as_ptr().add(byte_index);
        read_byte.write(read_byte.read() & bit_mask);
    }
}

fn allow_low_msr_write_passthrough(bitmap: &ResidentPages, index: u32) {
    debug_assert!(index <= 0x1fff);
    let byte_index = (index >> 3) as usize;
    let bit_mask = !(1_u8 << (index & 7));
    unsafe {
        let write_byte = bitmap
            .pointer()
            .as_ptr()
            .add(MSR_BITMAP_WRITE_LOW_OFFSET + byte_index);
        write_byte.write(write_byte.read() & bit_mask);
    }
}

fn allow_high_msr_passthrough(bitmap: &ResidentPages, index: u32) {
    debug_assert!((0xc000_0000..=0xc000_1fff).contains(&index));
    let relative_index = index - 0xc000_0000;
    let byte_index = (relative_index >> 3) as usize;
    let bit_mask = !(1_u8 << (relative_index & 7));
    unsafe {
        let read_byte = bitmap
            .pointer()
            .as_ptr()
            .add(MSR_BITMAP_READ_HIGH_OFFSET + byte_index);
        read_byte.write(read_byte.read() & bit_mask);
        let write_byte = bitmap
            .pointer()
            .as_ptr()
            .add(MSR_BITMAP_WRITE_HIGH_OFFSET + byte_index);
        write_byte.write(write_byte.read() & bit_mask);
    }
}

fn spec_ctrl_available(leaf7_edx: u32) -> bool {
    leaf7_edx & ((1 << 26) | (1 << 27) | (1 << 31)) != 0
}

fn resident_msr_switch_count() -> u64 {
    let cpuid = crate::arch::leaf;
    u64::from(cpuid(0).eax >= 7 && spec_ctrl_available(cpuid(7).edx))
}

fn configure_resident_msr_switch(msr_state: &ResidentPages) -> Result<(), VmcsError> {
    let entries = msr_state.pointer().as_ptr().cast::<VmxMsrEntry>();
    // The resident assembly never executes SYSCALL, SWAPGS, or RDTSCP. Preserve
    // those MSRs naturally across exits; only root speculation policy needs a switch.
    let count = resident_msr_switch_count();
    if count != 0 {
        let entry = VmxMsrEntry {
            index: IA32_SPEC_CTRL_MSR,
            reserved: 0,
            value: unsafe { arch::read_msr(IA32_SPEC_CTRL_MSR) },
        };
        unsafe {
            entries.write(entry);
            entries.add(RESIDENT_MSR_SWITCH_CAPACITY).write(entry);
        }
    }
    let guest_entry = msr_state.physical_address();
    let host_entry = guest_entry + (RESIDENT_MSR_SWITCH_CAPACITY * size_of::<VmxMsrEntry>()) as u64;
    vmwrite(VM_EXIT_MSR_STORE_ADDR, guest_entry)?;
    vmwrite(VM_EXIT_MSR_LOAD_ADDR, host_entry)?;
    vmwrite(VM_ENTRY_MSR_LOAD_ADDR, guest_entry)?;
    vmwrite(VM_EXIT_MSR_STORE_COUNT, count)?;
    vmwrite(VM_EXIT_MSR_LOAD_COUNT, count)?;
    vmwrite(VM_ENTRY_MSR_LOAD_COUNT, count)?;
    Ok(())
}

fn configure_nested_msr_composition(
    nested_state: &mut NestedVmxState,
    l0_msr_bitmap: u64,
    l0_msr_guest_list: u64,
    nested_msr_state: u64,
) {
    let l0_msr_host_list =
        l0_msr_guest_list + (RESIDENT_MSR_SWITCH_CAPACITY * size_of::<VmxMsrEntry>()) as u64;
    nested_state.configure_msr_composition(NestedMsrComposition {
        l0_msr_bitmap,
        composed_msr_bitmap: nested_msr_state + NESTED_MSR_BITMAP_OFFSET,
        l0_msr_guest_list,
        l0_msr_host_list,
        vmcs02_entry_msr_list: nested_msr_state + NESTED_VMCS02_ENTRY_MSR_LIST_OFFSET,
        vmcs02_exit_store_msr_list: nested_msr_state + NESTED_VMCS02_EXIT_STORE_MSR_LIST_OFFSET,
        vmcs01_entry_msr_list: nested_msr_state + NESTED_VMCS01_ENTRY_MSR_LIST_OFFSET,
    });
}

struct NestedVmcs02Configuration<'a> {
    vmcs01_region: u64,
    vmcs02_region: u64,
    msr_bitmap: u64,
    ept_pointer: u64,
    msr_state: &'a ResidentPages,
    host_cr3: u64,
    host_tables: &'a ResidentHostTables,
    segments: arch::SegmentationState,
    host_rsp: u64,
    host_rip: u64,
    guest_rip: u64,
    guest_rsp: u64,
    guest_rflags: u64,
    l1_cr4: u64,
}

fn configure_nested_vmcs02(
    configuration: NestedVmcs02Configuration<'_>,
) -> Result<(), ResidentProbeError> {
    let clear = unsafe { vmcs::vmclear(configuration.vmcs02_region) };
    if clear != VmxInstructionResult::Succeeded {
        return Err(ResidentProbeError::Vmclear(clear));
    }
    let load = unsafe { vmcs::vmptrld(configuration.vmcs02_region) };
    if load != VmxInstructionResult::Succeeded {
        return Err(ResidentProbeError::Vmcs(VmcsError::Vmptrld(load)));
    }

    let configure_result = (|| -> Result<(), ResidentProbeError> {
        let mut controls = vt_controls::configure_resident_boot(
            configuration.msr_bitmap,
            configuration.ept_pointer,
        )?;
        vt_controls::enable_resident_vpid(&mut controls, 2)?;
        vmwrite(EXCEPTION_BITMAP, 0)?;
        configure_resident_msr_switch(configuration.msr_state)?;
        configure_resident_host(
            configuration.host_cr3,
            configuration.host_tables,
            configuration.segments,
        )?;
        vt_state::configure_guest_with_rflags(
            configuration.guest_rip,
            configuration.guest_rsp,
            configuration.guest_rflags,
        )?;
        vt_controls::virtualize_resident_cr4_vmxe(configuration.l1_cr4)?;
        vmwrite(HOST_RSP, configuration.host_rsp)?;
        vmwrite(HOST_RIP, configuration.host_rip)?;
        Ok(())
    })();

    let restore = unsafe { vmcs::vmptrld(configuration.vmcs01_region) };
    if restore != VmxInstructionResult::Succeeded {
        return Err(ResidentProbeError::Vmcs(VmcsError::Vmptrld(restore)));
    }
    configure_result
}

fn vmcs12_extended_fields_are_dense() -> bool {
    VMCS12_EXTENDED_FIELDS
        .iter()
        .enumerate()
        .all(|(index, field)| field.index == index)
}

fn set_vmcs12_extended_field(vmcs12: &mut NestedVmcs12State, encoding: u64, value: u64) {
    let field = VMCS12_EXTENDED_FIELDS
        .iter()
        .find(|field| field.encoding == encoding)
        .expect("VMCS12 core field must be supported");
    vmcs12.extended_fields[field.index] = value;
}

fn set_vmcs12_guest_segment(
    vmcs12: &mut NestedVmcs12State,
    selector: u64,
    base: u64,
    limit: u64,
    access_rights: u64,
    segment: arch::SegmentState,
) {
    set_vmcs12_extended_field(vmcs12, selector, u64::from(segment.selector));
    set_vmcs12_extended_field(vmcs12, base, segment.base);
    set_vmcs12_extended_field(vmcs12, limit, u64::from(segment.limit));
    set_vmcs12_extended_field(vmcs12, access_rights, u64::from(segment.access_rights));
}

fn seed_nested_vmcs12_core_state(
    vmcs12: &mut NestedVmcs12State,
    mut segments: arch::SegmentationState,
    l1_cr4: u64,
) {
    use crate::nested::*;

    segments.tr = arch::vmx_usable_tr(segments.tr);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_VMCS_LINK_POINTER, u64::MAX);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_CR0, arch::read_cr0());
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_CR3, arch::read_cr3());
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_CR4, l1_cr4);
    set_vmcs12_guest_segment(
        vmcs12,
        VMCS_FIELD_GUEST_ES_SELECTOR,
        VMCS_FIELD_GUEST_ES_BASE,
        VMCS_FIELD_GUEST_ES_LIMIT,
        VMCS_FIELD_GUEST_ES_AR_BYTES,
        segments.es,
    );
    set_vmcs12_guest_segment(
        vmcs12,
        VMCS_FIELD_GUEST_CS_SELECTOR,
        VMCS_FIELD_GUEST_CS_BASE,
        VMCS_FIELD_GUEST_CS_LIMIT,
        VMCS_FIELD_GUEST_CS_AR_BYTES,
        segments.cs,
    );
    set_vmcs12_guest_segment(
        vmcs12,
        VMCS_FIELD_GUEST_SS_SELECTOR,
        VMCS_FIELD_GUEST_SS_BASE,
        VMCS_FIELD_GUEST_SS_LIMIT,
        VMCS_FIELD_GUEST_SS_AR_BYTES,
        segments.ss,
    );
    set_vmcs12_guest_segment(
        vmcs12,
        VMCS_FIELD_GUEST_DS_SELECTOR,
        VMCS_FIELD_GUEST_DS_BASE,
        VMCS_FIELD_GUEST_DS_LIMIT,
        VMCS_FIELD_GUEST_DS_AR_BYTES,
        segments.ds,
    );
    set_vmcs12_guest_segment(
        vmcs12,
        VMCS_FIELD_GUEST_FS_SELECTOR,
        VMCS_FIELD_GUEST_FS_BASE,
        VMCS_FIELD_GUEST_FS_LIMIT,
        VMCS_FIELD_GUEST_FS_AR_BYTES,
        segments.fs,
    );
    set_vmcs12_guest_segment(
        vmcs12,
        VMCS_FIELD_GUEST_GS_SELECTOR,
        VMCS_FIELD_GUEST_GS_BASE,
        VMCS_FIELD_GUEST_GS_LIMIT,
        VMCS_FIELD_GUEST_GS_AR_BYTES,
        segments.gs,
    );
    set_vmcs12_guest_segment(
        vmcs12,
        VMCS_FIELD_GUEST_LDTR_SELECTOR,
        VMCS_FIELD_GUEST_LDTR_BASE,
        VMCS_FIELD_GUEST_LDTR_LIMIT,
        VMCS_FIELD_GUEST_LDTR_AR_BYTES,
        segments.ldtr,
    );
    set_vmcs12_guest_segment(
        vmcs12,
        VMCS_FIELD_GUEST_TR_SELECTOR,
        VMCS_FIELD_GUEST_TR_BASE,
        VMCS_FIELD_GUEST_TR_LIMIT,
        VMCS_FIELD_GUEST_TR_AR_BYTES,
        segments.tr,
    );
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_GDTR_BASE, segments.gdtr.base);
    set_vmcs12_extended_field(
        vmcs12,
        VMCS_FIELD_GUEST_GDTR_LIMIT,
        u64::from(segments.gdtr.limit),
    );
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_IDTR_BASE, segments.idtr.base);
    set_vmcs12_extended_field(
        vmcs12,
        VMCS_FIELD_GUEST_IDTR_LIMIT,
        u64::from(segments.idtr.limit),
    );
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_INTERRUPTIBILITY_INFO, 0);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_ACTIVITY_STATE, 0);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_PENDING_DBG_EXCEPTIONS, 0);

    let sysenter_cs = unsafe { arch::read_msr(arch::IA32_SYSENTER_CS) };
    let sysenter_esp = unsafe { arch::read_msr(arch::IA32_SYSENTER_ESP) };
    let sysenter_eip = unsafe { arch::read_msr(arch::IA32_SYSENTER_EIP) };
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_SYSENTER_CS, sysenter_cs);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_SYSENTER_ESP, sysenter_esp);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_SYSENTER_EIP, sysenter_eip);

    let host_selector = |selector: u16| u64::from(selector & !0x7);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_HOST_CR0, arch::read_cr0());
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_HOST_CR3, arch::read_cr3());
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_HOST_CR4, arch::read_cr4());
    set_vmcs12_extended_field(
        vmcs12,
        VMCS_FIELD_HOST_ES_SELECTOR,
        host_selector(segments.es.selector),
    );
    set_vmcs12_extended_field(
        vmcs12,
        VMCS_FIELD_HOST_CS_SELECTOR,
        host_selector(segments.cs.selector),
    );
    set_vmcs12_extended_field(
        vmcs12,
        VMCS_FIELD_HOST_SS_SELECTOR,
        host_selector(segments.ss.selector),
    );
    set_vmcs12_extended_field(
        vmcs12,
        VMCS_FIELD_HOST_DS_SELECTOR,
        host_selector(segments.ds.selector),
    );
    set_vmcs12_extended_field(
        vmcs12,
        VMCS_FIELD_HOST_FS_SELECTOR,
        host_selector(segments.fs.selector),
    );
    set_vmcs12_extended_field(
        vmcs12,
        VMCS_FIELD_HOST_GS_SELECTOR,
        host_selector(segments.gs.selector),
    );
    set_vmcs12_extended_field(
        vmcs12,
        VMCS_FIELD_HOST_TR_SELECTOR,
        host_selector(segments.tr.selector),
    );
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_HOST_FS_BASE, segments.fs.base);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_HOST_GS_BASE, segments.gs.base);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_HOST_TR_BASE, segments.tr.base);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_HOST_GDTR_BASE, segments.gdtr.base);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_HOST_IDTR_BASE, segments.idtr.base);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_HOST_SYSENTER_CS, sysenter_cs);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_HOST_SYSENTER_ESP, sysenter_esp);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_HOST_SYSENTER_EIP, sysenter_eip);
}

fn seed_nested_vmcs12_backing(region: &ResidentPages, vmcs12: &NestedVmcs12State) {
    debug_assert!(region.byte_len() >= PAGE_SIZE);
    unsafe {
        let base = region.pointer().as_ptr();
        base.add(VMCS12_BACKING_MAGIC_OFFSET)
            .cast::<u64>()
            .write(VMCS12_BACKING_MAGIC);
        base.add(VMCS12_BACKING_STATE_OFFSET)
            .cast::<NestedVmcs12State>()
            .write(*vmcs12);
    }
}

fn nested_vmx_capabilities(host_vmx_basic: u64) -> NestedVmxCapabilities {
    let has_true_controls = host_vmx_basic & VMX_BASIC_TRUE_CONTROLS != 0;
    let host = unsafe {
        HostVmxCapabilities {
            vmx_basic: host_vmx_basic,
            pinbased_ctls: arch::read_msr(IA32_VMX_PINBASED_CTLS_MSR),
            procbased_ctls: arch::read_msr(IA32_VMX_PROCBASED_CTLS_MSR),
            exit_ctls: arch::read_msr(IA32_VMX_EXIT_CTLS_MSR),
            entry_ctls: arch::read_msr(IA32_VMX_ENTRY_CTLS_MSR),
            misc: arch::read_msr(IA32_VMX_MISC_MSR),
            cr0_fixed0: arch::read_msr(IA32_VMX_CR0_FIXED0_MSR),
            cr0_fixed1: arch::read_msr(IA32_VMX_CR0_FIXED1_MSR),
            cr4_fixed0: arch::read_msr(IA32_VMX_CR4_FIXED0_MSR),
            cr4_fixed1: arch::read_msr(IA32_VMX_CR4_FIXED1_MSR),
            vmcs_enum: arch::read_msr(IA32_VMX_VMCS_ENUM_MSR),
            procbased_ctls2: arch::read_msr(IA32_VMX_PROCBASED_CTLS2_MSR),
            ept_vpid_cap: arch::read_msr(IA32_VMX_EPT_VPID_CAP_MSR),
            true_pinbased_ctls: if has_true_controls {
                arch::read_msr(IA32_VMX_TRUE_PINBASED_CTLS_MSR)
            } else {
                0
            },
            true_procbased_ctls: if has_true_controls {
                arch::read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR)
            } else {
                0
            },
            true_exit_ctls: if has_true_controls {
                arch::read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR)
            } else {
                0
            },
            true_entry_ctls: if has_true_controls {
                arch::read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR)
            } else {
                0
            },
        }
    };
    let mut capabilities = NestedVmxCapabilities::from_host(host);
    crate::runtime::info(format_args!(
        "nested VMX host basic={:#x} misc={:#x} proc2={:#x} ept_vpid={:#x} guest misc={:#x} proc2={:#x} ept_vpid={:#x}",
        host.vmx_basic,
        host.misc,
        host.procbased_ctls2,
        host.ept_vpid_cap,
        capabilities.vmx_misc,
        capabilities.vmx_procbased_ctls2,
        capabilities.vmx_ept_vpid_cap,
    ));
    capabilities.expose_vmx = crate::boot::current().vt_nested;
    debug_assert_eq!(
        capabilities.vmx_msr(IA32_VMX_BASIC_MSR),
        Some(capabilities.vmx_basic)
    );
    capabilities
}

pub fn run_boot_loader(
    entry_rip: u64,
    event_context: u64,
    ept_probe_fault_rip: u64,
    ept_probe_resume_rip: u64,
) -> Result<ResidentBootReport, ResidentProbeError> {
    if !vmcs12_extended_fields_are_dense() {
        return Err(ResidentProbeError::Allocation(Status::OUT_OF_RESOURCES));
    }

    crate::boot::screen::stage("resident resource allocation");
    let initial_rflags = arch::read_rflags();
    let code = ResidentCode::allocate(event_context)?;
    let root_segments = arch::capture();
    let msr_bitmap = ResidentPages::allocate(MSR_BITMAP_PAGES, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let ept_test_page = ResidentPages::allocate(1, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let zero_page = ResidentPages::allocate(1, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let mut host_address_space = HostAddressSpace::reserve().map_err(ResidentProbeError::Paging)?;
    let vmx_basic = vt_vmxon::vmx_basic();
    let mut cpu_resources = ResidentCpuResources::allocate(
        vmx_basic,
        code.fatal,
        code.gp_handler,
        code.exception_stubs,
    )?;
    let topology = crate::smp::enumerate().map_err(ResidentProbeError::Allocation)?;
    let mut ap_resources = alloc::vec::Vec::new();
    {
        let handle = boot::get_handle_for_protocol::<uefi::proto::pi::mp::MpServices>()
            .map_err(|error| ResidentProbeError::Allocation(error.status()))?;
        let mp = boot::open_protocol_exclusive::<uefi::proto::pi::mp::MpServices>(handle)
            .map_err(|error| ResidentProbeError::Allocation(error.status()))?;
        for processor_number in 0..topology.total_processors {
            let info = mp
                .get_processor_info(processor_number)
                .map_err(|error| ResidentProbeError::Allocation(error.status()))?;
            if info.is_enabled() && !info.is_bsp() {
                ap_resources.push((
                    processor_number,
                    ResidentCpuResources::allocate(
                        vmx_basic,
                        code.fatal,
                        code.gp_handler,
                        code.exception_stubs,
                    )?,
                ));
            }
        }
    }
    unsafe {
        ept_test_page
            .pointer()
            .as_ptr()
            .cast::<u64>()
            .write(0x4550_5454_4553_5431);
    }
    unsafe {
        msr_bitmap
            .pointer()
            .as_ptr()
            .write_bytes(0xff, msr_bitmap.byte_len());
    }
    allow_low_msr_passthrough(&msr_bitmap, IA32_ARCH_CAPABILITIES_MSR);
    allow_low_msr_passthrough(&msr_bitmap, IA32_SPEC_CTRL_MSR);
    allow_low_msr_write_passthrough(&msr_bitmap, IA32_PRED_CMD_MSR);
    allow_low_msr_read_passthrough(&msr_bitmap, IA32_MCG_CAP_MSR);
    allow_low_msr_passthrough(&msr_bitmap, IA32_MCG_STATUS_MSR);
    allow_low_msr_passthrough(&msr_bitmap, IA32_MCG_CTL_MSR);
    // Resident CPUs own their physical APIC. Keep TSC synchronization and its
    // deadline timer in the same clock domain; L1 bitmap intercepts still apply to L2.
    for index in [IA32_TSC_MSR, IA32_TSC_ADJUST_MSR, IA32_TSC_DEADLINE_MSR] {
        allow_low_msr_passthrough(&msr_bitmap, index);
    }
    // L1 owns the local APIC; trapping its accesses only repeats the same MSR
    // instruction in root mode. VMCS02 still includes every L1 bitmap intercept.
    for index in IA32_X2APIC_MSR_BASE..=IA32_X2APIC_MSR_END {
        allow_low_msr_passthrough(&msr_bitmap, index);
    }
    allow_low_msr_passthrough(&msr_bitmap, IA32_XSS_MSR);
    let machine_check_bank_count = unsafe { arch::read_msr(IA32_MCG_CAP_MSR) } as u32 & 0xff;
    for bank in 0..machine_check_bank_count {
        allow_low_msr_passthrough(&msr_bitmap, IA32_MC0_CTL2_MSR + bank);
        allow_low_msr_passthrough(
            &msr_bitmap,
            IA32_MC0_CTL_MSR + bank * MACHINE_CHECK_BANK_MSR_STRIDE,
        );
        allow_low_msr_passthrough(
            &msr_bitmap,
            IA32_MC0_STATUS_MSR + bank * MACHINE_CHECK_BANK_MSR_STRIDE,
        );
    }
    allow_low_msr_passthrough(&msr_bitmap, IA32_MISC_ENABLE_MSR);
    allow_low_msr_passthrough(&msr_bitmap, arch::IA32_PAT);
    allow_high_msr_passthrough(&msr_bitmap, IA32_STAR_MSR);
    allow_high_msr_passthrough(&msr_bitmap, IA32_LSTAR_MSR);
    allow_high_msr_passthrough(&msr_bitmap, IA32_CSTAR_MSR);
    allow_high_msr_passthrough(&msr_bitmap, IA32_FMASK_MSR);
    // VM exits save FS/GS bases and VM entries restore them from the guest state.
    // Let hardware update those fields without introducing an L1-unrequested exit.
    allow_high_msr_passthrough(&msr_bitmap, IA32_FS_BASE_MSR);
    allow_high_msr_passthrough(&msr_bitmap, IA32_GS_BASE_MSR);
    allow_high_msr_passthrough(&msr_bitmap, IA32_KERNEL_GS_BASE_MSR);
    allow_high_msr_passthrough(&msr_bitmap, IA32_TSC_AUX_MSR);

    crate::boot::screen::stage("resident host paging");
    let host_space = host_address_space
        .clone_current()
        .map_err(ResidentProbeError::Paging)?;
    crate::boot::screen::stage("resident EPT setup");
    let mut ept = vt_ept::IdentityEpt::build()?;
    let pci_bar_ranges = ept.map_pci_bars()?;
    let high_address_end = ept.map_high_address_gaps()?;
    crate::boot::screen::message(format_args!(
        "resident high address EPT coverage to={high_address_end:#x} UC gaps"
    ));
    for &(start, end) in &pci_bar_ranges {
        if end > (1_u64 << 32) {
            crate::boot::screen::message(format_args!(
                "resident high PCI BAR EPT range={start:#x}..{end:#x} UC"
            ));
        }
    }
    let zero_page_physical_address = zero_page.physical_address();
    ept.conceal_guest_access(
        zero_page_physical_address,
        zero_page.pages(),
        zero_page_physical_address,
    )?;
    ept.conceal_guest_access(
        code.pages.physical_address(),
        code.pages.pages(),
        zero_page_physical_address,
    )?;
    ept.conceal_guest_access(
        msr_bitmap.physical_address(),
        msr_bitmap.pages(),
        zero_page_physical_address,
    )?;
    ept.conceal_guest_access(
        host_space.arena_physical_address,
        host_space.arena_pages,
        zero_page_physical_address,
    )?;
    ept.deny_guest_access(ept_test_page.physical_address(), ept_test_page.pages())?;
    cpu_resources.conceal_guest_access(&mut ept, zero_page_physical_address)?;
    for (_, resources) in &ap_resources {
        resources.conceal_guest_access(&mut ept, zero_page_physical_address)?;
    }
    ept.conceal_guest_access_to_tables(zero_page_physical_address)?;
    crate::boot::screen::stage("resident nested EPT setup");
    let mut ept12_template = vt_ept::IdentityEpt::build()?;
    ept12_template.map_high_address_gaps()?;
    let bsp_ept_composition = cpu_resources.prepare_nested_ept(&ept, &ept12_template)?;
    for (_, resources) in &mut ap_resources {
        resources.prepare_nested_ept(&ept, &ept12_template)?;
    }
    drop(ept12_template);
    let mut nested_ept02_regions = cpu_resources.nested_ept02_table_regions();
    for (_, resources) in &ap_resources {
        nested_ept02_regions.extend(resources.nested_ept02_table_regions());
    }
    ept.conceal_guest_access_to_regions(&nested_ept02_regions, zero_page_physical_address)?;
    // EPT02 starts sparse; later L2 compositions consult the protected EPT01.

    let nested_ept12_pointer = cpu_resources
        .nested_ept12_pointer()
        .ok_or(EptError::InvalidPageTable)?;
    let nested_ept02_pointer = cpu_resources
        .nested_ept02_pointer()
        .ok_or(EptError::InvalidPageTable)?;
    let nested_ept02_alternate_pointer = cpu_resources
        .nested_ept02_alternate_pointer()
        .ok_or(EptError::InvalidPageTable)?;
    let nested_ept02_table_pools = cpu_resources
        .nested_ept02_table_pools()
        .ok_or(EptError::InvalidPageTable)?;
    let nested_ept_source_gpa = cpu_resources.nested_ept_source_gpa();
    let nested_ept_target_gpa = cpu_resources.nested_ept_target_gpa();
    let nested_ept_second_target_gpa = cpu_resources.nested_ept_second_target_gpa();
    let nested_ept12_source_leaf = cpu_resources.nested_ept12_source_leaf();
    let nested_ept12_source_leaf_attributes = cpu_resources.nested_ept12_source_leaf_attributes();
    let nested_ept_alternate_composition = cpu_resources
        .nested_ept_alternate_composition()
        .ok_or(EptError::InvalidPageTable)?;

    let nested_vmxon_operand = cpu_resources.nested_vmxon_page.physical_address() + 8;
    let nested_vmxon_region = cpu_resources.nested_vmxon_page.physical_address();
    let nested_vmcs12_region = cpu_resources.nested_vmcs12_pages.physical_address();
    let nested_vmcs12_operand = nested_vmcs12_region + PAGE_SIZE as u64;
    let nested_vmptrst_destination = nested_vmcs12_operand + 8;
    let vmcs_physical_address = cpu_resources.vmcs_region.physical_address();
    let nested_vmcs02_physical_address = cpu_resources.nested_vmcs02_region.physical_address();
    let l0_msr_guest_list = cpu_resources.resident_msr_state.physical_address();
    let nested_msr_state = cpu_resources.nested_msr_state.physical_address();
    // Calibration can call Stall; finish all diagnostic protocol work before VMXON.
    let (diagnostic_interval_tsc, diagnostic_timer_rate) =
        vt_controls::resident_boot_timer_parameters();
    let watchdog_tsc_hz = if diagnostic_interval_tsc != 0 {
        diagnostic_interval_tsc
    } else {
        vt_controls::resident_tsc_hz()
    };
    if crate::runtime::framebuffer_enabled()
        && crate::boot::screen::prepare_resident_visuals()
        && let Some((visual_base, visual_stride_bytes)) =
            crate::boot::screen::resident_marker_layout()
    {
        let event_context = event_context as *mut ResidentEventContext;
        unsafe {
            (*event_context).visual_base = visual_base;
            (*event_context).visual_stride_bytes = visual_stride_bytes;
        }
    }
    crate::boot::screen::stage("resident BSP VMCS setup");
    let session =
        vt_vmxon::enter_vmx_root_with_borrowed_region(vmx_basic, &mut cpu_resources.vmxon_region)
            .map_err(ResidentProbeError::Vmxon)?;
    let l1_cr4 = session.report().original_cr4;
    EPT_TEST_PAGE_GPA.store(ept_test_page.physical_address(), Ordering::Release);
    let clear_result = unsafe { vmcs::vmclear(vmcs_physical_address) };
    if clear_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(ResidentProbeError::Vmclear(clear_result));
    }
    let load_result = unsafe { vmcs::vmptrld(vmcs_physical_address) };
    if load_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(ResidentProbeError::Vmcs(VmcsError::Vmptrld(load_result)));
    }

    let mut controls =
        vt_controls::configure_resident_boot(msr_bitmap.physical_address(), ept.ept_pointer())?;
    vt_controls::enable_resident_vpid(&mut controls, 1)?;
    vt_controls::enable_resident_boot_timer(
        &mut controls,
        diagnostic_interval_tsc,
        diagnostic_timer_rate,
    )?;
    configure_resident_msr_switch(&cpu_resources.resident_msr_state)?;
    configure_resident_host(
        host_space.host_cr3,
        &cpu_resources.host_tables,
        root_segments,
    )?;
    let guest_rsp =
        cpu_resources.guest_stack.physical_address() + cpu_resources.guest_stack.byte_len() as u64;
    let guest = vt_state::configure_guest_with_rflags(entry_rip, guest_rsp & !0xf, initial_rflags)?;
    vt_controls::virtualize_resident_cr4_vmxe(l1_cr4)?;
    let nested_capabilities = nested_vmx_capabilities(vmx_basic);
    let mut nested_state = NestedVmxState::new(
        nested_capabilities,
        nested_vmxon_operand,
        nested_vmxon_region,
        NestedVmcs12State::new(
            nested_capabilities.revision_id,
            nested_vmcs12_operand,
            nested_vmcs12_region,
            nested_vmptrst_destination,
        ),
        vmcs_physical_address,
        nested_vmcs02_physical_address,
    );
    nested_state.l1_cr4 = l1_cr4;
    configure_nested_msr_composition(
        &mut nested_state,
        msr_bitmap.physical_address(),
        l0_msr_guest_list,
        nested_msr_state,
    );
    nested_state.configure_ept(NestedEptConfiguration {
        ept12_pointer: nested_ept12_pointer,
        ept02_pointer: nested_ept02_pointer,
        source_gpa: nested_ept_source_gpa,
        target_gpa: nested_ept_target_gpa,
        composed_hpa: bsp_ept_composition.host_physical_address,
        permissions: bsp_ept_composition.permissions,
        alternate_ept02_pointer: nested_ept02_alternate_pointer,
        second_target_gpa: nested_ept_second_target_gpa,
        source_leaf: nested_ept12_source_leaf,
        source_leaf_attributes: nested_ept12_source_leaf_attributes,
        alternate_composed_hpa: nested_ept_alternate_composition.host_physical_address,
        alternate_permissions: nested_ept_alternate_composition.permissions,
    });
    nested_state.configure_ept02_table_pools(nested_ept02_table_pools);
    seed_nested_vmcs12_core_state(&mut nested_state.vmcs12, root_segments, l1_cr4);
    seed_nested_vmcs12_backing(&cpu_resources.nested_vmcs12_pages, &nested_state.vmcs12);

    let context = cpu_resources
        .context_pages
        .pointer()
        .as_ptr()
        .cast::<ResidentBootContext>();
    unsafe {
        context.write(ResidentBootContext::new(
            host_space.host_cr3,
            guest.cr3,
            event_context,
            ept_test_page.physical_address(),
            ept_probe_fault_rip,
            ept_probe_resume_rip,
            nested_state,
        ));
        (*context).diagnostic_interval_tsc = diagnostic_interval_tsc;
        (*context).watchdog_tsc_hz = watchdog_tsc_hz;
        let shared = event_context as *mut ResidentEventContext;
        (*shared).watchdog_tsc_hz = watchdog_tsc_hz;
        (*shared).cpu_contexts[0] = context as u64;
        (*context).cache_ept_pointer = ept.ept_pointer();
        ((cpu_resources.host_tables.tss + 112) as *mut u64).write(context as u64);
        (*context).diagnostic_timer_rate = diagnostic_timer_rate;
        (*context).diagnostic_deadline_tsc =
            core::arch::x86_64::_rdtsc().wrapping_add(diagnostic_interval_tsc);
    }
    let host_rsp = (cpu_resources.host_stack.physical_address()
        + cpu_resources.host_stack.byte_len() as u64
        - 8)
        & !0xf;
    unsafe {
        (host_rsp as *mut u64).write(context as u64);
    }
    configure_nested_vmcs02(NestedVmcs02Configuration {
        vmcs01_region: vmcs_physical_address,
        vmcs02_region: nested_vmcs02_physical_address,
        msr_bitmap: msr_bitmap.physical_address(),
        ept_pointer: nested_ept02_pointer,
        msr_state: &cpu_resources.resident_msr_state,
        host_cr3: host_space.host_cr3,
        host_tables: &cpu_resources.host_tables,
        segments: root_segments,
        host_rsp,
        host_rip: code.dispatch_entry,
        guest_rip: entry_rip,
        guest_rsp: guest_rsp & !0xf,
        guest_rflags: initial_rflags,
        l1_cr4,
    })?;

    // Firmware MP services run with the BSP's original CRs, tables, and IF.
    // VMCLEAR retains the prepared fields while relinquishing CPU ownership.
    let clear = unsafe { vmcs::vmclear(vmcs_physical_address) };
    drop(session);
    if clear != VmxInstructionResult::Succeeded {
        return Err(ResidentProbeError::Vmclear(clear));
    }
    crate::boot::screen::stage("resident AP launch");
    for (processor_number, resources) in &mut ap_resources {
        crate::boot::screen::message(format_args!("resident AP {} starting", processor_number));
        let mut launch = ResidentApLaunch {
            resources,
            host_cr3: host_space.host_cr3,
            event_context,
            ept_pointer: ept.ept_pointer(),
            msr_bitmap: msr_bitmap.physical_address(),
            dispatch_entry: code.dispatch_entry,
            processor_number: *processor_number,
        };
        let result = crate::smp::launch(*processor_number, &mut launch);
        let ap_context = resources
            .context_pages
            .pointer()
            .as_ptr()
            .cast::<ResidentBootContext>();
        let started = unsafe { core::ptr::addr_of!((*ap_context).ap_started).read_volatile() };
        let nested = unsafe { core::ptr::addr_of!((*ap_context).nested).read_volatile() };
        crate::runtime::info(format_args!(
            "smp resident processor={} started={} status={:?} vmxon={:#x} vmcs={:#x} host_stack={:#x} context={:#x} host_cr3={:#x} ept={:#x}",
            processor_number,
            started,
            result,
            resources.vmxon_region.physical_address(),
            resources.vmcs_region.physical_address(),
            resources.host_stack.physical_address(),
            ap_context as u64,
            host_space.host_cr3,
            ept.ept_pointer()
        ));
        crate::runtime::info(format_args!(
            "nested AP processor={} operand={:#x} region={:#x} vmxon={} vmxoff={} active={} failures={} complete={} cpuid_leaf1_ecx={:#x} cpuid_hypervisor_eax={:#x}",
            processor_number,
            nested.vmxon_operand,
            nested.vmxon_region,
            nested.vmxon_count,
            nested.vmxoff_count,
            nested.active,
            nested.failure_count,
            nested.probe_complete,
            unsafe { core::ptr::addr_of!((*ap_context).cpuid_leaf1_ecx).read_volatile() },
            unsafe { core::ptr::addr_of!((*ap_context).cpuid_hypervisor_eax).read_volatile() }
        ));
        crate::runtime::info(format_args!(
            "nested AP VMCS12 processor={} region={:#x} stored={:#x} guest_rip={:#x} vmclear={} vmptrld={} vmptrst={} vmwrite={} vmread={} vmlaunch={} vmresume={} complete={} entry_rejections={}",
            processor_number,
            nested.vmcs12.region,
            nested.vmcs12.last_stored_pointer,
            nested.vmcs12.guest_rip,
            nested.vmcs12.vmclear_count,
            nested.vmcs12.vmptrld_count,
            nested.vmcs12.vmptrst_count,
            nested.vmcs12.vmwrite_count,
            nested.vmcs12.vmread_count,
            nested.vmcs12.vmlaunch_count,
            nested.vmcs12.vmresume_count,
            nested.vmcs12.probe_complete,
            nested.vmcs12.entry_rejection_count
        ));
        crate::runtime::info(format_args!(
            "nested AP L2 processor={} vmcs01={:#x} vmcs02={:#x} entries={} exits={} reflections={} resumes={} resume_exits={} reason={:#x} rip={:#x} rsp={:#x}",
            processor_number,
            nested.vmcs01_region,
            nested.vmcs02_region,
            nested.l2_entry_count,
            nested.l2_exit_count,
            nested.l1_reflection_count,
            nested.l2_resume_count,
            nested.l2_resume_exit_count,
            nested.l2_last_exit_reason,
            nested.l2_last_exit_rip,
            nested.l2_last_exit_rsp
        ));
        if result.is_err()
            || started != 1
            || nested.vmxon_count != 2
            || nested.vmxoff_count != 1
            || nested.active != 0
            || nested.failure_count != 7
            || nested.probe_complete != 1
            || nested.vmcs12.last_stored_pointer != nested.vmcs12.region
            || nested.vmcs12.guest_rip == 0
            || nested.vmcs12.guest_rip != nested.l2_last_exit_rip
            || nested.vmcs12.guest_rsp == 0
            || nested.vmcs12.guest_rsp != nested.l2_last_exit_rsp
            || nested.vmcs12.host_rip == 0
            || nested.vmcs12.host_rsp == 0
            || nested.vmcs12.exit_reason & 0xffff != VMCALL_EXIT_REASON
            || nested.vmcs12.exit_instruction_len != 3
            || nested.vmcs12.vmclear_count != 2
            || nested.vmcs12.vmptrld_count != 2
            || nested.vmcs12.vmptrst_count != 1
            || nested.vmcs12.vmwrite_count != 31
            || nested.vmcs12.vmread_count != 36
            || nested.vmcs12.probe_complete != 1
            || nested.vmcs12.vmlaunch_count != 2
            || nested.vmcs12.vmresume_count != 3
            || nested.vmcs12.entry_rejection_count != 2
            || nested.vmcs12.control_validation_count != 3
            || nested.vmcs12.launch_state != VMCS12_LAUNCH_STATE_LAUNCHED
            || nested.vmcs12.extended_fields[0] != 1
            || nested.vmcs12.extended_fields[3]
                != (VMX_SECONDARY_ENABLE_EPT | VMX_SECONDARY_ENABLE_VPID) as u64
            || nested.vmcs01_region == nested.vmcs02_region
            || nested.l2_active != 0
            || nested.l2_entry_count != 3
            || nested.l2_exit_count != 3
            || nested.l2_last_exit_reason & 0xffff != VMCALL_EXIT_REASON
            || nested.l2_last_exit_rip == 0
            || nested.l2_last_exit_rsp == 0
            || nested.l1_reflection_count != 3
            || nested.l2_resume_count != 2
            || nested.l2_resume_exit_count != 2
            || nested.ept12_pointer == 0
            || nested.ept02_pointer == 0
            || nested.ept12_pointer == nested.ept02_pointer
            || nested.ept02_initial_pointer == 0
            || nested.ept02_alternate_pointer == 0
            || nested.ept02_initial_pointer == nested.ept02_alternate_pointer
            || nested.ept02_pointer != nested.ept02_alternate_pointer
            || nested.ept_source_gpa == nested.ept_target_gpa
            || nested.ept_source_gpa == nested.ept_second_target_gpa
            || nested.ept_target_gpa == nested.ept_second_target_gpa
            || nested.ept_composed_hpa != nested.ept_target_gpa
            || nested.ept_alternate_composed_hpa != nested.ept_second_target_gpa
            || nested.ept_permissions != 7
            || nested.ept_alternate_permissions != 7
            || nested.ept_composition_count < 2
            || nested.ept_probe_count != 3
            || nested.ept_observed_value != crate::smp::NESTED_EPT_TARGET_MARKER
            || nested.ept_observed_value_before_invept != crate::smp::NESTED_EPT_TARGET_MARKER
            || nested.ept_observed_value_after_invept != crate::smp::NESTED_EPT_SECOND_TARGET_MARKER
            || nested.invept_count != 2
            || nested.invept_software_count != 2
            || nested.invvpid_count != 2
            || nested.invvpid_software_count != 2
            || nested.control_merge_count != 3
            || nested.guest_state_sync_count != 3
            || nested.l1_host_restore_count != 3
            || nested.vmcs12.extended_fields[4] != 0
            || nested.last_synced_guest_cr0 != nested.vmcs12.extended_fields[29]
            || nested.last_synced_guest_cr3 != nested.vmcs12.extended_fields[30]
            || nested.last_synced_guest_cr4 != nested.vmcs12.extended_fields[31]
            || nested.last_restored_host_cr0 != nested.vmcs12.extended_fields[32]
            || nested.last_restored_host_cr3 != nested.vmcs12.extended_fields[33]
            || nested.last_restored_host_cr4 != nested.vmcs12.extended_fields[34]
            || nested.last_synced_guest_sysenter_eip != nested.vmcs12.extended_fields[87]
            || nested.last_restored_host_sysenter_eip != nested.vmcs12.extended_fields[90]
            || nested.inherited_l1_pat != nested.l2_saved_pat
            || nested.inherited_l1_efer != nested.l2_saved_efer
            || nested.vmcs12.extended_fields[16] != nested.ept12_pointer
        {
            crate::boot::screen::error(format_args!(
                "resident AP {} failed: status={result:?} started={started} complete={} vmx_failures={}",
                processor_number, nested.probe_complete, nested.failure_count
            ));
            resident_startup_halt();
        }
        unsafe {
            core::ptr::addr_of_mut!((*ap_context).telemetry_probe_active).write_volatile(0);
            core::ptr::addr_of_mut!((*ap_context).telemetry_active).write_volatile(0);
            // Startup validation must not seed the Windows telemetry session.
            for counter in [
                core::ptr::addr_of_mut!((*ap_context).exit_count),
                core::ptr::addr_of_mut!((*ap_context).watchdog_sequence),
                core::ptr::addr_of_mut!((*ap_context).watchdog_exit_count),
                core::ptr::addr_of_mut!((*ap_context).watchdog_handler_returns),
                core::ptr::addr_of_mut!((*ap_context).watchdog_resume_failures),
                core::ptr::addr_of_mut!((*ap_context).watchdog_last_reason),
                core::ptr::addr_of_mut!((*ap_context).watchdog_last_rip),
                core::ptr::addr_of_mut!((*ap_context).ept_violation_read),
                core::ptr::addr_of_mut!((*ap_context).ept_violation_write),
                core::ptr::addr_of_mut!((*ap_context).ept_violation_execute),
                core::ptr::addr_of_mut!((*ap_context).cr3_exits),
                core::ptr::addr_of_mut!((*ap_context).eptp_switches),
                core::ptr::addr_of_mut!((*ap_context).mtf_exits),
                core::ptr::addr_of_mut!((*ap_context).invept_exits),
                core::ptr::addr_of_mut!((*ap_context).preemption_timer_exits),
                core::ptr::addr_of_mut!((*ap_context).nested.l2_entry_count),
                core::ptr::addr_of_mut!((*ap_context).nested.failure_count),
                core::ptr::addr_of_mut!((*ap_context).nested.vmcs12.entry_rejection_count),
                core::ptr::addr_of_mut!((*ap_context).nested.invept_count),
                core::ptr::addr_of_mut!((*ap_context).nested.ept_composition_count),
                core::ptr::addr_of_mut!((*ap_context).nested.ept02_invalidation_count),
                core::ptr::addr_of_mut!((*ap_context).nested.l2_exit_count),
                core::ptr::addr_of_mut!((*ap_context).nested.l2_resume_count),
                core::ptr::addr_of_mut!((*ap_context).nested.l2_last_exit_reason),
                core::ptr::addr_of_mut!((*ap_context).nested.l2_last_exit_rip),
                core::ptr::addr_of_mut!((*ap_context).nested.l2_last_exit_rsp),
            ] {
                counter.write_volatile(0);
            }
            core::ptr::addr_of_mut!((*ap_context).watchdog_phase).write_volatile(1);
        }
        crate::boot::screen::message(format_args!("resident AP {} ready", processor_number));
    }
    crate::runtime::info(format_args!(
        "smp resident BSP context={:#x} vmcs={:#x} vmxon={:#x}",
        context as u64,
        vmcs_physical_address,
        cpu_resources.vmxon_region.physical_address()
    ));
    crate::boot::screen::page("resident BSP VMLAUNCH");
    crate::boot::screen::message(format_args!(
        "resident APs ready={} BSP VMCS={:#x} EPT={:#x}",
        ap_resources.len(),
        vmcs_physical_address,
        ept.ept_pointer()
    ));
    let first_high_bar = pci_bar_ranges
        .iter()
        .copied()
        .find(|&(_, end)| end > (1_u64 << 32))
        .unwrap_or((0, 0));
    crate::boot::screen::message(format_args!(
        "PCI BARs={} first high={:#x}..{:#x}",
        pci_bar_ranges.len(),
        first_high_bar.0,
        first_high_bar.1
    ));
    crate::boot::screen::message(format_args!(
        "runtime diagnostics use the saved framebuffer aperture without UEFI services"
    ));
    crate::boot::screen::message(format_args!(
        "mark rows: first reason bits, VMRESUME error bits, first eight exits"
    ));
    crate::boot::screen::message(format_args!(
        "hex rows: 0 exits 1 reason 2 RIP 3 RCX 4 MSR GP count 5 last GP MSR"
    ));
    crate::boot::screen::message(format_args!(
        "hex rows: 6 GPA 7 qualification 8 CPU mask 9 CPU A host fault B host RIP"
    ));
    crate::boot::screen::message(format_args!("hex rows: C host error code D host CR2"));
    crate::boot::screen::message(format_args!(
        "hex left E timer samples F last normal reason; right 0 CR0 1 CR3 2 CR4 3 EFER"
    ));
    crate::boot::screen::message(format_args!(
        "hex right 4 flags 5 activity 6 normal RIP 7 EFER write 8 RSP 9 interruptibility"
    ));
    crate::boot::screen::message(format_args!(
        "hex right A RDMSR B WRMSR C L2 entries D nested failures E nested error F expired"
    ));
    crate::boot::screen::message(format_args!(
        "BSP boot timer available={} interval TSC={:#x} rate={} samples=60",
        diagnostic_interval_tsc != 0,
        diagnostic_interval_tsc,
        diagnostic_timer_rate
    ));
    crate::boot::screen::message(format_args!(
        "EPT halt hex at right: GPA / guest RIP / qualification"
    ));
    let session = match vt_vmxon::enter_vmx_root_with_borrowed_region(
        vmx_basic,
        &mut cpu_resources.vmxon_region,
    ) {
        Ok(session) => session,
        Err(error) => {
            crate::boot::screen::error(format_args!("resident BSP VMXON failed: {error:?}"));
            resident_startup_halt();
        }
    };
    let load = unsafe { vmcs::vmptrld(vmcs_physical_address) };
    if load != VmxInstructionResult::Succeeded {
        drop(session);
        crate::boot::screen::error(format_args!("resident BSP VMPTRLD failed: {load:?}"));
        resident_startup_halt();
    }
    let raw_path =
        unsafe { matrixhv_resident_boot_run_asm(context, host_rsp, code.dispatch_entry) };
    if !ap_resources.is_empty() {
        let boot_context = unsafe { &*context };
        crate::boot::screen::error(format_args!(
            "BSP returned with resident APs: path={} stop={:#x} exit={:#x} rip={:#x}",
            raw_path,
            boot_context.stop_result,
            boot_context.last_reason,
            boot_context.last_guest_rip
        ));
        resident_startup_halt();
    }
    EPT_TEST_PAGE_GPA.store(0, Ordering::Release);
    if raw_path == 0 {
        cpu_resources.host_tables.pages.preserve();
    }
    let vm_instruction_error = vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
    let final_clear = unsafe { vmcs::vmclear(vmcs_physical_address) };
    host_address_space.restore_source_cr3();
    drop(session);
    let _ = &ept;
    if final_clear != VmxInstructionResult::Succeeded {
        return Err(ResidentProbeError::Vmclear(final_clear));
    }
    validate_run_path(raw_path, vm_instruction_error)?;

    let result = unsafe { &*context };
    if result.canary_start != BOOT_CONTEXT_CANARY_START
        || result.canary_end != BOOT_CONTEXT_CANARY_END
    {
        return Err(ResidentProbeError::CanaryCorrupted);
    }
    if result.last_host_cr3 != 0 && result.last_host_cr3 != host_space.host_cr3 {
        return Err(ResidentProbeError::HostCr3Mismatch {
            expected: host_space.host_cr3,
            observed: result.last_host_cr3,
        });
    }

    let report = ResidentBootReport {
        raw_path,
        vm_instruction_error,
        host_cr3: host_space.host_cr3,
        initial_guest_cr3: guest.cr3,
        exit_count: result.exit_count,
        cpuid_count: result.cpuid_count,
        rdmsr_count: result.rdmsr_count,
        wrmsr_count: result.wrmsr_count,
        xsetbv_count: result.xsetbv_count,
        vmcall_count: result.vmcall_count,
        start_checkpoint_seen: result.start_checkpoint_seen,
        post_start_exit_count: result.post_start_exit_count,
        post_ebs_exit_count: result.post_ebs_exit_count,
        post_va_exit_count: result.post_va_exit_count,
        ept_test_violation_seen: result.ept_test_violation_seen,
        last_reason: result.last_reason,
        last_instruction_len: result.last_instruction_len,
        last_qualification: result.last_qualification,
        last_guest_physical_address: result.last_guest_physical_address,
        last_guest_rax: result.last_guest_rax,
        last_guest_rcx: result.last_guest_rcx,
        last_guest_rdx: result.last_guest_rdx,
        last_guest_rip: result.last_guest_rip,
        last_guest_cr3: result.last_guest_cr3,
        last_host_cr3: result.last_host_cr3,
        stop_result: result.stop_result,
        cpuid_presence: result.cpuid_presence,
        cpuid_leaf1_count: result.cpuid_leaf1_count,
        cpuid_hypervisor_count: result.cpuid_hypervisor_count,
        cpuid_leaf1_ecx: result.cpuid_leaf1_ecx,
        cpuid_hypervisor_eax: result.cpuid_hypervisor_eax,
        nested: result.nested,
    };
    let _ = &cpu_resources;
    let _ = &zero_page;
    Ok(report)
}

fn resident_startup_halt() -> ! {
    crate::runtime::error(format_args!(
        "smp resident startup failed; retaining active CPU resources"
    ));
    unsafe { matrixhv_resident_startup_halt_asm() }
}

pub(crate) struct ResidentApLaunch<'a> {
    resources: &'a mut ResidentCpuResources,
    host_cr3: u64,
    event_context: u64,
    ept_pointer: u64,
    msr_bitmap: u64,
    dispatch_entry: u64,
    processor_number: usize,
}

impl ResidentApLaunch<'_> {
    pub(crate) fn prepare(
        &mut self,
        guest_rsp: u64,
        guest_rip: u64,
    ) -> Result<u64, ResidentProbeError> {
        let segments = arch::capture();
        let nested_vmxon_operand = self.resources.nested_vmxon_operand();
        let nested_vmxon_region = self.resources.nested_vmxon_region();
        let nested_vmcs12_operand = self.resources.nested_vmcs12_operand();
        let nested_vmcs12_region = self.resources.nested_vmcs12_region();
        let nested_vmptrst_destination = self.resources.nested_vmptrst_destination();
        let nested_vmcs02_region = self.resources.nested_vmcs02_region();
        let l0_msr_guest_list = self.resources.resident_msr_state.physical_address();
        let nested_msr_state = self.resources.nested_msr_state.physical_address();
        let nested_ept12_pointer = self
            .resources
            .nested_ept12_pointer()
            .ok_or(EptError::InvalidPageTable)?;
        let nested_ept02_pointer = self
            .resources
            .nested_ept02_pointer()
            .ok_or(EptError::InvalidPageTable)?;
        let nested_ept02_alternate_pointer = self
            .resources
            .nested_ept02_alternate_pointer()
            .ok_or(EptError::InvalidPageTable)?;
        let nested_ept02_table_pools = self
            .resources
            .nested_ept02_table_pools()
            .ok_or(EptError::InvalidPageTable)?;
        let nested_ept_source_gpa = self.resources.nested_ept_source_gpa();
        let nested_ept_target_gpa = self.resources.nested_ept_target_gpa();
        let nested_ept_second_target_gpa = self.resources.nested_ept_second_target_gpa();
        let nested_ept12_source_leaf = self.resources.nested_ept12_source_leaf();
        let nested_ept12_source_leaf_attributes =
            self.resources.nested_ept12_source_leaf_attributes();
        let nested_ept_composition = self
            .resources
            .nested_ept_composition()
            .ok_or(EptError::InvalidPageTable)?;
        let nested_ept_alternate_composition = self
            .resources
            .nested_ept_alternate_composition()
            .ok_or(EptError::InvalidPageTable)?;
        let vmx_basic = vt_vmxon::vmx_basic();
        let session = vt_vmxon::enter_vmx_root_with_borrowed_region(
            vmx_basic,
            &mut self.resources.vmxon_region,
        )
        .map_err(ResidentProbeError::Vmxon)?;
        let l1_cr4 = session.report().original_cr4;
        let vmcs = self.resources.vmcs_region.physical_address();
        let clear = unsafe { vmcs::vmclear(vmcs) };
        if clear != VmxInstructionResult::Succeeded {
            return Err(ResidentProbeError::Vmclear(clear));
        }
        let load = unsafe { vmcs::vmptrld(vmcs) };
        if load != VmxInstructionResult::Succeeded {
            return Err(ResidentProbeError::Vmcs(VmcsError::Vmptrld(load)));
        }
        let mut controls = vt_controls::configure_resident_ap(self.msr_bitmap, self.ept_pointer)?;
        vt_controls::enable_resident_vpid(&mut controls, 1)?;
        configure_resident_msr_switch(&self.resources.resident_msr_state)?;
        configure_resident_host(self.host_cr3, &self.resources.host_tables, segments)?;
        let guest = vt_state::configure_guest(guest_rip, guest_rsp)?;
        vt_controls::virtualize_resident_cr4_vmxe(l1_cr4)?;
        let nested_capabilities = nested_vmx_capabilities(vmx_basic);
        let mut nested_state = NestedVmxState::new(
            nested_capabilities,
            nested_vmxon_operand,
            nested_vmxon_region,
            NestedVmcs12State::new(
                nested_capabilities.revision_id,
                nested_vmcs12_operand,
                nested_vmcs12_region,
                nested_vmptrst_destination,
            ),
            vmcs,
            nested_vmcs02_region,
        );
        nested_state.l1_cr4 = l1_cr4;
        configure_nested_msr_composition(
            &mut nested_state,
            self.msr_bitmap,
            l0_msr_guest_list,
            nested_msr_state,
        );
        nested_state.configure_ept(NestedEptConfiguration {
            ept12_pointer: nested_ept12_pointer,
            ept02_pointer: nested_ept02_pointer,
            source_gpa: nested_ept_source_gpa,
            target_gpa: nested_ept_target_gpa,
            composed_hpa: nested_ept_composition.host_physical_address,
            permissions: nested_ept_composition.permissions,
            alternate_ept02_pointer: nested_ept02_alternate_pointer,
            second_target_gpa: nested_ept_second_target_gpa,
            source_leaf: nested_ept12_source_leaf,
            source_leaf_attributes: nested_ept12_source_leaf_attributes,
            alternate_composed_hpa: nested_ept_alternate_composition.host_physical_address,
            alternate_permissions: nested_ept_alternate_composition.permissions,
        });
        nested_state.configure_ept02_table_pools(nested_ept02_table_pools);
        seed_nested_vmcs12_core_state(&mut nested_state.vmcs12, segments, l1_cr4);
        seed_nested_vmcs12_backing(&self.resources.nested_vmcs12_pages, &nested_state.vmcs12);
        let context = self
            .resources
            .context_pages
            .pointer()
            .as_ptr()
            .cast::<ResidentBootContext>();
        let mut state = ResidentBootContext::new(
            self.host_cr3,
            guest.cr3,
            self.event_context,
            0,
            0,
            0,
            nested_state,
        );
        state.processor_number = self.processor_number as u64;
        // The AP startup probe explicitly collects diagnostics for its validation.
        state.telemetry_probe_active = 1;
        state.watchdog_tsc_hz =
            unsafe { (*(self.event_context as *const ResidentEventContext)).watchdog_tsc_hz };
        state.cache_ept_pointer = self.ept_pointer;
        let host_rsp = (self.resources.host_stack.physical_address()
            + self.resources.host_stack.byte_len() as u64
            - 8)
            & !0xf;
        unsafe {
            context.write(state);
            if self.processor_number < 64 {
                (*(self.event_context as *mut ResidentEventContext)).cpu_contexts
                    [self.processor_number] = context as u64;
            }
            ((self.resources.host_tables.tss + 112) as *mut u64).write(context as u64);
            (host_rsp as *mut u64).write(context as u64);
        }
        configure_nested_vmcs02(NestedVmcs02Configuration {
            vmcs01_region: vmcs,
            vmcs02_region: nested_vmcs02_region,
            msr_bitmap: self.msr_bitmap,
            ept_pointer: nested_ept02_pointer,
            msr_state: &self.resources.resident_msr_state,
            host_cr3: self.host_cr3,
            host_tables: &self.resources.host_tables,
            segments,
            host_rsp,
            host_rip: self.dispatch_entry,
            guest_rip,
            guest_rsp,
            guest_rflags: 0x2,
            l1_cr4,
        })?;
        vmwrite(HOST_RSP, host_rsp)?;
        vmwrite(HOST_RIP, self.dispatch_entry)?;
        // The successful guest continuation returns to firmware without dropping this root session.
        core::mem::forget(session);
        Ok(nested_vmxon_operand)
    }
}

fn configure_resident_host(
    host_cr3: u64,
    tables: &ResidentHostTables,
    segments: arch::SegmentationState,
) -> Result<(), VmcsError> {
    vmwrite(HOST_ES_SELECTOR, u64::from(tables.selectors.es))?;
    vmwrite(HOST_CS_SELECTOR, u64::from(tables.selectors.cs))?;
    vmwrite(HOST_SS_SELECTOR, u64::from(tables.selectors.ss))?;
    vmwrite(HOST_DS_SELECTOR, u64::from(tables.selectors.ds))?;
    vmwrite(HOST_FS_SELECTOR, u64::from(tables.selectors.fs))?;
    vmwrite(HOST_GS_SELECTOR, u64::from(tables.selectors.gs))?;
    vmwrite(HOST_TR_SELECTOR, u64::from(HOST_TSS_SELECTOR))?;
    vmwrite(HOST_CR0, arch::read_cr0())?;
    vmwrite(HOST_CR3, host_cr3)?;
    vmwrite(HOST_CR4, arch::read_cr4())?;
    vmwrite(HOST_IA32_PAT, unsafe { arch::read_msr(arch::IA32_PAT) })?;
    vmwrite(HOST_IA32_EFER, unsafe { arch::read_msr(arch::IA32_EFER) })?;
    vmwrite(HOST_FS_BASE, segments.fs.base)?;
    vmwrite(HOST_GS_BASE, tables.tss)?;
    vmwrite(HOST_TR_BASE, tables.tss)?;
    vmwrite(HOST_GDTR_BASE, tables.gdt)?;
    vmwrite(HOST_IDTR_BASE, tables.idt)?;
    vmwrite(
        HOST_SYSENTER_CS,
        unsafe { arch::read_msr(arch::IA32_SYSENTER_CS) } & 0xffff_ffff,
    )?;
    vmwrite(HOST_SYSENTER_ESP, unsafe {
        arch::read_msr(arch::IA32_SYSENTER_ESP)
    })?;
    vmwrite(HOST_SYSENTER_EIP, unsafe {
        arch::read_msr(arch::IA32_SYSENTER_EIP)
    })?;
    Ok(())
}

fn host_selector(selector: u16) -> u16 {
    selector & !0x7
}

fn validate_run_path(raw_path: u64, vm_instruction_error: u64) -> Result<(), ResidentProbeError> {
    match raw_path {
        0 => Ok(()),
        1 => Err(ResidentProbeError::VmlaunchVmFailInvalid),
        2 => Err(ResidentProbeError::VmlaunchVmFailValid(
            vm_instruction_error,
        )),
        3 => Err(ResidentProbeError::HostRspVmwrite),
        4 => Err(ResidentProbeError::HostRipVmwrite),
        other => Err(ResidentProbeError::UnexpectedRunPath(other)),
    }
}

fn tss_descriptor(base: u64) -> (u64, u64) {
    let limit = u64::from(TSS_LIMIT);
    let low = (limit & 0xffff)
        | ((base & 0xffff) << 16)
        | (((base >> 16) & 0xff) << 32)
        | (0x8b_u64 << 40)
        | (((limit >> 16) & 0xf) << 48)
        | (((base >> 24) & 0xff) << 56);
    (low, base >> 32)
}

fn guest_probe_address() -> u64 {
    matrixhv_resident_guest_probe_asm as *const () as usize as u64
}

unsafe extern "efiapi" {
    fn matrixhv_resident_startup_halt_asm() -> !;
    fn matrixhv_resident_probe_run_asm(
        context: *mut ResidentContext,
        host_rsp: u64,
        host_rip: u64,
    ) -> u64;
    fn matrixhv_resident_guest_probe_asm();
    fn matrixhv_resident_boot_run_asm(
        context: *mut ResidentBootContext,
        host_rsp: u64,
        host_rip: u64,
    ) -> u64;
}

unsafe extern "C" {
    static matrixhv_resident_island_start: u8;
    static matrixhv_resident_island_entry: u8;
    static matrixhv_resident_island_fatal: u8;
    static matrixhv_resident_island_gp: u8;
    static matrixhv_resident_exception_stubs: u8;
    static matrixhv_resident_island_event_context: u8;
    static matrixhv_resident_island_log_backend: u8;
    static matrixhv_resident_island_msr_switch_count: u8;
    static matrixhv_resident_island_visual_callback: u8;
    static matrixhv_resident_ebs_callback: u8;
    static matrixhv_resident_va_callback: u8;
    static matrixhv_resident_dispatch_entry: u8;
    static matrixhv_resident_island_end: u8;
}

global_asm!(
    include_str!("../asm/ap_startup.S"),
    include_str!("../asm/ept_cache.S"),
    include_str!("../asm/resident_island.S"),
    host_rsp = const HOST_RSP,
    host_rip = const HOST_RIP,
    b_root_rsp = const BCTX_ROOT_RSP,
    b_return_rip = const BCTX_RETURN_RIP,
    b_gdtr = const BCTX_ORIGINAL_GDTR,
    b_idtr = const BCTX_ORIGINAL_IDTR,
    b_fx = const BCTX_ROOT_FX_STATE,
    b_ap_started = const core::mem::offset_of!(ResidentBootContext, ap_started),
    b_processor_number = const core::mem::offset_of!(ResidentBootContext, processor_number),
    b_init_count = const core::mem::offset_of!(ResidentBootContext, init_count),
    b_sipi_count = const core::mem::offset_of!(ResidentBootContext, sipi_count),
    b_cache_ept_pointer = const core::mem::offset_of!(ResidentBootContext, cache_ept_pointer),
    b_cache_generation = const core::mem::offset_of!(ResidentBootContext, cache_generation),
    b_mtrr_dirty = const core::mem::offset_of!(ResidentBootContext, mtrr_dirty),
    b_mtrr_updates = const core::mem::offset_of!(ResidentBootContext, mtrr_updates),
    b_nmi_pending = const core::mem::offset_of!(ResidentBootContext, nmi_pending),
    b_nmi_count = const core::mem::offset_of!(ResidentBootContext, nmi_count),
    pin_based_vm_exec_control = const PIN_BASED_VM_EXEC_CONTROL,
    cpu_based_vm_exec_control = const CPU_BASED_VM_EXEC_CONTROL,
    virtual_apic_page_addr = const VIRTUAL_APIC_PAGE_ADDR,
    tpr_threshold = const TPR_THRESHOLD,
    secondary_vm_exec_control = const SECONDARY_VM_EXEC_CONTROL,
    xss_exiting_bitmap = const XSS_EXITING_BITMAP,
    vm_exit_controls = const VM_EXIT_CONTROLS,
    io_bitmap_a = const IO_BITMAP_A,
    io_bitmap_b = const IO_BITMAP_B,
    cr0_guest_host_mask = const CR0_GUEST_HOST_MASK,
    cr0_read_shadow = const CR0_READ_SHADOW,
    cr4_guest_host_mask = const CR4_GUEST_HOST_MASK,
    cr4_read_shadow = const CR4_READ_SHADOW,
    cr4_vmxe = const arch::CR4_VMXE,
    guest_activity_state = const GUEST_ACTIVITY_STATE,
    guest_cr0 = const GUEST_CR0,
    guest_pdptr0 = const GUEST_PDPTR0,
    guest_pdptr1 = const GUEST_PDPTR1,
    guest_pdptr2 = const GUEST_PDPTR2,
    guest_pdptr3 = const GUEST_PDPTR3,
    guest_cs_ar_bytes = const GUEST_CS_AR_BYTES,
    guest_cs_base = const GUEST_CS_BASE,
    guest_cs_limit = const GUEST_CS_LIMIT,
    guest_cs_selector = const GUEST_CS_SELECTOR,
    guest_dr7 = const GUEST_DR7,
    guest_ds_ar_bytes = const GUEST_DS_AR_BYTES,
    guest_ds_base = const GUEST_DS_BASE,
    guest_ds_limit = const GUEST_DS_LIMIT,
    guest_ds_selector = const GUEST_DS_SELECTOR,
    guest_es_ar_bytes = const GUEST_ES_AR_BYTES,
    guest_es_base = const GUEST_ES_BASE,
    guest_es_limit = const GUEST_ES_LIMIT,
    guest_es_selector = const GUEST_ES_SELECTOR,
    guest_fs_ar_bytes = const GUEST_FS_AR_BYTES,
    guest_fs_limit = const GUEST_FS_LIMIT,
    guest_fs_selector = const GUEST_FS_SELECTOR,
    guest_gdtr_base = const GUEST_GDTR_BASE,
    guest_gdtr_limit = const GUEST_GDTR_LIMIT,
    guest_gs_ar_bytes = const GUEST_GS_AR_BYTES,
    guest_gs_limit = const GUEST_GS_LIMIT,
    guest_gs_selector = const GUEST_GS_SELECTOR,
    guest_ia32_debugctl = const GUEST_IA32_DEBUGCTL,
    guest_pat = const GUEST_IA32_PAT,
    guest_idtr_base = const GUEST_IDTR_BASE,
    guest_idtr_limit = const GUEST_IDTR_LIMIT,
    guest_interruptibility_info = const GUEST_INTERRUPTIBILITY_INFO,
    guest_ldtr_ar_bytes = const GUEST_LDTR_AR_BYTES,
    guest_ldtr_base = const GUEST_LDTR_BASE,
    guest_ldtr_limit = const GUEST_LDTR_LIMIT,
    guest_ldtr_selector = const GUEST_LDTR_SELECTOR,
    guest_pending_dbg_exceptions = const GUEST_PENDING_DBG_EXCEPTIONS,
    guest_rflags = const GUEST_RFLAGS,
    guest_rsp = const GUEST_RSP,
    guest_ss_ar_bytes = const GUEST_SS_AR_BYTES,
    guest_ss_base = const GUEST_SS_BASE,
    guest_ss_limit = const GUEST_SS_LIMIT,
    guest_ss_selector = const GUEST_SS_SELECTOR,
    guest_tr_ar_bytes = const GUEST_TR_AR_BYTES,
    guest_tr_base = const GUEST_TR_BASE,
    guest_tr_limit = const GUEST_TR_LIMIT,
    guest_tr_selector = const GUEST_TR_SELECTOR,
    vm_entry_controls = const VM_ENTRY_CONTROLS,
    vm_entry_intr_info_field = const VM_ENTRY_INTR_INFO_FIELD,
    vm_entry_exception_error_code = const VM_ENTRY_EXCEPTION_ERROR_CODE,
    vm_entry_instruction_len = const VM_ENTRY_INSTRUCTION_LEN,
    vmcs_link_pointer = const VMCS_LINK_POINTER,
    exception_bitmap = const EXCEPTION_BITMAP,
    page_fault_error_code_mask = const PAGE_FAULT_ERROR_CODE_MASK,
    page_fault_error_code_match = const PAGE_FAULT_ERROR_CODE_MATCH,
    guest_cr3 = const GUEST_CR3,
    guest_efer = const GUEST_IA32_EFER,
    guest_gs_base = const GUEST_GS_BASE,
    guest_fs_base = const GUEST_FS_BASE,
    guest_sysenter_cs = const GUEST_SYSENTER_CS,
    guest_sysenter_esp = const GUEST_SYSENTER_ESP,
    guest_sysenter_eip = const GUEST_SYSENTER_EIP,
    tsc_offset = const TSC_OFFSET,
    ept_pointer = const EPT_POINTER,
    msr_bitmap = const MSR_BITMAP,
    guest_cr4 = const GUEST_CR4,
    vm_exit_msr_store_addr = const VM_EXIT_MSR_STORE_ADDR,
    vm_exit_msr_load_addr = const VM_EXIT_MSR_LOAD_ADDR,
    vm_entry_msr_load_addr = const VM_ENTRY_MSR_LOAD_ADDR,
    vm_exit_msr_store_count = const VM_EXIT_MSR_STORE_COUNT,
    vm_exit_msr_load_count = const VM_EXIT_MSR_LOAD_COUNT,
    vm_entry_msr_load_count = const VM_ENTRY_MSR_LOAD_COUNT,
    guest_rip = const GUEST_RIP,
    guest_physical_address = const GUEST_PHYSICAL_ADDRESS,
    guest_linear_address = const GUEST_LINEAR_ADDRESS,
    exit_reason = const VM_EXIT_REASON,
    exit_intr_info = const VM_EXIT_INTR_INFO,
    exit_intr_error_code = const VM_EXIT_INTR_ERROR_CODE,
    idt_vectoring_info_field = const IDT_VECTORING_INFO_FIELD,
    idt_vectoring_error_code = const IDT_VECTORING_ERROR_CODE,
    exit_instruction_len = const VM_EXIT_INSTRUCTION_LEN,
    exit_instruction_info = const VM_EXIT_INSTRUCTION_INFO,
    exit_qualification = const EXIT_QUALIFICATION,
    vm_instruction_error = const VM_INSTRUCTION_ERROR,
    complete = const CONTEXT_COMPLETE,
    boot_canary_start = const BOOT_CONTEXT_CANARY_START,
    boot_canary_end = const BOOT_CONTEXT_CANARY_END,
    event_magic = const EVENT_CONTEXT_MAGIC,
    event_canary = const EVENT_CONTEXT_CANARY,
    ept_violation_reason = const EPT_VIOLATION_EXIT_REASON,
    vm_entry_failure_msr_loading_reason = const VM_ENTRY_FAILURE_MSR_LOADING_EXIT_REASON,
    ept_test_read_access = const EPT_TEST_READ_ACCESS,
    vmclear_reason = const VMCLEAR_EXIT_REASON,
    vmlaunch_reason = const VMLAUNCH_EXIT_REASON,
    vmptrld_reason = const VMPTRLD_EXIT_REASON,
    vmptrst_reason = const VMPTRST_EXIT_REASON,
    vmread_reason = const VMREAD_EXIT_REASON,
    vmresume_reason = const VMRESUME_EXIT_REASON,
    vmwrite_reason = const VMWRITE_EXIT_REASON,
    vmxon_reason = const VMXON_EXIT_REASON,
    vmxoff_reason = const VMXOFF_EXIT_REASON,
    invept_reason = const INVEPT_EXIT_REASON,
    invvpid_reason = const INVVPID_EXIT_REASON,
    cpuid_reason = const CPUID_EXIT_REASON,
    vmcall_reason = const VMCALL_EXIT_REASON,
    rdmsr_reason = const RDMSR_EXIT_REASON,
    wrmsr_reason = const WRMSR_EXIT_REASON,
    xss_msr = const IA32_XSS_MSR,
    xsetbv_reason = const XSETBV_EXIT_REASON,
    tsc_msr = const IA32_TSC_MSR,
    spec_ctrl_msr = const IA32_SPEC_CTRL_MSR,
    platform_id_msr = const IA32_PLATFORM_ID_MSR,
    apic_base_msr = const IA32_APIC_BASE_MSR,
    feature_control_msr = const IA32_FEATURE_CONTROL_MSR,
    vmx_basic_msr = const IA32_VMX_BASIC_MSR,
    vmx_pinbased_ctls_msr = const IA32_VMX_PINBASED_CTLS_MSR,
    vmx_procbased_ctls_msr = const IA32_VMX_PROCBASED_CTLS_MSR,
    vmx_exit_ctls_msr = const IA32_VMX_EXIT_CTLS_MSR,
    vmx_entry_ctls_msr = const IA32_VMX_ENTRY_CTLS_MSR,
    vmx_misc_msr = const IA32_VMX_MISC_MSR,
    vmx_cr0_fixed0_msr = const IA32_VMX_CR0_FIXED0_MSR,
    vmx_cr0_fixed1_msr = const IA32_VMX_CR0_FIXED1_MSR,
    vmx_cr4_fixed0_msr = const IA32_VMX_CR4_FIXED0_MSR,
    vmx_cr4_fixed1_msr = const IA32_VMX_CR4_FIXED1_MSR,
    vmx_vmcs_enum_msr = const IA32_VMX_VMCS_ENUM_MSR,
    vmx_procbased_ctls2_msr = const IA32_VMX_PROCBASED_CTLS2_MSR,
    vmx_ept_vpid_cap_msr = const IA32_VMX_EPT_VPID_CAP_MSR,
    vmx_true_pinbased_ctls_msr = const IA32_VMX_TRUE_PINBASED_CTLS_MSR,
    vmx_true_procbased_ctls_msr = const IA32_VMX_TRUE_PROCBASED_CTLS_MSR,
    vmx_true_exit_ctls_msr = const IA32_VMX_TRUE_EXIT_CTLS_MSR,
    vmx_true_entry_ctls_msr = const IA32_VMX_TRUE_ENTRY_CTLS_MSR,
    bios_sign_id_msr = const IA32_BIOS_SIGN_ID_MSR,
    mtrrcap_msr = const IA32_MTRRCAP_MSR,
    pkg_energy_status_msr = const MSR_PKG_ENERGY_STATUS,
    rapl_power_unit_msr = const MSR_RAPL_POWER_UNIT,
    dram_energy_status_msr = const MSR_DRAM_ENERGY_STATUS,
    pp0_energy_status_msr = const MSR_PP0_ENERGY_STATUS,
    pp1_energy_status_msr = const MSR_PP1_ENERGY_STATUS,
    x2apic_msr_base = const IA32_X2APIC_MSR_BASE,
    x2apic_msr_end = const IA32_X2APIC_MSR_END,
    sysenter_cs_msr = const IA32_SYSENTER_CS_MSR,
    sysenter_esp_msr = const IA32_SYSENTER_ESP_MSR,
    sysenter_eip_msr = const IA32_SYSENTER_EIP_MSR,
    mtrr_physbase0_msr = const IA32_MTRR_PHYSBASE0_MSR,
    mtrr_fix64k_00000_msr = const IA32_MTRR_FIX64K_00000_MSR,
    mtrr_fix16k_80000_msr = const IA32_MTRR_FIX16K_80000_MSR,
    mtrr_fix16k_a0000_msr = const IA32_MTRR_FIX16K_A0000_MSR,
    mtrr_fix4k_c0000_msr = const IA32_MTRR_FIX4K_C0000_MSR,
    mtrr_fix4k_f8000_msr = const IA32_MTRR_FIX4K_F8000_MSR,
    mtrr_def_type_msr = const IA32_MTRR_DEF_TYPE_MSR,
    hyperv_guest_os_id_msr = const HYPERV_GUEST_OS_ID_MSR,
    hyperv_features_leaf = const HYPERV_FEATURES_LEAF,
    hypervisor_leaf_start = const HYPERVISOR_LEAF_START,
    hypervisor_leaf_end = const HYPERVISOR_LEAF_END,
    hyperv_guest_idle_access_mask = const HYPERV_GUEST_IDLE_ACCESS_MASK,
    hyperv_guest_idle_feature_mask = const HYPERV_GUEST_IDLE_FEATURE_MASK,
    hyperv_hypercall_msr = const HYPERV_HYPERCALL_MSR,
    hyperv_vp_index_msr = const HYPERV_VP_INDEX_MSR,
    hyperv_simp_msr = const HYPERV_SIMP_MSR,
    hyperv_sint3_msr = const HYPERV_SINT3_MSR,
    hyperv_stimer0_config_msr = const HYPERV_STIMER0_CONFIG_MSR,
    hyperv_stimer0_count_msr = const HYPERV_STIMER0_COUNT_MSR,
    hyperv_reference_tsc_msr = const HYPERV_REFERENCE_TSC_MSR,
    hyperv_reference_time_msr_span = const HYPERV_REFERENCE_TIME_MSR_SPAN,
    hyperv_vp_assist_msr = const HYPERV_VP_ASSIST_MSR,
    efer_msr = const IA32_EFER_MSR,
    amd_sev_status_msr = const AMD_SEV_STATUS_MSR,
    gs_base_msr = const IA32_GS_BASE_MSR,
    fs_base_msr = const IA32_FS_BASE_MSR,
    kernel_gs_base_msr = const IA32_KERNEL_GS_BASE_MSR,
    tsc_aux_msr = const IA32_TSC_AUX_MSR,
    star_msr = const IA32_STAR_MSR,
    lstar_msr = const IA32_LSTAR_MSR,
    cstar_msr = const IA32_CSTAR_MSR,
    fmask_msr = const IA32_FMASK_MSR,
    cpuid_vmx_clear_mask = const !CPUID_VMX_BIT,
    cpuid_vmx_set_mask = const CPUID_VMX_BIT,
    cpuid_osxsave_set_mask = const CPUID_OSXSAVE_BIT,
    cpuid_osxsave_clear_mask = const !CPUID_OSXSAVE_BIT,
    cpuid_hypervisor_set_mask = const CPUID_HYPERVISOR_PRESENT_BIT,
    cpuid_hypervisor_clear_mask = const !CPUID_HYPERVISOR_PRESENT_BIT,
    matrixhv_status_leaf = const MATRIXHV_STATUS_LEAF,
    matrixhv_status_signature_eax = const MATRIXHV_STATUS_SIGNATURE_EAX,
    matrixhv_status_signature_ebx = const MATRIXHV_STATUS_SIGNATURE_EBX,
    matrixhv_status_signature_ecx = const MATRIXHV_STATUS_SIGNATURE_ECX,
    matrixhv_status_protocol = const MATRIXHV_STATUS_PROTOCOL,
    vmxon_in_vmx_root_error = const VMXON_IN_VMX_ROOT_ERROR,
    vmclear_invalid_physical_address_error = const VMCLEAR_INVALID_PHYSICAL_ADDRESS_ERROR,
    vmclear_vmxon_pointer_error = const VMCLEAR_VMXON_POINTER_ERROR,
    vm_entry_invalid_control_fields_error = const VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR,
    vm_entry_invalid_host_state_field_error = const VM_ENTRY_INVALID_HOST_STATE_FIELD_ERROR,
    vm_entry_blocked_by_mov_ss_error = const VM_ENTRY_BLOCKED_BY_MOV_SS_ERROR,
    invalid_invalidation_operand_error = const INVALID_OPERAND_TO_INVEPT_INVVPID_ERROR,
    vmlaunch_non_clear_vmcs_error = const VMLAUNCH_NON_CLEAR_VMCS_ERROR,
    vmptrld_invalid_physical_address_error = const VMPTRLD_INVALID_PHYSICAL_ADDRESS_ERROR,
    vmptrld_vmxon_pointer_error = const VMPTRLD_VMXON_POINTER_ERROR,
    vmptrld_incorrect_revision_error = const VMPTRLD_INCORRECT_REVISION_ERROR,
    vmresume_non_launched_vmcs_error = const VMRESUME_NON_LAUNCHED_VMCS_ERROR,
    vmcs_unsupported_component_error = const VMCS_UNSUPPORTED_COMPONENT_ERROR,
    vmwrite_read_only_component_error = const VMWRITE_READ_ONLY_COMPONENT_ERROR,
    vmx_status_flags_clear_mask = const VMX_STATUS_FLAGS_CLEAR_MASK,
    vmfail_invalid_status = const VMFAIL_INVALID_STATUS,
    vmfail_valid_status = const VMFAIL_VALID_STATUS,
    nested_guest_msr_list_capacity = const NESTED_GUEST_MSR_LIST_CAPACITY,
    nested_msr_bitmap_qword_count = const NESTED_MSR_BITMAP_QWORD_COUNT,
    host_page_address_mask = const HOST_PAGE_ADDRESS_MASK,
    cr4_osxsave_mask = const 1_u64 << 18,
    start_checkpoint_magic = const RESIDENT_VMCALL_START_CHECKPOINT,
    stop_magic = const RESIDENT_VMCALL_STOP,
    nested_probe_failed_magic = const RESIDENT_VMCALL_NESTED_PROBE_FAILED,
    vmware_hypervisor_magic = const VMWARE_HYPERVISOR_MAGIC,
    vmware_hypervisor_port = const VMWARE_HYPERVISOR_PORT,
    unsupported_stop = const RESIDENT_STOP_UNSUPPORTED_EXIT,
    b_serial_lock = const BCTX_SERIAL_LOCK,
    b_expected_host_cr3 = const BCTX_EXPECTED_HOST_CR3,
    b_event_context = const BCTX_EVENT_CONTEXT,
    b_ept_test_gpa = const BCTX_EPT_TEST_GPA,
    b_ept_probe_fault_rip = const BCTX_EPT_PROBE_FAULT_RIP,
    b_ept_probe_resume_rip = const BCTX_EPT_PROBE_RESUME_RIP,
    b_ept_test_violation_seen = const BCTX_EPT_TEST_VIOLATION_SEEN,
    b_exit_count = const BCTX_EXIT_COUNT,
    b_telemetry_enabled = const core::mem::offset_of!(ResidentBootContext, telemetry_enabled),
    b_telemetry_active = const core::mem::offset_of!(ResidentBootContext, telemetry_active),
    b_telemetry_probe_active = const core::mem::offset_of!(ResidentBootContext, telemetry_probe_active),
    b_watchdog_tsc_hz = const core::mem::offset_of!(ResidentBootContext, watchdog_tsc_hz),
    b_watchdog_deadline = const core::mem::offset_of!(ResidentBootContext, watchdog_deadline_tsc),
    b_watchdog_sequence = const core::mem::offset_of!(ResidentBootContext, watchdog_sequence),
    b_watchdog_exit_count = const core::mem::offset_of!(ResidentBootContext, watchdog_exit_count),
    b_watchdog_phase = const core::mem::offset_of!(ResidentBootContext, watchdog_phase),
    b_watchdog_handler_returns = const core::mem::offset_of!(ResidentBootContext, watchdog_handler_returns),
    b_watchdog_resume_failures = const core::mem::offset_of!(ResidentBootContext, watchdog_resume_failures),
    b_watchdog_last_reason = const core::mem::offset_of!(ResidentBootContext, watchdog_last_reason),
    b_watchdog_last_rip = const core::mem::offset_of!(ResidentBootContext, watchdog_last_rip),
    b_entry_failure_state = const core::mem::offset_of!(ResidentBootContext, entry_failure_state),
    b_entry_failure_exit = const core::mem::offset_of!(ResidentBootContext, entry_failure_exit),
    b_entry_failure_tsc = const core::mem::offset_of!(ResidentBootContext, entry_failure_tsc),
    b_entry_failure_guest = const core::mem::offset_of!(ResidentBootContext, entry_failure),
    b_watchdog_before = const core::mem::offset_of!(ResidentBootContext, last_before),
    b_watchdog_after = const core::mem::offset_of!(ResidentBootContext, last_after_handler),
    b_watchdog_resume = const core::mem::offset_of!(ResidentBootContext, last_resume),
    b_ept_violation_read = const core::mem::offset_of!(ResidentBootContext, ept_violation_read),
    b_ept_violation_write = const core::mem::offset_of!(ResidentBootContext, ept_violation_write),
    b_ept_violation_execute = const core::mem::offset_of!(ResidentBootContext, ept_violation_execute),
    b_cr3_exits = const core::mem::offset_of!(ResidentBootContext, cr3_exits),
    b_eptp_switches = const core::mem::offset_of!(ResidentBootContext, eptp_switches),
    b_mtf_exits = const core::mem::offset_of!(ResidentBootContext, mtf_exits),
    b_invept_exits = const core::mem::offset_of!(ResidentBootContext, invept_exits),
    b_preemption_timer_exits = const core::mem::offset_of!(ResidentBootContext, preemption_timer_exits),
    b_cpuid_count = const BCTX_CPUID_COUNT,
    b_rdmsr_count = const BCTX_RDMSR_COUNT,
    b_wrmsr_count = const BCTX_WRMSR_COUNT,
    b_xsetbv_count = const BCTX_XSETBV_COUNT,
    b_vmcall_count = const BCTX_VMCALL_COUNT,
    b_start_checkpoint_seen = const BCTX_START_CHECKPOINT_SEEN,
    b_visual_first_exit_seen = const BCTX_VISUAL_FIRST_EXIT_SEEN,
    b_post_start_count = const BCTX_POST_START_COUNT,
    b_post_ebs_count = const BCTX_POST_EBS_COUNT,
    b_post_va_count = const BCTX_POST_VA_COUNT,
    b_msr_gp_count = const BCTX_MSR_GP_COUNT,
    b_last_gp_msr = const BCTX_LAST_GP_MSR,
    b_diagnostic_interval = const BCTX_DIAGNOSTIC_INTERVAL,
    log_serial_sink = const crate::runtime::SERIAL_SINK,
    log_framebuffer_sink = const crate::runtime::FRAMEBUFFER_SINK,
    serial_port = const crate::runtime::COM1,
    serial_status_port = const crate::runtime::COM1 + 5,
    serial_transmit_empty = const crate::runtime::TRANSMIT_EMPTY,
    serial_wait_limit = const crate::runtime::TX_WAIT_LIMIT,
    b_diagnostic_rate = const BCTX_DIAGNOSTIC_RATE,
    b_diagnostic_deadline = const BCTX_DIAGNOSTIC_DEADLINE,
    b_diagnostic_samples = const BCTX_DIAGNOSTIC_SAMPLES,
    b_diagnostic_expired = const BCTX_DIAGNOSTIC_EXPIRED,
    b_last_normal_reason = const BCTX_LAST_NORMAL_REASON,
    b_last_normal_rip = const BCTX_LAST_NORMAL_RIP,
    b_last_efer_write = const BCTX_LAST_EFER_WRITE,
    preemption_timer_reason = const VMX_PREEMPTION_TIMER_EXIT_REASON,
    vmx_preemption_timer_value = const VMX_PREEMPTION_TIMER_VALUE,
    b_last_reason = const BCTX_LAST_REASON,
    b_last_instruction_len = const BCTX_LAST_INSTRUCTION_LEN,
    b_last_qualification = const BCTX_LAST_QUALIFICATION,
    b_last_guest_physical_address = const BCTX_LAST_GUEST_PHYSICAL_ADDRESS,
    b_last_rax = const BCTX_LAST_GUEST_RAX,
    b_last_rcx = const BCTX_LAST_GUEST_RCX,
    b_last_rdx = const BCTX_LAST_GUEST_RDX,
    b_last_guest_rip = const BCTX_LAST_GUEST_RIP,
    b_last_guest_cr3 = const BCTX_LAST_GUEST_CR3,
    b_last_host_cr3 = const BCTX_LAST_HOST_CR3,
    b_stop_result = const BCTX_STOP_RESULT,
    b_canary_start = const BCTX_CANARY_START,
    b_canary_end = const BCTX_CANARY_END,
    b_cpuid_presence = const BCTX_CPUID_PRESENCE,
    b_cpuid_leaf1_count = const BCTX_CPUID_LEAF1_COUNT,
    b_cpuid_hypervisor_count = const BCTX_CPUID_HYPERVISOR_COUNT,
    b_cpuid_leaf1_ecx = const BCTX_CPUID_LEAF1_ECX,
    b_cpuid_hypervisor_eax = const BCTX_CPUID_HYPERVISOR_EAX,
    b_nested_feature_control = const BCTX_NESTED_FEATURE_CONTROL,
    b_nested_vmx_basic = const BCTX_NESTED_VMX_BASIC,
    b_nested_vmx_pinbased_ctls = const BCTX_NESTED_VMX_PINBASED_CTLS,
    b_nested_vmx_procbased_ctls = const BCTX_NESTED_VMX_PROCBASED_CTLS,
    b_nested_vmx_exit_ctls = const BCTX_NESTED_VMX_EXIT_CTLS,
    b_nested_vmx_entry_ctls = const BCTX_NESTED_VMX_ENTRY_CTLS,
    b_nested_vmx_misc = const BCTX_NESTED_VMX_MISC,
    b_nested_vmx_cr0_fixed0 = const BCTX_NESTED_VMX_CR0_FIXED0,
    b_nested_vmx_cr0_fixed1 = const BCTX_NESTED_VMX_CR0_FIXED1,
    b_nested_vmx_cr4_fixed0 = const BCTX_NESTED_VMX_CR4_FIXED0,
    b_nested_vmx_cr4_fixed1 = const BCTX_NESTED_VMX_CR4_FIXED1,
    b_nested_vmx_vmcs_enum = const BCTX_NESTED_VMX_VMCS_ENUM,
    b_nested_vmx_procbased_ctls2 = const BCTX_NESTED_VMX_PROCBASED_CTLS2,
    b_nested_vmx_ept_vpid_cap = const BCTX_NESTED_VMX_EPT_VPID_CAP,
    b_nested_vmx_true_pinbased_ctls = const BCTX_NESTED_VMX_TRUE_PINBASED_CTLS,
    b_nested_vmx_true_procbased_ctls = const BCTX_NESTED_VMX_TRUE_PROCBASED_CTLS,
    b_nested_vmx_true_exit_ctls = const BCTX_NESTED_VMX_TRUE_EXIT_CTLS,
    b_nested_vmx_true_entry_ctls = const BCTX_NESTED_VMX_TRUE_ENTRY_CTLS,
    b_nested_expose_vmx = const BCTX_NESTED_EXPOSE_VMX,
    b_nested_l1_cr4 = const BCTX_NESTED_L1_CR4,
    b_nested_vmxon_operand = const BCTX_NESTED_VMXON_OPERAND,
    b_nested_vmxon_region = const BCTX_NESTED_VMXON_REGION,
    b_nested_current_vmcs = const BCTX_NESTED_CURRENT_VMCS,
    b_nested_last_operand = const BCTX_NESTED_LAST_OPERAND,
    b_nested_instruction_error = const BCTX_NESTED_INSTRUCTION_ERROR,
    b_nested_vmxon_count = const BCTX_NESTED_VMXON_COUNT,
    b_nested_vmxoff_count = const BCTX_NESTED_VMXOFF_COUNT,
    b_nested_failure_count = const BCTX_NESTED_FAILURE_COUNT,
    b_nested_active = const BCTX_NESTED_ACTIVE,
    b_nested_probe_complete = const BCTX_NESTED_PROBE_COMPLETE,
    b_nested_vmcs12_operand = const BCTX_NESTED_VMCS12_OPERAND,
    b_nested_vmcs12_region = const BCTX_NESTED_VMCS12_REGION,
    b_nested_vmptrst_destination = const BCTX_NESTED_VMPTRST_DESTINATION,
    b_nested_last_stored_pointer = const BCTX_NESTED_LAST_STORED_POINTER,
    b_nested_vmcs12_revision_id = const BCTX_NESTED_VMCS12_REVISION_ID,
    b_nested_vmcs12_launch_state = const BCTX_NESTED_VMCS12_LAUNCH_STATE,
    b_nested_vmcs12_guest_rip = const BCTX_NESTED_VMCS12_GUEST_RIP,
    b_nested_vmcs12_guest_rsp = const BCTX_NESTED_VMCS12_GUEST_RSP,
    b_nested_vmcs12_guest_rflags = const BCTX_NESTED_VMCS12_GUEST_RFLAGS,
    b_nested_vmcs12_host_rsp = const BCTX_NESTED_VMCS12_HOST_RSP,
    b_nested_vmcs12_host_rip = const BCTX_NESTED_VMCS12_HOST_RIP,
    b_nested_vmcs12_exit_reason = const BCTX_NESTED_VMCS12_EXIT_REASON,
    b_nested_vmcs12_exit_instruction_len = const BCTX_NESTED_VMCS12_EXIT_INSTRUCTION_LEN,
    b_nested_vmcs12_exit_instruction_info = const BCTX_NESTED_VMCS12_EXIT_INSTRUCTION_INFO,
    b_nested_vmcs12_exit_qualification = const BCTX_NESTED_VMCS12_EXIT_QUALIFICATION,
    b_nested_vmcs12_extended_fields = const BCTX_NESTED_VMCS12_EXTENDED_FIELDS,
    b_nested_vmcs12_vpid = const BCTX_NESTED_VMCS12_VPID,
    b_nested_vmcs12_pin_based_control = const BCTX_NESTED_VMCS12_PIN_BASED_CONTROL,
    b_nested_vmcs12_primary_control = const BCTX_NESTED_VMCS12_PRIMARY_CONTROL,
    b_nested_vmcs12_secondary_control = const BCTX_NESTED_VMCS12_SECONDARY_CONTROL,
    b_nested_vmcs12_exception_bitmap = const BCTX_NESTED_VMCS12_EXCEPTION_BITMAP,
    b_nested_vmcs12_pf_error_mask = const BCTX_NESTED_VMCS12_PF_ERROR_MASK,
    b_nested_vmcs12_pf_error_match = const BCTX_NESTED_VMCS12_PF_ERROR_MATCH,
    b_nested_vmcs12_cr3_target_count = const BCTX_NESTED_VMCS12_CR3_TARGET_COUNT,
    b_nested_vmcs12_vm_exit_controls = const BCTX_NESTED_VMCS12_VM_EXIT_CONTROLS,
    b_nested_vmcs12_vm_exit_msr_store_count = const BCTX_NESTED_VMCS12_VM_EXIT_MSR_STORE_COUNT,
    b_nested_vmcs12_vm_exit_msr_load_count = const BCTX_NESTED_VMCS12_VM_EXIT_MSR_LOAD_COUNT,
    b_nested_vmcs12_vm_entry_controls = const BCTX_NESTED_VMCS12_VM_ENTRY_CONTROLS,
    b_nested_vmcs12_vm_entry_msr_load_count = const BCTX_NESTED_VMCS12_VM_ENTRY_MSR_LOAD_COUNT,
    b_nested_vmcs12_vm_entry_intr_info = const BCTX_NESTED_VMCS12_VM_ENTRY_INTR_INFO,
    b_nested_vmcs12_vm_entry_exception_error = const BCTX_NESTED_VMCS12_VM_ENTRY_EXCEPTION_ERROR,
    b_nested_vmcs12_vm_entry_instruction_len = const BCTX_NESTED_VMCS12_VM_ENTRY_INSTRUCTION_LEN,
    b_nested_vmcs12_vm_exit_intr_info = const BCTX_NESTED_VMCS12_VM_EXIT_INTR_INFO,
    b_nested_vmcs12_vm_exit_intr_error = const BCTX_NESTED_VMCS12_VM_EXIT_INTR_ERROR,
    b_nested_vmcs12_idt_vectoring_info = const BCTX_NESTED_VMCS12_IDT_VECTORING_INFO,
    b_nested_vmcs12_idt_vectoring_error = const BCTX_NESTED_VMCS12_IDT_VECTORING_ERROR,
    b_nested_vmcs12_ept_pointer = const BCTX_NESTED_VMCS12_EPT_POINTER,
    b_nested_vmcs12_tsc_offset = const BCTX_NESTED_VMCS12_TSC_OFFSET,
    b_nested_vmcs12_guest_physical_address = const BCTX_NESTED_VMCS12_GUEST_PHYSICAL_ADDRESS,
    b_nested_vmcs12_cr0_mask = const BCTX_NESTED_VMCS12_CR0_MASK,
    b_nested_vmcs12_cr4_mask = const BCTX_NESTED_VMCS12_CR4_MASK,
    b_nested_vmcs12_cr0_shadow = const BCTX_NESTED_VMCS12_CR0_SHADOW,
    b_nested_vmcs12_cr4_shadow = const BCTX_NESTED_VMCS12_CR4_SHADOW,
    b_nested_vmcs12_msr_bitmap = const BCTX_NESTED_VMCS12_MSR_BITMAP,
    b_nested_vmcs12_io_bitmap_a = const BCTX_NESTED_VMCS12_IO_BITMAP_A,
    b_nested_vmcs12_io_bitmap_b = const BCTX_NESTED_VMCS12_IO_BITMAP_B,
    b_nested_vmcs12_tpr_threshold = const BCTX_NESTED_VMCS12_TPR_THRESHOLD,
    b_nested_vmcs12_virtual_apic_page = const BCTX_NESTED_VMCS12_VIRTUAL_APIC_PAGE,
    b_nested_vmcs12_xss_exiting_bitmap = const BCTX_NESTED_VMCS12_XSS_EXITING_BITMAP,
    b_nested_vmcs12_vm_exit_msr_store_addr = const BCTX_NESTED_VMCS12_VM_EXIT_MSR_STORE_ADDR,
    b_nested_vmcs12_vm_exit_msr_load_addr = const BCTX_NESTED_VMCS12_VM_EXIT_MSR_LOAD_ADDR,
    b_nested_vmcs12_vm_entry_msr_load_addr = const BCTX_NESTED_VMCS12_VM_ENTRY_MSR_LOAD_ADDR,
    b_nested_vmcs12_guest_cr0 = const BCTX_NESTED_VMCS12_GUEST_CR0,
    b_nested_vmcs12_guest_cr3 = const BCTX_NESTED_VMCS12_GUEST_CR3,
    b_nested_vmcs12_guest_cr4 = const BCTX_NESTED_VMCS12_GUEST_CR4,
    b_nested_vmcs12_host_cr0 = const BCTX_NESTED_VMCS12_HOST_CR0,
    b_nested_vmcs12_host_cr3 = const BCTX_NESTED_VMCS12_HOST_CR3,
    b_nested_vmcs12_host_cr4 = const BCTX_NESTED_VMCS12_HOST_CR4,
    b_nested_vmcs12_guest_sysenter_eip = const BCTX_NESTED_VMCS12_GUEST_SYSENTER_EIP,
    b_nested_vmcs12_host_sysenter_esp = const BCTX_NESTED_VMCS12_HOST_SYSENTER_ESP,
    b_nested_vmcs12_host_sysenter_eip = const BCTX_NESTED_VMCS12_HOST_SYSENTER_EIP,
    b_nested_vmcs12_control_validation_count = const BCTX_NESTED_VMCS12_CONTROL_VALIDATION_COUNT,
    b_nested_vmclear_count = const BCTX_NESTED_VMCLEAR_COUNT,
    b_nested_vmptrld_count = const BCTX_NESTED_VMPTRLD_COUNT,
    b_nested_vmptrst_count = const BCTX_NESTED_VMPTRST_COUNT,
    b_nested_vmwrite_count = const BCTX_NESTED_VMWRITE_COUNT,
    b_nested_vmread_count = const BCTX_NESTED_VMREAD_COUNT,
    b_nested_vmcs12_probe_complete = const BCTX_NESTED_VMCS12_PROBE_COMPLETE,
    b_nested_vmlaunch_count = const BCTX_NESTED_VMLAUNCH_COUNT,
    b_nested_vmresume_count = const BCTX_NESTED_VMRESUME_COUNT,
    b_nested_entry_rejection_count = const BCTX_NESTED_ENTRY_REJECTION_COUNT,
    b_nested_vmcs01_region = const BCTX_NESTED_VMCS01_REGION,
    b_nested_vmcs02_region = const BCTX_NESTED_VMCS02_REGION,
    b_nested_vmcs02_control_cache_valid = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs02_control_cache_valid),
    b_nested_vmcs02_guest_cache_valid = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs02_guest_cache_valid),
    b_nested_vmcs02_rare_state_pending = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs02_rare_state_pending),
    nested_rare_guest_fields_low = const (0xff_u64 << 35) | (0x3ff_u64 << 50),
    nested_rare_guest_fields_high = const (0xffff_u64 << 1) | (1_u64 << 28),
    b_nested_vmcs02_field_cache = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs02_field_cache),
    b_nested_vmcs02_last_vpid = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs02_last_vpid),
    b_nested_vmcs02_vpid_cache = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs02_vpid_cache),
    b_nested_physical_address_bits = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, physical_address_bits),
    b_nested_host_mapping_cache = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, host_mapping_cache),
    virtual_processor_id = const VIRTUAL_PROCESSOR_ID,
    b_nested_vmcs02_launched = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs02_launched),
    b_nested_l2_active = const BCTX_NESTED_L2_ACTIVE,
    b_nested_l2_entry_was_resume = const BCTX_NESTED_L2_ENTRY_WAS_RESUME,
    b_nested_l2_entry_count = const BCTX_NESTED_L2_ENTRY_COUNT,
    b_nested_l2_exit_count = const BCTX_NESTED_L2_EXIT_COUNT,
    b_nested_l2_last_exit_reason = const BCTX_NESTED_L2_LAST_EXIT_REASON,
    b_nested_reflected_exit_counts = const core::mem::offset_of!(ResidentBootContext, nested) + core::mem::offset_of!(NestedVmxState, reflected_exit_counts),
    b_nested_exit_started_tsc = const core::mem::offset_of!(ResidentBootContext, nested) + core::mem::offset_of!(NestedVmxState, exit_started_tsc),
    b_nested_exit_handler_cycles = const core::mem::offset_of!(ResidentBootContext, nested) + core::mem::offset_of!(NestedVmxState, exit_handler_cycles),
    b_nested_ept02_cached_mbec = const core::mem::offset_of!(ResidentBootContext, nested) + core::mem::offset_of!(NestedVmxState, ept02_cached_mbec),
    b_nested_l2_last_exit_rip = const BCTX_NESTED_L2_LAST_EXIT_RIP,
    b_nested_l2_last_exit_rsp = const BCTX_NESTED_L2_LAST_EXIT_RSP,
    b_nested_l1_reflection_count = const BCTX_NESTED_L1_REFLECTION_COUNT,
    b_nested_l2_resume_count = const BCTX_NESTED_L2_RESUME_COUNT,
    b_nested_l2_resume_exit_count = const BCTX_NESTED_L2_RESUME_EXIT_COUNT,
    b_nested_ept12_pointer = const BCTX_NESTED_EPT12_POINTER,
    b_nested_ept02_pointer = const BCTX_NESTED_EPT02_POINTER,
    b_nested_ept02_alternate_pointer = const BCTX_NESTED_EPT02_ALTERNATE_POINTER,
    b_nested_ept02_initial_pointer = const BCTX_NESTED_EPT02_INITIAL_POINTER,
    b_nested_ept02_table_pool = const BCTX_NESTED_EPT02_TABLE_POOL,
    b_nested_ept02_mbec = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_mbec),
    b_nested_ept02_cache_initialized = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_cache_initialized),
    b_nested_ept02_cached_ept12_pointer = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_cached_ept12_pointer),
    b_nested_ept02_cached_pointer = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_cached_pointer),
    b_nested_ept02_cached_table_pool = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_cached_table_pool),
    b_nested_ept02_cached_table_pool_pages = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_cached_table_pool_pages),
    b_nested_ept02_cached_table_pool_used = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_cached_table_pool_used),
    b_nested_ept02_table_pool_pages = const BCTX_NESTED_EPT02_TABLE_POOL_PAGES,
    b_nested_ept02_table_pool_used = const BCTX_NESTED_EPT02_TABLE_POOL_USED,
    b_nested_ept01_pointer = const BCTX_NESTED_EPT01_POINTER,
    b_nested_ept02_recycle_count = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_recycle_count),
    b_nested_ept02_invalidation_count = const BCTX_NESTED_EPT02_INVALIDATION_COUNT,
    b_nested_ept_target_gpa = const BCTX_NESTED_EPT_TARGET_GPA,
    b_nested_ept_composition_count = const BCTX_NESTED_EPT_COMPOSITION_COUNT,
    b_nested_ept_second_target_gpa = const BCTX_NESTED_EPT_SECOND_TARGET_GPA,
    b_nested_ept12_source_leaf = const BCTX_NESTED_EPT12_SOURCE_LEAF,
    b_nested_ept12_source_leaf_attributes = const BCTX_NESTED_EPT12_SOURCE_LEAF_ATTRIBUTES,
    b_nested_invept_count = const BCTX_NESTED_INVEPT_COUNT,
    b_nested_invept_software_count = const BCTX_NESTED_INVEPT_SOFTWARE_COUNT,
    b_nested_invvpid_count = const BCTX_NESTED_INVVPID_COUNT,
    b_nested_invvpid_software_count = const BCTX_NESTED_INVVPID_SOFTWARE_COUNT,
    b_nested_ept_probe_count = const BCTX_NESTED_EPT_PROBE_COUNT,
    b_nested_ept_observed_value = const BCTX_NESTED_EPT_OBSERVED_VALUE,
    b_nested_ept_observed_value_before_invept = const BCTX_NESTED_EPT_OBSERVED_VALUE_BEFORE_INVEPT,
    b_nested_control_merge_count = const BCTX_NESTED_CONTROL_MERGE_COUNT,
    b_nested_guest_state_sync_count = const BCTX_NESTED_GUEST_STATE_SYNC_COUNT,
    b_nested_l1_host_restore_count = const BCTX_NESTED_L1_HOST_RESTORE_COUNT,
    b_nested_last_synced_guest_cr0 = const BCTX_NESTED_LAST_SYNCED_GUEST_CR0,
    b_nested_last_synced_guest_cr3 = const BCTX_NESTED_LAST_SYNCED_GUEST_CR3,
    b_nested_last_synced_guest_cr4 = const BCTX_NESTED_LAST_SYNCED_GUEST_CR4,
    b_nested_last_restored_host_cr0 = const BCTX_NESTED_LAST_RESTORED_HOST_CR0,
    b_nested_last_restored_host_cr3 = const BCTX_NESTED_LAST_RESTORED_HOST_CR3,
    b_nested_last_restored_host_cr4 = const BCTX_NESTED_LAST_RESTORED_HOST_CR4,
    b_nested_last_synced_guest_sysenter_eip = const BCTX_NESTED_LAST_SYNCED_GUEST_SYSENTER_EIP,
    b_nested_last_restored_host_sysenter_eip = const BCTX_NESTED_LAST_RESTORED_HOST_SYSENTER_EIP,
    b_nested_inherited_l1_pat = const BCTX_NESTED_INHERITED_L1_PAT,
    b_nested_inherited_l1_efer = const BCTX_NESTED_INHERITED_L1_EFER,
    b_nested_inherited_l1_tsc_offset = const BCTX_NESTED_INHERITED_L1_TSC_OFFSET,
    b_nested_vmcs01_pin_based_controls = const BCTX_NESTED_VMCS01_PIN_BASED_CONTROLS,
    b_nested_vmcs01_primary_controls = const BCTX_NESTED_VMCS01_PRIMARY_CONTROLS,
    b_nested_vmcs01_secondary_controls = const BCTX_NESTED_VMCS01_SECONDARY_CONTROLS,
    b_nested_vmcs01_exit_controls = const BCTX_NESTED_VMCS01_EXIT_CONTROLS,
    b_nested_vmcs01_entry_controls = const BCTX_NESTED_VMCS01_ENTRY_CONTROLS,
    b_nested_l2_saved_pat = const BCTX_NESTED_L2_SAVED_PAT,
    b_nested_l2_saved_efer = const BCTX_NESTED_L2_SAVED_EFER,
    b_nested_last_merged_secondary_controls = const BCTX_NESTED_LAST_MERGED_SECONDARY_CONTROLS,
    b_nested_last_synced_guest_gs_base = const BCTX_NESTED_LAST_SYNCED_GUEST_GS_BASE,
    b_nested_last_captured_guest_gs_base = const BCTX_NESTED_LAST_CAPTURED_GUEST_GS_BASE,
    b_nested_last_restored_host_gs_base = const BCTX_NESTED_LAST_RESTORED_HOST_GS_BASE,
    b_nested_last_restored_host_cs_ar = const BCTX_NESTED_LAST_RESTORED_HOST_CS_AR,
    b_nested_l0_msr_bitmap = const BCTX_NESTED_L0_MSR_BITMAP,
    b_nested_composed_msr_bitmap = const BCTX_NESTED_COMPOSED_MSR_BITMAP,
    b_nested_l0_msr_guest_list = const BCTX_NESTED_L0_MSR_GUEST_LIST,
    b_nested_l0_msr_host_list = const BCTX_NESTED_L0_MSR_HOST_LIST,
    b_nested_vmcs02_entry_msr_list = const BCTX_NESTED_VMCS02_ENTRY_MSR_LIST,
    b_nested_vmcs02_exit_store_msr_list = const BCTX_NESTED_VMCS02_EXIT_STORE_MSR_LIST,
    b_nested_vmcs01_entry_msr_list = const BCTX_NESTED_VMCS01_ENTRY_MSR_LIST,
    b_nested_vmcs01_msr_entry_composed = const BCTX_NESTED_VMCS01_MSR_ENTRY_COMPOSED,
    b_nested_ept_observed_value_after_invept = const BCTX_NESTED_EPT_OBSERVED_VALUE_AFTER_INVEPT,
    nested_invept_descriptor_offset = const crate::smp::NESTED_INVEPT_DESCRIPTOR_OFFSET,
    nested_invept_rip_offset = const crate::smp::NESTED_INVEPT_RIP_OFFSET,
    nested_invept_after_rip_offset = const crate::smp::NESTED_INVEPT_AFTER_RIP_OFFSET,
    nested_invvpid_descriptor_offset = const crate::smp::NESTED_INVVPID_DESCRIPTOR_OFFSET,
    nested_invvpid_rip_offset = const crate::smp::NESTED_INVVPID_RIP_OFFSET,
    nested_invvpid_after_rip_offset = const crate::smp::NESTED_INVVPID_AFTER_RIP_OFFSET,
    nested_ept_target_marker = const crate::smp::NESTED_EPT_TARGET_MARKER,
    nested_ept_second_target_marker = const crate::smp::NESTED_EPT_SECOND_TARGET_MARKER,
    vmcs12_launch_state_clear = const VMCS12_LAUNCH_STATE_CLEAR,
    vmcs12_launch_state_launched = const VMCS12_LAUNCH_STATE_LAUNCHED,
    vmcs12_extended_field_count = const VMCS12_EXTENDED_FIELD_COUNT,
    vmcs12_backing_magic = const VMCS12_BACKING_MAGIC,
    vmcs12_backing_magic_offset = const VMCS12_BACKING_MAGIC_OFFSET,
    vmcs12_backing_state_offset = const VMCS12_BACKING_STATE_OFFSET,
    vmcs12_backing_qword_count = const VMCS12_BACKING_QWORD_COUNT,
    vmcs12_revision_id_offset = const core::mem::offset_of!(NestedVmcs12State, revision_id),
    vmcs12_launch_state_offset = const core::mem::offset_of!(NestedVmcs12State, launch_state),
    vmcs12_vmclear_count_offset = const core::mem::offset_of!(NestedVmcs12State, vmclear_count),
    nested_guest_state_table_count = const 50,
    nested_host_state_table_count = const 18,
    vmcs_field_exit_qualification = const VMCS_FIELD_EXIT_QUALIFICATION,
    vmcs_field_guest_rflags = const VMCS_FIELD_GUEST_RFLAGS,
    vmcs_field_guest_rip = const VMCS_FIELD_GUEST_RIP,
    vmcs_field_guest_rsp = const VMCS_FIELD_GUEST_RSP,
    vmcs_field_host_rip = const VMCS_FIELD_HOST_RIP,
    vmcs_field_host_rsp = const VMCS_FIELD_HOST_RSP,
    vmcs_field_exit_instruction_len = const VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN,
    vmcs_field_exit_instruction_info = const VMCS_FIELD_VM_EXIT_INSTRUCTION_INFO,
    vmcs_field_exit_reason = const VMCS_FIELD_VM_EXIT_REASON,
    vmcs_field_exit_intr_info = const VMCS_FIELD_VM_EXIT_INTR_INFO,
    vmcs_field_exit_intr_error = const VMCS_FIELD_VM_EXIT_INTR_ERROR_CODE,
    vmcs_field_idt_vectoring_info = const VMCS_FIELD_IDT_VECTORING_INFO_FIELD,
    vmcs_field_idt_vectoring_error = const VMCS_FIELD_IDT_VECTORING_ERROR_CODE,
    vmcs_field_guest_physical_address = const VMCS_FIELD_GUEST_PHYSICAL_ADDRESS,
    vmcs_field_guest_linear_address = const VMCS_FIELD_GUEST_LINEAR_ADDRESS,
    vmcs_field_instruction_error = const VMCS_FIELD_VM_INSTRUCTION_ERROR,
    event_magic_offset = const EVENT_CTX_MAGIC,
    event_ebs_seen = const EVENT_CTX_EBS_SEEN,
    event_va_seen = const EVENT_CTX_VA_SEEN,
    event_canary_offset = const EVENT_CTX_CANARY,
    event_visual_base = const EVENT_CTX_VISUAL_BASE,
    event_visual_stride_bytes = const EVENT_CTX_VISUAL_STRIDE_BYTES,
    event_post_ebs_cpu_mask = const EVENT_CTX_POST_EBS_CPU_MASK,
    event_diagnostic_halted = const EVENT_CTX_DIAGNOSTIC_HALTED,
    event_host_fault_vector = const EVENT_CTX_HOST_FAULT_VECTOR,
    event_cpu_contexts = const core::mem::offset_of!(ResidentEventContext, cpu_contexts),
    event_host_fault_rip = const EVENT_CTX_HOST_FAULT_RIP,
    event_host_fault_error_code = const EVENT_CTX_HOST_FAULT_ERROR_CODE,
    event_host_fault_address = const EVENT_CTX_HOST_FAULT_ADDRESS,
    event_init_cpu_mask = const core::mem::offset_of!(ResidentEventContext, init_cpu_mask),
    event_sipi_cpu_mask = const core::mem::offset_of!(ResidentEventContext, sipi_cpu_mask),
    event_halted_cpu_mask = const core::mem::offset_of!(ResidentEventContext, halted_cpu_mask),
    event_failed_processor = const core::mem::offset_of!(ResidentEventContext, failed_processor),
    event_failed_exit_reason = const core::mem::offset_of!(ResidentEventContext, failed_exit_reason),
    event_failed_qualification = const core::mem::offset_of!(ResidentEventContext, failed_qualification),
    event_failed_stop_result = const core::mem::offset_of!(ResidentEventContext, failed_stop_result),
    visual_marker_step_bytes = const crate::boot::screen::RESIDENT_MARKER_STEP * 4,
    visual_marker_row_step = const crate::boot::screen::RESIDENT_MARKER_ROW_STEP,
    visual_marker_side = const crate::boot::screen::RESIDENT_MARKER_SIZE,
    visual_hex_y = const crate::boot::screen::RESIDENT_HEX_Y,
    visual_hex_row_step = const crate::boot::screen::RESIDENT_HEX_ROW_STEP,
    visual_hex_last_row = const crate::boot::screen::RESIDENT_HEX_ROWS - 1,
    visual_hex_column_step_bytes = const crate::boot::screen::RESIDENT_HEX_COLUMN_STEP * 4,
    post_ebs_exit_message_len = const POST_EBS_EXIT_MESSAGE_LEN,
    post_va_exit_message_len = const POST_VA_EXIT_MESSAGE_LEN,
    first_start_exit_message_len = const FIRST_START_EXIT_MESSAGE_LEN,
    start_checkpoint_message_len = const START_CHECKPOINT_MESSAGE_LEN,
    start_returned_message_len = const START_RETURNED_MESSAGE_LEN,
    post_ebs_stop_message_len = const POST_EBS_STOP_MESSAGE_LEN,
    unsupported_exit_message_len = const UNSUPPORTED_EXIT_MESSAGE_LEN,
    nested_entry_failure_dump_message_len = const b"[MATRIXHV][NESTED] VM_ENTRY_FAILURE_VMCS12 ".len(),
    nested_extended_field_count = const crate::nested::VMCS12_EXTENDED_FIELD_COUNT,
    host_cr3_mismatch_message_len = const HOST_CR3_MISMATCH_MESSAGE_LEN,
    event_corrupt_message_len = const EVENT_CORRUPT_MESSAGE_LEN,
    vmread_failed_message_len = const VMREAD_FAILED_MESSAGE_LEN,
    vmwrite_failed_message_len = const VMWRITE_FAILED_MESSAGE_LEN,
    vmresume_failed_message_len = const VMRESUME_FAILED_MESSAGE_LEN,
    ept_test_violation_message_len = const EPT_TEST_VIOLATION_MESSAGE_LEN,
    ept_unexpected_violation_message_len = const EPT_UNEXPECTED_VIOLATION_MESSAGE_LEN,
    ept_violation_rip_len = const EPT_VIOLATION_RIP_LEN,
    ept_violation_read_len = const EPT_VIOLATION_READ_LEN,
    nested_vmxon_message_len = const NESTED_VMXON_MESSAGE_LEN,
    nested_vmxoff_message_len = const NESTED_VMXOFF_MESSAGE_LEN,
    nested_pointer_message_len = const NESTED_POINTER_MESSAGE_LEN,
    nested_failure_message_len = const NESTED_FAILURE_MESSAGE_LEN,
    nested_vmcs12_message_len = const NESTED_VMCS12_MESSAGE_LEN,
    nested_region_message_len = const NESTED_REGION_MESSAGE_LEN,
    nested_value_message_len = const NESTED_VALUE_MESSAGE_LEN,
    nested_l2_exit_message_len = const NESTED_L2_EXIT_MESSAGE_LEN,
    state_reason_len = const STATE_REASON_LEN,
    state_rip_len = const STATE_RIP_LEN,
    state_newline_len = const STATE_NEWLINE_LEN,
);
