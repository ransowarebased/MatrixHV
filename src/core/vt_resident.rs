use core::arch::global_asm;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use uefi::Status;
use uefi::boot::{self, EventNotifyFn, EventType, Tpl};

use super::vt_controls::{self, VmxControlsError};
use super::vt_ept::{self, EptError};
use super::vt_state;
use super::vt_vmcs::{self, VmcsError, VmcsRegion, vmwrite};
use super::vt_vmcs_fields::*;
use super::vt_vmxon::{self, VmxInstructionResult, VmxonError};
use crate::arch::x86_64::{control_regs, msr, registers, segmentation};
use crate::memory::paging::{HostAddressSpace, HostPagingError};
use crate::memory::resident::{
    AddressConstraint, PAGE_SIZE, RESIDENT_CODE_MEMORY_TYPE, RESIDENT_EVENT_MEMORY_TYPE,
    RESIDENT_MEMORY_TYPE, ResidentPages,
};
use crate::nested::capabilities::{
    CPUID_HYPERVISOR_PRESENT_BIT, CPUID_OSXSAVE_BIT, CPUID_VMX_BIT, HYPERV_FEATURES_LEAF,
    HYPERVISOR_LEAF_END, HYPERVISOR_LEAF_START, HostVmxCapabilities, IA32_VMX_BASIC_MSR,
    IA32_VMX_CR0_FIXED0_MSR, IA32_VMX_CR0_FIXED1_MSR, IA32_VMX_CR4_FIXED0_MSR,
    IA32_VMX_CR4_FIXED1_MSR, IA32_VMX_ENTRY_CTLS_MSR, IA32_VMX_EPT_VPID_CAP_MSR,
    IA32_VMX_EXIT_CTLS_MSR, IA32_VMX_MISC_MSR, IA32_VMX_PINBASED_CTLS_MSR,
    IA32_VMX_PROCBASED_CTLS_MSR, IA32_VMX_PROCBASED_CTLS2_MSR, IA32_VMX_TRUE_ENTRY_CTLS_MSR,
    IA32_VMX_TRUE_EXIT_CTLS_MSR, IA32_VMX_TRUE_PINBASED_CTLS_MSR, IA32_VMX_TRUE_PROCBASED_CTLS_MSR,
    IA32_VMX_VMCS_ENUM_MSR, MATRIXHV_STATUS_LEAF, MATRIXHV_STATUS_PROTOCOL,
    MATRIXHV_STATUS_SIGNATURE_EAX, MATRIXHV_STATUS_SIGNATURE_EBX, MATRIXHV_STATUS_SIGNATURE_ECX,
    NestedVmxCapabilities, VMX_BASIC_TRUE_CONTROLS, VMX_SECONDARY_ENABLE_EPT,
    VMX_SECONDARY_ENABLE_VPID,
};
use crate::nested::state::{NestedEptConfiguration, NestedMsrComposition, NestedVmxState};
use crate::nested::vmcs::{
    INVALID_OPERAND_TO_INVEPT_INVVPID_ERROR, INVEPT_EXIT_REASON, INVVPID_EXIT_REASON,
    NestedVmcs12State, VM_ENTRY_BLOCKED_BY_MOV_SS_ERROR, VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR,
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
    VMWRITE_EXIT_REASON, VMWRITE_READ_ONLY_COMPONENT_ERROR, VMX_STATUS_FLAGS_CLEAR_MASK,
    VMXOFF_EXIT_REASON, VMXON_EXIT_REASON, VMXON_IN_VMX_ROOT_ERROR,
};
use crate::smp::per_cpu::ResidentCpuResources;

const GUEST_STACK_PAGES: usize = 4;
pub(crate) const BOOT_GUEST_STACK_PAGES: usize = 64;
pub(crate) const HOST_STACK_PAGES: usize = 4;
const HOST_TABLE_PAGES: usize = 2;
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
const RESIDENT_MSR_SWITCH_COUNT: usize = 1;
const NESTED_MSR_BITMAP_OFFSET: u64 = 0;
const NESTED_VMCS02_ENTRY_MSR_LIST_OFFSET: u64 = PAGE_SIZE as u64;
const NESTED_VMCS02_EXIT_STORE_MSR_LIST_OFFSET: u64 = (PAGE_SIZE * 3) as u64;
const NESTED_VMCS01_ENTRY_MSR_LIST_OFFSET: u64 = (PAGE_SIZE * 5) as u64;
const NESTED_MSR_LIST_CAPACITY: usize = (PAGE_SIZE * 2) / size_of::<VmxMsrEntry>();
const NESTED_GUEST_MSR_LIST_CAPACITY: usize = NESTED_MSR_LIST_CAPACITY - RESIDENT_MSR_SWITCH_COUNT;
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
const STATE_INSTRUCTION_LEN_LEN: usize = b" len=0x".len();
const STATE_QUALIFICATION_LEN: usize = b" qual=0x".len();
const STATE_GUEST_CR3_LEN: usize = b" guest_cr3=0x".len();
const STATE_HOST_CR3_LEN: usize = b" host_cr3=0x".len();
const STATE_RAX_LEN: usize = b" rax=0x".len();
const STATE_RCX_LEN: usize = b" rcx=0x".len();
const STATE_RDX_LEN: usize = b" rdx=0x".len();
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
    exit_boot_services_seen: u64,
    virtual_address_change_seen: u64,
    canary: u64,
    serial_lock: AtomicU64,
}

#[repr(C, align(16))]
struct RootFxState([u8; 512]);

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
    post_start_exit_count: u64,
    post_ebs_exit_count: u64,
    post_va_exit_count: u64,
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
    tsc_adjust: u64,
    nested: NestedVmxState,
    original_gdtr: [u8; 10],
    original_idtr: [u8; 10],
    root_fx_state: RootFxState,
}

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
            post_start_exit_count: 0,
            post_ebs_exit_count: 0,
            post_va_exit_count: 0,
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
            cpuid_presence: u64::from(crate::boot::config::current().cpuid_presence),
            cpuid_leaf1_count: 0,
            cpuid_hypervisor_count: 0,
            cpuid_leaf1_ecx: 0,
            cpuid_hypervisor_eax: 0,
            tsc_adjust: 0,
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
const BCTX_POST_START_COUNT: usize =
    core::mem::offset_of!(ResidentBootContext, post_start_exit_count);
const BCTX_POST_EBS_COUNT: usize = core::mem::offset_of!(ResidentBootContext, post_ebs_exit_count);
const BCTX_POST_VA_COUNT: usize = core::mem::offset_of!(ResidentBootContext, post_va_exit_count);
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
const BCTX_TSC_ADJUST: usize = core::mem::offset_of!(ResidentBootContext, tsc_adjust);
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
const _: () = assert!(size_of::<ResidentBootContext>() <= PAGE_SIZE);

const EVENT_CTX_MAGIC: usize = core::mem::offset_of!(ResidentEventContext, magic);
const EVENT_CTX_EBS_SEEN: usize =
    core::mem::offset_of!(ResidentEventContext, exit_boot_services_seen);
const EVENT_CTX_VA_SEEN: usize =
    core::mem::offset_of!(ResidentEventContext, virtual_address_change_seen);
const EVENT_CTX_CANARY: usize = core::mem::offset_of!(ResidentEventContext, canary);
const EVENT_CTX_SERIAL_LOCK: usize = core::mem::offset_of!(ResidentEventContext, serial_lock);

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
    exit_boot_services_callback: u64,
    virtual_address_change_callback: u64,
    dispatch_entry: u64,
}

impl ResidentCode {
    fn allocate() -> Result<Self, ResidentProbeError> {
        let start = core::ptr::addr_of!(matrixhv_resident_island_start) as u64;
        let entry = core::ptr::addr_of!(matrixhv_resident_island_entry) as u64;
        let fatal = core::ptr::addr_of!(matrixhv_resident_island_fatal) as u64;
        let exit_boot_services_callback =
            core::ptr::addr_of!(matrixhv_resident_ebs_callback) as u64;
        let virtual_address_change_callback =
            core::ptr::addr_of!(matrixhv_resident_va_callback) as u64;
        let dispatch_entry = core::ptr::addr_of!(matrixhv_resident_dispatch_entry) as u64;
        let end = core::ptr::addr_of!(matrixhv_resident_island_end) as u64;
        if entry < start
            || fatal < start
            || exit_boot_services_callback < start
            || virtual_address_change_callback < start
            || dispatch_entry < start
            || end <= start
            || entry >= end
            || fatal >= end
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
        }
        let base = pages.physical_address();
        Ok(Self {
            entry: base + (entry - start),
            fatal: base + (fatal - start),
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
    fn inherited(segments: segmentation::SegmentationState) -> Result<Self, ResidentProbeError> {
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

            let idt_pointer = idt as *mut IdtEntry;
            for index in 0..IDT_ENTRY_COUNT {
                idt_pointer
                    .add(index)
                    .write(IdtEntry::interrupt_gate(fatal_handler, selectors.cs));
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

    let code = ResidentCode::allocate()?;
    let root_segments = segmentation::capture();
    let selectors = ResidentHostSelectors::inherited(root_segments)?;
    let mut tables = ResidentHostTables::allocate(code.fatal, selectors)?;
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
    let session = vt_vmxon::enter_vmx_root().map_err(ResidentProbeError::Vmxon)?;

    let host_space = host_address_space
        .clone_current()
        .map_err(ResidentProbeError::Paging)?;
    let source_cr3 = host_space.source_cr3;
    let context = context_pages.pointer().as_ptr().cast::<ResidentContext>();
    unsafe {
        context.write(ResidentContext::new(source_cr3, host_space.host_cr3));
    }

    let clear_result = unsafe { vt_vmcs::vmclear(vmcs_physical_address) };
    if clear_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(ResidentProbeError::Vmclear(clear_result));
    }
    let load_result = unsafe { vt_vmcs::vmptrld(vmcs_physical_address) };
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
    let vm_instruction_error = vt_vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
    let final_clear = unsafe { vt_vmcs::vmclear(vmcs_physical_address) };
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

pub fn arm_residency_events() -> Result<ResidentEventReport, ResidentProbeError> {
    let mut code = ResidentCode::allocate()?;
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
            exit_boot_services_seen: 0,
            virtual_address_change_seen: 0,
            canary: EVENT_CONTEXT_CANARY,
            serial_lock: AtomicU64::new(0),
        });
    }
    let serial_lock_address = context_pages.physical_address() + EVENT_CTX_SERIAL_LOCK as u64;
    crate::runtime::serial::install_shared_lock(serial_lock_address);
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

fn configure_resident_msr_switch(msr_state: &ResidentPages) -> Result<(), VmcsError> {
    let entries = msr_state.pointer().as_ptr().cast::<VmxMsrEntry>();
    // The resident assembly never executes SYSCALL, SWAPGS, or RDTSCP. Preserve
    // those MSRs naturally across exits; only root speculation policy needs a switch.
    let initial_values = [(IA32_SPEC_CTRL_MSR, unsafe { msr::read(IA32_SPEC_CTRL_MSR) })];
    for (offset, (index, value)) in initial_values.into_iter().enumerate() {
        let entry = VmxMsrEntry {
            index,
            reserved: 0,
            value,
        };
        unsafe {
            entries.add(offset).write(entry);
            entries.add(RESIDENT_MSR_SWITCH_COUNT + offset).write(entry);
        }
    }
    let guest_entry = msr_state.physical_address();
    let host_entry = guest_entry + (RESIDENT_MSR_SWITCH_COUNT * size_of::<VmxMsrEntry>()) as u64;
    vmwrite(VM_EXIT_MSR_STORE_ADDR, guest_entry)?;
    vmwrite(VM_EXIT_MSR_LOAD_ADDR, host_entry)?;
    vmwrite(VM_ENTRY_MSR_LOAD_ADDR, guest_entry)?;
    vmwrite(VM_EXIT_MSR_STORE_COUNT, RESIDENT_MSR_SWITCH_COUNT as u64)?;
    vmwrite(VM_EXIT_MSR_LOAD_COUNT, RESIDENT_MSR_SWITCH_COUNT as u64)?;
    vmwrite(VM_ENTRY_MSR_LOAD_COUNT, RESIDENT_MSR_SWITCH_COUNT as u64)?;
    Ok(())
}

fn configure_nested_msr_composition(
    nested_state: &mut NestedVmxState,
    l0_msr_bitmap: u64,
    l0_msr_guest_list: u64,
    nested_msr_state: u64,
) {
    let l0_msr_host_list =
        l0_msr_guest_list + (RESIDENT_MSR_SWITCH_COUNT * size_of::<VmxMsrEntry>()) as u64;
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
    segments: segmentation::SegmentationState,
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
    let clear = unsafe { vt_vmcs::vmclear(configuration.vmcs02_region) };
    if clear != VmxInstructionResult::Succeeded {
        return Err(ResidentProbeError::Vmclear(clear));
    }
    let load = unsafe { vt_vmcs::vmptrld(configuration.vmcs02_region) };
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

    let restore = unsafe { vt_vmcs::vmptrld(configuration.vmcs01_region) };
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
    segment: segmentation::SegmentState,
) {
    set_vmcs12_extended_field(vmcs12, selector, u64::from(segment.selector));
    set_vmcs12_extended_field(vmcs12, base, segment.base);
    set_vmcs12_extended_field(vmcs12, limit, u64::from(segment.limit));
    set_vmcs12_extended_field(vmcs12, access_rights, u64::from(segment.access_rights));
}

fn seed_nested_vmcs12_core_state(
    vmcs12: &mut NestedVmcs12State,
    mut segments: segmentation::SegmentationState,
    l1_cr4: u64,
) {
    use crate::nested::vmcs::*;

    segments.tr = segmentation::vmx_usable_tr(segments.tr);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_VMCS_LINK_POINTER, u64::MAX);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_CR0, control_regs::read_cr0());
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_CR3, control_regs::read_cr3());
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

    let sysenter_cs = unsafe { msr::read(msr::IA32_SYSENTER_CS) };
    let sysenter_esp = unsafe { msr::read(msr::IA32_SYSENTER_ESP) };
    let sysenter_eip = unsafe { msr::read(msr::IA32_SYSENTER_EIP) };
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_SYSENTER_CS, sysenter_cs);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_SYSENTER_ESP, sysenter_esp);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_GUEST_SYSENTER_EIP, sysenter_eip);

    let host_selector = |selector: u16| u64::from(selector & !0x7);
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_HOST_CR0, control_regs::read_cr0());
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_HOST_CR3, control_regs::read_cr3());
    set_vmcs12_extended_field(vmcs12, VMCS_FIELD_HOST_CR4, control_regs::read_cr4());
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
            pinbased_ctls: msr::read(IA32_VMX_PINBASED_CTLS_MSR),
            procbased_ctls: msr::read(IA32_VMX_PROCBASED_CTLS_MSR),
            exit_ctls: msr::read(IA32_VMX_EXIT_CTLS_MSR),
            entry_ctls: msr::read(IA32_VMX_ENTRY_CTLS_MSR),
            misc: msr::read(IA32_VMX_MISC_MSR),
            cr0_fixed0: msr::read(IA32_VMX_CR0_FIXED0_MSR),
            cr0_fixed1: msr::read(IA32_VMX_CR0_FIXED1_MSR),
            cr4_fixed0: msr::read(IA32_VMX_CR4_FIXED0_MSR),
            cr4_fixed1: msr::read(IA32_VMX_CR4_FIXED1_MSR),
            vmcs_enum: msr::read(IA32_VMX_VMCS_ENUM_MSR),
            procbased_ctls2: msr::read(IA32_VMX_PROCBASED_CTLS2_MSR),
            ept_vpid_cap: msr::read(IA32_VMX_EPT_VPID_CAP_MSR),
            true_pinbased_ctls: if has_true_controls {
                msr::read(IA32_VMX_TRUE_PINBASED_CTLS_MSR)
            } else {
                0
            },
            true_procbased_ctls: if has_true_controls {
                msr::read(IA32_VMX_TRUE_PROCBASED_CTLS_MSR)
            } else {
                0
            },
            true_exit_ctls: if has_true_controls {
                msr::read(IA32_VMX_TRUE_EXIT_CTLS_MSR)
            } else {
                0
            },
            true_entry_ctls: if has_true_controls {
                msr::read(IA32_VMX_TRUE_ENTRY_CTLS_MSR)
            } else {
                0
            },
        }
    };
    let mut capabilities = NestedVmxCapabilities::from_host(host);
    crate::runtime::logger::info(format_args!(
        "nested VMX host basic={:#x} misc={:#x} proc2={:#x} ept_vpid={:#x} guest misc={:#x} proc2={:#x} ept_vpid={:#x}",
        host.vmx_basic,
        host.misc,
        host.procbased_ctls2,
        host.ept_vpid_cap,
        capabilities.vmx_misc,
        capabilities.vmx_procbased_ctls2,
        capabilities.vmx_ept_vpid_cap,
    ));
    capabilities.expose_vmx = crate::boot::config::current().vt_nested;
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
    if size_of::<ResidentBootContext>() > PAGE_SIZE
        || core::mem::offset_of!(ResidentBootContext, root_fx_state) & 0xf != 0
        || !vmcs12_extended_fields_are_dense()
    {
        return Err(ResidentProbeError::Allocation(Status::OUT_OF_RESOURCES));
    }

    let initial_rflags = registers::read_rflags();
    let code = ResidentCode::allocate()?;
    let root_segments = segmentation::capture();
    let msr_bitmap = ResidentPages::allocate(MSR_BITMAP_PAGES, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let ept_test_page = ResidentPages::allocate(1, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let zero_page = ResidentPages::allocate(1, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let mut host_address_space = HostAddressSpace::reserve().map_err(ResidentProbeError::Paging)?;
    let vmx_basic = vt_vmxon::vmx_basic();
    let mut cpu_resources = ResidentCpuResources::allocate(vmx_basic, code.fatal)?;
    let topology = crate::smp::topology::enumerate().map_err(ResidentProbeError::Allocation)?;
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
                    ResidentCpuResources::allocate(vmx_basic, code.fatal)?,
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
    allow_low_msr_passthrough(&msr_bitmap, IA32_TSC_DEADLINE_MSR);
    allow_low_msr_passthrough(&msr_bitmap, IA32_XSS_MSR);
    let machine_check_bank_count = unsafe { msr::read(IA32_MCG_CAP_MSR) } as u32 & 0xff;
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
    allow_low_msr_passthrough(&msr_bitmap, msr::IA32_PAT);
    allow_high_msr_passthrough(&msr_bitmap, IA32_STAR_MSR);
    allow_high_msr_passthrough(&msr_bitmap, IA32_LSTAR_MSR);
    allow_high_msr_passthrough(&msr_bitmap, IA32_CSTAR_MSR);
    allow_high_msr_passthrough(&msr_bitmap, IA32_FMASK_MSR);
    allow_high_msr_passthrough(&msr_bitmap, IA32_KERNEL_GS_BASE_MSR);
    allow_high_msr_passthrough(&msr_bitmap, IA32_TSC_AUX_MSR);

    let host_space = host_address_space
        .clone_current()
        .map_err(ResidentProbeError::Paging)?;
    let mut ept = vt_ept::IdentityEpt::build()?;
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
    let bsp_ept_composition = cpu_resources.prepare_nested_ept(&ept)?;
    for (_, resources) in &mut ap_resources {
        resources.prepare_nested_ept(&ept)?;
    }
    let mut nested_ept02_regions = cpu_resources.nested_ept02_table_regions();
    for (_, resources) in &ap_resources {
        nested_ept02_regions.extend(resources.nested_ept02_table_regions());
    }
    ept.conceal_guest_access_to_regions(&nested_ept02_regions, zero_page_physical_address)?;
    cpu_resources
        .conceal_nested_ept02_regions(&nested_ept02_regions, zero_page_physical_address)?;
    for (_, resources) in &mut ap_resources {
        resources
            .conceal_nested_ept02_regions(&nested_ept02_regions, zero_page_physical_address)?;
    }

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
    let session =
        vt_vmxon::enter_vmx_root_with_borrowed_region(vmx_basic, &mut cpu_resources.vmxon_region)
            .map_err(ResidentProbeError::Vmxon)?;
    let l1_cr4 = session.report().original_cr4;
    EPT_TEST_PAGE_GPA.store(ept_test_page.physical_address(), Ordering::Release);
    let clear_result = unsafe { vt_vmcs::vmclear(vmcs_physical_address) };
    if clear_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(ResidentProbeError::Vmclear(clear_result));
    }
    let load_result = unsafe { vt_vmcs::vmptrld(vmcs_physical_address) };
    if load_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(ResidentProbeError::Vmcs(VmcsError::Vmptrld(load_result)));
    }

    let mut controls =
        vt_controls::configure_resident_boot(msr_bitmap.physical_address(), ept.ept_pointer())?;
    vt_controls::enable_resident_vpid(&mut controls, 1)?;
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

    for (processor_number, resources) in &mut ap_resources {
        let mut launch = ResidentApLaunch {
            resources,
            host_cr3: host_space.host_cr3,
            event_context,
            ept_pointer: ept.ept_pointer(),
            msr_bitmap: msr_bitmap.physical_address(),
            dispatch_entry: code.dispatch_entry,
            processor_number: *processor_number,
        };
        let result = crate::smp::ap_startup::launch(*processor_number, &mut launch);
        let ap_context = resources
            .context_pages
            .pointer()
            .as_ptr()
            .cast::<ResidentBootContext>();
        let started = unsafe { core::ptr::addr_of!((*ap_context).ap_started).read_volatile() };
        let nested = unsafe { core::ptr::addr_of!((*ap_context).nested).read_volatile() };
        crate::runtime::logger::info(format_args!(
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
        crate::runtime::logger::info(format_args!(
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
        crate::runtime::logger::info(format_args!(
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
        crate::runtime::logger::info(format_args!(
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
            || nested.ept_observed_value != crate::smp::per_cpu::NESTED_EPT_TARGET_MARKER
            || nested.ept_observed_value_before_invept
                != crate::smp::per_cpu::NESTED_EPT_TARGET_MARKER
            || nested.ept_observed_value_after_invept
                != crate::smp::per_cpu::NESTED_EPT_SECOND_TARGET_MARKER
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
            resident_startup_halt();
        }
    }
    crate::runtime::logger::info(format_args!(
        "smp resident BSP context={:#x} vmcs={:#x} vmxon={:#x}",
        context as u64,
        vmcs_physical_address,
        session.report().region_physical_address
    ));
    let raw_path =
        unsafe { matrixhv_resident_boot_run_asm(context, host_rsp, code.dispatch_entry) };
    if !ap_resources.is_empty() {
        resident_startup_halt();
    }
    EPT_TEST_PAGE_GPA.store(0, Ordering::Release);
    if raw_path == 0 {
        cpu_resources.host_tables.pages.preserve();
    }
    let vm_instruction_error = vt_vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
    let final_clear = unsafe { vt_vmcs::vmclear(vmcs_physical_address) };
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
    crate::runtime::logger::error(format_args!(
        "smp resident startup failed; retaining active CPU resources"
    ));
    loop {
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
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
        let segments = segmentation::capture();
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
        let clear = unsafe { vt_vmcs::vmclear(vmcs) };
        if clear != VmxInstructionResult::Succeeded {
            return Err(ResidentProbeError::Vmclear(clear));
        }
        let load = unsafe { vt_vmcs::vmptrld(vmcs) };
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
        let host_rsp = (self.resources.host_stack.physical_address()
            + self.resources.host_stack.byte_len() as u64
            - 8)
            & !0xf;
        unsafe {
            context.write(state);
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
    segments: segmentation::SegmentationState,
) -> Result<(), VmcsError> {
    vmwrite(HOST_ES_SELECTOR, u64::from(tables.selectors.es))?;
    vmwrite(HOST_CS_SELECTOR, u64::from(tables.selectors.cs))?;
    vmwrite(HOST_SS_SELECTOR, u64::from(tables.selectors.ss))?;
    vmwrite(HOST_DS_SELECTOR, u64::from(tables.selectors.ds))?;
    vmwrite(HOST_FS_SELECTOR, u64::from(tables.selectors.fs))?;
    vmwrite(HOST_GS_SELECTOR, u64::from(tables.selectors.gs))?;
    vmwrite(HOST_TR_SELECTOR, u64::from(HOST_TSS_SELECTOR))?;
    vmwrite(HOST_CR0, control_regs::read_cr0())?;
    vmwrite(HOST_CR3, host_cr3)?;
    vmwrite(HOST_CR4, control_regs::read_cr4())?;
    vmwrite(HOST_IA32_PAT, unsafe { msr::read(msr::IA32_PAT) })?;
    vmwrite(HOST_IA32_EFER, unsafe { msr::read(msr::IA32_EFER) })?;
    vmwrite(HOST_FS_BASE, segments.fs.base)?;
    vmwrite(HOST_GS_BASE, segments.gs.base)?;
    vmwrite(HOST_TR_BASE, tables.tss)?;
    vmwrite(HOST_GDTR_BASE, tables.gdt)?;
    vmwrite(HOST_IDTR_BASE, tables.idt)?;
    vmwrite(
        HOST_SYSENTER_CS,
        unsafe { msr::read(msr::IA32_SYSENTER_CS) } & 0xffff_ffff,
    )?;
    vmwrite(HOST_SYSENTER_ESP, unsafe {
        msr::read(msr::IA32_SYSENTER_ESP)
    })?;
    vmwrite(HOST_SYSENTER_EIP, unsafe {
        msr::read(msr::IA32_SYSENTER_EIP)
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
    static matrixhv_resident_ebs_callback: u8;
    static matrixhv_resident_va_callback: u8;
    static matrixhv_resident_dispatch_entry: u8;
    static matrixhv_resident_island_end: u8;
}

global_asm!(
    ".text",
    ".globl matrixhv_resident_guest_probe_asm",
    "matrixhv_resident_guest_probe_asm:",
    "vmcall",
    "ud2",
    ".globl matrixhv_resident_probe_run_asm",
    "matrixhv_resident_probe_run_asm:",
    "push rbx",
    "push rbp",
    "push rdi",
    "push rsi",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov qword ptr [rcx + 0], rsp",
    "lea rax, [rip + 9f]",
    "mov qword ptr [rcx + 8], rax",
    "sgdt [rcx + 88]",
    "sidt [rcx + 98]",
    "mov rax, {host_rsp}",
    "vmwrite rax, rdx",
    "jc 3f",
    "jz 3f",
    "mov rax, {host_rip}",
    "vmwrite rax, r8",
    "jc 4f",
    "jz 4f",
    "vmlaunch",
    "jc 1f",
    "jz 2f",
    "mov eax, 5",
    "jmp 8f",
    "1:",
    "mov eax, 1",
    "jmp 8f",
    "2:",
    "mov eax, 2",
    "jmp 8f",
    "3:",
    "mov eax, 3",
    "jmp 8f",
    "4:",
    "mov eax, 4",
    "jmp 8f",
    "9:",
    "lgdt [r10 + 88]",
    "lidt [r10 + 98]",
    "xor eax, eax",
    "8:",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rsi",
    "pop rdi",
    "pop rbp",
    "pop rbx",
    "ret",
    ".globl matrixhv_resident_boot_run_asm",
    "matrixhv_resident_boot_run_asm:",
    "push rbx",
    "push rbp",
    "push rdi",
    "push rsi",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov qword ptr [rcx + {b_root_rsp}], rsp",
    "lea rax, [rip + .Lresident_boot_return]",
    "mov qword ptr [rcx + {b_return_rip}], rax",
    "sgdt [rcx + {b_gdtr}]",
    "sidt [rcx + {b_idtr}]",
    "fxsave64 [rcx + {b_fx}]",
    "mov rax, {host_rsp}",
    "vmwrite rax, rdx",
    "jc .Lresident_boot_rsp_fail",
    "jz .Lresident_boot_rsp_fail",
    "mov rax, {host_rip}",
    "vmwrite rax, r8",
    "jc .Lresident_boot_rip_fail",
    "jz .Lresident_boot_rip_fail",
    "mov rax, qword ptr [rcx + {b_nested_vmxon_operand}]",
    "vmlaunch",
    "jc .Lresident_boot_fail_invalid",
    "jz .Lresident_boot_fail_valid",
    "mov eax, 5",
    "jmp .Lresident_boot_failure_restore",
    ".Lresident_boot_fail_invalid:",
    "mov eax, 1",
    "jmp .Lresident_boot_failure_restore",
    ".Lresident_boot_fail_valid:",
    "mov eax, 2",
    "jmp .Lresident_boot_failure_restore",
    ".Lresident_boot_rsp_fail:",
    "mov eax, 3",
    "jmp .Lresident_boot_failure_restore",
    ".Lresident_boot_rip_fail:",
    "mov eax, 4",
    ".Lresident_boot_failure_restore:",
    "fxrstor64 [rcx + {b_fx}]",
    "jmp .Lresident_boot_pop",
    ".Lresident_boot_return:",
    "lgdt [r12 + {b_gdtr}]",
    "lidt [r12 + {b_idtr}]",
    "fxrstor64 [r12 + {b_fx}]",
    "xor eax, eax",
    ".Lresident_boot_pop:",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rsi",
    "pop rdi",
    "pop rbp",
    "pop rbx",
    "ret",
    host_rsp = const HOST_RSP,
    host_rip = const HOST_RIP,
    b_root_rsp = const BCTX_ROOT_RSP,
    b_return_rip = const BCTX_RETURN_RIP,
    b_gdtr = const BCTX_ORIGINAL_GDTR,
    b_idtr = const BCTX_ORIGINAL_IDTR,
    b_fx = const BCTX_ROOT_FX_STATE,
    b_nested_vmxon_operand = const BCTX_NESTED_VMXON_OPERAND,
);

global_asm!(
    ".section .text.matrixhv_resident_island,\"ax\"",
    ".p2align 4",
    ".globl matrixhv_resident_island_start",
    ".globl matrixhv_resident_island_entry",
    "matrixhv_resident_island_start:",
    "matrixhv_resident_island_entry:",
    "cld",
    "mov r10, qword ptr [rsp]",
    "mov rax, cr3",
    "mov qword ptr [r10 + 32], rax",
    "mov rax, {guest_cr3}",
    "vmread r11, rax",
    "jc matrixhv_resident_island_fatal",
    "jz matrixhv_resident_island_fatal",
    "mov qword ptr [r10 + 40], r11",
    "mov rax, {exit_reason}",
    "vmread r11, rax",
    "jc matrixhv_resident_island_fatal",
    "jz matrixhv_resident_island_fatal",
    "mov qword ptr [r10 + 48], r11",
    "mov rax, {guest_rip}",
    "vmread r11, rax",
    "jc matrixhv_resident_island_fatal",
    "jz matrixhv_resident_island_fatal",
    "mov qword ptr [r10 + 56], r11",
    "mov rax, {complete}",
    "mov qword ptr [r10 + 72], rax",
    "mov rax, qword ptr [r10 + 16]",
    "mov cr3, rax",
    "mov rsp, qword ptr [r10 + 0]",
    "jmp qword ptr [r10 + 8]",
    ".globl matrixhv_resident_dispatch_entry",
    "matrixhv_resident_dispatch_entry:",
    "cld",
    "push r15",
    "push r14",
    "push r13",
    "push r12",
    "push r11",
    "push r10",
    "push r9",
    "push r8",
    "push rdi",
    "push rsi",
    "push rbp",
    "push rbx",
    "push rdx",
    "push rcx",
    "push rax",
    "mov r12, qword ptr [rsp + 120]",
    "test r12, r12",
    "jz matrixhv_resident_island_fatal",
    "lfence",
    "rdtsc",
    "shl rdx, 32",
    "or rax, rdx",
    "mov qword ptr [r12 + {b_nested_exit_started_tsc}], rax",
    "mov rax, {boot_canary_start}",
    "cmp qword ptr [r12 + {b_canary_start}], rax",
    "jne matrixhv_resident_island_fatal",
    "mov rax, {boot_canary_end}",
    "cmp qword ptr [r12 + {b_canary_end}], rax",
    "jne matrixhv_resident_island_fatal",
    "inc qword ptr [r12 + {b_exit_count}]",
    "mov rax, qword ptr [rsp + 0]",
    "mov qword ptr [r12 + {b_last_rax}], rax",
    "mov rax, qword ptr [rsp + 8]",
    "mov qword ptr [r12 + {b_last_rcx}], rax",
    "mov rax, qword ptr [rsp + 16]",
    "mov qword ptr [r12 + {b_last_rdx}], rax",
    "mov rax, cr3",
    "mov qword ptr [r12 + {b_last_host_cr3}], rax",
    "mov rax, {guest_cr3}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_last_guest_cr3}], r11",
    "mov rax, {exit_reason}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_last_reason}], r11",
    "mov rax, {guest_rip}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_last_guest_rip}], r11",
    "mov rax, {exit_instruction_len}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_last_instruction_len}], r11",
    "mov rax, {exit_qualification}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_last_qualification}], r11",
    "mov rax, qword ptr [r12 + {b_last_host_cr3}]",
    "cmp rax, qword ptr [r12 + {b_expected_host_cr3}]",
    "jne .Lresident_dispatch_host_cr3_mismatch",
    "cmp qword ptr [r12 + {b_nested_l2_active}], 1",
    "je .Lresident_nested_l2_reflect",
    "cmp qword ptr [r12 + {b_nested_vmcs01_msr_entry_composed}], 0",
    "je .Lresident_dispatch_vmcs01_msr_entry_ready",
    "mov rax, {vm_entry_msr_load_addr}",
    "mov r11, qword ptr [r12 + {b_nested_l0_msr_guest_list}]",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {vm_entry_msr_load_count}",
    "mov r11d, {resident_msr_switch_count}",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov qword ptr [r12 + {b_nested_vmcs01_msr_entry_composed}], 0",
    ".Lresident_dispatch_vmcs01_msr_entry_ready:",
    "mov rdi, qword ptr [r12 + {b_event_context}]",
    "test rdi, rdi",
    "jz .Lresident_dispatch_after_events",
    "mov rax, {event_magic}",
    "cmp qword ptr [rdi + {event_magic_offset}], rax",
    "jne .Lresident_dispatch_event_corrupt",
    "mov rax, {event_canary}",
    "cmp qword ptr [rdi + {event_canary_offset}], rax",
    "jne .Lresident_dispatch_event_corrupt",
    "cmp qword ptr [rdi + {event_ebs_seen}], 0",
    "je .Lresident_dispatch_check_va",
    "inc qword ptr [r12 + {b_post_ebs_count}]",
    "cmp qword ptr [r12 + {b_processor_number}], 0",
    "jne .Lresident_dispatch_check_va",
    "cmp qword ptr [r12 + {b_post_ebs_count}], 1",
    "jne .Lresident_dispatch_check_va",
    "lea rsi, [rip + .Lpost_ebs_exit_message]",
    "mov r9d, {post_ebs_exit_message_len}",
    "call .Lresident_serial_write",
    "call .Lresident_serial_state",
    ".Lresident_dispatch_check_va:",
    "cmp qword ptr [rdi + {event_va_seen}], 0",
    "je .Lresident_dispatch_after_events",
    "inc qword ptr [r12 + {b_post_va_count}]",
    "cmp qword ptr [r12 + {b_processor_number}], 0",
    "jne .Lresident_dispatch_after_events",
    "cmp qword ptr [r12 + {b_post_va_count}], 1",
    "jne .Lresident_dispatch_after_events",
    "lea rsi, [rip + .Lpost_va_exit_message]",
    "mov r9d, {post_va_exit_message_len}",
    "call .Lresident_serial_write",
    "call .Lresident_serial_state",
    ".Lresident_dispatch_after_events:",
    "cmp qword ptr [r12 + {b_start_checkpoint_seen}], 0",
    "je .Lresident_dispatch_reason",
    "inc qword ptr [r12 + {b_post_start_count}]",
    "cmp qword ptr [r12 + {b_post_start_count}], 1",
    "jne .Lresident_dispatch_reason",
    "lea rsi, [rip + .Lfirst_start_exit_message]",
    "mov r9d, {first_start_exit_message_len}",
    "call .Lresident_serial_write",
    "call .Lresident_serial_state",
    ".Lresident_dispatch_reason:",
    "mov rax, qword ptr [r12 + {b_last_reason}]",
    "test eax, 0x80000000",
    "jnz .Lresident_dispatch_unsupported",
    "and eax, 0xffff",
    "cmp eax, 0",
    "je .Lresident_dispatch_exception",
    "cmp eax, 3",
    "je .Lresident_ap_init",
    "cmp eax, 4",
    "je .Lresident_ap_sipi",
    "cmp eax, 28",
    "je .Lresident_ap_cr_access",
    "cmp eax, {ept_violation_reason}",
    "je .Lresident_dispatch_ept_violation",
    "cmp eax, {vmclear_reason}",
    "je .Lresident_dispatch_vmclear",
    "cmp eax, {vmlaunch_reason}",
    "je .Lresident_dispatch_vmlaunch",
    "cmp eax, {vmptrld_reason}",
    "je .Lresident_dispatch_vmptrld",
    "cmp eax, {vmptrst_reason}",
    "je .Lresident_dispatch_vmptrst",
    "cmp eax, {vmread_reason}",
    "je .Lresident_dispatch_vmread",
    "cmp eax, {vmresume_reason}",
    "je .Lresident_dispatch_vmresume",
    "cmp eax, {vmwrite_reason}",
    "je .Lresident_dispatch_vmwrite",
    "cmp eax, {vmxon_reason}",
    "je .Lresident_dispatch_vmxon",
    "cmp eax, {vmxoff_reason}",
    "je .Lresident_dispatch_vmxoff",
    "cmp eax, {invept_reason}",
    "je .Lresident_dispatch_invept",
    "cmp eax, {invvpid_reason}",
    "je .Lresident_dispatch_invvpid",
    "cmp eax, {cpuid_reason}",
    "je .Lresident_dispatch_cpuid",
    "cmp eax, {vmcall_reason}",
    "je .Lresident_dispatch_vmcall",
    "cmp eax, {rdmsr_reason}",
    "je .Lresident_dispatch_rdmsr",
    "cmp eax, {wrmsr_reason}",
    "je .Lresident_dispatch_wrmsr",
    "cmp eax, {xsetbv_reason}",
    "je .Lresident_dispatch_xsetbv",
    "jmp .Lresident_dispatch_unsupported",
    include_str!("../../asm/ap_startup.S"),
    ".Lresident_nested_l2_reflect:",
    "mov r10, qword ptr [r12 + {b_last_reason}]",
    "test r10d, 0x80000000",
    "jnz .Lresident_nested_l2_failure_dump",
    "mov qword ptr [r12 + {b_nested_vmcs02_launched}], 1",
    "jmp .Lresident_nested_l2_reflect_after_failure_dump",
    ".Lresident_nested_l2_failure_dump:",
    "lea rsi, [rip + .Lnested_entry_failure_dump_message]",
    "mov r9d, {nested_entry_failure_dump_message_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_guest_rip}]",
    "call .Lresident_serial_hex64",
    "mov al, 0x20",
    "call .Lresident_serial_char",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_guest_rsp}]",
    "call .Lresident_serial_hex64",
    "mov al, 0x20",
    "call .Lresident_serial_char",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_guest_rflags}]",
    "call .Lresident_serial_hex64",
    "mov al, 0x20",
    "call .Lresident_serial_char",
    "mov rax, qword ptr [r12 + {b_last_qualification}]",
    "call .Lresident_serial_hex64",
    "mov r14d, 0",
    "lea r15, [r12 + {b_nested_vmcs12_extended_fields}]",
    ".Lresident_nested_l2_failure_dump_field:",
    "mov al, 0x20",
    "call .Lresident_serial_char",
    "mov rax, qword ptr [r15 + r14 * 8]",
    "call .Lresident_serial_hex64",
    "inc r14d",
    "cmp r14d, {nested_extended_field_count}",
    "jne .Lresident_nested_l2_failure_dump_field",
    "mov al, 0x0a",
    "call .Lresident_serial_char",
    ".Lresident_nested_l2_reflect_after_failure_dump:",
    "mov r10, qword ptr [r12 + {b_last_reason}]",
    "mov eax, r10d",
    "and eax, 0xffff",
    "cmp eax, {ept_violation_reason}",
    "jne .Lresident_nested_l2_probe_reflection",
    "call .Lresident_nested_resolve_ept02_violation",
    "test eax, eax",
    "jnz .Lresident_nested_l2_resume_ept",
    "mov r10, qword ptr [r12 + {b_last_reason}]",
    "jmp .Lresident_nested_l2_reflect_generic",
    ".Lresident_nested_l2_probe_reflection:",
    "cmp qword ptr [r12 + {b_nested_l2_exit_count}], 3",
    "jae .Lresident_nested_l2_reflect_generic",
    "cmp eax, {vmcall_reason}",
    "jne .Lresident_dispatch_halt",
    "cmp qword ptr [r12 + {b_nested_l2_exit_count}], 0",
    "je .Lresident_nested_l2_ept_probe_first",
    "cmp qword ptr [r12 + {b_nested_l2_exit_count}], 1",
    "je .Lresident_nested_l2_ept_probe_before_invept",
    "cmp qword ptr [r12 + {b_nested_l2_exit_count}], 2",
    "je .Lresident_nested_l2_ept_probe_after_invept",
    "jmp .Lresident_nested_l2_reflect_generic",
    ".Lresident_nested_l2_ept_probe_first:",
    "mov r11, qword ptr [rsp + 96]",
    "mov qword ptr [r12 + {b_nested_ept_observed_value}], r11",
    "mov rax, {nested_ept_target_marker}",
    "cmp r11, rax",
    "jne .Lresident_dispatch_halt",
    "inc qword ptr [r12 + {b_nested_ept_probe_count}]",
    "jmp .Lresident_nested_l2_ept_probe_done",
    ".Lresident_nested_l2_ept_probe_before_invept:",
    "mov r11, qword ptr [rsp + 96]",
    "mov qword ptr [r12 + {b_nested_ept_observed_value_before_invept}], r11",
    "mov rax, {nested_ept_target_marker}",
    "cmp r11, rax",
    "jne .Lresident_dispatch_halt",
    "inc qword ptr [r12 + {b_nested_ept_probe_count}]",
    "jmp .Lresident_nested_l2_ept_probe_done",
    ".Lresident_nested_l2_ept_probe_after_invept:",
    "mov r11, qword ptr [rsp + 96]",
    "mov qword ptr [r12 + {b_nested_ept_observed_value_after_invept}], r11",
    "mov rax, {nested_ept_second_target_marker}",
    "cmp r11, rax",
    "jne .Lresident_dispatch_halt",
    "inc qword ptr [r12 + {b_nested_ept_probe_count}]",
    ".Lresident_nested_l2_reflect_generic:",
    ".Lresident_nested_l2_ept_probe_done:",
    "mov eax, r10d",
    "and eax, 0xffff",
    "cmp eax, 44",
    "jae .Lresident_nested_l2_exit_count_ready",
    "inc dword ptr [r12 + {b_nested_reflected_exit_counts} + rax * 4]",
    ".Lresident_nested_l2_exit_count_ready:",
    "inc qword ptr [r12 + {b_nested_l2_exit_count}]",
    "inc qword ptr [r12 + {b_nested_l1_reflection_count}]",
    "cmp qword ptr [r12 + {b_nested_l2_resume_count}], 0",
    "je .Lresident_nested_l2_reflect_resume_counted",
    "inc qword ptr [r12 + {b_nested_l2_resume_exit_count}]",
    ".Lresident_nested_l2_reflect_resume_counted:",
    "mov qword ptr [r12 + {b_nested_l2_last_exit_reason}], r10",
    "mov qword ptr [r12 + {b_nested_vmcs12_exit_reason}], r10",
    "mov r11, qword ptr [r12 + {b_last_instruction_len}]",
    "mov qword ptr [r12 + {b_nested_vmcs12_exit_instruction_len}], r11",
    "mov rax, {exit_instruction_info}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_vmcs12_exit_instruction_info}], r11",
    "mov rax, {guest_linear_address}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 116 * 8], r11",
    "mov r11, qword ptr [r12 + {b_last_qualification}]",
    "mov eax, r10d",
    "and eax, 0xffff",
    "cmp eax, {vm_entry_failure_msr_loading_reason}",
    "jne .Lresident_nested_l2_qualification_ready",
    "test r10d, 0x80000000",
    "jz .Lresident_nested_l2_qualification_ready",
    "cmp r11, {resident_msr_switch_count}",
    "jbe .Lresident_nested_l2_qualification_ready",
    "sub r11, {resident_msr_switch_count}",
    ".Lresident_nested_l2_qualification_ready:",
    "mov qword ptr [r12 + {b_nested_vmcs12_exit_qualification}], r11",
    "mov eax, r10d",
    "and eax, 0xffff",
    "cmp eax, {ept_violation_reason}",
    "jne .Lresident_nested_l2_guest_physical_address_ready",
    "mov r11, qword ptr [r12 + {b_last_guest_physical_address}]",
    "mov qword ptr [r12 + {b_nested_vmcs12_guest_physical_address}], r11",
    ".Lresident_nested_l2_guest_physical_address_ready:",
    "mov r11, qword ptr [r12 + {b_last_guest_rip}]",
    "mov qword ptr [r12 + {b_nested_l2_last_exit_rip}], r11",
    "mov qword ptr [r12 + {b_nested_vmcs12_guest_rip}], r11",
    "mov rax, {guest_rsp}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_vmcs12_guest_rsp}], r11",
    "mov qword ptr [r12 + {b_nested_l2_last_exit_rsp}], r11",
    "mov rax, {guest_rflags}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_vmcs12_guest_rflags}], r11",
    "mov rax, {exit_intr_info}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_vmcs12_vm_exit_intr_info}], r11",
    "mov rax, {exit_intr_error_code}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_vmcs12_vm_exit_intr_error}], r11",
    "mov rax, {idt_vectoring_info_field}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_vmcs12_idt_vectoring_info}], r11",
    "mov rax, {idt_vectoring_error_code}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_vmcs12_idt_vectoring_error}], r11",
    "call .Lresident_nested_capture_vmcs02_guest_state",
    "mov r10, qword ptr [r12 + {b_nested_l2_last_exit_reason}]",
    "call .Lresident_nested_complete_vmcs02_msr_exit",
    "mov r10, qword ptr [r12 + {b_nested_l2_last_exit_reason}]",
    "test r10d, 0x80000000",
    "jnz .Lresident_nested_l2_entry_failure",
    "mov qword ptr [r12 + {b_nested_vmcs12_vm_entry_intr_info}], 0",
    "jmp .Lresident_nested_l2_mark_launched",
    ".Lresident_nested_l2_entry_failure:",
    "cmp qword ptr [r12 + {b_nested_l2_entry_was_resume}], 1",
    "jne .Lresident_nested_l2_launch_state_ready",
    ".Lresident_nested_l2_mark_launched:",
    "mov qword ptr [r12 + {b_nested_vmcs12_launch_state}], {vmcs12_launch_state_launched}",
    ".Lresident_nested_l2_launch_state_ready:",
    "mov qword ptr [r12 + {b_nested_l2_active}], 0",
    "vmptrld [r12 + {b_nested_vmcs01_region}]",
    "jna .Lresident_dispatch_halt",
    "call .Lresident_nested_activate_vmcs01_msr_entry",
    "call .Lresident_nested_restore_l1_host_state",
    "mov rax, {guest_rip}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_host_rip}]",
    "vmwrite rax, r11",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_rsp}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_host_rsp}]",
    "vmwrite rax, r11",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_rflags}",
    "mov r11, 2",
    "vmwrite rax, r11",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_interruptibility_info}",
    "xor r11d, r11d",
    "vmwrite rax, r11",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "mov rax, {vm_entry_intr_info_field}",
    "vmwrite rax, r11",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "mov rax, qword ptr [r12 + {b_nested_l2_exit_count}]",
    "cmp rax, 32",
    "jbe .Lresident_nested_l2_log_exit",
    "lea rdx, [rax - 1]",
    "test rax, rdx",
    "jnz .Lresident_dispatch_resume",
    ".Lresident_nested_l2_log_exit:",
    "lea rsi, [rip + .Lnested_l2_exit_message]",
    "mov r9d, {nested_l2_exit_message_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_processor_number}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_reason]",
    "mov r9d, {state_reason_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_nested_l2_last_exit_reason}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_rip]",
    "mov r9d, {state_rip_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_nested_l2_last_exit_rip}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_newline]",
    "mov r9d, {state_newline_len}",
    "call .Lresident_serial_write",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_ept_violation:",
    "mov rax, {guest_physical_address}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_last_guest_physical_address}], r11",
    "mov r10, r11",
    "and r10, -4096",
    "cmp r10, qword ptr [r12 + {b_ept_test_gpa}]",
    "jne .Lresident_dispatch_ept_unexpected",
    "mov r10, qword ptr [r12 + {b_last_guest_rip}]",
    "cmp r10, qword ptr [r12 + {b_ept_probe_fault_rip}]",
    "jne .Lresident_dispatch_ept_unexpected",
    "mov r10, qword ptr [r12 + {b_last_qualification}]",
    "and r10d, 7",
    "cmp r10, {ept_test_read_access}",
    "jne .Lresident_dispatch_ept_unexpected",
    "mov qword ptr [r12 + {b_ept_test_violation_seen}], 1",
    "lea rsi, [rip + .Lept_test_violation_message]",
    "mov r9d, {ept_test_violation_message_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_guest_physical_address}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lept_violation_rip]",
    "mov r9d, {ept_violation_rip_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_guest_rip}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lept_violation_read]",
    "mov r9d, {ept_violation_read_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_qualification}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_newline]",
    "mov r9d, {state_newline_len}",
    "call .Lresident_serial_write",
    "mov r10, qword ptr [r12 + {b_ept_probe_resume_rip}]",
    "mov rax, {guest_rip}",
    "vmwrite rax, r10",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_ept_unexpected:",
    "lea rsi, [rip + .Lept_unexpected_violation_message]",
    "mov r9d, {ept_unexpected_violation_message_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_guest_physical_address}]",
    "call .Lresident_serial_hex64",
    "call .Lresident_serial_state",
    "jmp .Lresident_dispatch_halt",
    ".Lresident_nested_read_gpr:",
    "cmp eax, 15",
    "ja .Lresident_dispatch_halt",
    "cmp eax, 4",
    "je .Lresident_nested_read_gpr_rsp",
    "lea rdx, [rip + .Lresident_guest_gpr_offsets]",
    "movzx edx, byte ptr [rdx + rax]",
    "mov r11, qword ptr [r15 + rdx]",
    "ret",
    ".Lresident_nested_read_gpr_rsp:",
    "mov rax, {guest_rsp}",
    "vmread r11, rax",
    "ret",
    ".Lresident_nested_write_gpr:",
    "cmp eax, 15",
    "ja .Lresident_dispatch_halt",
    "cmp eax, 4",
    "je .Lresident_nested_write_gpr_rsp",
    "lea rdx, [rip + .Lresident_guest_gpr_offsets]",
    "movzx edx, byte ptr [rdx + rax]",
    "mov qword ptr [r15 + rdx], r11",
    "ret",
    ".Lresident_nested_write_gpr_rsp:",
    "mov rax, {guest_rsp}",
    "vmwrite rax, r11",
    "ret",
    ".Lresident_nested_decode_memory_operand:",
    "lea r15, [rsp + 8]",
    "mov rax, {exit_instruction_info}",
    "vmread r13, rax",
    "mov r14, qword ptr [r12 + {b_last_qualification}]",
    "mov eax, r13d",
    "shr eax, 7",
    "and eax, 7",
    "cmp eax, 1",
    "je .Lresident_nested_operand_sign_extend_32",
    "test eax, eax",
    "jne .Lresident_nested_operand_base",
    "movsx r14, r14w",
    "jmp .Lresident_nested_operand_base",
    ".Lresident_nested_operand_sign_extend_32:",
    "movsxd r14, r14d",
    ".Lresident_nested_operand_base:",
    "bt r13d, 27",
    "jc .Lresident_nested_operand_index",
    "mov eax, r13d",
    "shr eax, 23",
    "and eax, 15",
    "call .Lresident_nested_read_gpr",
    "add r14, r11",
    ".Lresident_nested_operand_index:",
    "bt r13d, 22",
    "jc .Lresident_nested_operand_truncate",
    "mov eax, r13d",
    "shr eax, 18",
    "and eax, 15",
    "call .Lresident_nested_read_gpr",
    "mov ecx, r13d",
    "and ecx, 3",
    "shl r11, cl",
    "add r14, r11",
    ".Lresident_nested_operand_truncate:",
    "mov eax, r13d",
    "shr eax, 7",
    "and eax, 7",
    "cmp eax, 1",
    "je .Lresident_nested_operand_truncate_32",
    "test eax, eax",
    "jne .Lresident_nested_operand_segment",
    "movzx r14d, r14w",
    "jmp .Lresident_nested_operand_segment",
    ".Lresident_nested_operand_truncate_32:",
    "mov r14d, r14d",
    ".Lresident_nested_operand_segment:",
    "mov eax, r13d",
    "shr eax, 15",
    "and eax, 7",
    "cmp eax, 0",
    "je .Lresident_nested_operand_segment_es",
    "cmp eax, 1",
    "je .Lresident_nested_operand_segment_cs",
    "cmp eax, 2",
    "je .Lresident_nested_operand_segment_ss",
    "cmp eax, 3",
    "je .Lresident_nested_operand_segment_ds",
    "cmp eax, 4",
    "je .Lresident_nested_operand_segment_fs",
    "cmp eax, 5",
    "je .Lresident_nested_operand_segment_gs",
    "jmp .Lresident_dispatch_halt",
    ".Lresident_nested_operand_segment_es:",
    "mov rax, {guest_es_base}",
    "jmp .Lresident_nested_operand_segment_read",
    ".Lresident_nested_operand_segment_cs:",
    "mov rax, {guest_cs_base}",
    "jmp .Lresident_nested_operand_segment_read",
    ".Lresident_nested_operand_segment_ss:",
    "mov rax, {guest_ss_base}",
    "jmp .Lresident_nested_operand_segment_read",
    ".Lresident_nested_operand_segment_ds:",
    "mov rax, {guest_ds_base}",
    "jmp .Lresident_nested_operand_segment_read",
    ".Lresident_nested_operand_segment_fs:",
    "mov rax, {guest_fs_base}",
    "jmp .Lresident_nested_operand_segment_read",
    ".Lresident_nested_operand_segment_gs:",
    "mov rax, {guest_gs_base}",
    ".Lresident_nested_operand_segment_read:",
    "vmread r11, rax",
    "add r14, r11",
    "mov r10, r14",
    "call .Lresident_nested_translate_linear_address",
    "ret",
    ".Lresident_nested_translate_linear_address:",
    "mov rdi, r10",
    "mov rax, {guest_cr0}",
    "vmread r11, rax",
    "bt r11, 31",
    "jnc .Lresident_nested_translate_identity",
    "mov rdx, {host_page_address_mask}",
    "mov rax, {vm_entry_controls}",
    "vmread r11, rax",
    "bt r11, 9",
    "jnc .Lresident_nested_translate_legacy",
    "mov rax, {guest_cr4}",
    "vmread r11, rax",
    "mov ecx, 39",
    "bt r11, 12",
    "jnc .Lresident_nested_translate_long_root",
    "mov ecx, 48",
    ".Lresident_nested_translate_long_root:",
    "mov rax, {guest_cr3}",
    "vmread r11, rax",
    "and r11, rdx",
    ".Lresident_nested_translate_long_level:",
    "mov rax, rdi",
    "shr rax, cl",
    "and eax, 0x1ff",
    "mov r11, qword ptr [r11 + rax * 8]",
    "test r11b, 1",
    "jz .Lresident_nested_translate_failure",
    "cmp ecx, 30",
    "je .Lresident_nested_translate_long_1g",
    "cmp ecx, 21",
    "je .Lresident_nested_translate_long_2m",
    "cmp ecx, 12",
    "je .Lresident_nested_translate_long_4k",
    "and r11, rdx",
    "sub ecx, 9",
    "jmp .Lresident_nested_translate_long_level",
    ".Lresident_nested_translate_long_1g:",
    "test r11b, 0x80",
    "jz .Lresident_nested_translate_long_next",
    "mov r10, r11",
    "mov rax, 0x000fffffc0000000",
    "and r10, rax",
    "mov eax, edi",
    "and eax, 0x3fffffff",
    "or r10, rax",
    "clc",
    "ret",
    ".Lresident_nested_translate_long_2m:",
    "test r11b, 0x80",
    "jz .Lresident_nested_translate_long_next",
    "mov r10, r11",
    "mov rax, 0x000fffffffe00000",
    "and r10, rax",
    "mov eax, edi",
    "and eax, 0x1fffff",
    "or r10, rax",
    "clc",
    "ret",
    ".Lresident_nested_translate_long_next:",
    "and r11, rdx",
    "sub ecx, 9",
    "jmp .Lresident_nested_translate_long_level",
    ".Lresident_nested_translate_long_4k:",
    "and r11, rdx",
    "mov r10, rdi",
    "and r10d, 0xfff",
    "or r10, r11",
    "clc",
    "ret",
    ".Lresident_nested_translate_legacy:",
    "mov rax, {guest_cr4}",
    "vmread r13, rax",
    "bt r13, 5",
    "jnc .Lresident_nested_translate_legacy_32",
    "mov rax, {guest_cr3}",
    "vmread r11, rax",
    "and r11, -32",
    "mov eax, edi",
    "shr eax, 30",
    "and eax, 3",
    "mov r11, qword ptr [r11 + rax * 8]",
    "test r11b, 1",
    "jz .Lresident_nested_translate_failure",
    "and r11, rdx",
    "mov eax, edi",
    "shr eax, 21",
    "and eax, 0x1ff",
    "mov r11, qword ptr [r11 + rax * 8]",
    "test r11b, 1",
    "jz .Lresident_nested_translate_failure",
    "test r11b, 0x80",
    "jnz .Lresident_nested_translate_long_2m",
    "and r11, rdx",
    "mov eax, edi",
    "shr eax, 12",
    "and eax, 0x1ff",
    "mov r11, qword ptr [r11 + rax * 8]",
    "test r11b, 1",
    "jz .Lresident_nested_translate_failure",
    "jmp .Lresident_nested_translate_long_4k",
    ".Lresident_nested_translate_legacy_32:",
    "mov rax, {guest_cr3}",
    "vmread r11, rax",
    "and r11d, 0xfffff000",
    "mov eax, edi",
    "shr eax, 22",
    "mov r11d, dword ptr [r11 + rax * 4]",
    "test r11b, 1",
    "jz .Lresident_nested_translate_failure",
    "test r11b, 0x80",
    "jz .Lresident_nested_translate_legacy_4k",
    "bt r13, 4",
    "jnc .Lresident_nested_translate_failure",
    "and r11d, 0xffc00000",
    "mov r10d, edi",
    "and r10d, 0x3fffff",
    "or r10, r11",
    "clc",
    "ret",
    ".Lresident_nested_translate_legacy_4k:",
    "and r11d, 0xfffff000",
    "mov eax, edi",
    "shr eax, 12",
    "and eax, 0x3ff",
    "mov r11d, dword ptr [r11 + rax * 4]",
    "test r11b, 1",
    "jz .Lresident_nested_translate_failure",
    "and r11d, 0xfffff000",
    "mov r10d, edi",
    "and r10d, 0xfff",
    "or r10, r11",
    "clc",
    "ret",
    ".Lresident_nested_translate_identity:",
    "mov r10, rdi",
    "clc",
    "ret",
    ".Lresident_nested_translate_failure:",
    "mov r10, rdi",
    "stc",
    "ret",
    ".Lresident_nested_physical_address_is_valid:",
    "test r11, 0xfff",
    "jnz .Lresident_nested_physical_address_invalid",
    ".Lresident_nested_address_width_is_valid:",
    "mov eax, 0x80000000",
    "cpuid",
    "cmp eax, 0x80000008",
    "jb .Lresident_nested_physical_address_invalid",
    "mov eax, 0x80000008",
    "cpuid",
    "and eax, 0xff",
    "cmp eax, 64",
    "jae .Lresident_nested_physical_address_valid",
    "mov ecx, eax",
    "mov rax, r11",
    "shr rax, cl",
    "test rax, rax",
    "jnz .Lresident_nested_physical_address_invalid",
    ".Lresident_nested_physical_address_valid:",
    "mov eax, 1",
    "ret",
    ".Lresident_nested_physical_address_invalid:",
    "xor eax, eax",
    "ret",
    ".Lresident_nested_prepare_ept02:",
    "bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31",
    "jnc .Lresident_nested_prepare_ept02_done",
    "bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 1",
    "jnc .Lresident_nested_prepare_ept02_done",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_secondary_control}]",
    "shr edx, 22",
    "and edx, 1",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_ept_pointer}]",
    "cmp rax, qword ptr [r12 + {b_nested_ept12_pointer}]",
    "jne .Lresident_nested_prepare_ept02_other_context",
    "cmp rdx, qword ptr [r12 + {b_nested_ept02_mbec}]",
    "je .Lresident_nested_prepare_ept02_done",
    ".Lresident_nested_prepare_ept02_other_context:",
    "cmp qword ptr [r12 + {b_nested_ept02_cache_initialized}], 0",
    "jne .Lresident_nested_select_ept02_cache",
    // The boot probe selects a precomposed root; runtime caches own separate table pools.
    "mov qword ptr [r12 + {b_nested_ept02_cache_initialized}], 1",
    "mov r11, qword ptr [r12 + {b_nested_ept02_initial_pointer}]",
    "mov qword ptr [r12 + {b_nested_ept02_pointer}], r11",
    "jmp .Lresident_nested_replace_ept02_cache",
    ".Lresident_nested_select_ept02_cache:",
    "call .Lresident_nested_swap_ept02_cache",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_ept_pointer}]",
    "cmp rax, qword ptr [r12 + {b_nested_ept12_pointer}]",
    "jne .Lresident_nested_replace_ept02_cache",
    "cmp rdx, qword ptr [r12 + {b_nested_ept02_mbec}]",
    "je .Lresident_nested_prepare_ept02_done",
    ".Lresident_nested_replace_ept02_cache:",
    "mov qword ptr [r12 + {b_nested_ept12_pointer}], rax",
    "mov qword ptr [r12 + {b_nested_ept02_mbec}], rdx",
    "call .Lresident_nested_invalidate_ept02",
    ".Lresident_nested_prepare_ept02_done:",
    "ret",
    ".Lresident_nested_swap_ept02_cache:",
    "mov rax, qword ptr [r12 + {b_nested_ept12_pointer}]",
    "mov r11, qword ptr [r12 + {b_nested_ept02_cached_ept12_pointer}]",
    "mov qword ptr [r12 + {b_nested_ept02_cached_ept12_pointer}], rax",
    "mov qword ptr [r12 + {b_nested_ept12_pointer}], r11",
    "mov rax, qword ptr [r12 + {b_nested_ept02_pointer}]",
    "mov r11, qword ptr [r12 + {b_nested_ept02_cached_pointer}]",
    "mov qword ptr [r12 + {b_nested_ept02_cached_pointer}], rax",
    "mov qword ptr [r12 + {b_nested_ept02_pointer}], r11",
    "mov rax, qword ptr [r12 + {b_nested_ept02_table_pool}]",
    "mov r11, qword ptr [r12 + {b_nested_ept02_cached_table_pool}]",
    "mov qword ptr [r12 + {b_nested_ept02_cached_table_pool}], rax",
    "mov qword ptr [r12 + {b_nested_ept02_table_pool}], r11",
    "mov rax, qword ptr [r12 + {b_nested_ept02_table_pool_pages}]",
    "mov r11, qword ptr [r12 + {b_nested_ept02_cached_table_pool_pages}]",
    "mov qword ptr [r12 + {b_nested_ept02_cached_table_pool_pages}], rax",
    "mov qword ptr [r12 + {b_nested_ept02_table_pool_pages}], r11",
    "mov rax, qword ptr [r12 + {b_nested_ept02_table_pool_used}]",
    "mov r11, qword ptr [r12 + {b_nested_ept02_cached_table_pool_used}]",
    "mov qword ptr [r12 + {b_nested_ept02_cached_table_pool_used}], rax",
    "mov qword ptr [r12 + {b_nested_ept02_table_pool_used}], r11",
    "mov rax, qword ptr [r12 + {b_nested_ept02_mbec}]",
    "mov r11, qword ptr [r12 + {b_nested_ept02_cached_mbec}]",
    "mov qword ptr [r12 + {b_nested_ept02_cached_mbec}], rax",
    "mov qword ptr [r12 + {b_nested_ept02_mbec}], r11",
    "ret",
    ".Lresident_nested_activate_vmcs02_ept:",
    "mov r11, qword ptr [r12 + {b_nested_ept01_pointer}]",
    "bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31",
    "jnc .Lresident_nested_activate_vmcs02_ept_write",
    "bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 1",
    "jnc .Lresident_nested_activate_vmcs02_ept_write",
    "mov r11, qword ptr [r12 + {b_nested_ept02_pointer}]",
    "bt qword ptr [r12 + {b_nested_vmcs12_ept_pointer}], 6",
    "jnc .Lresident_nested_activate_vmcs02_ept_write",
    "or r11, 0x40",
    ".Lresident_nested_activate_vmcs02_ept_write:",
    "mov rax, {ept_pointer}",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "ret",
    ".Lresident_nested_resolve_ept02_violation:",
    "xor r14d, r14d",
    "xor r15d, r15d",
    "mov rax, {guest_physical_address}",
    "vmread r8, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_last_guest_physical_address}], r8",
    "bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 1",
    "jnc .Lresident_nested_ept02_unresolved",
    "mov r9, qword ptr [r12 + {b_nested_vmcs12_ept_pointer}]",
    "mov edi, 1",
    "call .Lresident_nested_translate_ept02",
    "test eax, eax",
    "jz .Lresident_nested_ept02_unresolved",
    "mov eax, dword ptr [r12 + {b_last_qualification}]",
    "and eax, 7",
    "cmp qword ptr [r12 + {b_nested_ept02_mbec}], 0",
    "je .Lresident_nested_ept02_access_mask_ready",
    "test eax, 4",
    "jz .Lresident_nested_ept02_access_mask_ready",
    "bt dword ptr [r12 + {b_last_qualification}], 9",
    "jnc .Lresident_nested_ept02_access_mask_ready",
    "xor eax, 0x404",
    ".Lresident_nested_ept02_access_mask_ready:",
    "mov edx, r14d",
    "and edx, eax",
    "cmp edx, eax",
    "jne .Lresident_nested_ept02_unresolved",
    "mov r9, qword ptr [r12 + {b_nested_ept02_pointer}]",
    "mov rdx, {host_page_address_mask}",
    "and r9, rdx",
    "mov rcx, r8",
    "shr rcx, 39",
    "and ecx, 0x1ff",
    "mov r10, qword ptr [r9 + rcx * 8]",
    "test r10, 0x407",
    "jnz .Lresident_nested_ept02_pml4_ready",
    "mov rdx, rcx",
    "call .Lresident_nested_allocate_ept02_table",
    "test r11, r11",
    "jz .Lresident_nested_ept02_recycle",
    "mov r10, r11",
    "or r10, 0x407",
    "mov qword ptr [r9 + rdx * 8], r10",
    ".Lresident_nested_ept02_pml4_ready:",
    "mov r9, r10",
    "mov rdx, {host_page_address_mask}",
    "and r9, rdx",
    "mov rcx, r8",
    "shr rcx, 30",
    "and ecx, 0x1ff",
    "mov r10, qword ptr [r9 + rcx * 8]",
    "test r10, 0x407",
    "jnz .Lresident_nested_ept02_pdpt_ready",
    "mov rdx, rcx",
    "call .Lresident_nested_allocate_ept02_table",
    "test r11, r11",
    "jz .Lresident_nested_ept02_recycle",
    "mov r10, r11",
    "or r10, 0x407",
    "mov qword ptr [r9 + rdx * 8], r10",
    ".Lresident_nested_ept02_pdpt_ready:",
    "test r10b, 0x80",
    "jnz .Lresident_nested_ept02_recycle",
    "mov r9, r10",
    "mov rdx, {host_page_address_mask}",
    "and r9, rdx",
    "mov rcx, r8",
    "shr rcx, 21",
    "and ecx, 0x1ff",
    "mov r10, qword ptr [r9 + rcx * 8]",
    "test r10, 0x407",
    "jnz .Lresident_nested_ept02_pd_ready",
    "test r15b, 0x80",
    "jnz .Lresident_nested_ept02_install_large_leaf",
    "mov rdx, rcx",
    "call .Lresident_nested_allocate_ept02_table",
    "test r11, r11",
    "jz .Lresident_nested_ept02_recycle",
    "mov r10, r11",
    "or r10, 0x407",
    "mov qword ptr [r9 + rdx * 8], r10",
    ".Lresident_nested_ept02_pd_ready:",
    "test r10b, 0x80",
    "jz .Lresident_nested_ept02_pt_ready",
    "test r15b, 0x80",
    "jnz .Lresident_nested_ept02_install_large_leaf",
    "jmp .Lresident_nested_ept02_recycle",
    ".Lresident_nested_ept02_pt_ready:",
    "mov r9, r10",
    "mov rdx, {host_page_address_mask}",
    "and r9, rdx",
    "mov rcx, r8",
    "shr rcx, 12",
    "and ecx, 0x1ff",
    "and r15d, 0x338",
    "jmp .Lresident_nested_ept02_install_leaf",
    ".Lresident_nested_ept02_install_large_leaf:",
    "and r13, -2097152",
    ".Lresident_nested_ept02_install_leaf:",
    "or r13, r14",
    "or r13, r15",
    "mov rbp, qword ptr [r9 + rcx * 8]",
    "mov qword ptr [r9 + rcx * 8], r13",
    "inc qword ptr [r12 + {b_nested_ept_composition_count}]",
    "test ebp, 0x407",
    "jz .Lresident_nested_ept02_installed",
    "inc qword ptr [r12 + {b_nested_ept02_invalidation_count}]",
    "call .Lresident_nested_flush_ept02",
    ".Lresident_nested_ept02_installed:",
    "mov eax, 1",
    "ret",
    ".Lresident_nested_ept02_recycle:",
    // Exhausting L0's translation cache is not an EPT12 permission violation.
    // INVEPT retires the old translations before the table pages are reused.
    "call .Lresident_nested_invalidate_ept02",
    "jmp .Lresident_nested_resolve_ept02_violation",
    ".Lresident_nested_ept02_unresolved:",
    "mov r10, qword ptr [r12 + {b_last_qualification}]",
    "and r10, -121",
    "mov rax, r14",
    "and eax, 7",
    "shl rax, 3",
    "or r10, rax",
    "mov rax, r14",
    "and eax, 0x400",
    "shr rax, 4",
    "or r10, rax",
    "mov qword ptr [r12 + {b_last_qualification}], r10",
    "xor eax, eax",
    "ret",
    ".Lresident_nested_translate_ept02:",
    "mov rbp, r9",
    "xor r14d, r14d",
    "xor r15d, r15d",
    "mov rdx, {host_page_address_mask}",
    "and r9, rdx",
    "test r9, r9",
    "jz .Lresident_nested_translate_ept02_failed",
    "mov r14d, 7",
    "cmp qword ptr [r12 + {b_nested_ept02_mbec}], 0",
    "je .Lresident_nested_ept12_mode_ready",
    "or r14d, 0x400",
    ".Lresident_nested_ept12_mode_ready:",
    "mov r11, r9",
    "call .Lresident_nested_host_page_is_mapped",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "mov rcx, r8",
    "shr rcx, 39",
    "and ecx, 0x1ff",
    "lea rsi, [r9 + rcx * 8]",
    "mov r10, qword ptr [rsi]",
    "mov eax, r10d",
    "and eax, r14d",
    "mov r14d, eax",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "call .Lresident_nested_track_ept12_access",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "mov r9, r10",
    "mov rdx, {host_page_address_mask}",
    "and r9, rdx",
    "mov r11, r9",
    "call .Lresident_nested_host_page_is_mapped",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "mov rcx, r8",
    "shr rcx, 30",
    "and ecx, 0x1ff",
    "lea rsi, [r9 + rcx * 8]",
    "mov r10, qword ptr [rsi]",
    "mov eax, r10d",
    "and eax, r14d",
    "mov r14d, eax",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "call .Lresident_nested_track_ept12_access",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "test r10b, 0x80",
    "jnz .Lresident_nested_ept12_1g_leaf",
    "mov r9, r10",
    "mov rdx, {host_page_address_mask}",
    "and r9, rdx",
    "mov r11, r9",
    "call .Lresident_nested_host_page_is_mapped",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "mov rcx, r8",
    "shr rcx, 21",
    "and ecx, 0x1ff",
    "lea rsi, [r9 + rcx * 8]",
    "mov r10, qword ptr [rsi]",
    "mov eax, r10d",
    "and eax, r14d",
    "mov r14d, eax",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "call .Lresident_nested_track_ept12_access",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "test r10b, 0x80",
    "jnz .Lresident_nested_ept12_2m_leaf",
    "mov r9, r10",
    "mov rdx, {host_page_address_mask}",
    "and r9, rdx",
    "mov r11, r9",
    "call .Lresident_nested_host_page_is_mapped",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "mov rcx, r8",
    "shr rcx, 12",
    "and ecx, 0x1ff",
    "lea rsi, [r9 + rcx * 8]",
    "mov r10, qword ptr [rsi]",
    "mov eax, r10d",
    "and eax, r14d",
    "mov r14d, eax",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "call .Lresident_nested_track_ept12_access",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "mov r13, r10",
    "mov rdx, {host_page_address_mask}",
    "and r13, rdx",
    "mov eax, r8d",
    "and eax, 0xfff",
    "add r13, rax",
    "jmp .Lresident_nested_ept12_translation_ready",
    ".Lresident_nested_ept12_2m_leaf:",
    "mov r15d, 0x80",
    "mov r13, r10",
    "mov rdx, {host_page_address_mask}",
    "and r13, rdx",
    "and r13, -2097152",
    "mov eax, r8d",
    "and eax, 0x1fffff",
    "add r13, rax",
    "jmp .Lresident_nested_ept12_translation_ready",
    ".Lresident_nested_ept12_1g_leaf:",
    "mov r15d, 0x80",
    "mov r13, r10",
    "mov rdx, {host_page_address_mask}",
    "and r13, rdx",
    "and r13, -1073741824",
    "mov eax, r8d",
    "and eax, 0x3fffffff",
    "add r13, rax",
    ".Lresident_nested_ept12_translation_ready:",
    "mov ebx, r10d",
    "and ebx, 0x38",
    "and r13, -4096",
    "mov r11, r13",
    "call .Lresident_nested_host_page_is_mapped",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    // Large composed leaves require uniform permissions and translations in both EPTs.
    "mov r9, qword ptr [r12 + {b_nested_ept01_pointer}]",
    "mov rdx, {host_page_address_mask}",
    "and r9, rdx",
    "mov rcx, r13",
    "shr rcx, 39",
    "and ecx, 0x1ff",
    "mov r10, qword ptr [r9 + rcx * 8]",
    "mov eax, r10d",
    "and eax, 7",
    "mov ecx, eax",
    "and ecx, 4",
    "shl ecx, 8",
    "or eax, ecx",
    "and r14, rax",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "mov r9, r10",
    "and r9, rdx",
    "mov rcx, r13",
    "shr rcx, 30",
    "and ecx, 0x1ff",
    "mov r10, qword ptr [r9 + rcx * 8]",
    "mov eax, r10d",
    "and eax, 7",
    "mov ecx, eax",
    "and ecx, 4",
    "shl ecx, 8",
    "or eax, ecx",
    "and r14, rax",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "test r10b, 0x80",
    "jnz .Lresident_nested_ept01_30_leaf",
    "mov r9, r10",
    "and r9, rdx",
    "mov rcx, r13",
    "shr rcx, 21",
    "and ecx, 0x1ff",
    "mov r10, qword ptr [r9 + rcx * 8]",
    "mov eax, r10d",
    "and eax, 7",
    "mov ecx, eax",
    "and ecx, 4",
    "shl ecx, 8",
    "or eax, ecx",
    "and r14, rax",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "test r10b, 0x80",
    "jnz .Lresident_nested_ept01_21_leaf",
    "mov r9, r10",
    "and r9, rdx",
    "mov rcx, r13",
    "shr rcx, 12",
    "and ecx, 0x1ff",
    "mov r10, qword ptr [r9 + rcx * 8]",
    "mov eax, r10d",
    "and eax, 7",
    "mov ecx, eax",
    "and ecx, 4",
    "shl ecx, 8",
    "or eax, ecx",
    "and r14, rax",
    "test eax, eax",
    "jz .Lresident_nested_translate_ept02_failed",
    "xor r15d, r15d",
    "mov eax, r13d",
    "and eax, 0xfff",
    "mov r13, r10",
    "and r13, rdx",
    "or r13, rax",
    "jmp .Lresident_nested_ept01_translation_ready",
    ".Lresident_nested_ept01_21_leaf:",
    "mov eax, r13d",
    "and eax, 2097151",
    "mov r13, r10",
    "and r13, rdx",
    "and r13, -2097152",
    "or r13, rax",
    "jmp .Lresident_nested_ept01_translation_ready",
    ".Lresident_nested_ept01_30_leaf:",
    "mov eax, r13d",
    "and eax, 1073741823",
    "mov r13, r10",
    "and r13, rdx",
    "and r13, -1073741824",
    "or r13, rax",
    "jmp .Lresident_nested_ept01_translation_ready",
    ".Lresident_nested_ept01_translation_ready:",
    "cmp ebx, 0x30",
    "jne .Lresident_nested_ept02_memory_type_ready",
    "mov eax, r10d",
    "and eax, 0x38",
    "cmp eax, 0x30",
    "jne .Lresident_nested_ept02_memory_type_ready",
    "or r15d, 0x30",
    ".Lresident_nested_ept02_memory_type_ready:",
    "and r13, -4096",
    "test bpl, 0x40",
    "jz .Lresident_nested_translate_ept02_success",
    // Hardware A/D keeps guest page walks classified as writes. EPT12 tracking is
    // maintained in software; clean leaves remain write-protected until first use.
    "or r15d, 0x300",
    "bt qword ptr [rsi], 9",
    "jc .Lresident_nested_translate_ept02_success",
    "test edi, edi",
    "jz .Lresident_nested_ept02_clean_leaf",
    "test byte ptr [r12 + {b_last_qualification}], 2",
    "jz .Lresident_nested_ept02_clean_leaf",
    "test r14b, 2",
    "jz .Lresident_nested_translate_ept02_success",
    "lock bts qword ptr [rsi], 9",
    "jmp .Lresident_nested_translate_ept02_success",
    ".Lresident_nested_ept02_clean_leaf:",
    "and r14d, -3",
    ".Lresident_nested_translate_ept02_success:",
    "mov eax, 1",
    "ret",
    ".Lresident_nested_translate_ept02_failed:",
    "xor eax, eax",
    "ret",
    ".Lresident_nested_track_ept12_access:",
    "test bpl, 0x40",
    "jz .Lresident_nested_ept12_access_ready",
    "test r10d, 0x100",
    "jnz .Lresident_nested_ept12_access_ready",
    "test edi, edi",
    "jz .Lresident_nested_translate_ept02_failed",
    "lock bts qword ptr [rsi], 8",
    ".Lresident_nested_ept12_access_ready:",
    "mov eax, 1",
    "ret",
    ".Lresident_nested_allocate_ept02_table:",
    "mov rax, qword ptr [r12 + {b_nested_ept02_table_pool_used}]",
    "cmp rax, qword ptr [r12 + {b_nested_ept02_table_pool_pages}]",
    "jae .Lresident_nested_allocate_ept02_table_failed",
    "mov r11, rax",
    "shl r11, 12",
    "add r11, qword ptr [r12 + {b_nested_ept02_table_pool}]",
    "inc qword ptr [r12 + {b_nested_ept02_table_pool_used}]",
    "mov rdi, r11",
    "xor eax, eax",
    "mov ecx, 512",
    "cld",
    "rep stosq",
    "ret",
    ".Lresident_nested_allocate_ept02_table_failed:",
    "xor r11d, r11d",
    "ret",
    ".Lresident_nested_invalidate_ept02:",
    "inc qword ptr [r12 + {b_nested_ept02_invalidation_count}]",
    "mov r8, qword ptr [r12 + {b_nested_ept02_pointer}]",
    "mov rdx, {host_page_address_mask}",
    "and r8, rdx",
    "mov rdi, r8",
    "mov ecx, 512",
    "xor eax, eax",
    "cld",
    "rep stosq",
    "mov rdi, qword ptr [r12 + {b_nested_ept02_table_pool}]",
    "mov rcx, qword ptr [r12 + {b_nested_ept02_table_pool_used}]",
    "shl rcx, 9",
    "rep stosq",
    "mov qword ptr [r12 + {b_nested_ept02_table_pool_used}], 0",
    ".Lresident_nested_flush_ept02:",
    "sub rsp, 16",
    "mov r11, qword ptr [r12 + {b_nested_ept02_pointer}]",
    "mov qword ptr [rsp], r11",
    "mov qword ptr [rsp + 8], 0",
    "mov eax, 1",
    "invept rax, xmmword ptr [rsp]",
    "lea rsp, [rsp + 16]",
    "jna .Lresident_dispatch_halt",
    "ret",
    // Re-read both EPT levels before retaining a cached leaf across an L1 invalidation.
    // Revoked access and split large pages are removed before the hardware INVEPT.
    ".Lresident_nested_revalidate_ept02:",
    "cmp qword ptr [r12 + {b_nested_ept02_cache_initialized}], 0",
    "je .Lresident_nested_invalidate_ept02",
    "inc qword ptr [r12 + {b_nested_ept02_invalidation_count}]",
    "mov rdi, qword ptr [r12 + {b_nested_ept02_pointer}]",
    "mov rax, {host_page_address_mask}",
    "and rdi, rax",
    "xor r8d, r8d",
    "mov ecx, 39",
    "call .Lresident_nested_revalidate_ept02_table",
    "jmp .Lresident_nested_flush_ept02",
    ".Lresident_nested_revalidate_ept02_table:",
    "sub rsp, 48",
    "mov qword ptr [rsp], rdi",
    "mov qword ptr [rsp + 8], r8",
    "mov qword ptr [rsp + 16], rcx",
    "mov qword ptr [rsp + 24], 0",
    ".Lresident_nested_revalidate_ept02_entry:",
    "mov rax, qword ptr [rsp + 24]",
    "mov rdi, qword ptr [rsp]",
    "lea rdi, [rdi + rax * 8]",
    "mov r10, qword ptr [rdi]",
    "test r10, 0x407",
    "jz .Lresident_nested_revalidate_ept02_next",
    "mov rcx, qword ptr [rsp + 16]",
    "shl rax, cl",
    "mov r8, qword ptr [rsp + 8]",
    "or r8, rax",
    "cmp ecx, 12",
    "je .Lresident_nested_revalidate_ept02_leaf",
    "test r10b, 0x80",
    "jnz .Lresident_nested_revalidate_ept02_leaf",
    "mov rdi, {host_page_address_mask}",
    "and rdi, r10",
    "sub ecx, 9",
    "call .Lresident_nested_revalidate_ept02_table",
    "jmp .Lresident_nested_revalidate_ept02_next",
    ".Lresident_nested_revalidate_ept02_leaf:",
    "mov qword ptr [rsp + 32], rdi",
    "mov r9, qword ptr [r12 + {b_nested_ept12_pointer}]",
    "xor edi, edi",
    "call .Lresident_nested_translate_ept02",
    "test eax, eax",
    "jz .Lresident_nested_revalidate_ept02_remove",
    "cmp qword ptr [rsp + 16], 12",
    "je .Lresident_nested_revalidate_ept02_small_leaf",
    "cmp qword ptr [rsp + 16], 21",
    "jne .Lresident_nested_revalidate_ept02_remove",
    "test r15b, 0x80",
    "jz .Lresident_nested_revalidate_ept02_remove",
    "and r13, -2097152",
    "jmp .Lresident_nested_revalidate_ept02_write",
    ".Lresident_nested_revalidate_ept02_small_leaf:",
    "and r15d, 0x338",
    ".Lresident_nested_revalidate_ept02_write:",
    "or r13, r14",
    "or r13, r15",
    "mov rdi, qword ptr [rsp + 32]",
    "cmp qword ptr [rdi], r13",
    "je .Lresident_nested_revalidate_ept02_next",
    "mov qword ptr [rdi], r13",
    "jmp .Lresident_nested_revalidate_ept02_next",
    ".Lresident_nested_revalidate_ept02_remove:",
    "mov rdi, qword ptr [rsp + 32]",
    "mov qword ptr [rdi], 0",
    ".Lresident_nested_revalidate_ept02_next:",
    "inc qword ptr [rsp + 24]",
    "cmp qword ptr [rsp + 24], 512",
    "jne .Lresident_nested_revalidate_ept02_entry",
    "add rsp, 48",
    "ret",
    ".Lresident_nested_host_page_is_mapped:",
    "mov rax, qword ptr [r12 + {b_expected_host_cr3}]",
    "mov rdx, {host_page_address_mask}",
    "and rax, rdx",
    "mov rcx, r11",
    "shr rcx, 39",
    "and ecx, 0x1ff",
    "mov rax, qword ptr [rax + rcx * 8]",
    "test al, 1",
    "jz .Lresident_nested_host_page_is_unmapped",
    "and rax, rdx",
    "mov rcx, r11",
    "shr rcx, 30",
    "and ecx, 0x1ff",
    "mov rax, qword ptr [rax + rcx * 8]",
    "test al, 1",
    "jz .Lresident_nested_host_page_is_unmapped",
    "test al, 0x80",
    "jnz .Lresident_nested_host_page_is_mapped_success",
    "and rax, rdx",
    "mov rcx, r11",
    "shr rcx, 21",
    "and ecx, 0x1ff",
    "mov rax, qword ptr [rax + rcx * 8]",
    "test al, 1",
    "jz .Lresident_nested_host_page_is_unmapped",
    "test al, 0x80",
    "jnz .Lresident_nested_host_page_is_mapped_success",
    "and rax, rdx",
    "mov rcx, r11",
    "shr rcx, 12",
    "and ecx, 0x1ff",
    "mov rax, qword ptr [rax + rcx * 8]",
    "test al, 1",
    "jz .Lresident_nested_host_page_is_unmapped",
    ".Lresident_nested_host_page_is_mapped_success:",
    "mov eax, 1",
    "ret",
    ".Lresident_nested_host_page_is_unmapped:",
    "xor eax, eax",
    "ret",
    ".Lresident_nested_host_msr_list_is_mapped:",
    "test r10d, r10d",
    "jz .Lresident_nested_host_msr_list_is_mapped_success",
    "mov r8, r11",
    "mov r9d, r10d",
    "shl r9, 4",
    "add r9, r8",
    "jc .Lresident_nested_host_msr_list_is_unmapped",
    "dec r9",
    "and r8, -4096",
    "and r9, -4096",
    ".Lresident_nested_host_msr_list_page_loop:",
    "mov r11, r8",
    "call .Lresident_nested_host_page_is_mapped",
    "test eax, eax",
    "jz .Lresident_nested_host_msr_list_is_unmapped",
    "cmp r8, r9",
    "je .Lresident_nested_host_msr_list_is_mapped_success",
    "add r8, 4096",
    "jmp .Lresident_nested_host_msr_list_page_loop",
    ".Lresident_nested_host_msr_list_is_mapped_success:",
    "mov eax, 1",
    "ret",
    ".Lresident_nested_host_msr_list_is_unmapped:",
    "xor eax, eax",
    "ret",
    ".Lresident_nested_exit_store_list_is_safe:",
    "test r10d, r10d",
    "jz .Lresident_nested_exit_store_list_is_safe_success",
    "mov r8, rsi",
    "mov r9d, r10d",
    ".Lresident_nested_exit_store_list_is_safe_loop:",
    "cmp dword ptr [r8 + 4], 0",
    "jne .Lresident_nested_exit_store_list_is_unsafe",
    "mov eax, dword ptr [r8]",
    "cmp eax, {spec_ctrl_msr}",
    "je .Lresident_nested_exit_store_list_is_safe_next",
    "cmp eax, {kernel_gs_base_msr}",
    "je .Lresident_nested_exit_store_list_is_safe_next",
    "cmp eax, {tsc_aux_msr}",
    "je .Lresident_nested_exit_store_list_is_safe_next",
    "cmp eax, {star_msr}",
    "je .Lresident_nested_exit_store_list_is_safe_next",
    "cmp eax, {lstar_msr}",
    "je .Lresident_nested_exit_store_list_is_safe_next",
    "cmp eax, {cstar_msr}",
    "je .Lresident_nested_exit_store_list_is_safe_next",
    "cmp eax, {fmask_msr}",
    "je .Lresident_nested_exit_store_list_is_safe_next",
    "cmp eax, {tsc_msr}",
    "jne .Lresident_nested_exit_store_list_is_unsafe",
    ".Lresident_nested_exit_store_list_is_safe_next:",
    "add r8, 16",
    "dec r9d",
    "jnz .Lresident_nested_exit_store_list_is_safe_loop",
    ".Lresident_nested_exit_store_list_is_safe_success:",
    "mov eax, 1",
    "ret",
    ".Lresident_nested_exit_store_list_is_unsafe:",
    "xor eax, eax",
    "ret",
    ".Lresident_nested_store_current_vmcs12:",
    "mov rdi, qword ptr [r12 + {b_nested_current_vmcs}]",
    "cmp rdi, -1",
    "je .Lresident_nested_store_current_vmcs12_done",
    "mov rax, {vmcs12_backing_magic}",
    "mov qword ptr [rdi + {vmcs12_backing_magic_offset}], rax",
    "add rdi, {vmcs12_backing_state_offset}",
    "lea rsi, [r12 + {b_nested_vmcs12_operand}]",
    "mov ecx, {vmcs12_backing_qword_count}",
    "cld",
    "rep movsq",
    ".Lresident_nested_store_current_vmcs12_done:",
    "ret",
    ".Lresident_nested_initialize_vmcs12_backing:",
    "mov rax, {vmcs12_backing_magic}",
    "cmp qword ptr [r11 + {vmcs12_backing_magic_offset}], rax",
    "je .Lresident_nested_initialize_vmcs12_backing_done",
    "lea rdi, [r11 + {vmcs12_backing_state_offset}]",
    "xor eax, eax",
    "mov ecx, {vmcs12_backing_qword_count}",
    "cld",
    "rep stosq",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_revision_id}]",
    "mov qword ptr [r11 + {vmcs12_backing_state_offset} + {vmcs12_revision_id_offset}], rax",
    "mov qword ptr [r11 + {vmcs12_backing_state_offset} + {vmcs12_launch_state_offset}], {vmcs12_launch_state_clear}",
    ".Lresident_nested_initialize_vmcs12_backing_mark:",
    "mov rax, {vmcs12_backing_magic}",
    "mov qword ptr [r11 + {vmcs12_backing_magic_offset}], rax",
    ".Lresident_nested_initialize_vmcs12_backing_done:",
    "ret",
    ".Lresident_nested_load_vmcs12_backing:",
    "lea rsi, [r11 + {vmcs12_backing_state_offset}]",
    "lea rdi, [r12 + {b_nested_vmcs12_operand}]",
    "mov ecx, {vmcs12_backing_qword_count}",
    "cld",
    "rep movsq",
    "ret",
    ".Lresident_dispatch_vmclear:",
    "cmp qword ptr [r12 + {b_nested_active}], 1",
    "jne .Lresident_nested_inject_ud",
    "mov rax, {guest_cs_selector}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "test r11b, 3",
    "jnz .Lresident_nested_inject_gp",
    "call .Lresident_nested_decode_memory_operand",
    "jc .Lresident_nested_inject_pf_read",
    "mov r14, r10",
    "mov r11, qword ptr [r10]",
    "mov qword ptr [r12 + {b_nested_last_operand}], r11",
    "call .Lresident_nested_physical_address_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_vmclear_invalid_address",
    "cmp r11, qword ptr [r12 + {b_nested_vmxon_region}]",
    "je .Lresident_nested_vmclear_vmxon_pointer",
    "xor r13d, r13d",
    "cmp r11, qword ptr [r12 + {b_nested_current_vmcs}]",
    "jne .Lresident_nested_vmclear_not_current",
    "mov r13d, 1",
    "call .Lresident_nested_store_current_vmcs12",
    ".Lresident_nested_vmclear_not_current:",
    "call .Lresident_nested_initialize_vmcs12_backing",
    "inc qword ptr [r11 + {vmcs12_backing_state_offset} + {vmcs12_vmclear_count_offset}]",
    "mov qword ptr [r11 + {vmcs12_backing_state_offset} + {vmcs12_launch_state_offset}], {vmcs12_launch_state_clear}",
    "vmclear [r12 + {b_nested_vmcs02_region}]",
    "jna .Lresident_dispatch_halt",
    "mov qword ptr [r12 + {b_nested_vmcs02_launched}], 0",
    "mov qword ptr [r12 + {b_nested_vmcs02_guest_cache_valid}], 0",
    "mov qword ptr [r12 + {b_nested_vmcs02_control_cache_valid}], 0",
    "mov qword ptr [r12 + {b_nested_vmcs02_control_cache_valid} + 8], 0",
    "test r13d, r13d",
    "jz .Lresident_nested_succeed",
    "mov rax, qword ptr [r11 + {vmcs12_backing_state_offset} + {vmcs12_vmclear_count_offset}]",
    "mov qword ptr [r12 + {b_nested_vmclear_count}], rax",
    "mov qword ptr [r12 + {b_nested_vmcs12_launch_state}], {vmcs12_launch_state_clear}",
    "mov qword ptr [r12 + {b_nested_current_vmcs}], -1",
    "jmp .Lresident_nested_succeed",
    ".Lresident_nested_vmclear_invalid_address:",
    "mov r10d, {vmclear_invalid_physical_address_error}",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_nested_vmclear_vmxon_pointer:",
    "mov r10d, {vmclear_vmxon_pointer_error}",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_dispatch_vmlaunch:",
    "inc qword ptr [r12 + {b_nested_vmlaunch_count}]",
    "inc qword ptr [r12 + {b_nested_entry_rejection_count}]",
    "cmp qword ptr [r12 + {b_nested_active}], 1",
    "jne .Lresident_nested_inject_ud",
    "mov rax, {guest_cs_selector}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "test r11b, 3",
    "jnz .Lresident_nested_inject_gp",
    "cmp qword ptr [r12 + {b_nested_current_vmcs}], -1",
    "je .Lresident_nested_vmfail_invalid",
    "mov rax, {guest_interruptibility_info}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "test r11b, 2",
    "jnz .Lresident_nested_entry_mov_ss",
    "cmp qword ptr [r12 + {b_nested_vmcs12_launch_state}], {vmcs12_launch_state_clear}",
    "jne .Lresident_nested_vmlaunch_non_clear",
    "call .Lresident_nested_validate_entry",
    "test r10d, r10d",
    "jnz .Lresident_nested_vmfail_with_error",
    "call .Lresident_nested_snapshot_vmcs01_effective_state",
    "dec qword ptr [r12 + {b_nested_entry_rejection_count}]",
    "mov qword ptr [r12 + {b_nested_l2_entry_was_resume}], 0",
    "mov qword ptr [r12 + {b_nested_l2_active}], 1",
    "inc qword ptr [r12 + {b_nested_l2_entry_count}]",
    "vmptrld [r12 + {b_nested_vmcs02_region}]",
    "jna .Lresident_dispatch_halt",
    "call .Lresident_nested_prepare_ept02",
    "call .Lresident_nested_merge_vmcs02_controls",
    "call .Lresident_nested_sync_vmcs02_guest_state",
    "call .Lresident_nested_activate_vmcs02_ept",
    "mov rax, {guest_rip}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rip}]",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_rsp}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rsp}]",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_rflags}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rflags}]",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "jmp .Lresident_nested_l2_enter",
    ".Lresident_nested_vmlaunch_non_clear:",
    "mov r10d, {vmlaunch_non_clear_vmcs_error}",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_dispatch_vmptrld:",
    "cmp qword ptr [r12 + {b_nested_active}], 1",
    "jne .Lresident_nested_inject_ud",
    "mov rax, {guest_cs_selector}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "test r11b, 3",
    "jnz .Lresident_nested_inject_gp",
    "call .Lresident_nested_decode_memory_operand",
    "jc .Lresident_nested_inject_pf_read",
    "mov r14, r10",
    "mov r11, qword ptr [r10]",
    "mov qword ptr [r12 + {b_nested_last_operand}], r11",
    "call .Lresident_nested_physical_address_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_vmptrld_invalid_address",
    "cmp r11, qword ptr [r12 + {b_nested_vmxon_region}]",
    "je .Lresident_nested_vmptrld_vmxon_pointer",
    "mov edx, dword ptr [r11]",
    "and edx, 0x7fffffff",
    "cmp rdx, qword ptr [r12 + {b_nested_vmcs12_revision_id}]",
    "jne .Lresident_nested_vmptrld_bad_revision",
    "bt dword ptr [r11], 31",
    "jc .Lresident_nested_vmptrld_bad_revision",
    "cmp r11, qword ptr [r12 + {b_nested_current_vmcs}]",
    "je .Lresident_nested_vmptrld_state_ready",
    "call .Lresident_nested_store_current_vmcs12",
    "call .Lresident_nested_initialize_vmcs12_backing",
    "call .Lresident_nested_load_vmcs12_backing",
    ".Lresident_nested_vmptrld_state_ready:",
    "mov qword ptr [r12 + {b_nested_vmcs12_operand}], r14",
    "mov qword ptr [r12 + {b_nested_vmcs12_region}], r11",
    "mov qword ptr [r12 + {b_nested_current_vmcs}], r11",
    "inc qword ptr [r12 + {b_nested_vmptrld_count}]",
    "jmp .Lresident_nested_succeed",
    ".Lresident_nested_vmptrld_invalid_address:",
    "mov r10d, {vmptrld_invalid_physical_address_error}",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_nested_vmptrld_vmxon_pointer:",
    "mov r10d, {vmptrld_vmxon_pointer_error}",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_nested_vmptrld_bad_revision:",
    "mov r10d, {vmptrld_incorrect_revision_error}",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_dispatch_vmptrst:",
    "inc qword ptr [r12 + {b_nested_vmptrst_count}]",
    "cmp qword ptr [r12 + {b_nested_active}], 1",
    "jne .Lresident_nested_inject_ud",
    "mov rax, {guest_cs_selector}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "test r11b, 3",
    "jnz .Lresident_nested_inject_gp",
    "call .Lresident_nested_decode_memory_operand",
    "jc .Lresident_nested_inject_pf_write",
    "mov qword ptr [r12 + {b_nested_vmptrst_destination}], r10",
    "mov r11, qword ptr [r12 + {b_nested_current_vmcs}]",
    "mov qword ptr [r10], r11",
    "mov qword ptr [r12 + {b_nested_last_stored_pointer}], r11",
    "jmp .Lresident_nested_succeed",
    ".Lresident_dispatch_vmwrite:",
    "inc qword ptr [r12 + {b_nested_vmwrite_count}]",
    "cmp qword ptr [r12 + {b_nested_active}], 1",
    "jne .Lresident_nested_inject_ud",
    "mov rax, {guest_cs_selector}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "test r11b, 3",
    "jnz .Lresident_nested_inject_gp",
    "cmp qword ptr [r12 + {b_nested_current_vmcs}], -1",
    "je .Lresident_nested_vmfail_invalid",
    "mov rax, {exit_instruction_info}",
    "vmread r13, rax",
    "mov eax, r13d",
    "shr eax, 28",
    "and eax, 15",
    "mov r15, rsp",
    "call .Lresident_nested_read_gpr",
    "mov r10, r11",
    "bt r13d, 10",
    "jnc .Lresident_nested_vmwrite_memory_value",
    "mov eax, r13d",
    "shr eax, 3",
    "and eax, 15",
    "mov r15, rsp",
    "call .Lresident_nested_read_gpr",
    "jmp .Lresident_nested_vmwrite_operands_ready",
    ".Lresident_nested_vmwrite_memory_value:",
    "mov rbx, r10",
    "call .Lresident_nested_decode_memory_operand",
    "jc .Lresident_nested_inject_pf_read",
    "mov r11, qword ptr [r10]",
    "mov r10, rbx",
    ".Lresident_nested_vmwrite_operands_ready:",
    "cmp r10, {vmcs_field_guest_rip}",
    "je .Lresident_nested_vmwrite_guest_rip",
    "cmp r10, {vmcs_field_guest_rsp}",
    "je .Lresident_nested_vmwrite_guest_rsp",
    "cmp r10, {vmcs_field_guest_rflags}",
    "je .Lresident_nested_vmwrite_guest_rflags",
    "cmp r10, {vmcs_field_host_rsp}",
    "je .Lresident_nested_vmwrite_host_rsp",
    "cmp r10, {vmcs_field_host_rip}",
    "je .Lresident_nested_vmwrite_host_rip",
    "cmp r10, {vmcs_field_instruction_error}",
    "je .Lresident_nested_vmwrite_read_only",
    "cmp r10, {vmcs_field_exit_reason}",
    "je .Lresident_nested_vmwrite_read_only",
    "cmp r10, {vmcs_field_exit_instruction_len}",
    "je .Lresident_nested_vmwrite_read_only",
    "cmp r10, {vmcs_field_exit_instruction_info}",
    "je .Lresident_nested_vmwrite_read_only",
    "cmp r10, {vmcs_field_exit_qualification}",
    "je .Lresident_nested_vmwrite_read_only",
    "cmp r10, {vmcs_field_exit_intr_info}",
    "je .Lresident_nested_vmwrite_read_only",
    "cmp r10, {vmcs_field_exit_intr_error}",
    "je .Lresident_nested_vmwrite_read_only",
    "cmp r10, {vmcs_field_idt_vectoring_info}",
    "je .Lresident_nested_vmwrite_read_only",
    "cmp r10, {vmcs_field_idt_vectoring_error}",
    "je .Lresident_nested_vmwrite_read_only",
    "cmp r10, {vmcs_field_guest_physical_address}",
    "je .Lresident_nested_vmwrite_read_only",
    "cmp r10, {vmcs_field_guest_linear_address}",
    "je .Lresident_nested_vmwrite_read_only",
    "mov rdx, r10",
    "mov rax, r10",
    "and rax, 0x6000",
    "cmp rax, 0x2000",
    "jne .Lresident_nested_vmwrite_extended_lookup",
    "and rdx, -2",
    ".Lresident_nested_vmwrite_extended_lookup:",
    "call .Lresident_vmcs12_field_index",
    "cmp eax, {vmcs12_extended_field_count}",
    "jb .Lresident_nested_vmwrite_extended",
    "mov r10d, {vmcs_unsupported_component_error}",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_nested_vmwrite_extended:",
    "cmp rdx, r10",
    "je .Lresident_nested_vmwrite_extended_full",
    "shl r11, 32",
    "mov rsi, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + rax * 8]",
    "mov esi, esi",
    "or r11, rsi",
    ".Lresident_nested_vmwrite_extended_full:",
    "mov qword ptr [r12 + {b_nested_vmcs12_extended_fields} + rax * 8], r11",
    "jmp .Lresident_nested_succeed",
    ".Lresident_nested_vmwrite_read_only:",
    "mov r10d, {vmwrite_read_only_component_error}",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_nested_vmwrite_guest_rip:",
    "mov qword ptr [r12 + {b_nested_vmcs12_guest_rip}], r11",
    "jmp .Lresident_nested_succeed",
    ".Lresident_nested_vmwrite_guest_rsp:",
    "mov qword ptr [r12 + {b_nested_vmcs12_guest_rsp}], r11",
    "jmp .Lresident_nested_succeed",
    ".Lresident_nested_vmwrite_guest_rflags:",
    "mov qword ptr [r12 + {b_nested_vmcs12_guest_rflags}], r11",
    "jmp .Lresident_nested_succeed",
    ".Lresident_nested_vmwrite_host_rsp:",
    "mov qword ptr [r12 + {b_nested_vmcs12_host_rsp}], r11",
    "jmp .Lresident_nested_succeed",
    ".Lresident_nested_vmwrite_host_rip:",
    "mov qword ptr [r12 + {b_nested_vmcs12_host_rip}], r11",
    "jmp .Lresident_nested_succeed",
    ".Lresident_dispatch_vmread:",
    "inc qword ptr [r12 + {b_nested_vmread_count}]",
    "cmp qword ptr [r12 + {b_nested_active}], 1",
    "jne .Lresident_nested_inject_ud",
    "mov rax, {guest_cs_selector}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "test r11b, 3",
    "jnz .Lresident_nested_inject_gp",
    "cmp qword ptr [r12 + {b_nested_current_vmcs}], -1",
    "je .Lresident_nested_vmfail_invalid",
    "mov rax, {exit_instruction_info}",
    "vmread r13, rax",
    "mov eax, r13d",
    "shr eax, 28",
    "and eax, 15",
    "mov r15, rsp",
    "call .Lresident_nested_read_gpr",
    "mov r10, r11",
    "cmp r10, {vmcs_field_guest_rip}",
    "je .Lresident_nested_vmread_guest_rip",
    "cmp r10, {vmcs_field_guest_rsp}",
    "je .Lresident_nested_vmread_guest_rsp",
    "cmp r10, {vmcs_field_guest_rflags}",
    "je .Lresident_nested_vmread_guest_rflags",
    "cmp r10, {vmcs_field_host_rsp}",
    "je .Lresident_nested_vmread_host_rsp",
    "cmp r10, {vmcs_field_host_rip}",
    "je .Lresident_nested_vmread_host_rip",
    "cmp r10, {vmcs_field_instruction_error}",
    "je .Lresident_nested_vmread_instruction_error",
    "cmp r10, {vmcs_field_exit_reason}",
    "je .Lresident_nested_vmread_exit_reason",
    "cmp r10, {vmcs_field_exit_instruction_len}",
    "je .Lresident_nested_vmread_exit_instruction_len",
    "cmp r10, {vmcs_field_exit_qualification}",
    "je .Lresident_nested_vmread_exit_qualification",
    "mov rdx, r10",
    "mov rax, r10",
    "and rax, 0x6000",
    "cmp rax, 0x2000",
    "jne .Lresident_nested_vmread_extended_lookup",
    "and rdx, -2",
    ".Lresident_nested_vmread_extended_lookup:",
    "call .Lresident_vmcs12_field_index",
    "cmp eax, {vmcs12_extended_field_count}",
    "jb .Lresident_nested_vmread_extended",
    "mov r10d, {vmcs_unsupported_component_error}",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_nested_vmread_extended:",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + rax * 8]",
    "cmp rdx, r10",
    "je .Lresident_nested_vmread_value",
    "shr r11, 32",
    "jmp .Lresident_nested_vmread_value",
    ".Lresident_nested_vmread_instruction_error:",
    "mov r11, qword ptr [r12 + {b_nested_instruction_error}]",
    "jmp .Lresident_nested_vmread_value",
    ".Lresident_nested_vmread_exit_reason:",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_exit_reason}]",
    "jmp .Lresident_nested_vmread_value",
    ".Lresident_nested_vmread_exit_instruction_len:",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_exit_instruction_len}]",
    "jmp .Lresident_nested_vmread_value",
    ".Lresident_nested_vmread_exit_qualification:",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_exit_qualification}]",
    "jmp .Lresident_nested_vmread_value",
    ".Lresident_nested_vmread_guest_rsp:",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rsp}]",
    "jmp .Lresident_nested_vmread_value",
    ".Lresident_nested_vmread_guest_rflags:",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rflags}]",
    "jmp .Lresident_nested_vmread_value",
    ".Lresident_nested_vmread_host_rsp:",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_host_rsp}]",
    "jmp .Lresident_nested_vmread_value",
    ".Lresident_nested_vmread_host_rip:",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_host_rip}]",
    "jmp .Lresident_nested_vmread_value",
    ".Lresident_nested_vmread_guest_rip:",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rip}]",
    "mov qword ptr [r12 + {b_nested_vmcs12_probe_complete}], 1",
    "cmp qword ptr [r12 + {b_nested_vmxoff_count}], 0",
    "jne .Lresident_nested_vmread_value",
    "push r13",
    "lea rsi, [rip + .Lnested_vmcs12_message]",
    "mov r9d, {nested_vmcs12_message_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_processor_number}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lnested_region_message]",
    "mov r9d, {nested_region_message_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_region}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lnested_value_message]",
    "mov r9d, {nested_value_message_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_guest_rip}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_newline]",
    "mov r9d, {state_newline_len}",
    "call .Lresident_serial_write",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rip}]",
    "pop r13",
    ".Lresident_nested_vmread_value:",
    "mov rbx, r11",
    "bt r13d, 10",
    "jnc .Lresident_nested_vmread_memory_destination",
    "mov eax, r13d",
    "shr eax, 3",
    "and eax, 15",
    "mov r11, rbx",
    "mov r15, rsp",
    "call .Lresident_nested_write_gpr",
    "jmp .Lresident_nested_succeed",
    ".Lresident_nested_vmread_memory_destination:",
    "call .Lresident_nested_decode_memory_operand",
    "jc .Lresident_nested_inject_pf_write",
    "mov qword ptr [r10], rbx",
    "jmp .Lresident_nested_succeed",
    ".Lresident_nested_validate_entry:",
    "bt qword ptr [r12 + {b_nested_vmx_basic}], 55",
    "jnc .Lresident_nested_validate_legacy_controls",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_pin_based_control}]",
    "mov r11, qword ptr [r12 + {b_nested_vmx_true_pinbased_ctls}]",
    "call .Lresident_nested_control_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_primary_control}]",
    "mov r11, qword ptr [r12 + {b_nested_vmx_true_procbased_ctls}]",
    "call .Lresident_nested_control_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    "bt edx, 31",
    "jnc .Lresident_nested_validate_true_secondary_done",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_secondary_control}]",
    "mov r11, qword ptr [r12 + {b_nested_vmx_procbased_ctls2}]",
    "call .Lresident_nested_control_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    ".Lresident_nested_validate_true_secondary_done:",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_vm_exit_controls}]",
    "mov r11, qword ptr [r12 + {b_nested_vmx_true_exit_ctls}]",
    "call .Lresident_nested_control_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}]",
    "mov r11, qword ptr [r12 + {b_nested_vmx_true_entry_ctls}]",
    "call .Lresident_nested_control_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    "jmp .Lresident_nested_validate_neutral_controls",
    ".Lresident_nested_validate_legacy_controls:",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_pin_based_control}]",
    "mov r11, qword ptr [r12 + {b_nested_vmx_pinbased_ctls}]",
    "call .Lresident_nested_control_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_primary_control}]",
    "mov r11, qword ptr [r12 + {b_nested_vmx_procbased_ctls}]",
    "call .Lresident_nested_control_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    "bt edx, 31",
    "jnc .Lresident_nested_validate_legacy_secondary_done",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_secondary_control}]",
    "mov r11, qword ptr [r12 + {b_nested_vmx_procbased_ctls2}]",
    "call .Lresident_nested_control_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    ".Lresident_nested_validate_legacy_secondary_done:",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_vm_exit_controls}]",
    "mov r11, qword ptr [r12 + {b_nested_vmx_exit_ctls}]",
    "call .Lresident_nested_control_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}]",
    "mov r11, qword ptr [r12 + {b_nested_vmx_entry_ctls}]",
    "call .Lresident_nested_control_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    ".Lresident_nested_validate_neutral_controls:",
    "cmp qword ptr [r12 + {b_nested_vmcs12_cr3_target_count}], 4",
    "ja .Lresident_nested_validate_invalid_controls",
    "bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 25",
    "jnc .Lresident_nested_validate_io_bitmaps_done",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_io_bitmap_a}]",
    "call .Lresident_nested_physical_address_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_io_bitmap_b}]",
    "call .Lresident_nested_physical_address_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    ".Lresident_nested_validate_io_bitmaps_done:",
    "bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 28",
    "jnc .Lresident_nested_validate_msr_bitmap_done",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_msr_bitmap}]",
    "call .Lresident_nested_physical_address_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    ".Lresident_nested_validate_msr_bitmap_done:",
    "bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 21",
    "jnc .Lresident_nested_validate_tpr_shadow_done",
    "cmp dword ptr [r12 + {b_nested_vmcs12_tpr_threshold}], 15",
    "ja .Lresident_nested_validate_invalid_controls",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_virtual_apic_page}]",
    "call .Lresident_nested_physical_address_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    ".Lresident_nested_validate_tpr_shadow_done:",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_store_addr}]",
    "mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_store_count}]",
    "call .Lresident_nested_msr_list_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_load_addr}]",
    "mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_load_count}]",
    "call .Lresident_nested_msr_list_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_vm_entry_msr_load_addr}]",
    "mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_entry_msr_load_count}]",
    "call .Lresident_nested_msr_list_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    "call .Lresident_nested_entry_event_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    ".Lresident_nested_validate_ept:",
    "bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31",
    "jnc .Lresident_nested_validate_host_state",
    "bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 22",
    "jnc .Lresident_nested_validate_mbec_done",
    "bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 1",
    "jnc .Lresident_nested_validate_invalid_controls",
    ".Lresident_nested_validate_mbec_done:",
    "bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 1",
    "jnc .Lresident_nested_validate_vpid",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_ept_pointer}]",
    "mov r11, rax",
    "and r11d, 0x3f",
    "cmp r11d, 0x1e",
    "jne .Lresident_nested_validate_invalid_controls",
    "test rax, 0xf80",
    "jnz .Lresident_nested_validate_invalid_controls",
    "test al, 0x40",
    "jz .Lresident_nested_validate_ept_ad_ready",
    "bt qword ptr [r12 + {b_nested_vmx_ept_vpid_cap}], 21",
    "jnc .Lresident_nested_validate_invalid_controls",
    ".Lresident_nested_validate_ept_ad_ready:",
    "mov r11, rax",
    "and r11, -4096",
    "call .Lresident_nested_physical_address_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_controls",
    ".Lresident_nested_validate_vpid:",
    "bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 5",
    "jnc .Lresident_nested_validate_host_state",
    "cmp word ptr [r12 + {b_nested_vmcs12_vpid}], 0",
    "je .Lresident_nested_validate_invalid_controls",
    ".Lresident_nested_validate_host_state:",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_host_rip}]",
    "mov r11, rax",
    "shl r11, 16",
    "sar r11, 16",
    "cmp rax, r11",
    "jne .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_host_cr0}]",
    "mov r11, qword ptr [r12 + {b_nested_vmx_cr0_fixed0}]",
    "mov rcx, rax",
    "and rcx, r11",
    "cmp rcx, r11",
    "jne .Lresident_nested_validate_invalid_host_state",
    "mov r11, qword ptr [r12 + {b_nested_vmx_cr0_fixed1}]",
    "not r11",
    "test rax, r11",
    "jnz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_host_cr4}]",
    "mov r11, qword ptr [r12 + {b_nested_vmx_cr4_fixed0}]",
    "mov rcx, rax",
    "and rcx, r11",
    "cmp rcx, r11",
    "jne .Lresident_nested_validate_invalid_host_state",
    "mov r11, qword ptr [r12 + {b_nested_vmx_cr4_fixed1}]",
    "not r11",
    "test rax, r11",
    "jnz .Lresident_nested_validate_invalid_host_state",
    "bt rax, 5",
    "jnc .Lresident_nested_validate_invalid_host_state",
    "mov eax, 0x80000000",
    "cpuid",
    "cmp eax, 0x80000008",
    "jb .Lresident_nested_validate_invalid_host_state",
    "mov eax, 0x80000008",
    "cpuid",
    "and eax, 0xff",
    "mov ecx, eax",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_host_cr3}]",
    "shr r11, cl",
    "test r11, r11",
    "jnz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 43 * 8]",
    "test ax, 7",
    "jnz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 44 * 8]",
    "test ax, 7",
    "jnz .Lresident_nested_validate_invalid_host_state",
    "test ax, ax",
    "jz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 45 * 8]",
    "test ax, 7",
    "jnz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 46 * 8]",
    "test ax, 7",
    "jnz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 47 * 8]",
    "test ax, 7",
    "jnz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 48 * 8]",
    "test ax, 7",
    "jnz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 49 * 8]",
    "test ax, 7",
    "jnz .Lresident_nested_validate_invalid_host_state",
    "test ax, ax",
    "jz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 60 * 8]",
    "call .Lresident_nested_value_is_canonical",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 61 * 8]",
    "call .Lresident_nested_value_is_canonical",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 62 * 8]",
    "call .Lresident_nested_value_is_canonical",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 63 * 8]",
    "call .Lresident_nested_value_is_canonical",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 64 * 8]",
    "call .Lresident_nested_value_is_canonical",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_host_sysenter_esp}]",
    "call .Lresident_nested_value_is_canonical",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_host_state",
    "mov rax, qword ptr [r12 + {b_nested_vmcs12_host_sysenter_eip}]",
    "call .Lresident_nested_value_is_canonical",
    "test eax, eax",
    "jz .Lresident_nested_validate_invalid_host_state",
    "inc qword ptr [r12 + {b_nested_vmcs12_control_validation_count}]",
    "xor r10d, r10d",
    "ret",
    ".Lresident_nested_validate_invalid_controls:",
    "mov r10d, {vm_entry_invalid_control_fields_error}",
    "ret",
    ".Lresident_nested_validate_invalid_host_state:",
    "mov r10d, {vm_entry_invalid_host_state_field_error}",
    "ret",
    ".Lresident_nested_control_is_valid:",
    "mov eax, edx",
    "mov ecx, r11d",
    "and eax, ecx",
    "cmp eax, ecx",
    "jne .Lresident_nested_control_invalid",
    "shr r11, 32",
    "not r11d",
    "test edx, r11d",
    "jnz .Lresident_nested_control_invalid",
    "mov eax, 1",
    "ret",
    ".Lresident_nested_control_invalid:",
    "xor eax, eax",
    "ret",
    ".Lresident_nested_msr_list_is_valid:",
    "test r10d, r10d",
    "jz .Lresident_nested_msr_list_valid",
    "cmp r10d, {nested_guest_msr_list_capacity}",
    "ja .Lresident_nested_msr_list_invalid",
    "test r11b, 15",
    "jnz .Lresident_nested_msr_list_invalid",
    "call .Lresident_nested_address_width_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_msr_list_invalid",
    "mov eax, r10d",
    "shl rax, 4",
    "dec rax",
    "add r11, rax",
    "jc .Lresident_nested_msr_list_invalid",
    "call .Lresident_nested_address_width_is_valid",
    "ret",
    ".Lresident_nested_msr_list_valid:",
    "mov eax, 1",
    "ret",
    ".Lresident_nested_msr_list_invalid:",
    "xor eax, eax",
    "ret",
    ".Lresident_nested_entry_event_is_valid:",
    "mov eax, dword ptr [r12 + {b_nested_vmcs12_vm_entry_intr_info}]",
    "test eax, 0x80000000",
    "jz .Lresident_nested_entry_event_valid",
    "test eax, 0x7ffff000",
    "jnz .Lresident_nested_entry_event_invalid",
    "mov edx, eax",
    "shr edx, 8",
    "and edx, 7",
    "cmp edx, 1",
    "je .Lresident_nested_entry_event_invalid",
    "mov ecx, eax",
    "and ecx, 0xff",
    "cmp edx, 7",
    "jne .Lresident_nested_entry_event_check_nmi",
    "test ecx, ecx",
    "jnz .Lresident_nested_entry_event_invalid",
    ".Lresident_nested_entry_event_check_nmi:",
    "cmp edx, 2",
    "jne .Lresident_nested_entry_event_check_exception",
    "cmp ecx, 2",
    "jne .Lresident_nested_entry_event_invalid",
    ".Lresident_nested_entry_event_check_exception:",
    "cmp edx, 3",
    "jne .Lresident_nested_entry_event_check_error_code",
    "cmp ecx, 31",
    "ja .Lresident_nested_entry_event_invalid",
    "cmp ecx, 8",
    "je .Lresident_nested_entry_event_requires_error_code",
    "cmp ecx, 10",
    "je .Lresident_nested_entry_event_requires_error_code",
    "cmp ecx, 11",
    "je .Lresident_nested_entry_event_requires_error_code",
    "cmp ecx, 12",
    "je .Lresident_nested_entry_event_requires_error_code",
    "cmp ecx, 13",
    "je .Lresident_nested_entry_event_requires_error_code",
    "cmp ecx, 14",
    "je .Lresident_nested_entry_event_requires_error_code",
    "cmp ecx, 17",
    "je .Lresident_nested_entry_event_requires_error_code",
    "test eax, 0x800",
    "jnz .Lresident_nested_entry_event_invalid",
    "jmp .Lresident_nested_entry_event_check_instruction_length",
    ".Lresident_nested_entry_event_requires_error_code:",
    "test eax, 0x800",
    "jz .Lresident_nested_entry_event_invalid",
    ".Lresident_nested_entry_event_check_error_code:",
    "test eax, 0x800",
    "jz .Lresident_nested_entry_event_check_instruction_length",
    "cmp edx, 3",
    "jne .Lresident_nested_entry_event_invalid",
    "cmp dword ptr [r12 + {b_nested_vmcs12_vm_entry_exception_error}], 0xffff",
    "ja .Lresident_nested_entry_event_invalid",
    ".Lresident_nested_entry_event_check_instruction_length:",
    "cmp edx, 4",
    "je .Lresident_nested_entry_event_validate_instruction_length",
    "cmp edx, 5",
    "je .Lresident_nested_entry_event_validate_instruction_length",
    "cmp edx, 6",
    "jne .Lresident_nested_entry_event_valid",
    ".Lresident_nested_entry_event_validate_instruction_length:",
    "cmp dword ptr [r12 + {b_nested_vmcs12_vm_entry_instruction_len}], 15",
    "ja .Lresident_nested_entry_event_invalid",
    ".Lresident_nested_entry_event_valid:",
    "mov eax, 1",
    "ret",
    ".Lresident_nested_entry_event_invalid:",
    "xor eax, eax",
    "ret",
    ".Lresident_nested_value_is_canonical:",
    "mov r11, rax",
    "shl r11, 16",
    "sar r11, 16",
    "cmp rax, r11",
    "sete al",
    "movzx eax, al",
    "ret",
    // Normalize the architectural width, type, and index into a bounded byte table.
    ".Lresident_vmcs12_field_index:",
    "mov rax, rdx",
    "and rax, -0x6c3f",
    "jnz .Lresident_vmcs12_field_index_missing",
    "mov eax, edx",
    "shr eax, 5",
    "and eax, 0x360",
    "mov ecx, edx",
    "shr ecx, 1",
    "and ecx, 31",
    "or eax, ecx",
    "lea rsi, [rip + .Lresident_vmcs12_field_index_table]",
    "movzx eax, byte ptr [rsi + rax]",
    "ret",
    ".Lresident_vmcs12_field_index_missing:",
    "mov eax, 255",
    "ret",
    // Cache only controls that are not rewritten by VM entry, VM exit, or internal resumes.
    ".Lresident_nested_write_vmcs02_control:",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rax",
    "mov rdx, rax",
    "call .Lresident_vmcs12_field_index",
    "cmp eax, {vmcs12_extended_field_count}",
    "jae .Lresident_dispatch_halt",
    "mov edx, eax",
    "pop rax",
    "bt qword ptr [r12 + {b_nested_vmcs02_control_cache_valid}], rdx",
    "jnc .Lresident_nested_write_vmcs02_control_changed",
    "cmp r11, qword ptr [r12 + {b_nested_vmcs02_field_cache} + rdx * 8]",
    "je .Lresident_nested_write_vmcs02_control_done",
    ".Lresident_nested_write_vmcs02_control_changed:",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov qword ptr [r12 + {b_nested_vmcs02_field_cache} + rdx * 8], r11",
    "bts qword ptr [r12 + {b_nested_vmcs02_control_cache_valid}], rdx",
    ".Lresident_nested_write_vmcs02_control_done:",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "ret",
    ".Lresident_nested_merge_vmcs02_controls:",
    "call .Lresident_nested_prepare_vpid02",
    "mov rax, {pin_based_vm_exec_control}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs01_pin_based_controls}]",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_pin_based_control}]",
    "or r11d, edx",
    "call .Lresident_nested_write_vmcs02_control",
    "mov rax, {cpu_based_vm_exec_control}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs01_primary_controls}]",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_primary_control}]",
    "or r11d, edx",
    "call .Lresident_nested_write_vmcs02_control",
    "bt r11, 21",
    "jnc .Lresident_nested_merge_tpr_shadow_done",
    "mov rax, {virtual_apic_page_addr}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_virtual_apic_page}]",
    "call .Lresident_nested_write_vmcs02_control",
    "mov rax, {tpr_threshold}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_tpr_threshold}]",
    "call .Lresident_nested_write_vmcs02_control",
    ".Lresident_nested_merge_tpr_shadow_done:",
    "bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 25",
    "jnc .Lresident_nested_merge_io_bitmaps_done",
    "mov rax, {io_bitmap_a}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_io_bitmap_a}]",
    "call .Lresident_nested_write_vmcs02_control",
    "mov rax, {io_bitmap_b}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_io_bitmap_b}]",
    "call .Lresident_nested_write_vmcs02_control",
    ".Lresident_nested_merge_io_bitmaps_done:",
    "bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 28",
    "jnc .Lresident_nested_merge_l0_msr_bitmap",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_msr_bitmap}]",
    "call .Lresident_nested_host_page_is_mapped",
    "test eax, eax",
    "jz .Lresident_nested_intercept_unmapped_msr_bitmap",
    "mov rsi, qword ptr [r12 + {b_nested_l0_msr_bitmap}]",
    "mov rdi, qword ptr [r12 + {b_nested_composed_msr_bitmap}]",
    "mov rdx, qword ptr [r12 + {b_nested_vmcs12_msr_bitmap}]",
    "mov ecx, {nested_msr_bitmap_qword_count}",
    ".Lresident_nested_merge_msr_bitmap_loop:",
    "mov r11, qword ptr [rsi]",
    "or r11, qword ptr [rdx]",
    // An outer hypervisor may write-protect active bitmaps; unchanged stores cause exits.
    "cmp qword ptr [rdi], r11",
    "je .Lresident_nested_merge_msr_bitmap_next",
    "mov qword ptr [rdi], r11",
    ".Lresident_nested_merge_msr_bitmap_next:",
    "add rsi, 8",
    "add rdi, 8",
    "add rdx, 8",
    "dec ecx",
    "jnz .Lresident_nested_merge_msr_bitmap_loop",
    "jmp .Lresident_nested_use_composed_msr_bitmap",
    ".Lresident_nested_intercept_unmapped_msr_bitmap:",
    "mov rdi, qword ptr [r12 + {b_nested_composed_msr_bitmap}]",
    "mov ecx, {nested_msr_bitmap_qword_count}",
    "mov rax, -1",
    "cld",
    "rep stosq",
    ".Lresident_nested_use_composed_msr_bitmap:",
    "mov r11, qword ptr [r12 + {b_nested_composed_msr_bitmap}]",
    "jmp .Lresident_nested_write_msr_bitmap",
    ".Lresident_nested_merge_l0_msr_bitmap:",
    "mov r11, qword ptr [r12 + {b_nested_l0_msr_bitmap}]",
    ".Lresident_nested_write_msr_bitmap:",
    "mov rax, {msr_bitmap}",
    "call .Lresident_nested_write_vmcs02_control",
    ".Lresident_nested_merge_msr_bitmap_done:",
    "mov rax, {secondary_vm_exec_control}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs01_secondary_controls}]",
    "cmp qword ptr [r12 + {b_nested_vmcs02_last_vpid}], 0",
    "jne .Lresident_nested_merge_vpid_ready",
    "and r11d, -33",
    ".Lresident_nested_merge_vpid_ready:",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_secondary_control}]",
    "and edx, 0x50188e",
    "or r11d, edx",
    "call .Lresident_nested_write_vmcs02_control",
    "mov qword ptr [r12 + {b_nested_last_merged_secondary_controls}], r11",
    "xor r11d, r11d",
    "bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 20",
    "jnc .Lresident_nested_merge_xss_bitmap_ready",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_xss_exiting_bitmap}]",
    ".Lresident_nested_merge_xss_bitmap_ready:",
    "mov rax, {xss_exiting_bitmap}",
    "call .Lresident_nested_write_vmcs02_control",
    "mov rax, {vm_exit_controls}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs01_exit_controls}]",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_vm_exit_controls}]",
    "or r11d, edx",
    "call .Lresident_nested_write_vmcs02_control",
    "mov rax, {vm_entry_controls}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs01_entry_controls}]",
    "btr r11, 9",
    "mov edx, dword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}]",
    "or r11d, edx",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {exception_bitmap}",
    "mov r11d, dword ptr [r12 + {b_nested_vmcs12_exception_bitmap}]",
    "call .Lresident_nested_write_vmcs02_control",
    "mov rax, {page_fault_error_code_mask}",
    "mov r11d, dword ptr [r12 + {b_nested_vmcs12_pf_error_mask}]",
    "call .Lresident_nested_write_vmcs02_control",
    "mov rax, {page_fault_error_code_match}",
    "mov r11d, dword ptr [r12 + {b_nested_vmcs12_pf_error_match}]",
    "call .Lresident_nested_write_vmcs02_control",
    "mov rax, {cr0_guest_host_mask}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_cr0_mask}]",
    "call .Lresident_nested_write_vmcs02_control",
    "mov rax, {cr0_read_shadow}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_cr0_shadow}]",
    "call .Lresident_nested_write_vmcs02_control",
    "mov r10, qword ptr [r12 + {b_nested_vmcs12_cr4_mask}]",
    "mov r11, r10",
    "or r11, {cr4_vmxe}",
    "mov rax, {cr4_guest_host_mask}",
    "call .Lresident_nested_write_vmcs02_control",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_cr4_shadow}]",
    "and r11, r10",
    "test r10, {cr4_vmxe}",
    "jnz .Lresident_nested_vmcs02_cr4_shadow_ready",
    "mov rdx, qword ptr [r12 + {b_nested_vmcs12_guest_cr4}]",
    "and rdx, {cr4_vmxe}",
    "or r11, rdx",
    ".Lresident_nested_vmcs02_cr4_shadow_ready:",
    "mov rax, {cr4_read_shadow}",
    "call .Lresident_nested_write_vmcs02_control",
    "call .Lresident_nested_compose_vmcs02_msr_lists",
    "inc qword ptr [r12 + {b_nested_control_merge_count}]",
    "ret",
    ".Lresident_nested_prepare_vpid02:",
    "xor r10d, r10d",
    "bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31",
    "jnc .Lresident_nested_vpid02_selected",
    "bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 5",
    "jnc .Lresident_nested_vpid02_selected",
    "movzx r10d, word ptr [r12 + {b_nested_vmcs12_vpid}]",
    ".Lresident_nested_vpid02_selected:",
    "cmp r10, qword ptr [r12 + {b_nested_vmcs02_last_vpid}]",
    "je .Lresident_nested_vpid02_ready",
    "mov qword ptr [r12 + {b_nested_vmcs02_last_vpid}], r10",
    "test r10d, r10d",
    "jnz .Lresident_nested_flush_vpid02",
    ".Lresident_nested_vpid02_ready:",
    "ret",
    // L1 and L2 own distinct hardware tags. Different virtual L2 tags share tag 2
    // only after a full single-context invalidation, including global translations.
    ".Lresident_nested_flush_vpid02:",
    "bt dword ptr [r12 + {b_nested_vmcs01_secondary_controls}], 5",
    "jnc .Lresident_nested_vpid02_ready",
    "sub rsp, 16",
    "mov qword ptr [rsp], 2",
    "mov qword ptr [rsp + 8], 0",
    "mov eax, 1",
    "invvpid rax, xmmword ptr [rsp]",
    "lea rsp, [rsp + 16]",
    "jna .Lresident_dispatch_halt",
    "ret",
    ".Lresident_nested_compose_vmcs02_msr_lists:",
    "cld",
    "mov rsi, qword ptr [r12 + {b_nested_l0_msr_guest_list}]",
    "mov rdi, qword ptr [r12 + {b_nested_vmcs02_entry_msr_list}]",
    "mov ecx, {resident_msr_switch_qword_count}",
    "rep movsq",
    "mov rsi, qword ptr [r12 + {b_nested_vmcs12_vm_entry_msr_load_addr}]",
    "mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_entry_msr_load_count}]",
    "mov r11, rsi",
    "call .Lresident_nested_host_msr_list_is_mapped",
    "test eax, eax",
    "jnz .Lresident_nested_copy_vmcs12_entry_msr_list",
    "xor r10d, r10d",
    "jmp .Lresident_nested_copy_vmcs12_entry_msr_list_done",
    ".Lresident_nested_copy_vmcs12_entry_msr_list:",
    "mov ecx, r10d",
    "shl ecx, 1",
    "rep movsq",
    ".Lresident_nested_copy_vmcs12_entry_msr_list_done:",
    "mov rax, {vm_entry_msr_load_addr}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs02_entry_msr_list}]",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "add r10d, {resident_msr_switch_count}",
    "mov rax, {vm_entry_msr_load_count}",
    "mov r11d, r10d",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rsi, qword ptr [r12 + {b_nested_l0_msr_guest_list}]",
    "mov rdi, qword ptr [r12 + {b_nested_vmcs02_exit_store_msr_list}]",
    "mov ecx, {resident_msr_switch_qword_count}",
    "rep movsq",
    "mov rsi, qword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_store_addr}]",
    "mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_store_count}]",
    "mov r11, rsi",
    "call .Lresident_nested_host_msr_list_is_mapped",
    "test eax, eax",
    "jnz .Lresident_nested_copy_vmcs12_exit_store_msr_list",
    "xor r10d, r10d",
    "jmp .Lresident_nested_copy_vmcs12_exit_store_msr_list_done",
    ".Lresident_nested_copy_vmcs12_exit_store_msr_list:",
    "call .Lresident_nested_exit_store_list_is_safe",
    "test eax, eax",
    "jnz .Lresident_nested_copy_safe_vmcs12_exit_store_msr_list",
    "xor r10d, r10d",
    "jmp .Lresident_nested_copy_vmcs12_exit_store_msr_list_done",
    ".Lresident_nested_copy_safe_vmcs12_exit_store_msr_list:",
    "mov ecx, r10d",
    "shl ecx, 1",
    "rep movsq",
    ".Lresident_nested_copy_vmcs12_exit_store_msr_list_done:",
    "mov rax, {vm_exit_msr_store_addr}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs02_exit_store_msr_list}]",
    "call .Lresident_nested_write_vmcs02_control",
    "add r10d, {resident_msr_switch_count}",
    "mov rax, {vm_exit_msr_store_count}",
    "mov r11d, r10d",
    "call .Lresident_nested_write_vmcs02_control",
    "mov rax, {vm_exit_msr_load_addr}",
    "mov r11, qword ptr [r12 + {b_nested_l0_msr_host_list}]",
    "call .Lresident_nested_write_vmcs02_control",
    "mov rax, {vm_exit_msr_load_count}",
    "mov r11d, {resident_msr_switch_count}",
    "call .Lresident_nested_write_vmcs02_control",
    "ret",
    ".Lresident_nested_snapshot_vmcs01_effective_state:",
    "mov rax, {guest_pat}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_inherited_l1_pat}], r11",
    "mov rax, {guest_efer}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_inherited_l1_efer}], r11",
    "mov rax, {tsc_offset}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_inherited_l1_tsc_offset}], r11",
    "mov rax, {pin_based_vm_exec_control}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_vmcs01_pin_based_controls}], r11",
    "mov rax, {cpu_based_vm_exec_control}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_vmcs01_primary_controls}], r11",
    "mov rax, {secondary_vm_exec_control}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_vmcs01_secondary_controls}], r11",
    "mov rax, {vm_exit_controls}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_vmcs01_exit_controls}], r11",
    "mov rax, {vm_entry_controls}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_vmcs01_entry_controls}], r11",
    "mov rax, {ept_pointer}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_ept01_pointer}], r11",
    "ret",
    ".Lresident_nested_sync_vmcs02_guest_state:",
    "mov rax, {vmcs_link_pointer}",
    "mov r11, -1",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_pat}",
    "mov r11, qword ptr [r12 + {b_nested_inherited_l1_pat}]",
    "bt dword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}], 14",
    "jnc .Lresident_nested_vmcs02_guest_pat_ready",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 25 * 8]",
    ".Lresident_nested_vmcs02_guest_pat_ready:",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_efer}",
    "mov r11, qword ptr [r12 + {b_nested_inherited_l1_efer}]",
    "bt dword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}], 15",
    "jnc .Lresident_nested_vmcs02_guest_efer_ready",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 26 * 8]",
    ".Lresident_nested_vmcs02_guest_efer_ready:",
    "btr r11, 10",
    "bt dword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}], 9",
    "jnc .Lresident_nested_vmcs02_guest_lma_ready",
    "bts r11, 10",
    ".Lresident_nested_vmcs02_guest_lma_ready:",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {tsc_offset}",
    "mov r11, qword ptr [r12 + {b_nested_inherited_l1_tsc_offset}]",
    "bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 3",
    "jnc .Lresident_nested_vmcs02_tsc_offset_ready",
    "add r11, qword ptr [r12 + {b_nested_vmcs12_tsc_offset}]",
    ".Lresident_nested_vmcs02_tsc_offset_ready:",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "call .Lresident_nested_sync_vmcs02_guest_fields",
    "bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31",
    "jnc .Lresident_nested_synthesize_vmcs02_pdptrs",
    "bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 1",
    "jc .Lresident_nested_vmcs02_pdptrs_ready",
    ".Lresident_nested_synthesize_vmcs02_pdptrs:",
    "bt qword ptr [r12 + {b_nested_vmcs12_guest_cr0}], 31",
    "jnc .Lresident_nested_vmcs02_pdptrs_ready",
    "bt qword ptr [r12 + {b_nested_vmcs12_guest_cr4}], 5",
    "jnc .Lresident_nested_vmcs02_pdptrs_ready",
    "bt dword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}], 9",
    "jc .Lresident_nested_vmcs02_pdptrs_ready",
    "mov r10, qword ptr [r12 + {b_nested_vmcs12_guest_cr3}]",
    "and r10, -32",
    "mov r11, r10",
    "call .Lresident_nested_host_page_is_mapped",
    "test eax, eax",
    "jz .Lresident_nested_vmcs02_pdptrs_ready",
    "mov r11, qword ptr [r10]",
    "mov rax, {guest_pdptr0}",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov r11, qword ptr [r10 + 8]",
    "mov rax, {guest_pdptr1}",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov r11, qword ptr [r10 + 16]",
    "mov rax, {guest_pdptr2}",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov r11, qword ptr [r10 + 24]",
    "mov rax, {guest_pdptr3}",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    ".Lresident_nested_vmcs02_pdptrs_ready:",
    "mov rax, {guest_gs_base}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_last_synced_guest_gs_base}], r11",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_cr0}]",
    "mov qword ptr [r12 + {b_nested_last_synced_guest_cr0}], r11",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_cr3}]",
    "mov qword ptr [r12 + {b_nested_last_synced_guest_cr3}], r11",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_cr4}]",
    "mov qword ptr [r12 + {b_nested_last_synced_guest_cr4}], r11",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_sysenter_eip}]",
    "mov qword ptr [r12 + {b_nested_last_synced_guest_sysenter_eip}], r11",
    "mov rax, {vm_entry_intr_info_field}",
    "mov r11d, dword ptr [r12 + {b_nested_vmcs12_vm_entry_intr_info}]",
    "bt qword ptr [r12 + {b_nested_vmcs12_guest_rflags}], 1",
    "jc .Lresident_nested_vmcs02_entry_event_ready",
    "xor r11d, r11d",
    ".Lresident_nested_vmcs02_entry_event_ready:",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {vm_entry_exception_error_code}",
    "mov r11d, dword ptr [r12 + {b_nested_vmcs12_vm_entry_exception_error}]",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {vm_entry_instruction_len}",
    "mov r11d, dword ptr [r12 + {b_nested_vmcs12_vm_entry_instruction_len}]",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "inc qword ptr [r12 + {b_nested_guest_state_sync_count}]",
    "ret",
    ".Lresident_nested_sync_vmcs02_guest_fields:",
    "lea rsi, [rip + .Lresident_nested_guest_state_table]",
    "mov ecx, {nested_guest_state_table_count}",
    ".Lresident_nested_sync_vmcs02_guest_state_loop:",
    "mov edx, dword ptr [rsi]",
    "mov rax, qword ptr [rsi + 8]",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + rdx * 8]",
    "cmp qword ptr [r12 + {b_nested_vmcs02_guest_cache_valid}], 0",
    "je .Lresident_nested_sync_vmcs02_guest_field_write",
    // PDPTR synthesis below can modify these fields after the cache is populated.
    "cmp edx, 111",
    "jae .Lresident_nested_sync_vmcs02_guest_field_write",
    "cmp r11, qword ptr [r12 + {b_nested_vmcs02_field_cache} + rdx * 8]",
    "je .Lresident_nested_sync_vmcs02_guest_field_done",
    ".Lresident_nested_sync_vmcs02_guest_field_write:",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov qword ptr [r12 + {b_nested_vmcs02_field_cache} + rdx * 8], r11",
    ".Lresident_nested_sync_vmcs02_guest_field_done:",
    "add rsi, 16",
    "dec ecx",
    "jnz .Lresident_nested_sync_vmcs02_guest_state_loop",
    "mov qword ptr [r12 + {b_nested_vmcs02_guest_cache_valid}], 1",
    "ret",
    ".Lresident_nested_capture_vmcs02_guest_state:",
    "mov rax, {guest_pat}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_l2_saved_pat}], r11",
    "mov rax, {guest_efer}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_l2_saved_efer}], r11",
    // VM exits update the entry mode after unrestricted guests change EFER.LMA.
    "test dword ptr [r12 + {b_nested_l2_last_exit_reason}], 0x80000000",
    "jnz .Lresident_nested_capture_vmcs02_entry_mode_done",
    "bt qword ptr [r12 + {b_nested_vmx_misc}], 5",
    "jnc .Lresident_nested_capture_vmcs02_entry_mode_done",
    "shr r11, 1",
    "and r11d, 0x200",
    "btr qword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}], 9",
    "or qword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}], r11",
    ".Lresident_nested_capture_vmcs02_entry_mode_done:",
    "lea rsi, [rip + .Lresident_nested_guest_state_table]",
    "mov ecx, {nested_guest_state_table_count}",
    ".Lresident_nested_capture_vmcs02_guest_state_loop:",
    "mov edx, dword ptr [rsi]",
    "mov rax, qword ptr [rsi + 8]",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_vmcs02_field_cache} + rdx * 8], r11",
    "mov qword ptr [r12 + {b_nested_vmcs12_extended_fields} + rdx * 8], r11",
    "add rsi, 16",
    "dec ecx",
    "jnz .Lresident_nested_capture_vmcs02_guest_state_loop",
    "mov rax, {guest_gs_base}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_last_captured_guest_gs_base}], r11",
    "ret",
    ".Lresident_nested_complete_vmcs02_msr_exit:",
    "test r10d, 0x80000000",
    "jnz .Lresident_nested_compose_vmcs01_msr_entry",
    "mov rsi, qword ptr [r12 + {b_nested_vmcs02_exit_store_msr_list}]",
    "mov rdi, qword ptr [r12 + {b_nested_l0_msr_guest_list}]",
    "mov ecx, {resident_msr_switch_count}",
    ".Lresident_nested_copy_l0_msr_store_loop:",
    "mov rax, qword ptr [rsi + 8]",
    "mov qword ptr [rdi + 8], rax",
    "add rsi, 16",
    "add rdi, 16",
    "dec ecx",
    "jnz .Lresident_nested_copy_l0_msr_store_loop",
    "mov rsi, qword ptr [r12 + {b_nested_vmcs02_exit_store_msr_list}]",
    "add rsi, {resident_msr_switch_byte_count}",
    "mov rdx, qword ptr [r12 + {b_nested_vmcs02_exit_store_msr_list}]",
    "mov rdi, qword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_store_addr}]",
    "mov ecx, dword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_store_count}]",
    "test ecx, ecx",
    "jz .Lresident_nested_compose_vmcs01_msr_entry",
    "mov r11, rdi",
    "mov r10d, ecx",
    "call .Lresident_nested_host_msr_list_is_mapped",
    "test eax, eax",
    "jz .Lresident_nested_compose_vmcs01_msr_entry",
    "mov ecx, r10d",
    "mov rdx, qword ptr [r12 + {b_nested_vmcs02_exit_store_msr_list}]",
    ".Lresident_nested_copy_l1_msr_store_loop:",
    "mov eax, dword ptr [rdi]",
    "mov r8, rdx",
    "mov r9d, {resident_msr_switch_count}",
    ".Lresident_nested_find_l0_msr_store_loop:",
    "cmp eax, dword ptr [r8]",
    "je .Lresident_nested_use_l0_msr_store",
    "add r8, 16",
    "dec r9d",
    "jnz .Lresident_nested_find_l0_msr_store_loop",
    "mov rax, qword ptr [rsi + 8]",
    "jmp .Lresident_nested_write_l1_msr_store",
    ".Lresident_nested_use_l0_msr_store:",
    "mov rax, qword ptr [r8 + 8]",
    ".Lresident_nested_write_l1_msr_store:",
    "mov qword ptr [rdi + 8], rax",
    "add rsi, 16",
    "add rdi, 16",
    "dec ecx",
    "jnz .Lresident_nested_copy_l1_msr_store_loop",
    ".Lresident_nested_compose_vmcs01_msr_entry:",
    "cld",
    "mov rsi, qword ptr [r12 + {b_nested_l0_msr_guest_list}]",
    "mov rdi, qword ptr [r12 + {b_nested_vmcs01_entry_msr_list}]",
    "mov ecx, {resident_msr_switch_qword_count}",
    "rep movsq",
    "mov rsi, qword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_load_addr}]",
    "mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_load_count}]",
    "mov r11, rsi",
    "call .Lresident_nested_host_msr_list_is_mapped",
    "test eax, eax",
    "jz .Lresident_nested_compose_vmcs01_msr_entry_done",
    "mov ecx, r10d",
    "shl ecx, 1",
    "rep movsq",
    ".Lresident_nested_compose_vmcs01_msr_entry_done:",
    "ret",
    ".Lresident_nested_activate_vmcs01_msr_entry:",
    "mov rax, {vm_entry_msr_load_addr}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs01_entry_msr_list}]",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_load_addr}]",
    "mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_load_count}]",
    "call .Lresident_nested_host_msr_list_is_mapped",
    "test eax, eax",
    "jnz .Lresident_nested_activate_vmcs01_guest_msr_entry",
    "xor r10d, r10d",
    ".Lresident_nested_activate_vmcs01_guest_msr_entry:",
    "mov r11d, r10d",
    "add r11d, {resident_msr_switch_count}",
    "mov rax, {vm_entry_msr_load_count}",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov qword ptr [r12 + {b_nested_vmcs01_msr_entry_composed}], 1",
    "ret",
    ".Lresident_nested_restore_l1_host_state:",
    "mov rax, {guest_pat}",
    "mov r11, qword ptr [r12 + {b_nested_l2_saved_pat}]",
    "bt dword ptr [r12 + {b_nested_vmcs12_vm_exit_controls}], 19",
    "jnc .Lresident_nested_l1_host_pat_ready",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 27 * 8]",
    ".Lresident_nested_l1_host_pat_ready:",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_efer}",
    "mov r11, qword ptr [r12 + {b_nested_l2_saved_efer}]",
    "bt dword ptr [r12 + {b_nested_vmcs12_vm_exit_controls}], 21",
    "jnc .Lresident_nested_l1_host_efer_ready",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 28 * 8]",
    ".Lresident_nested_l1_host_efer_ready:",
    "or r11, 0x500",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "lea rsi, [rip + .Lresident_nested_host_state_table]",
    "mov ecx, {nested_host_state_table_count}",
    ".Lresident_nested_restore_l1_host_state_loop:",
    "mov edx, dword ptr [rsi]",
    "mov rax, qword ptr [rsi + 8]",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + rdx * 8]",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "add rsi, 16",
    "dec ecx",
    "jnz .Lresident_nested_restore_l1_host_state_loop",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_host_cr0}]",
    "mov qword ptr [r12 + {b_nested_last_restored_host_cr0}], r11",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_host_cr3}]",
    "mov qword ptr [r12 + {b_nested_last_restored_host_cr3}], r11",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_host_cr4}]",
    "mov qword ptr [r12 + {b_nested_last_restored_host_cr4}], r11",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_host_sysenter_eip}]",
    "mov qword ptr [r12 + {b_nested_last_restored_host_sysenter_eip}], r11",
    "mov rax, {guest_cs_base}",
    "xor r11d, r11d",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_cs_limit}",
    "mov r11d, -1",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_cs_ar_bytes}",
    "mov r11d, 0xa09b",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_es_base}",
    "xor r11d, r11d",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "cmp word ptr [r12 + {b_nested_vmcs12_extended_fields} + 43 * 8], 0",
    "je .Lresident_nested_restore_es_unusable",
    "mov rax, {guest_es_limit}",
    "mov r11d, -1",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_es_ar_bytes}",
    "mov r11d, 0xc093",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "jmp .Lresident_nested_restore_es_done",
    ".Lresident_nested_restore_es_unusable:",
    "mov rax, {guest_es_limit}",
    "xor r11d, r11d",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_es_ar_bytes}",
    "mov r11d, 0x10000",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    ".Lresident_nested_restore_es_done:",
    "mov rax, {guest_ss_base}",
    "xor r11d, r11d",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "cmp word ptr [r12 + {b_nested_vmcs12_extended_fields} + 45 * 8], 0",
    "je .Lresident_nested_restore_ss_unusable",
    "mov rax, {guest_ss_limit}",
    "mov r11d, -1",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_ss_ar_bytes}",
    "mov r11d, 0xc093",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "jmp .Lresident_nested_restore_ss_done",
    ".Lresident_nested_restore_ss_unusable:",
    "mov rax, {guest_ss_limit}",
    "xor r11d, r11d",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_ss_ar_bytes}",
    "mov r11d, 0x10000",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    ".Lresident_nested_restore_ss_done:",
    "mov rax, {guest_ds_base}",
    "xor r11d, r11d",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "cmp word ptr [r12 + {b_nested_vmcs12_extended_fields} + 46 * 8], 0",
    "je .Lresident_nested_restore_ds_unusable",
    "mov rax, {guest_ds_limit}",
    "mov r11d, -1",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_ds_ar_bytes}",
    "mov r11d, 0xc093",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "jmp .Lresident_nested_restore_ds_done",
    ".Lresident_nested_restore_ds_unusable:",
    "mov rax, {guest_ds_limit}",
    "xor r11d, r11d",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_ds_ar_bytes}",
    "mov r11d, 0x10000",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    ".Lresident_nested_restore_ds_done:",
    "cmp word ptr [r12 + {b_nested_vmcs12_extended_fields} + 47 * 8], 0",
    "je .Lresident_nested_restore_fs_unusable",
    "mov rax, {guest_fs_limit}",
    "mov r11d, -1",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_fs_ar_bytes}",
    "mov r11d, 0xc093",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "jmp .Lresident_nested_restore_fs_done",
    ".Lresident_nested_restore_fs_unusable:",
    "mov rax, {guest_fs_limit}",
    "xor r11d, r11d",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_fs_ar_bytes}",
    "mov r11d, 0x10000",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    ".Lresident_nested_restore_fs_done:",
    "cmp word ptr [r12 + {b_nested_vmcs12_extended_fields} + 48 * 8], 0",
    "je .Lresident_nested_restore_gs_unusable",
    "mov rax, {guest_gs_limit}",
    "mov r11d, -1",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_gs_ar_bytes}",
    "mov r11d, 0xc093",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "jmp .Lresident_nested_restore_gs_done",
    ".Lresident_nested_restore_gs_unusable:",
    "mov rax, {guest_gs_limit}",
    "xor r11d, r11d",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_gs_ar_bytes}",
    "mov r11d, 0x10000",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    ".Lresident_nested_restore_gs_done:",
    "mov rax, {guest_tr_limit}",
    "mov r11d, 0x67",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_tr_ar_bytes}",
    "mov r11d, 0x8b",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_ldtr_selector}",
    "xor r11d, r11d",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_ldtr_base}",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_ldtr_limit}",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_ldtr_ar_bytes}",
    "mov r11d, 0x10000",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_gdtr_limit}",
    "mov r11d, 0xffff",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_idtr_limit}",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_activity_state}",
    "xor r11d, r11d",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_pending_dbg_exceptions}",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_dr7}",
    "mov r11d, 0x400",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_ia32_debugctl}",
    "xor r11d, r11d",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_gs_base}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_last_restored_host_gs_base}], r11",
    "mov rax, {guest_cs_ar_bytes}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r12 + {b_nested_last_restored_host_cs_ar}], r11",
    "inc qword ptr [r12 + {b_nested_l1_host_restore_count}]",
    "ret",
    ".Lresident_nested_l2_enter:",
    // VMCS02 is shared by all VMCS12 contexts on this CPU.
    "cmp qword ptr [r12 + {b_nested_vmcs02_launched}], 0",
    "jne .Lresident_nested_l2_resume_registers",
    ".Lresident_nested_l2_launch_registers:",
    "call .Lresident_profile_exit_handler",
    "pop rax",
    "pop rcx",
    "pop rdx",
    "pop rbx",
    "pop rbp",
    "pop rsi",
    "pop rdi",
    "pop r8",
    "pop r9",
    "pop r10",
    "pop r11",
    "pop r12",
    "pop r13",
    "pop r14",
    "pop r15",
    "vmlaunch",
    "push r15",
    "push r14",
    "push r13",
    "push r12",
    "push r11",
    "push r10",
    "push r9",
    "push r8",
    "push rdi",
    "push rsi",
    "push rbp",
    "push rbx",
    "push rdx",
    "push rcx",
    "push rax",
    "pushfq",
    "mov r12, qword ptr [rsp + 128]",
    "mov r10, qword ptr [rsp]",
    "add rsp, 8",
    "mov qword ptr [r12 + {b_nested_l2_active}], 0",
    "dec qword ptr [r12 + {b_nested_l2_entry_count}]",
    "cmp qword ptr [r12 + {b_nested_l2_entry_was_resume}], 0",
    "je .Lresident_nested_l2_launch_failure_counted",
    "dec qword ptr [r12 + {b_nested_l2_resume_count}]",
    ".Lresident_nested_l2_launch_failure_counted:",
    "inc qword ptr [r12 + {b_nested_entry_rejection_count}]",
    "test r10b, 1",
    "jnz .Lresident_nested_l2_launch_fail_invalid",
    "test r10b, 0x40",
    "jz .Lresident_dispatch_halt",
    "mov rax, {vm_instruction_error}",
    "vmread r10, rax",
    "jna .Lresident_dispatch_halt",
    "vmptrld [r12 + {b_nested_vmcs01_region}]",
    "jna .Lresident_dispatch_halt",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_nested_l2_launch_fail_invalid:",
    "vmptrld [r12 + {b_nested_vmcs01_region}]",
    "jna .Lresident_dispatch_halt",
    "jmp .Lresident_nested_vmfail_invalid",
    ".Lresident_nested_l2_resume_ept:",
    // Restore the root-switched MSRs captured at this internal exit.
    // Replaying L1's entry list would overwrite state that L2 has already changed.
    "mov rax, {vm_entry_msr_load_addr}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs02_exit_store_msr_list}]",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {vm_entry_msr_load_count}",
    "mov r11d, {resident_msr_switch_count}",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    // Internal EPT exits retry interrupted delivery, not an already delivered entry event.
    "mov rax, {idt_vectoring_info_field}",
    "vmread r10, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "bt r10d, 31",
    "jc .Lresident_nested_l2_retry_event",
    "xor r10d, r10d",
    "jmp .Lresident_nested_l2_retry_event_ready",
    ".Lresident_nested_l2_retry_event:",
    "and r10d, 0x80000fff",
    "bt r10d, 11",
    "jnc .Lresident_nested_l2_retry_event_type",
    "mov rax, {idt_vectoring_error_code}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov rax, {vm_entry_exception_error_code}",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    ".Lresident_nested_l2_retry_event_type:",
    "mov edx, r10d",
    "and edx, 0x700",
    "cmp edx, 0x200",
    "jne .Lresident_nested_l2_retry_software_event",
    "mov rax, {guest_interruptibility_info}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "btr r11, 3",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "jmp .Lresident_nested_l2_retry_event_ready",
    ".Lresident_nested_l2_retry_software_event:",
    "cmp edx, 0x400",
    "jb .Lresident_nested_l2_retry_event_ready",
    "cmp edx, 0x600",
    "ja .Lresident_nested_l2_retry_event_ready",
    "mov rax, {exit_instruction_len}",
    "vmread r11, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov rax, {vm_entry_instruction_len}",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    ".Lresident_nested_l2_retry_event_ready:",
    "mov rax, {vm_entry_intr_info_field}",
    "vmwrite rax, r10",
    "jna .Lresident_dispatch_vmwrite_failed",
    ".Lresident_nested_l2_resume:",
    "cmp qword ptr [r12 + {b_nested_vmcs02_launched}], 0",
    "je .Lresident_nested_l2_launch_registers",
    ".Lresident_nested_l2_resume_registers:",
    "call .Lresident_profile_exit_handler",
    "pop rax",
    "pop rcx",
    "pop rdx",
    "pop rbx",
    "pop rbp",
    "pop rsi",
    "pop rdi",
    "pop r8",
    "pop r9",
    "pop r10",
    "pop r11",
    "pop r12",
    "pop r13",
    "pop r14",
    "pop r15",
    "vmresume",
    "push r15",
    "push r14",
    "push r13",
    "push r12",
    "push r11",
    "push r10",
    "push r9",
    "push r8",
    "push rdi",
    "push rsi",
    "push rbp",
    "push rbx",
    "push rdx",
    "push rcx",
    "push rax",
    "pushfq",
    "mov r12, qword ptr [rsp + 128]",
    "mov r10, qword ptr [rsp]",
    "add rsp, 8",
    "mov qword ptr [r12 + {b_nested_l2_active}], 0",
    "dec qword ptr [r12 + {b_nested_l2_entry_count}]",
    "cmp qword ptr [r12 + {b_nested_l2_entry_was_resume}], 0",
    "je .Lresident_nested_l2_resume_failure_counted",
    "dec qword ptr [r12 + {b_nested_l2_resume_count}]",
    ".Lresident_nested_l2_resume_failure_counted:",
    "inc qword ptr [r12 + {b_nested_entry_rejection_count}]",
    "test r10b, 1",
    "jnz .Lresident_nested_l2_resume_fail_invalid",
    "test r10b, 0x40",
    "jz .Lresident_dispatch_halt",
    "mov rax, {vm_instruction_error}",
    "vmread r10, rax",
    "jna .Lresident_dispatch_halt",
    "vmptrld [r12 + {b_nested_vmcs01_region}]",
    "jna .Lresident_dispatch_halt",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_nested_l2_resume_fail_invalid:",
    "vmptrld [r12 + {b_nested_vmcs01_region}]",
    "jna .Lresident_dispatch_halt",
    "jmp .Lresident_nested_vmfail_invalid",
    ".Lresident_dispatch_vmresume:",
    "inc qword ptr [r12 + {b_nested_vmresume_count}]",
    "inc qword ptr [r12 + {b_nested_entry_rejection_count}]",
    "cmp qword ptr [r12 + {b_nested_active}], 1",
    "jne .Lresident_nested_inject_ud",
    "mov rax, {guest_cs_selector}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "test r11b, 3",
    "jnz .Lresident_nested_inject_gp",
    "cmp qword ptr [r12 + {b_nested_current_vmcs}], -1",
    "je .Lresident_nested_vmfail_invalid",
    "mov rax, {guest_interruptibility_info}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "test r11b, 2",
    "jnz .Lresident_nested_entry_mov_ss",
    "cmp qword ptr [r12 + {b_nested_vmcs12_launch_state}], {vmcs12_launch_state_launched}",
    "jne .Lresident_nested_vmresume_non_launched",
    "call .Lresident_nested_validate_entry",
    "test r10d, r10d",
    "jnz .Lresident_nested_vmfail_with_error",
    "call .Lresident_nested_snapshot_vmcs01_effective_state",
    "dec qword ptr [r12 + {b_nested_entry_rejection_count}]",
    "mov qword ptr [r12 + {b_nested_l2_entry_was_resume}], 1",
    "mov qword ptr [r12 + {b_nested_l2_active}], 1",
    "inc qword ptr [r12 + {b_nested_l2_entry_count}]",
    "inc qword ptr [r12 + {b_nested_l2_resume_count}]",
    "vmptrld [r12 + {b_nested_vmcs02_region}]",
    "jna .Lresident_dispatch_halt",
    "call .Lresident_nested_prepare_ept02",
    "call .Lresident_nested_merge_vmcs02_controls",
    "call .Lresident_nested_sync_vmcs02_guest_state",
    "call .Lresident_nested_activate_vmcs02_ept",
    "mov rax, {guest_rip}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rip}]",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_rsp}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rsp}]",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "mov rax, {guest_rflags}",
    "mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rflags}]",
    "vmwrite rax, r11",
    "jna .Lresident_dispatch_vmwrite_failed",
    "jmp .Lresident_nested_l2_resume",
    ".Lresident_nested_entry_mov_ss:",
    "mov r10d, {vm_entry_blocked_by_mov_ss_error}",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_nested_vmresume_non_launched:",
    "mov r10d, {vmresume_non_launched_vmcs_error}",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_dispatch_exception:",
    "mov rax, {exit_intr_info}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "mov r13, r11",
    "test r11d, 0x80000000",
    "jz .Lresident_dispatch_unsupported",
    "and r11d, 0x7ff",
    "cmp r11d, 0x306",
    "jne .Lresident_dispatch_reinject_exception",
    "cmp qword ptr [r12 + {b_nested_active}], 1",
    "jne .Lresident_dispatch_reinject_exception",
    "mov r10, qword ptr [r12 + {b_nested_vmxon_region}]",
    "mov rax, qword ptr [r12 + {b_last_guest_rip}]",
    "cmp rax, qword ptr [r10 + {nested_invept_rip_offset}]",
    "je .Lresident_dispatch_invept_software_prepare",
    "cmp rax, qword ptr [r10 + {nested_invvpid_rip_offset}]",
    "je .Lresident_dispatch_invvpid_software_prepare",
    ".Lresident_dispatch_reinject_exception:",
    "mov rax, {vm_entry_intr_info_field}",
    "vmwrite rax, r13",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_invept_software_prepare:",
    "mov r11, qword ptr [r10 + {nested_invept_after_rip_offset}]",
    "sub r11, qword ptr [r12 + {b_last_guest_rip}]",
    "test r11, r11",
    "jz .Lresident_dispatch_reinject_exception",
    "cmp r11, 15",
    "ja .Lresident_dispatch_reinject_exception",
    "mov qword ptr [r12 + {b_last_instruction_len}], r11",
    "jmp .Lresident_dispatch_invept",
    ".Lresident_dispatch_invvpid_software_prepare:",
    "mov r11, qword ptr [r10 + {nested_invvpid_after_rip_offset}]",
    "sub r11, qword ptr [r12 + {b_last_guest_rip}]",
    "test r11, r11",
    "jz .Lresident_dispatch_reinject_exception",
    "cmp r11, 15",
    "ja .Lresident_dispatch_reinject_exception",
    "mov qword ptr [r12 + {b_last_instruction_len}], r11",
    "jmp .Lresident_dispatch_invvpid",
    ".Lresident_dispatch_invept:",
    "inc qword ptr [r12 + {b_nested_invept_count}]",
    "cmp qword ptr [r12 + {b_nested_active}], 1",
    "jne .Lresident_nested_inject_ud",
    "mov rax, {guest_cs_selector}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "test r11b, 3",
    "jnz .Lresident_nested_inject_gp",
    "mov r10, qword ptr [r12 + {b_nested_vmxon_region}]",
    "mov rax, qword ptr [r12 + {b_last_guest_rip}]",
    "cmp rax, qword ptr [r10 + {nested_invept_rip_offset}]",
    "je .Lresident_dispatch_invept_probe",
    "mov eax, dword ptr [r12 + {b_last_reason}]",
    "and eax, 0xffff",
    "cmp eax, {invept_reason}",
    "je .Lresident_dispatch_invept_hardware",
    "jmp .Lresident_nested_inject_ud",
    ".Lresident_dispatch_invept_probe:",
    "inc qword ptr [r12 + {b_nested_invept_software_count}]",
    "mov r11, qword ptr [r12 + {b_nested_vmxon_operand}]",
    "cmp qword ptr [rsp + 24], r11",
    "jne .Lresident_nested_invalid_invalidation_operand",
    "cmp qword ptr [rsp + 8], 1",
    "jne .Lresident_nested_invalid_invalidation_operand",
    "mov r10, qword ptr [r12 + {b_nested_vmxon_region}]",
    "mov r11, qword ptr [r10 + {nested_invept_descriptor_offset}]",
    "cmp r11, qword ptr [r12 + {b_nested_ept12_pointer}]",
    "jne .Lresident_nested_invalid_invalidation_operand",
    "cmp qword ptr [r10 + {nested_invept_descriptor_offset} + 8], 0",
    "jne .Lresident_nested_invalid_invalidation_operand",
    "mov r10, qword ptr [r12 + {b_nested_ept12_source_leaf}]",
    "test r10, r10",
    "jz .Lresident_nested_invalid_invalidation_operand",
    "mov r11, qword ptr [r10]",
    "mov rax, r11",
    "and eax, 0xfff",
    "cmp rax, qword ptr [r12 + {b_nested_ept12_source_leaf_attributes}]",
    "jne .Lresident_nested_invalid_invalidation_operand",
    "and r11, -4096",
    "cmp r11, qword ptr [r12 + {b_nested_ept_target_gpa}]",
    "je .Lresident_nested_invept_select_initial",
    "cmp r11, qword ptr [r12 + {b_nested_ept_second_target_gpa}]",
    "jne .Lresident_nested_invalid_invalidation_operand",
    "mov r11, qword ptr [r12 + {b_nested_ept02_alternate_pointer}]",
    "mov qword ptr [r12 + {b_nested_ept02_pointer}], r11",
    "jmp .Lresident_nested_succeed",
    ".Lresident_nested_invept_select_initial:",
    "mov r11, qword ptr [r12 + {b_nested_ept02_initial_pointer}]",
    "mov qword ptr [r12 + {b_nested_ept02_pointer}], r11",
    "jmp .Lresident_nested_succeed",
    ".Lresident_dispatch_invept_hardware:",
    "mov rax, {exit_instruction_info}",
    "vmread r13, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov eax, r13d",
    "shr eax, 28",
    "and eax, 15",
    "mov r15, rsp",
    "call .Lresident_nested_read_gpr",
    "mov r9, r11",
    "cmp r9, 1",
    "je .Lresident_dispatch_invept_hardware_decode",
    "cmp r9, 2",
    "jne .Lresident_nested_invalid_invalidation_operand",
    ".Lresident_dispatch_invept_hardware_decode:",
    "call .Lresident_nested_decode_memory_operand",
    "jc .Lresident_nested_inject_pf_read",
    "cmp r9, 2",
    "je .Lresident_dispatch_invept_all_contexts",
    "cmp qword ptr [r10 + 8], 0",
    "jne .Lresident_nested_invalid_invalidation_operand",
    "mov r14, qword ptr [r10]",
    "mov r11, r14",
    "and r11d, 0x3f",
    "cmp r11d, 0x1e",
    "jne .Lresident_nested_invalid_invalidation_operand",
    "test r14, 0xf80",
    "jnz .Lresident_nested_invalid_invalidation_operand",
    "test r14b, 0x40",
    "jz .Lresident_nested_invept_ad_ready",
    "bt qword ptr [r12 + {b_nested_vmx_ept_vpid_cap}], 21",
    "jnc .Lresident_nested_invalid_invalidation_operand",
    ".Lresident_nested_invept_ad_ready:",
    "mov r11, r14",
    "mov rdx, {host_page_address_mask}",
    "and r11, rdx",
    "call .Lresident_nested_physical_address_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_invalid_invalidation_operand",
    "call .Lresident_nested_host_page_is_mapped",
    "test eax, eax",
    "jz .Lresident_nested_invalid_invalidation_operand",
    // INVEPT identifies a context by EPTP[51:12], independent of A/D and MBEC.
    ".Lresident_nested_invalidate_ept12_context:",
    "mov rax, {host_page_address_mask}",
    "and r14, rax",
    "mov r11, qword ptr [r12 + {b_nested_ept12_pointer}]",
    "and r11, rax",
    "cmp r14, r11",
    "jne .Lresident_dispatch_invept_cached_context",
    "push r14",
    "call .Lresident_nested_revalidate_ept02",
    "pop r14",
    ".Lresident_dispatch_invept_cached_context:",
    "cmp qword ptr [r12 + {b_nested_ept02_cache_initialized}], 0",
    "je .Lresident_nested_succeed",
    "mov rax, {host_page_address_mask}",
    "and rax, qword ptr [r12 + {b_nested_ept02_cached_ept12_pointer}]",
    "cmp r14, rax",
    "jne .Lresident_nested_succeed",
    "call .Lresident_nested_swap_ept02_cache",
    "call .Lresident_nested_revalidate_ept02",
    "call .Lresident_nested_swap_ept02_cache",
    "jmp .Lresident_nested_succeed",
    ".Lresident_dispatch_invept_all_contexts:",
    "cmp qword ptr [r10], 0",
    "jne .Lresident_nested_invalid_invalidation_operand",
    "cmp qword ptr [r10 + 8], 0",
    "jne .Lresident_nested_invalid_invalidation_operand",
    "call .Lresident_nested_revalidate_ept02",
    "cmp qword ptr [r12 + {b_nested_ept02_cache_initialized}], 0",
    "je .Lresident_nested_succeed",
    "call .Lresident_nested_swap_ept02_cache",
    "call .Lresident_nested_revalidate_ept02",
    "call .Lresident_nested_swap_ept02_cache",
    "jmp .Lresident_nested_succeed",
    ".Lresident_dispatch_invvpid:",
    "inc qword ptr [r12 + {b_nested_invvpid_count}]",
    "cmp qword ptr [r12 + {b_nested_active}], 1",
    "jne .Lresident_nested_inject_ud",
    "mov rax, {guest_cs_selector}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "test r11b, 3",
    "jnz .Lresident_nested_inject_gp",
    "mov r10, qword ptr [r12 + {b_nested_vmxon_region}]",
    "mov rax, qword ptr [r12 + {b_last_guest_rip}]",
    "cmp rax, qword ptr [r10 + {nested_invvpid_rip_offset}]",
    "je .Lresident_dispatch_invvpid_probe",
    "mov eax, dword ptr [r12 + {b_last_reason}]",
    "and eax, 0xffff",
    "cmp eax, {invvpid_reason}",
    "je .Lresident_dispatch_invvpid_hardware",
    "jmp .Lresident_nested_inject_ud",
    ".Lresident_dispatch_invvpid_probe:",
    "inc qword ptr [r12 + {b_nested_invvpid_software_count}]",
    "mov r11, qword ptr [r12 + {b_nested_vmxon_operand}]",
    "cmp qword ptr [rsp + 24], r11",
    "jne .Lresident_nested_invalid_invalidation_operand",
    "cmp qword ptr [rsp + 8], 1",
    "jne .Lresident_nested_invalid_invalidation_operand",
    "mov r10, qword ptr [r12 + {b_nested_vmxon_region}]",
    "mov r11, qword ptr [r10 + {nested_invvpid_descriptor_offset}]",
    "mov rax, r11",
    "shr rax, 16",
    "test rax, rax",
    "jnz .Lresident_nested_invalid_invalidation_operand",
    "test r11w, r11w",
    "jz .Lresident_nested_invalid_invalidation_operand",
    "cmp r11w, word ptr [r12 + {b_nested_vmcs12_vpid}]",
    "jne .Lresident_nested_invalid_invalidation_operand",
    "call .Lresident_nested_flush_vpid02",
    "jmp .Lresident_nested_succeed",
    // A matching virtual tag invalidates only VMCS02's hardware translations.
    ".Lresident_dispatch_invvpid_hardware:",
    "mov rax, {exit_instruction_info}",
    "vmread r13, rax",
    "jna .Lresident_dispatch_vmread_failed",
    "mov eax, r13d",
    "shr eax, 28",
    "and eax, 15",
    "mov r15, rsp",
    "call .Lresident_nested_read_gpr",
    "mov r9, r11",
    "cmp r9, 3",
    "ja .Lresident_nested_invalid_invalidation_operand",
    "call .Lresident_nested_decode_memory_operand",
    "jc .Lresident_nested_inject_pf_read",
    ".Lresident_nested_invvpid_validate:",
    "mov r11, qword ptr [r10]",
    "mov rax, r11",
    "shr rax, 16",
    "test rax, rax",
    "jnz .Lresident_nested_invalid_invalidation_operand",
    "cmp r9, 2",
    "je .Lresident_dispatch_invvpid_all_contexts",
    "test r11w, r11w",
    "jz .Lresident_nested_invalid_invalidation_operand",
    "cmp r9, 0",
    "je .Lresident_dispatch_invvpid_individual_address",
    "jmp .Lresident_dispatch_invvpid_flush_context",
    ".Lresident_dispatch_invvpid_individual_address:",
    "mov rax, qword ptr [r10 + 8]",
    "mov r11, rax",
    "shl r11, 16",
    "sar r11, 16",
    "cmp rax, r11",
    "jne .Lresident_nested_invalid_invalidation_operand",
    ".Lresident_dispatch_invvpid_flush_context:",
    "movzx r11d, word ptr [r10]",
    "cmp r11, qword ptr [r12 + {b_nested_vmcs02_last_vpid}]",
    "jne .Lresident_nested_succeed",
    "call .Lresident_nested_flush_vpid02",
    "jmp .Lresident_nested_succeed",
    ".Lresident_dispatch_invvpid_all_contexts:",
    "call .Lresident_nested_flush_vpid02",
    "jmp .Lresident_nested_succeed",
    ".Lresident_nested_invalid_invalidation_operand:",
    "mov r10d, {invalid_invalidation_operand_error}",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_dispatch_vmxon:",
    "inc qword ptr [r12 + {b_nested_vmxon_count}]",
    "mov r11, qword ptr [r12 + {b_nested_l1_cr4}]",
    "test r11, 0x2000",
    "jz .Lresident_nested_inject_ud",
    "mov rax, {guest_cs_selector}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "test r11b, 3",
    "jnz .Lresident_nested_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_feature_control}]",
    "and r11d, 5",
    "cmp r11d, 5",
    "jne .Lresident_nested_inject_gp",
    "cmp qword ptr [r12 + {b_nested_active}], 0",
    "jne .Lresident_nested_vmxon_active",
    "call .Lresident_nested_decode_memory_operand",
    "jc .Lresident_nested_inject_pf_read",
    "mov r14, r10",
    "mov r11, qword ptr [r10]",
    "mov qword ptr [r12 + {b_nested_last_operand}], r11",
    "call .Lresident_nested_physical_address_is_valid",
    "test eax, eax",
    "jz .Lresident_nested_vmfail_invalid",
    "mov edx, dword ptr [r11]",
    "mov eax, dword ptr [r12 + {b_nested_vmx_basic}]",
    "and eax, 0x7fffffff",
    "cmp edx, eax",
    "jne .Lresident_nested_vmfail_invalid",
    "mov qword ptr [r12 + {b_nested_vmxon_operand}], r14",
    "mov qword ptr [r12 + {b_nested_vmxon_region}], r11",
    "mov qword ptr [r12 + {b_nested_active}], 1",
    "mov qword ptr [r12 + {b_nested_current_vmcs}], -1",
    "mov qword ptr [r12 + {b_nested_instruction_error}], 0",
    "lea rsi, [rip + .Lnested_vmxon_message]",
    "mov r9d, {nested_vmxon_message_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_processor_number}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lnested_pointer_message]",
    "mov r9d, {nested_pointer_message_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_nested_last_operand}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_rip]",
    "mov r9d, {state_rip_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_guest_rip}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_newline]",
    "mov r9d, {state_newline_len}",
    "call .Lresident_serial_write",
    "jmp .Lresident_nested_succeed",
    ".Lresident_nested_vmxon_active:",
    "mov r10d, {vmxon_in_vmx_root_error}",
    "jmp .Lresident_nested_vmfail_with_error",
    ".Lresident_dispatch_vmxoff:",
    "inc qword ptr [r12 + {b_nested_vmxoff_count}]",
    "cmp qword ptr [r12 + {b_nested_active}], 1",
    "jne .Lresident_nested_inject_ud",
    "mov rax, {guest_cs_selector}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "test r11b, 3",
    "jnz .Lresident_nested_inject_gp",
    "mov rax, {exception_bitmap}",
    "xor r11d, r11d",
    "vmwrite rax, r11",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "call .Lresident_nested_store_current_vmcs12",
    "mov qword ptr [r12 + {b_nested_active}], 0",
    "mov qword ptr [r12 + {b_nested_current_vmcs}], -1",
    "mov qword ptr [r12 + {b_nested_instruction_error}], 0",
    "mov qword ptr [r12 + {b_nested_probe_complete}], 1",
    "lea rsi, [rip + .Lnested_vmxoff_message]",
    "mov r9d, {nested_vmxoff_message_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_processor_number}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lnested_pointer_message]",
    "mov r9d, {nested_pointer_message_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_nested_last_operand}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_rip]",
    "mov r9d, {state_rip_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_guest_rip}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_newline]",
    "mov r9d, {state_newline_len}",
    "call .Lresident_serial_write",
    "jmp .Lresident_nested_succeed",
    ".Lresident_nested_vmfail_with_error:",
    "inc qword ptr [r12 + {b_nested_failure_count}]",
    "cmp qword ptr [r12 + {b_nested_current_vmcs}], -1",
    "je .Lresident_nested_vmfail_invalid_flags",
    "mov qword ptr [r12 + {b_nested_instruction_error}], r10",
    "mov rax, {guest_rflags}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "and r11, {vmx_status_flags_clear_mask}",
    "or r11, {vmfail_valid_status}",
    "vmwrite rax, r11",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_nested_vmfail_invalid:",
    "inc qword ptr [r12 + {b_nested_failure_count}]",
    ".Lresident_nested_vmfail_invalid_flags:",
    "mov rax, {guest_rflags}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "and r11, {vmx_status_flags_clear_mask}",
    "or r11, {vmfail_invalid_status}",
    "vmwrite rax, r11",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_nested_succeed:",
    "mov rax, {guest_rflags}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "and r11, {vmx_status_flags_clear_mask}",
    "vmwrite rax, r11",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_nested_inject_pf_write:",
    "mov r11d, 2",
    "jmp .Lresident_nested_inject_pf",
    ".Lresident_nested_inject_pf_read:",
    "xor r11d, r11d",
    ".Lresident_nested_inject_pf:",
    "inc qword ptr [r12 + {b_nested_failure_count}]",
    "mov cr2, r10",
    "mov rax, {vm_entry_exception_error_code}",
    "vmwrite rax, r11",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "mov rax, {vm_entry_intr_info_field}",
    "mov r10d, 0x80000b0e",
    "vmwrite rax, r10",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_nested_inject_ud:",
    "inc qword ptr [r12 + {b_nested_failure_count}]",
    "mov rax, {vm_entry_intr_info_field}",
    "mov r10d, 0x80000306",
    "vmwrite rax, r10",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_nested_inject_gp:",
    "inc qword ptr [r12 + {b_nested_failure_count}]",
    "jmp .Lresident_dispatch_inject_gp",
    ".Lresident_dispatch_cpuid:",
    "inc qword ptr [r12 + {b_cpuid_count}]",
    "mov eax, dword ptr [rsp + 0]",
    "mov ecx, dword ptr [rsp + 8]",
    "mov r8d, eax",
    "cmp r8d, {matrixhv_status_leaf}",
    "je .Lresident_dispatch_cpuid_matrixhv",
    "cpuid",
    "mov qword ptr [rsp + 0], rax",
    "mov qword ptr [rsp + 24], rbx",
    "mov qword ptr [rsp + 8], rcx",
    "mov qword ptr [rsp + 16], rdx",
    "cmp r8d, {hypervisor_leaf_start}",
    "jb .Lresident_dispatch_cpuid_standard",
    "cmp r8d, {hypervisor_leaf_end}",
    "ja .Lresident_dispatch_cpuid_standard",
    "inc qword ptr [r12 + {b_cpuid_hypervisor_count}]",
    "cmp qword ptr [r12 + {b_cpuid_presence}], 0",
    "jne .Lresident_dispatch_cpuid_hypervisor_present",
    "mov qword ptr [rsp + 0], 0",
    "mov qword ptr [rsp + 24], 0",
    "mov qword ptr [rsp + 8], 0",
    "mov qword ptr [rsp + 16], 0",
    "mov qword ptr [r12 + {b_cpuid_hypervisor_eax}], 0",
    "jmp .Lresident_dispatch_cpuid_advance",
    ".Lresident_dispatch_cpuid_hypervisor_present:",
    "mov r10d, dword ptr [rsp + 0]",
    "mov qword ptr [r12 + {b_cpuid_hypervisor_eax}], r10",
    "cmp r8d, {hyperv_features_leaf}",
    "jne .Lresident_dispatch_cpuid_advance",
    "and dword ptr [rsp + 0], {hyperv_guest_idle_access_mask}",
    "and dword ptr [rsp + 16], {hyperv_guest_idle_feature_mask}",
    "jmp .Lresident_dispatch_cpuid_advance",
    ".Lresident_dispatch_cpuid_matrixhv:",
    "inc qword ptr [r12 + {b_cpuid_hypervisor_count}]",
    "mov r10d, {matrixhv_status_signature_eax}",
    "mov qword ptr [rsp + 0], r10",
    "mov qword ptr [r12 + {b_cpuid_hypervisor_eax}], r10",
    "mov r10d, {matrixhv_status_signature_ebx}",
    "mov qword ptr [rsp + 24], r10",
    "mov r10d, {matrixhv_status_signature_ecx}",
    "mov qword ptr [rsp + 8], r10",
    "mov r10d, {matrixhv_status_protocol}",
    "mov qword ptr [rsp + 16], r10",
    "jmp .Lresident_dispatch_cpuid_advance",
    ".Lresident_dispatch_cpuid_standard:",
    "cmp r8d, 1",
    "jne .Lresident_dispatch_cpuid_advance",
    "inc qword ptr [r12 + {b_cpuid_leaf1_count}]",
    "mov r10d, dword ptr [rsp + 8]",
    "and r10d, {cpuid_vmx_clear_mask}",
    "and r10d, {cpuid_osxsave_clear_mask}",
    "mov rax, {guest_cr4}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "test r11, {cr4_osxsave_mask}",
    "jz .Lresident_dispatch_cpuid_osxsave_ready",
    "or r10d, {cpuid_osxsave_set_mask}",
    ".Lresident_dispatch_cpuid_osxsave_ready:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_cpuid_vmx_ready",
    "or r10d, {cpuid_vmx_set_mask}",
    ".Lresident_dispatch_cpuid_vmx_ready:",
    "cmp qword ptr [r12 + {b_cpuid_presence}], 0",
    "je .Lresident_dispatch_cpuid_presence_hidden",
    "or r10d, {cpuid_hypervisor_set_mask}",
    "jmp .Lresident_dispatch_cpuid_presence_ready",
    ".Lresident_dispatch_cpuid_presence_hidden:",
    "and r10d, {cpuid_hypervisor_clear_mask}",
    ".Lresident_dispatch_cpuid_presence_ready:",
    "mov qword ptr [rsp + 8], r10",
    "mov qword ptr [r12 + {b_cpuid_leaf1_ecx}], r10",
    ".Lresident_dispatch_cpuid_advance:",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_rdmsr:",
    "inc qword ptr [r12 + {b_rdmsr_count}]",
    "mov ecx, dword ptr [rsp + 8]",
    "cmp ecx, {tsc_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {tsc_adjust_msr}",
    "je .Lresident_dispatch_rdmsr_tsc_adjust",
    "cmp ecx, {platform_id_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {apic_base_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {xss_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {feature_control_msr}",
    "je .Lresident_dispatch_rdmsr_feature_control",
    "cmp ecx, {vmx_basic_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_basic",
    "cmp ecx, {vmx_pinbased_ctls_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_pinbased_ctls",
    "cmp ecx, {vmx_procbased_ctls_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_procbased_ctls",
    "cmp ecx, {vmx_exit_ctls_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_exit_ctls",
    "cmp ecx, {vmx_entry_ctls_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_entry_ctls",
    "cmp ecx, {vmx_misc_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_misc",
    "cmp ecx, {vmx_cr0_fixed0_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_cr0_fixed0",
    "cmp ecx, {vmx_cr0_fixed1_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_cr0_fixed1",
    "cmp ecx, {vmx_cr4_fixed0_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_cr4_fixed0",
    "cmp ecx, {vmx_cr4_fixed1_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_cr4_fixed1",
    "cmp ecx, {vmx_vmcs_enum_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_vmcs_enum",
    "cmp ecx, {vmx_procbased_ctls2_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_procbased_ctls2",
    "cmp ecx, {vmx_ept_vpid_cap_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_ept_vpid_cap",
    "cmp ecx, {vmx_true_pinbased_ctls_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_true_pinbased_ctls",
    "cmp ecx, {vmx_true_procbased_ctls_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_true_procbased_ctls",
    "cmp ecx, {vmx_true_exit_ctls_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_true_exit_ctls",
    "cmp ecx, {vmx_true_entry_ctls_msr}",
    "je .Lresident_dispatch_rdmsr_vmx_true_entry_ctls",
    "cmp ecx, {bios_sign_id_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {mtrrcap_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {pkg_energy_status_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {rapl_power_unit_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {dram_energy_status_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {pp0_energy_status_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {pp1_energy_status_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {x2apic_msr_base}",
    "jb .Lresident_dispatch_rdmsr_before_x2apic",
    "cmp ecx, {x2apic_msr_end}",
    "jbe .Lresident_dispatch_rdmsr_passthrough",
    ".Lresident_dispatch_rdmsr_before_x2apic:",
    "cmp ecx, {mtrr_physbase0_msr}",
    "jb .Lresident_dispatch_rdmsr_after_variable_mtrr",
    "mov r10d, ecx",
    "mov ecx, {mtrrcap_msr}",
    "rdmsr",
    "and eax, 0xff",
    "shl eax, 1",
    "add eax, {mtrr_physbase0_msr}",
    "cmp r10d, eax",
    "jae .Lresident_dispatch_rdmsr_after_variable_mtrr",
    "mov ecx, r10d",
    "jmp .Lresident_dispatch_rdmsr_passthrough",
    ".Lresident_dispatch_rdmsr_after_variable_mtrr:",
    "mov ecx, dword ptr [rsp + 8]",
    "cmp ecx, {mtrr_fix64k_00000_msr}",
    "je .Lresident_dispatch_rdmsr_fixed_mtrr",
    "cmp ecx, {mtrr_fix16k_80000_msr}",
    "je .Lresident_dispatch_rdmsr_fixed_mtrr",
    "cmp ecx, {mtrr_fix16k_a0000_msr}",
    "je .Lresident_dispatch_rdmsr_fixed_mtrr",
    "cmp ecx, {mtrr_fix4k_c0000_msr}",
    "jb .Lresident_dispatch_rdmsr_after_fixed_mtrr",
    "cmp ecx, {mtrr_fix4k_f8000_msr}",
    "jbe .Lresident_dispatch_rdmsr_fixed_mtrr",
    ".Lresident_dispatch_rdmsr_after_fixed_mtrr:",
    "cmp ecx, {mtrr_def_type_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {hyperv_hypercall_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {hyperv_vp_index_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {hyperv_simp_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "mov eax, ecx",
    "sub eax, {hyperv_reference_tsc_msr}",
    "cmp eax, {hyperv_reference_time_msr_span}",
    "jbe .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {sysenter_cs_msr}",
    "je .Lresident_dispatch_rdmsr_sysenter_cs",
    "cmp ecx, {sysenter_esp_msr}",
    "je .Lresident_dispatch_rdmsr_sysenter_esp",
    "cmp ecx, {sysenter_eip_msr}",
    "je .Lresident_dispatch_rdmsr_sysenter_eip",
    "cmp ecx, {efer_msr}",
    "je .Lresident_dispatch_rdmsr_efer",
    "cmp ecx, {gs_base_msr}",
    "je .Lresident_dispatch_rdmsr_gs_base",
    "cmp ecx, {fs_base_msr}",
    "je .Lresident_dispatch_rdmsr_fs_base",
    "cmp ecx, {amd_sev_status_msr}",
    "je .Lresident_dispatch_rdmsr_zero",
    "cmp ecx, {kernel_gs_base_msr}",
    "je .Lresident_dispatch_rdmsr_kernel_gs_base",
    "cmp ecx, 0x480",
    "jb .Lresident_dispatch_rdmsr_not_vmx",
    "cmp ecx, 0x490",
    "jbe .Lresident_dispatch_inject_gp",
    ".Lresident_dispatch_rdmsr_not_vmx:",
    "jmp .Lresident_dispatch_inject_gp",
    ".Lresident_dispatch_rdmsr_tsc_adjust:",
    "mov r11, qword ptr [r12 + {b_tsc_adjust}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_feature_control:",
    "mov r11, qword ptr [r12 + {b_nested_feature_control}]",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "jne .Lresident_dispatch_rdmsr_nested_value",
    "and r11, -5",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_basic:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_basic}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_pinbased_ctls:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_pinbased_ctls}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_procbased_ctls:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_procbased_ctls}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_exit_ctls:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_exit_ctls}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_entry_ctls:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_entry_ctls}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_misc:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_misc}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_cr0_fixed0:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_cr0_fixed0}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_cr0_fixed1:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_cr0_fixed1}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_cr4_fixed0:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_cr4_fixed0}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_cr4_fixed1:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_cr4_fixed1}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_vmcs_enum:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_vmcs_enum}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_procbased_ctls2:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_procbased_ctls2}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_ept_vpid_cap:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_ept_vpid_cap}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_true_pinbased_ctls:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "bt qword ptr [r12 + {b_nested_vmx_basic}], 55",
    "jnc .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_true_pinbased_ctls}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_true_procbased_ctls:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "bt qword ptr [r12 + {b_nested_vmx_basic}], 55",
    "jnc .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_true_procbased_ctls}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_true_exit_ctls:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "bt qword ptr [r12 + {b_nested_vmx_basic}], 55",
    "jnc .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_true_exit_ctls}]",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_vmx_true_entry_ctls:",
    "cmp qword ptr [r12 + {b_nested_expose_vmx}], 0",
    "je .Lresident_dispatch_inject_gp",
    "bt qword ptr [r12 + {b_nested_vmx_basic}], 55",
    "jnc .Lresident_dispatch_inject_gp",
    "mov r11, qword ptr [r12 + {b_nested_vmx_true_entry_ctls}]",
    ".Lresident_dispatch_rdmsr_nested_value:",
    "mov eax, r11d",
    "mov qword ptr [rsp + 0], rax",
    "shr r11, 32",
    "mov eax, r11d",
    "mov qword ptr [rsp + 16], rax",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_rdmsr_zero:",
    "xor r11d, r11d",
    "jmp .Lresident_dispatch_rdmsr_nested_value",
    ".Lresident_dispatch_rdmsr_fixed_mtrr:",
    "mov r10d, ecx",
    "mov ecx, {mtrrcap_msr}",
    "rdmsr",
    "test eax, 0x100",
    "jz .Lresident_dispatch_unsupported",
    "mov ecx, r10d",
    "jmp .Lresident_dispatch_rdmsr_passthrough",
    ".Lresident_dispatch_rdmsr_passthrough:",
    "rdmsr",
    "mov qword ptr [rsp + 0], rax",
    "mov qword ptr [rsp + 16], rdx",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_rdmsr_sysenter_cs:",
    "mov rax, {guest_sysenter_cs}",
    "jmp .Lresident_dispatch_rdmsr_vmcs_value",
    ".Lresident_dispatch_rdmsr_fs_base:",
    "mov rax, {guest_fs_base}",
    "jmp .Lresident_dispatch_rdmsr_vmcs_value",
    ".Lresident_dispatch_rdmsr_sysenter_esp:",
    "mov rax, {guest_sysenter_esp}",
    "jmp .Lresident_dispatch_rdmsr_vmcs_value",
    ".Lresident_dispatch_rdmsr_sysenter_eip:",
    "mov rax, {guest_sysenter_eip}",
    ".Lresident_dispatch_rdmsr_vmcs_value:",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "mov eax, r11d",
    "mov qword ptr [rsp + 0], rax",
    "shr r11, 32",
    "mov eax, r11d",
    "mov qword ptr [rsp + 16], rax",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_rdmsr_efer:",
    "mov rax, {guest_efer}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "mov eax, r11d",
    "mov qword ptr [rsp + 0], rax",
    "shr r11, 32",
    "mov eax, r11d",
    "mov qword ptr [rsp + 16], rax",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_rdmsr_gs_base:",
    "mov rax, {guest_gs_base}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "mov eax, r11d",
    "mov qword ptr [rsp + 0], rax",
    "shr r11, 32",
    "mov eax, r11d",
    "mov qword ptr [rsp + 16], rax",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_rdmsr_kernel_gs_base:",
    "mov rax, {vm_entry_msr_load_addr}",
    "vmread r10, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "mov r11, qword ptr [r10 + 8]",
    "mov eax, r11d",
    "mov qword ptr [rsp + 0], rax",
    "shr r11, 32",
    "mov eax, r11d",
    "mov qword ptr [rsp + 16], rax",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_wrmsr:",
    "inc qword ptr [r12 + {b_wrmsr_count}]",
    "mov ecx, dword ptr [rsp + 8]",
    "cmp ecx, {tsc_msr}",
    "je .Lresident_dispatch_wrmsr_tsc",
    "cmp ecx, {tsc_adjust_msr}",
    "je .Lresident_dispatch_wrmsr_tsc_adjust",
    "cmp ecx, {apic_base_msr}",
    "je .Lresident_dispatch_wrmsr_passthrough",
    "cmp ecx, {xss_msr}",
    "je .Lresident_dispatch_wrmsr_passthrough",
    "cmp ecx, {bios_sign_id_msr}",
    "je .Lresident_dispatch_wrmsr_passthrough",
    "cmp ecx, {mtrr_def_type_msr}",
    "je .Lresident_dispatch_wrmsr_passthrough",
    "cmp ecx, {x2apic_msr_base}",
    "jb .Lresident_dispatch_wrmsr_before_x2apic",
    "cmp ecx, {x2apic_msr_end}",
    "jbe .Lresident_dispatch_wrmsr_passthrough",
    ".Lresident_dispatch_wrmsr_before_x2apic:",
    "cmp ecx, {mtrr_physbase0_msr}",
    "jb .Lresident_dispatch_wrmsr_after_variable_mtrr",
    "mov r10d, ecx",
    "mov ecx, {mtrrcap_msr}",
    "rdmsr",
    "and eax, 0xff",
    "shl eax, 1",
    "add eax, {mtrr_physbase0_msr}",
    "cmp r10d, eax",
    "jae .Lresident_dispatch_wrmsr_after_variable_mtrr",
    "mov ecx, r10d",
    "jmp .Lresident_dispatch_wrmsr_passthrough",
    ".Lresident_dispatch_wrmsr_after_variable_mtrr:",
    "mov ecx, dword ptr [rsp + 8]",
    "cmp ecx, {mtrr_fix64k_00000_msr}",
    "je .Lresident_dispatch_wrmsr_fixed_mtrr",
    "cmp ecx, {mtrr_fix16k_80000_msr}",
    "je .Lresident_dispatch_wrmsr_fixed_mtrr",
    "cmp ecx, {mtrr_fix16k_a0000_msr}",
    "je .Lresident_dispatch_wrmsr_fixed_mtrr",
    "cmp ecx, {mtrr_fix4k_c0000_msr}",
    "jb .Lresident_dispatch_wrmsr_after_fixed_mtrr",
    "cmp ecx, {mtrr_fix4k_f8000_msr}",
    "jbe .Lresident_dispatch_wrmsr_fixed_mtrr",
    ".Lresident_dispatch_wrmsr_after_fixed_mtrr:",
    "cmp ecx, {hyperv_guest_os_id_msr}",
    "je .Lresident_dispatch_wrmsr_passthrough",
    "cmp ecx, {hyperv_hypercall_msr}",
    "je .Lresident_dispatch_wrmsr_passthrough",
    "cmp ecx, {hyperv_reference_tsc_msr}",
    "je .Lresident_dispatch_wrmsr_passthrough",
    "cmp ecx, {hyperv_vp_assist_msr}",
    "je .Lresident_dispatch_wrmsr_passthrough",
    "cmp ecx, {hyperv_simp_msr}",
    "je .Lresident_dispatch_wrmsr_passthrough",
    "cmp ecx, {hyperv_sint3_msr}",
    "je .Lresident_dispatch_wrmsr_passthrough",
    "cmp ecx, {hyperv_stimer0_config_msr}",
    "je .Lresident_dispatch_wrmsr_passthrough",
    "cmp ecx, {hyperv_stimer0_count_msr}",
    "je .Lresident_dispatch_wrmsr_passthrough",
    "cmp ecx, {sysenter_cs_msr}",
    "je .Lresident_dispatch_wrmsr_sysenter_cs",
    "cmp ecx, {sysenter_esp_msr}",
    "je .Lresident_dispatch_wrmsr_sysenter_esp",
    "cmp ecx, {sysenter_eip_msr}",
    "je .Lresident_dispatch_wrmsr_sysenter_eip",
    "cmp ecx, {gs_base_msr}",
    "je .Lresident_dispatch_wrmsr_gs_base",
    "cmp ecx, {fs_base_msr}",
    "je .Lresident_dispatch_wrmsr_fs_base",
    "cmp ecx, {kernel_gs_base_msr}",
    "je .Lresident_dispatch_wrmsr_kernel_gs_base",
    "cmp ecx, {feature_control_msr}",
    "je .Lresident_dispatch_inject_gp",
    "cmp ecx, 0x480",
    "jb .Lresident_dispatch_wrmsr_not_vmx",
    "cmp ecx, 0x490",
    "jbe .Lresident_dispatch_inject_gp",
    ".Lresident_dispatch_wrmsr_not_vmx:",
    "cmp ecx, {efer_msr}",
    "jne .Lresident_dispatch_inject_gp",
    "mov eax, dword ptr [rsp + 0]",
    "mov edx, dword ptr [rsp + 16]",
    "shl rdx, 32",
    "or rax, rdx",
    "mov r11, rax",
    "mov rax, {guest_efer}",
    "vmwrite rax, r11",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_wrmsr_tsc:",
    "mov r10d, dword ptr [rsp + 0]",
    "mov r11d, dword ptr [rsp + 16]",
    "shl r11, 32",
    "or r10, r11",
    "rdtsc",
    "shl rdx, 32",
    "or rax, rdx",
    "sub r10, rax",
    "mov r11, r10",
    "mov rax, {tsc_offset}",
    "vmread rdx, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "sub r11, rdx",
    "add qword ptr [r12 + {b_tsc_adjust}], r11",
    "vmwrite rax, r10",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_wrmsr_tsc_adjust:",
    "mov r10d, dword ptr [rsp + 0]",
    "mov r11d, dword ptr [rsp + 16]",
    "shl r11, 32",
    "or r10, r11",
    "mov r11, qword ptr [r12 + {b_tsc_adjust}]",
    "mov qword ptr [r12 + {b_tsc_adjust}], r10",
    "sub r10, r11",
    "mov rax, {tsc_offset}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "add r11, r10",
    "vmwrite rax, r11",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_wrmsr_fs_base:",
    "mov r10, {guest_fs_base}",
    "jmp .Lresident_dispatch_wrmsr_vmcs_value",
    ".Lresident_dispatch_wrmsr_sysenter_cs:",
    "mov r10, {guest_sysenter_cs}",
    "jmp .Lresident_dispatch_wrmsr_vmcs_value",
    ".Lresident_dispatch_wrmsr_sysenter_esp:",
    "mov r10, {guest_sysenter_esp}",
    "jmp .Lresident_dispatch_wrmsr_vmcs_value",
    ".Lresident_dispatch_wrmsr_sysenter_eip:",
    "mov r10, {guest_sysenter_eip}",
    ".Lresident_dispatch_wrmsr_vmcs_value:",
    "mov eax, dword ptr [rsp + 0]",
    "mov edx, dword ptr [rsp + 16]",
    "shl rdx, 32",
    "or rax, rdx",
    "mov r11, rax",
    "vmwrite r10, r11",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_wrmsr_kernel_gs_base:",
    "mov eax, dword ptr [rsp + 0]",
    "mov edx, dword ptr [rsp + 16]",
    "shl rdx, 32",
    "or rax, rdx",
    "mov r11, rax",
    "mov rax, {vm_entry_msr_load_addr}",
    "vmread r10, rax",
    "jc .Lresident_dispatch_vmread_failed",
    "jz .Lresident_dispatch_vmread_failed",
    "mov qword ptr [r10 + 8], r11",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_wrmsr_gs_base:",
    "mov eax, dword ptr [rsp + 0]",
    "mov edx, dword ptr [rsp + 16]",
    "shl rdx, 32",
    "or rax, rdx",
    "mov r11, rax",
    "mov rax, {guest_gs_base}",
    "vmwrite rax, r11",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_wrmsr_fixed_mtrr:",
    "mov r10d, ecx",
    "mov ecx, {mtrrcap_msr}",
    "rdmsr",
    "test eax, 0x100",
    "jz .Lresident_dispatch_unsupported",
    "mov ecx, r10d",
    ".Lresident_dispatch_wrmsr_passthrough:",
    "mov eax, dword ptr [rsp + 0]",
    "mov edx, dword ptr [rsp + 16]",
    "wrmsr",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_xsetbv:",
    "inc qword ptr [r12 + {b_xsetbv_count}]",
    "cmp qword ptr [rsp + 8], 0",
    "jne .Lresident_dispatch_unsupported",
    "mov r11, cr4",
    "mov r10, r11",
    "or r10, 0x40000",
    "mov cr4, r10",
    "mov eax, dword ptr [rsp + 0]",
    "mov edx, dword ptr [rsp + 16]",
    "xor ecx, ecx",
    "xsetbv",
    "mov cr4, r11",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_vmcall:",
    "inc qword ptr [r12 + {b_vmcall_count}]",
    "mov rax, qword ptr [rsp + 0]",
    "mov r11, 0x4856415052454144",
    "cmp rax, r11",
    "je .Lresident_ap_ready",
    "mov r11, {start_checkpoint_magic}",
    "cmp rax, r11",
    "je .Lresident_dispatch_start_checkpoint",
    "mov r11, {stop_magic}",
    "cmp rax, r11",
    "je .Lresident_dispatch_stop",
    "mov r11, {nested_probe_failed_magic}",
    "cmp rax, r11",
    "je .Lresident_dispatch_nested_probe_failed",
    "cmp eax, {vmware_hypervisor_magic}",
    "je .Lresident_dispatch_vmware_hypercall",
    "jmp .Lresident_dispatch_unsupported",
    ".Lresident_dispatch_vmware_hypercall:",
    "mov rax, qword ptr [rsp + 0]",
    "mov rcx, qword ptr [rsp + 8]",
    "mov rdx, qword ptr [rsp + 16]",
    "mov rbx, qword ptr [rsp + 24]",
    "mov rsi, qword ptr [rsp + 40]",
    "mov rdi, qword ptr [rsp + 48]",
    "mov dx, {vmware_hypervisor_port}",
    "in eax, dx",
    "mov qword ptr [rsp + 0], rax",
    "mov qword ptr [rsp + 8], rcx",
    "mov qword ptr [rsp + 16], rdx",
    "mov qword ptr [rsp + 24], rbx",
    "mov qword ptr [rsp + 40], rsi",
    "mov qword ptr [rsp + 48], rdi",
    "mov r12, qword ptr [rsp + 120]",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_start_checkpoint:",
    "mov qword ptr [r12 + {b_start_checkpoint_seen}], 1",
    "lea rsi, [rip + .Lstart_checkpoint_message]",
    "mov r9d, {start_checkpoint_message_len}",
    "call .Lresident_serial_write",
    "call .Lresident_serial_state",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_stop:",
    "mov rdi, qword ptr [r12 + {b_event_context}]",
    "test rdi, rdi",
    "jz .Lresident_dispatch_stop_record",
    "cmp qword ptr [rdi + {event_ebs_seen}], 0",
    "jne .Lresident_dispatch_post_ebs_stop",
    ".Lresident_dispatch_stop_record:",
    "mov rax, qword ptr [rsp + 16]",
    "mov qword ptr [r12 + {b_stop_result}], rax",
    "lea rsi, [rip + .Lstart_returned_message]",
    "mov r9d, {start_returned_message_len}",
    "call .Lresident_serial_write",
    "call .Lresident_serial_state",
    "jmp .Lresident_dispatch_halt",
    ".Lresident_dispatch_post_ebs_stop:",
    "lea rsi, [rip + .Lpost_ebs_stop_message]",
    "mov r9d, {post_ebs_stop_message_len}",
    "call .Lresident_serial_write",
    "call .Lresident_serial_state",
    "jmp .Lresident_dispatch_halt",
    ".Lresident_dispatch_nested_probe_failed:",
    "lea rsi, [rip + .Lnested_failure_message]",
    "mov r9d, {nested_failure_message_len}",
    "call .Lresident_serial_write",
    "call .Lresident_serial_state",
    "jmp .Lresident_dispatch_halt",
    ".Lresident_dispatch_unsupported:",
    "mov rax, {unsupported_stop}",
    "mov qword ptr [r12 + {b_stop_result}], rax",
    "lea rsi, [rip + .Lunsupported_exit_message]",
    "mov r9d, {unsupported_exit_message_len}",
    "call .Lresident_serial_write",
    "call .Lresident_serial_state",
    "jmp .Lresident_dispatch_halt",
    ".Lresident_dispatch_host_cr3_mismatch:",
    "lea rsi, [rip + .Lhost_cr3_mismatch_message]",
    "mov r9d, {host_cr3_mismatch_message_len}",
    "call .Lresident_serial_write",
    "call .Lresident_serial_state",
    "jmp .Lresident_dispatch_halt",
    ".Lresident_dispatch_event_corrupt:",
    "lea rsi, [rip + .Levent_corrupt_message]",
    "mov r9d, {event_corrupt_message_len}",
    "call .Lresident_serial_write",
    "call .Lresident_serial_state",
    "jmp .Lresident_dispatch_halt",
    ".Lresident_dispatch_vmread_failed:",
    "lea rsi, [rip + .Lvmread_failed_message]",
    "mov r9d, {vmread_failed_message_len}",
    "call .Lresident_serial_write",
    "jmp .Lresident_dispatch_halt",
    ".Lresident_dispatch_inject_gp:",
    "mov rax, {vm_entry_exception_error_code}",
    "xor r10d, r10d",
    "vmwrite rax, r10",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "mov rax, {vm_entry_intr_info_field}",
    "mov r10d, 0x80000b0d",
    "vmwrite rax, r10",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_advance_guest_rip:",
    "mov r10, qword ptr [r12 + {b_last_guest_rip}]",
    "add r10, qword ptr [r12 + {b_last_instruction_len}]",
    "mov rax, {guest_rip}",
    "vmwrite rax, r10",
    "jc .Lresident_dispatch_vmwrite_failed",
    "jz .Lresident_dispatch_vmwrite_failed",
    "ret",
    ".Lresident_dispatch_vmwrite_failed:",
    "lea rsi, [rip + .Lvmwrite_failed_message]",
    "mov r9d, {vmwrite_failed_message_len}",
    "call .Lresident_serial_write",
    "call .Lresident_serial_state",
    "jmp .Lresident_dispatch_halt",
    ".Lresident_dispatch_resume:",
    "call .Lresident_profile_exit_handler",
    "pop rax",
    "pop rcx",
    "pop rdx",
    "pop rbx",
    "pop rbp",
    "pop rsi",
    "pop rdi",
    "pop r8",
    "pop r9",
    "pop r10",
    "pop r11",
    "pop r12",
    "pop r13",
    "pop r14",
    "pop r15",
    "vmresume",
    "mov r12, qword ptr [rsp]",
    "lea rsi, [rip + .Lvmresume_failed_message]",
    "mov r9d, {vmresume_failed_message_len}",
    "call .Lresident_serial_write",
    "mov rax, {vm_instruction_error}",
    "vmread r11, rax",
    "jc .Lresident_dispatch_vmresume_error_unknown",
    "jz .Lresident_dispatch_vmresume_error_unknown",
    "mov rax, r11",
    "jmp .Lresident_dispatch_vmresume_error_print",
    ".Lresident_dispatch_vmresume_error_unknown:",
    "mov rax, -1",
    ".Lresident_dispatch_vmresume_error_print:",
    "call .Lresident_serial_hex64",
    "call .Lresident_serial_state",
    // Separate emulated VMCS access, entry, EPT invalidation, and other exit costs.
    ".Lresident_profile_exit_handler:",
    "mov ecx, 2",
    "mov r11d, dword ptr [r12 + {b_last_reason}]",
    "cmp r11d, {vmread_reason}",
    "je .Lresident_profile_vmcs_access",
    "cmp r11d, {vmwrite_reason}",
    "je .Lresident_profile_vmcs_access",
    "cmp r11d, {vmresume_reason}",
    "je .Lresident_profile_nested_entry",
    "cmp r11d, {vmlaunch_reason}",
    "je .Lresident_profile_nested_entry",
    "cmp r11d, {invept_reason}",
    "jne .Lresident_profile_accumulate",
    "mov ecx, 3",
    "jmp .Lresident_profile_accumulate",
    ".Lresident_profile_vmcs_access:",
    "xor ecx, ecx",
    "jmp .Lresident_profile_accumulate",
    ".Lresident_profile_nested_entry:",
    "mov ecx, 1",
    ".Lresident_profile_accumulate:",
    "lfence",
    "rdtsc",
    "shl rdx, 32",
    "or rax, rdx",
    "sub rax, qword ptr [r12 + {b_nested_exit_started_tsc}]",
    "add qword ptr [r12 + {b_nested_exit_handler_cycles} + rcx * 8], rax",
    "ret",
    ".Lresident_dispatch_halt:",
    "cli",
    ".Lresident_dispatch_halt_loop:",
    "pause",
    "jmp .Lresident_dispatch_halt_loop",
    ".globl matrixhv_resident_island_fatal",
    "matrixhv_resident_island_fatal:",
    "cli",
    "mov dx, 0x3f8",
    "mov al, 0x21",
    "out dx, al",
    "1:",
    "hlt",
    "jmp 1b",
    ".globl matrixhv_resident_ebs_callback",
    "matrixhv_resident_ebs_callback:",
    "mov r8, rdx",
    "mov qword ptr [r8 + {event_ebs_seen}], 1",
    "ret",
    ".globl matrixhv_resident_va_callback",
    "matrixhv_resident_va_callback:",
    "mov r8, rdx",
    "mov qword ptr [r8 + {event_va_seen}], 1",
    "ret",
    ".Lresident_serial_write:",
    "test r9d, r9d",
    "jz .Lresident_serial_write_done",
    "lodsb",
    "call .Lresident_serial_char",
    "dec r9d",
    "jmp .Lresident_serial_write",
    ".Lresident_serial_write_done:",
    "ret",
    ".Lresident_serial_char:",
    "mov r10b, al",
    "call .Lresident_serial_acquire",
    "mov dx, 0x3fd",
    "mov ecx, 100000",
    ".Lresident_serial_wait:",
    "in al, dx",
    "test al, 0x20",
    "jnz .Lresident_serial_ready",
    "dec ecx",
    "jnz .Lresident_serial_wait",
    "cmp r10b, 0x0a",
    "je .Lresident_serial_release",
    "ret",
    ".Lresident_serial_ready:",
    "mov dx, 0x3f8",
    "mov al, r10b",
    "out dx, al",
    "cmp r10b, 0x0a",
    "je .Lresident_serial_release",
    "ret",
    ".Lresident_serial_acquire:",
    "mov rcx, qword ptr [r12 + {b_serial_lock}]",
    "test rcx, rcx",
    "jz .Lresident_serial_acquire_done",
    "mov rdx, r12",
    ".Lresident_serial_acquire_retry:",
    "cmp qword ptr [rcx], r12",
    "je .Lresident_serial_acquire_done",
    "xor eax, eax",
    "lock cmpxchg qword ptr [rcx], rdx",
    "je .Lresident_serial_acquire_done",
    "pause",
    "jmp .Lresident_serial_acquire_retry",
    ".Lresident_serial_acquire_done:",
    "ret",
    ".Lresident_serial_release:",
    "mov rcx, qword ptr [r12 + {b_serial_lock}]",
    "test rcx, rcx",
    "jz .Lresident_serial_release_done",
    "cmp qword ptr [rcx], r12",
    "jne .Lresident_serial_release_done",
    "mov qword ptr [rcx], 0",
    ".Lresident_serial_release_done:",
    "ret",
    ".Lresident_serial_hex64:",
    "mov rbx, rax",
    "mov r13d, 16",
    ".Lresident_serial_hex64_loop:",
    "rol rbx, 4",
    "mov al, bl",
    "and al, 0x0f",
    "cmp al, 9",
    "jbe .Lresident_serial_hex64_digit",
    "add al, 0x37",
    "jmp .Lresident_serial_hex64_emit",
    ".Lresident_serial_hex64_digit:",
    "add al, 0x30",
    ".Lresident_serial_hex64_emit:",
    "call .Lresident_serial_char",
    "dec r13d",
    "jnz .Lresident_serial_hex64_loop",
    "ret",
    ".Lresident_serial_state:",
    "lea rsi, [rip + .Lstate_reason]",
    "mov r9d, {state_reason_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_reason}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_rip]",
    "mov r9d, {state_rip_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_guest_rip}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_len]",
    "mov r9d, {state_instruction_len_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_instruction_len}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_qualification]",
    "mov r9d, {state_qualification_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_qualification}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_guest_cr3]",
    "mov r9d, {state_guest_cr3_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_guest_cr3}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_host_cr3]",
    "mov r9d, {state_host_cr3_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_host_cr3}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_rax]",
    "mov r9d, {state_rax_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_rax}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_rcx]",
    "mov r9d, {state_rcx_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_rcx}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_rdx]",
    "mov r9d, {state_rdx_len}",
    "call .Lresident_serial_write",
    "mov rax, qword ptr [r12 + {b_last_rdx}]",
    "call .Lresident_serial_hex64",
    "lea rsi, [rip + .Lstate_newline]",
    "mov r9d, {state_newline_len}",
    "call .Lresident_serial_write",
    "ret",
    ".balign 8",
    ".Lresident_vmcs12_field_index_table:",
    ".byte 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 35, 36, 37, 38, 39, 40, 41, 42, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 43, 44, 45, 46, 47, 48, 49, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 93, 94, 18, 103, 104, 105, 255, 255, 17, 101, 102, 255, 255, 16, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 95, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 110, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 23, 24, 25, 26, 255, 111, 112, 113, 114, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 27, 28, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 100, 3",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 106, 107, 108, 109, 255, 115, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80",
    ".byte 81, 82, 83, 84, 255, 85, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 88, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 19, 20, 21, 22, 96, 97, 98, 99, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 116, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 29, 30, 31, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 91, 255, 255",
    ".byte 255, 92, 86, 87, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 32, 33, 34, 60, 61, 62, 63, 64, 89, 90, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255",
    ".balign 8",
    ".Lresident_guest_gpr_offsets:",
    ".byte 0, 8, 16, 24, 0, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112",
    ".balign 8",
    ".Lresident_nested_guest_state_table:",
    ".long 29, 0; .quad 0x6800",
    ".long 30, 0; .quad 0x6802",
    ".long 31, 0; .quad 0x6804",
    ".long 35, 0; .quad 0x0800",
    ".long 36, 0; .quad 0x0802",
    ".long 37, 0; .quad 0x0804",
    ".long 38, 0; .quad 0x0806",
    ".long 39, 0; .quad 0x0808",
    ".long 40, 0; .quad 0x080a",
    ".long 41, 0; .quad 0x080c",
    ".long 42, 0; .quad 0x080e",
    ".long 50, 0; .quad 0x6806",
    ".long 51, 0; .quad 0x6808",
    ".long 52, 0; .quad 0x680a",
    ".long 53, 0; .quad 0x680c",
    ".long 54, 0; .quad 0x680e",
    ".long 55, 0; .quad 0x6810",
    ".long 56, 0; .quad 0x6812",
    ".long 57, 0; .quad 0x6814",
    ".long 58, 0; .quad 0x6816",
    ".long 59, 0; .quad 0x6818",
    ".long 65, 0; .quad 0x4800",
    ".long 66, 0; .quad 0x4802",
    ".long 67, 0; .quad 0x4804",
    ".long 68, 0; .quad 0x4806",
    ".long 69, 0; .quad 0x4808",
    ".long 70, 0; .quad 0x480a",
    ".long 71, 0; .quad 0x480c",
    ".long 72, 0; .quad 0x480e",
    ".long 73, 0; .quad 0x4810",
    ".long 74, 0; .quad 0x4812",
    ".long 75, 0; .quad 0x4814",
    ".long 76, 0; .quad 0x4816",
    ".long 77, 0; .quad 0x4818",
    ".long 78, 0; .quad 0x481a",
    ".long 79, 0; .quad 0x481c",
    ".long 80, 0; .quad 0x481e",
    ".long 81, 0; .quad 0x4820",
    ".long 82, 0; .quad 0x4822",
    ".long 83, 0; .quad 0x4824",
    ".long 84, 0; .quad 0x4826",
    ".long 85, 0; .quad 0x482a",
    ".long 86, 0; .quad 0x6824",
    ".long 87, 0; .quad 0x6826",
    ".long 91, 0; .quad 0x681a",
    ".long 92, 0; .quad 0x6822",
    ".long 111, 0; .quad 0x280a",
    ".long 112, 0; .quad 0x280c",
    ".long 113, 0; .quad 0x280e",
    ".long 114, 0; .quad 0x2810",
    ".balign 8",
    ".Lresident_nested_host_state_table:",
    ".long 32, 0; .quad 0x6800",
    ".long 33, 0; .quad 0x6802",
    ".long 34, 0; .quad 0x6804",
    ".long 43, 0; .quad 0x0800",
    ".long 44, 0; .quad 0x0802",
    ".long 45, 0; .quad 0x0804",
    ".long 46, 0; .quad 0x0806",
    ".long 47, 0; .quad 0x0808",
    ".long 48, 0; .quad 0x080a",
    ".long 49, 0; .quad 0x080e",
    ".long 60, 0; .quad 0x680e",
    ".long 61, 0; .quad 0x6810",
    ".long 62, 0; .quad 0x6814",
    ".long 63, 0; .quad 0x6816",
    ".long 64, 0; .quad 0x6818",
    ".long 88, 0; .quad 0x482a",
    ".long 89, 0; .quad 0x6824",
    ".long 90, 0; .quad 0x6826",
    ".Lpost_ebs_exit_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:POST_EBS_VMEXIT\"",
    ".Lpost_ebs_exit_message_end:",
    ".Lpost_va_exit_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:POST_VA_VMEXIT\"",
    ".Lpost_va_exit_message_end:",
    ".Lfirst_start_exit_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:START_IMAGE_FIRST_EXIT\"",
    ".Lfirst_start_exit_message_end:",
    ".Lstart_checkpoint_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:START_IMAGE_CHECKPOINT_RESUME\"",
    ".Lstart_checkpoint_message_end:",
    ".Lstart_returned_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:START_IMAGE_RETURNED\"",
    ".Lstart_returned_message_end:",
    ".Lpost_ebs_stop_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:POST_EBS_TERMINAL_VMCALL\"",
    ".Lpost_ebs_stop_message_end:",
    ".Lunsupported_exit_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:UNSUPPORTED_EXIT\"",
    ".Lunsupported_exit_message_end:",
    ".Lnested_entry_failure_dump_message:",
    ".ascii \"[MATRIXHV][NESTED] VM_ENTRY_FAILURE_VMCS12 \"",
    ".Lnested_entry_failure_dump_message_end:",
    ".Lhost_cr3_mismatch_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:HOST_CR3_MISMATCH\"",
    ".Lhost_cr3_mismatch_message_end:",
    ".Levent_corrupt_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:EVENT_CONTEXT_CORRUPT\"",
    ".Levent_corrupt_message_end:",
    ".Lvmread_failed_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:VMREAD_FAILED\\r\\n\"",
    ".Lvmread_failed_message_end:",
    ".Lvmwrite_failed_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:VMWRITE_FAILED\"",
    ".Lvmwrite_failed_message_end:",
    ".Lvmresume_failed_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:VMRESUME_FAILED error=0x\"",
    ".Lvmresume_failed_message_end:",
    ".Lept_test_violation_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:EPT_VIOLATION_TEST gpa=0x\"",
    ".Lept_test_violation_message_end:",
    ".Lept_unexpected_violation_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:EPT_VIOLATION_UNEXPECTED gpa=0x\"",
    ".Lept_unexpected_violation_message_end:",
    ".Lept_violation_rip:",
    ".ascii \" rip=0x\"",
    ".Lept_violation_rip_end:",
    ".Lept_violation_read:",
    ".ascii \" access=read qual=0x\"",
    ".Lept_violation_read_end:",
    ".Lnested_vmxon_message:",
    ".ascii \"[MATRIXHV][NESTED] VMXON cpu=0x\"",
    ".Lnested_vmxon_message_end:",
    ".Lnested_vmxoff_message:",
    ".ascii \"[MATRIXHV][NESTED] VMXOFF cpu=0x\"",
    ".Lnested_vmxoff_message_end:",
    ".Lnested_pointer_message:",
    ".ascii \" pointer=0x\"",
    ".Lnested_pointer_message_end:",
    ".Lnested_failure_message:",
    ".ascii \"[MATRIXHV][NESTED] PROBE_FAILED\"",
    ".Lnested_failure_message_end:",
    ".Lnested_vmcs12_message:",
    ".ascii \"[MATRIXHV][NESTED] VMCS12 cpu=0x\"",
    ".Lnested_vmcs12_message_end:",
    ".Lnested_region_message:",
    ".ascii \" region=0x\"",
    ".Lnested_region_message_end:",
    ".Lnested_value_message:",
    ".ascii \" value=0x\"",
    ".Lnested_value_message_end:",
    ".Lnested_l2_exit_message:",
    ".ascii \"[MATRIXHV][NESTED] L2_EXIT cpu=0x\"",
    ".Lnested_l2_exit_message_end:",
    ".Lstate_reason:",
    ".ascii \" reason=0x\"",
    ".Lstate_reason_end:",
    ".Lstate_rip:",
    ".ascii \" rip=0x\"",
    ".Lstate_rip_end:",
    ".Lstate_len:",
    ".ascii \" len=0x\"",
    ".Lstate_len_end:",
    ".Lstate_qualification:",
    ".ascii \" qual=0x\"",
    ".Lstate_qualification_end:",
    ".Lstate_guest_cr3:",
    ".ascii \" guest_cr3=0x\"",
    ".Lstate_guest_cr3_end:",
    ".Lstate_host_cr3:",
    ".ascii \" host_cr3=0x\"",
    ".Lstate_host_cr3_end:",
    ".Lstate_rax:",
    ".ascii \" rax=0x\"",
    ".Lstate_rax_end:",
    ".Lstate_rcx:",
    ".ascii \" rcx=0x\"",
    ".Lstate_rcx_end:",
    ".Lstate_rdx:",
    ".ascii \" rdx=0x\"",
    ".Lstate_rdx_end:",
    ".Lstate_newline:",
    ".ascii \"\\r\\n\"",
    ".Lstate_newline_end:",
    ".globl matrixhv_resident_island_end",
    "matrixhv_resident_island_end:",
    ".text",
    b_ap_started = const core::mem::offset_of!(ResidentBootContext, ap_started),
    b_processor_number = const core::mem::offset_of!(ResidentBootContext, processor_number),
    b_init_count = const core::mem::offset_of!(ResidentBootContext, init_count),
    b_sipi_count = const core::mem::offset_of!(ResidentBootContext, sipi_count),
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
    cr4_vmxe = const registers::CR4_VMXE,
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
    tsc_adjust_msr = const IA32_TSC_ADJUST_MSR,
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
    resident_msr_switch_count = const RESIDENT_MSR_SWITCH_COUNT,
    resident_msr_switch_qword_count = const RESIDENT_MSR_SWITCH_COUNT * 2,
    resident_msr_switch_byte_count = const RESIDENT_MSR_SWITCH_COUNT * size_of::<VmxMsrEntry>(),
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
    b_cpuid_count = const BCTX_CPUID_COUNT,
    b_rdmsr_count = const BCTX_RDMSR_COUNT,
    b_wrmsr_count = const BCTX_WRMSR_COUNT,
    b_xsetbv_count = const BCTX_XSETBV_COUNT,
    b_vmcall_count = const BCTX_VMCALL_COUNT,
    b_start_checkpoint_seen = const BCTX_START_CHECKPOINT_SEEN,
    b_post_start_count = const BCTX_POST_START_COUNT,
    b_post_ebs_count = const BCTX_POST_EBS_COUNT,
    b_post_va_count = const BCTX_POST_VA_COUNT,
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
    b_tsc_adjust = const BCTX_TSC_ADJUST,
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
    b_nested_vmcs02_field_cache = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs02_field_cache),
    b_nested_vmcs02_last_vpid = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vmcs02_last_vpid),
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
    nested_invept_descriptor_offset = const crate::smp::per_cpu::NESTED_INVEPT_DESCRIPTOR_OFFSET,
    nested_invept_rip_offset = const crate::smp::per_cpu::NESTED_INVEPT_RIP_OFFSET,
    nested_invept_after_rip_offset = const crate::smp::per_cpu::NESTED_INVEPT_AFTER_RIP_OFFSET,
    nested_invvpid_descriptor_offset = const crate::smp::per_cpu::NESTED_INVVPID_DESCRIPTOR_OFFSET,
    nested_invvpid_rip_offset = const crate::smp::per_cpu::NESTED_INVVPID_RIP_OFFSET,
    nested_invvpid_after_rip_offset = const crate::smp::per_cpu::NESTED_INVVPID_AFTER_RIP_OFFSET,
    nested_ept_target_marker = const crate::smp::per_cpu::NESTED_EPT_TARGET_MARKER,
    nested_ept_second_target_marker = const crate::smp::per_cpu::NESTED_EPT_SECOND_TARGET_MARKER,
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
    post_ebs_exit_message_len = const POST_EBS_EXIT_MESSAGE_LEN,
    post_va_exit_message_len = const POST_VA_EXIT_MESSAGE_LEN,
    first_start_exit_message_len = const FIRST_START_EXIT_MESSAGE_LEN,
    start_checkpoint_message_len = const START_CHECKPOINT_MESSAGE_LEN,
    start_returned_message_len = const START_RETURNED_MESSAGE_LEN,
    post_ebs_stop_message_len = const POST_EBS_STOP_MESSAGE_LEN,
    unsupported_exit_message_len = const UNSUPPORTED_EXIT_MESSAGE_LEN,
    nested_entry_failure_dump_message_len = const b"[MATRIXHV][NESTED] VM_ENTRY_FAILURE_VMCS12 ".len(),
    nested_extended_field_count = const crate::nested::vmcs::VMCS12_EXTENDED_FIELD_COUNT,
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
    state_instruction_len_len = const STATE_INSTRUCTION_LEN_LEN,
    state_qualification_len = const STATE_QUALIFICATION_LEN,
    state_guest_cr3_len = const STATE_GUEST_CR3_LEN,
    state_host_cr3_len = const STATE_HOST_CR3_LEN,
    state_rax_len = const STATE_RAX_LEN,
    state_rcx_len = const STATE_RCX_LEN,
    state_rdx_len = const STATE_RDX_LEN,
    state_newline_len = const STATE_NEWLINE_LEN,
);
