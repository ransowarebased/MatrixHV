use core::arch::global_asm;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use uefi::Status;
use uefi::boot::{self, EventNotifyFn, EventType, Tpl};

use super::vt_controls::{self, VmxControlsError};
use super::vt_ept::{self, EptError};
use super::vt_guest;
use super::vt_vmcs::{self, VmcsError, VmcsRegion, vmwrite};
use super::vt_vmcs_fields::*;
use super::vt_vmxon::{self, VmxInstructionResult, VmxonError};
use crate::arch::x86_64::{control_regs, msr, registers, segmentation};
use crate::memory::paging::{HostAddressSpace, HostPagingError};
use crate::memory::resident::{
    AddressConstraint, PAGE_SIZE, RESIDENT_CODE_MEMORY_TYPE, RESIDENT_MEMORY_TYPE, ResidentPages,
};

const GUEST_STACK_PAGES: usize = 4;
const BOOT_GUEST_STACK_PAGES: usize = 64;
const HOST_STACK_PAGES: usize = 4;
const HOST_TABLE_PAGES: usize = 2;
const RESIDENT_CODE_PAGES: usize = 2;
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
const EPT_TEST_READ_ACCESS: u64 = 1;
const IA32_TSC_MSR: u32 = 0x10;
const IA32_PLATFORM_ID_MSR: u32 = 0x17;
const IA32_APIC_BASE_MSR: u32 = 0x1b;
const IA32_FEATURE_CONTROL_MSR: u32 = 0x3a;
const IA32_BIOS_SIGN_ID_MSR: u32 = 0x8b;
const IA32_MTRRCAP_MSR: u32 = 0xfe;
const IA32_ARCH_CAPABILITIES_MSR: u32 = 0x10a;
const IA32_MCG_CAP_MSR: u32 = 0x179;
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
const IA32_MTRR_DEF_TYPE_MSR: u32 = 0x2ff;
const IA32_MC0_CTL_MSR: u32 = 0x400;
const IA32_MC0_STATUS_MSR: u32 = 0x401;
const MACHINE_CHECK_BANK_MSR_STRIDE: u32 = 4;
const HYPERV_FEATURES_CPUID_LEAF: u32 = 0x4000_0003;
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
const RESIDENT_MSR_SWITCH_COUNT: usize = 6;

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

pub const RESIDENT_VMCALL_START_CHECKPOINT: u64 = 0x4856_5354_4152_5421;
pub const RESIDENT_VMCALL_STOP: u64 = 0x4856_5354_4f50_2121;
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
    CodeTooLarge(usize),
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
}

#[repr(C, align(16))]
struct ResidentEventContext {
    magic: u64,
    exit_boot_services_seen: u64,
    virtual_address_change_seen: u64,
    canary: u64,
}

#[repr(C, align(16))]
struct ResidentBootContext {
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
    original_gdtr: [u8; 10],
    original_idtr: [u8; 10],
    alignment_padding: [u8; 28],
    root_fx_state: [u8; 512],
}

impl ResidentBootContext {
    fn new(
        expected_host_cr3: u64,
        initial_guest_cr3: u64,
        event_context: u64,
        ept_test_gpa: u64,
        ept_probe_fault_rip: u64,
        ept_probe_resume_rip: u64,
    ) -> Self {
        Self {
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
            original_gdtr: [0; 10],
            original_idtr: [0; 10],
            alignment_padding: [0; 28],
            root_fx_state: [0; 512],
        }
    }
}

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
const BCTX_ORIGINAL_GDTR: usize = core::mem::offset_of!(ResidentBootContext, original_gdtr);
const BCTX_ORIGINAL_IDTR: usize = core::mem::offset_of!(ResidentBootContext, original_idtr);
const BCTX_ROOT_FX_STATE: usize = core::mem::offset_of!(ResidentBootContext, root_fx_state);

const EVENT_CTX_MAGIC: usize = core::mem::offset_of!(ResidentEventContext, magic);
const EVENT_CTX_EBS_SEEN: usize =
    core::mem::offset_of!(ResidentEventContext, exit_boot_services_seen);
const EVENT_CTX_VA_SEEN: usize =
    core::mem::offset_of!(ResidentEventContext, virtual_address_change_seen);
const EVENT_CTX_CANARY: usize = core::mem::offset_of!(ResidentEventContext, canary);

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
        if length > RESIDENT_CODE_PAGES * PAGE_SIZE {
            return Err(ResidentProbeError::CodeTooLarge(length));
        }

        let pages = ResidentPages::allocate_typed(
            RESIDENT_CODE_PAGES,
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

struct ResidentHostTables {
    pages: ResidentPages,
    gdt: u64,
    tss: u64,
    idt: u64,
    selectors: ResidentHostSelectors,
}

#[derive(Clone, Copy)]
struct ResidentHostSelectors {
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

    fn fixed() -> Self {
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
    fn allocate(
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
    let guest = vt_guest::configure(guest_probe_address(), guest_rsp & !0xf)?;

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
    let mut context_pages = ResidentPages::allocate(1, AddressConstraint::Any)
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
        });
    }
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
        data_memory_type: RESIDENT_MEMORY_TYPE.0,
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
    let initial_values = [
        (IA32_KERNEL_GS_BASE_MSR, unsafe {
            msr::read(IA32_KERNEL_GS_BASE_MSR)
        }),
        (IA32_TSC_AUX_MSR, unsafe { msr::read(IA32_TSC_AUX_MSR) }),
        (IA32_STAR_MSR, unsafe { msr::read(IA32_STAR_MSR) }),
        (IA32_LSTAR_MSR, unsafe { msr::read(IA32_LSTAR_MSR) }),
        (IA32_CSTAR_MSR, unsafe { msr::read(IA32_CSTAR_MSR) }),
        (IA32_FMASK_MSR, unsafe { msr::read(IA32_FMASK_MSR) }),
    ];
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

pub fn run_windows_boot(
    entry_rip: u64,
    event_context: u64,
    ept_probe_fault_rip: u64,
    ept_probe_resume_rip: u64,
) -> Result<ResidentBootReport, ResidentProbeError> {
    if size_of::<ResidentBootContext>() > PAGE_SIZE
        || core::mem::offset_of!(ResidentBootContext, root_fx_state) & 0xf != 0
    {
        return Err(ResidentProbeError::Allocation(Status::OUT_OF_RESOURCES));
    }

    let initial_rflags = registers::read_rflags();
    let code = ResidentCode::allocate()?;
    let root_segments = segmentation::capture();
    let mut tables = ResidentHostTables::allocate(code.fatal, ResidentHostSelectors::fixed())?;
    let context_pages = ResidentPages::allocate(1, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let guest_stack = ResidentPages::allocate(BOOT_GUEST_STACK_PAGES, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let host_stack = ResidentPages::allocate(HOST_STACK_PAGES, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let msr_bitmap = ResidentPages::allocate(MSR_BITMAP_PAGES, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let resident_msr_state = ResidentPages::allocate(1, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let ept_test_page = ResidentPages::allocate(1, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
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
    allow_low_msr_read_passthrough(&msr_bitmap, IA32_MCG_CAP_MSR);
    allow_low_msr_passthrough(&msr_bitmap, IA32_MCG_CTL_MSR);
    let machine_check_bank_count = unsafe { msr::read(IA32_MCG_CAP_MSR) } as u32 & 0xff;
    for bank in 0..machine_check_bank_count {
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
    let mut host_address_space = HostAddressSpace::reserve().map_err(ResidentProbeError::Paging)?;

    let vmx_basic = vt_vmxon::vmx_basic();
    let revision_id = vt_vmxon::revision_id(vmx_basic);
    let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
    vmcs_region.write_revision_id(revision_id);
    let vmcs_physical_address = vmcs_region.physical_address();
    let mut ept = vt_ept::IdentityEpt::build()?;
    let session = vt_vmxon::enter_vmx_root().map_err(ResidentProbeError::Vmxon)?;

    let host_space = host_address_space
        .clone_current()
        .map_err(ResidentProbeError::Paging)?;
    ept.deny_guest_access(code.pages.physical_address(), code.pages.pages())?;
    ept.deny_guest_access(tables.pages.physical_address(), tables.pages.pages())?;
    ept.deny_guest_access(context_pages.physical_address(), context_pages.pages())?;
    ept.deny_guest_access(host_stack.physical_address(), host_stack.pages())?;
    ept.deny_guest_access(msr_bitmap.physical_address(), msr_bitmap.pages())?;
    ept.deny_guest_access(
        resident_msr_state.physical_address(),
        resident_msr_state.pages(),
    )?;
    ept.deny_guest_access(host_space.arena_physical_address, host_space.arena_pages)?;
    ept.deny_guest_access(vmcs_physical_address, 1)?;
    ept.deny_guest_access(session.report().region_physical_address, 1)?;
    ept.deny_guest_access(ept_test_page.physical_address(), ept_test_page.pages())?;
    ept.deny_guest_access_to_tables()?;
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

    let _controls =
        vt_controls::configure_resident_boot(msr_bitmap.physical_address(), ept.ept_pointer())?;
    configure_resident_msr_switch(&resident_msr_state)?;
    configure_resident_host(host_space.host_cr3, &tables, root_segments)?;
    let guest_rsp = guest_stack.physical_address() + guest_stack.byte_len() as u64;
    let guest = vt_guest::configure_with_rflags(entry_rip, guest_rsp & !0xf, initial_rflags)?;

    let context = context_pages
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
        ));
    }
    let host_rsp = (host_stack.physical_address() + host_stack.byte_len() as u64 - 8) & !0xf;
    unsafe {
        (host_rsp as *mut u64).write(context as u64);
    }

    let raw_path =
        unsafe { matrixhv_resident_boot_run_asm(context, host_rsp, code.dispatch_entry) };
    EPT_TEST_PAGE_GPA.store(0, Ordering::Release);
    if raw_path == 0 {
        tables.pages.preserve();
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
    };
    let _ = &tables.pages;
    Ok(report)
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
    "cmp eax, {ept_violation_reason}",
    "je .Lresident_dispatch_ept_violation",
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
    ".Lresident_dispatch_cpuid:",
    "inc qword ptr [r12 + {b_cpuid_count}]",
    "mov eax, dword ptr [rsp + 0]",
    "mov ecx, dword ptr [rsp + 8]",
    "mov r8d, eax",
    "cpuid",
    "mov qword ptr [rsp + 0], rax",
    "mov qword ptr [rsp + 24], rbx",
    "mov qword ptr [rsp + 8], rcx",
    "mov qword ptr [rsp + 16], rdx",
    "cmp r8d, {hyperv_features_leaf}",
    "jne .Lresident_dispatch_cpuid_standard",
    "and dword ptr [rsp + 0], {hyperv_guest_idle_access_mask}",
    "and dword ptr [rsp + 16], {hyperv_guest_idle_feature_mask}",
    "jmp .Lresident_dispatch_cpuid_advance",
    ".Lresident_dispatch_cpuid_standard:",
    "cmp r8d, 1",
    "jne .Lresident_dispatch_cpuid_advance",
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
    "mov qword ptr [rsp + 8], r10",
    ".Lresident_dispatch_cpuid_advance:",
    "call .Lresident_advance_guest_rip",
    "jmp .Lresident_dispatch_resume",
    ".Lresident_dispatch_rdmsr:",
    "inc qword ptr [r12 + {b_rdmsr_count}]",
    "mov ecx, dword ptr [rsp + 8]",
    "cmp ecx, {tsc_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {platform_id_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {apic_base_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {feature_control_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {bios_sign_id_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
    "cmp ecx, {mtrrcap_msr}",
    "je .Lresident_dispatch_rdmsr_passthrough",
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
    "cmp ecx, {kernel_gs_base_msr}",
    "je .Lresident_dispatch_rdmsr_kernel_gs_base",
    "jmp .Lresident_dispatch_unsupported",
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
    "cmp ecx, {bios_sign_id_msr}",
    "je .Lresident_dispatch_wrmsr_passthrough",
    "cmp ecx, {mtrr_def_type_msr}",
    "je .Lresident_dispatch_wrmsr_passthrough",
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
    "cmp ecx, {efer_msr}",
    "jne .Lresident_dispatch_unsupported",
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
    "mov r11, {start_checkpoint_magic}",
    "cmp rax, r11",
    "je .Lresident_dispatch_start_checkpoint",
    "mov r11, {stop_magic}",
    "cmp rax, r11",
    "je .Lresident_dispatch_stop",
    "jmp .Lresident_dispatch_unsupported",
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
    "push rsi",
    "mov r8, rdx",
    "mov qword ptr [r8 + 8], 1",
    "lea rsi, [rip + .Lebs_message]",
    "mov r9d, {ebs_message_len}",
    "call .Lresident_serial_write",
    "pop rsi",
    "ret",
    ".globl matrixhv_resident_va_callback",
    "matrixhv_resident_va_callback:",
    "push rsi",
    "mov r8, rdx",
    "mov qword ptr [r8 + 16], 1",
    "lea rsi, [rip + .Lva_message]",
    "mov r9d, {va_message_len}",
    "call .Lresident_serial_write",
    "pop rsi",
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
    "mov dx, 0x3fd",
    "mov ecx, 100000",
    ".Lresident_serial_wait:",
    "in al, dx",
    "test al, 0x20",
    "jnz .Lresident_serial_ready",
    "dec ecx",
    "jnz .Lresident_serial_wait",
    "ret",
    ".Lresident_serial_ready:",
    "mov dx, 0x3f8",
    "mov al, r10b",
    "out dx, al",
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
    ".Lebs_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:EBS_SIGNAL\\r\\n\"",
    ".Lebs_message_end:",
    ".Lva_message:",
    ".ascii \"[MATRIXHV][RESIDENT] HV:VA_CHANGE_POST_EBS\\r\\n\"",
    ".Lva_message_end:",
    ".globl matrixhv_resident_island_end",
    "matrixhv_resident_island_end:",
    ".text",
    guest_cr3 = const GUEST_CR3,
    guest_efer = const GUEST_IA32_EFER,
    guest_gs_base = const GUEST_GS_BASE,
    guest_fs_base = const GUEST_FS_BASE,
    guest_sysenter_cs = const GUEST_SYSENTER_CS,
    guest_sysenter_esp = const GUEST_SYSENTER_ESP,
    guest_sysenter_eip = const GUEST_SYSENTER_EIP,
    guest_cr4 = const GUEST_CR4,
    vm_entry_msr_load_addr = const VM_ENTRY_MSR_LOAD_ADDR,
    guest_rip = const GUEST_RIP,
    guest_physical_address = const GUEST_PHYSICAL_ADDRESS,
    exit_reason = const VM_EXIT_REASON,
    exit_instruction_len = const VM_EXIT_INSTRUCTION_LEN,
    exit_qualification = const EXIT_QUALIFICATION,
    vm_instruction_error = const VM_INSTRUCTION_ERROR,
    complete = const CONTEXT_COMPLETE,
    boot_canary_start = const BOOT_CONTEXT_CANARY_START,
    boot_canary_end = const BOOT_CONTEXT_CANARY_END,
    event_magic = const EVENT_CONTEXT_MAGIC,
    event_canary = const EVENT_CONTEXT_CANARY,
    ept_violation_reason = const EPT_VIOLATION_EXIT_REASON,
    ept_test_read_access = const EPT_TEST_READ_ACCESS,
    cpuid_reason = const CPUID_EXIT_REASON,
    vmcall_reason = const VMCALL_EXIT_REASON,
    rdmsr_reason = const RDMSR_EXIT_REASON,
    wrmsr_reason = const WRMSR_EXIT_REASON,
    xsetbv_reason = const XSETBV_EXIT_REASON,
    tsc_msr = const IA32_TSC_MSR,
    platform_id_msr = const IA32_PLATFORM_ID_MSR,
    apic_base_msr = const IA32_APIC_BASE_MSR,
    feature_control_msr = const IA32_FEATURE_CONTROL_MSR,
    bios_sign_id_msr = const IA32_BIOS_SIGN_ID_MSR,
    mtrrcap_msr = const IA32_MTRRCAP_MSR,
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
    hyperv_features_leaf = const HYPERV_FEATURES_CPUID_LEAF,
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
    gs_base_msr = const IA32_GS_BASE_MSR,
    fs_base_msr = const IA32_FS_BASE_MSR,
    kernel_gs_base_msr = const IA32_KERNEL_GS_BASE_MSR,
    cpuid_vmx_clear_mask = const !(1_u32 << 5),
    cpuid_osxsave_set_mask = const 1_u32 << 27,
    cpuid_osxsave_clear_mask = const !(1_u32 << 27),
    cr4_osxsave_mask = const 1_u64 << 18,
    start_checkpoint_magic = const RESIDENT_VMCALL_START_CHECKPOINT,
    stop_magic = const RESIDENT_VMCALL_STOP,
    unsupported_stop = const RESIDENT_STOP_UNSUPPORTED_EXIT,
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
    host_cr3_mismatch_message_len = const HOST_CR3_MISMATCH_MESSAGE_LEN,
    event_corrupt_message_len = const EVENT_CORRUPT_MESSAGE_LEN,
    vmread_failed_message_len = const VMREAD_FAILED_MESSAGE_LEN,
    vmwrite_failed_message_len = const VMWRITE_FAILED_MESSAGE_LEN,
    vmresume_failed_message_len = const VMRESUME_FAILED_MESSAGE_LEN,
    ept_test_violation_message_len = const EPT_TEST_VIOLATION_MESSAGE_LEN,
    ept_unexpected_violation_message_len = const EPT_UNEXPECTED_VIOLATION_MESSAGE_LEN,
    ept_violation_rip_len = const EPT_VIOLATION_RIP_LEN,
    ept_violation_read_len = const EPT_VIOLATION_READ_LEN,
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
    ebs_message_len = const 36,
    va_message_len = const 44,
);
