pub(crate) mod abi;
pub mod boot;

use super::bridge::{
    CONTROL_NATIVE_SNAPSHOT_CAPACITY, CONTROL_NATIVE_STACK_BYTES, CONTROL_OFF_COMMIT_VMCALL,
    CONTROL_OFF_PREPARE_VMCALL, CONTROL_OFF_PREPARED_RESULT, CONTROL_PROBE_RESULT,
    CONTROL_PROBE_VMCALL, ControlCpuState, ControlNativeSnapshot, ControlNativeStorage,
    VariableBridge,
};
use super::controls::VmxControlsError;
use super::ept::EptError;
use super::exits::{
    CPUID_EXIT_REASON, EPT_MISCONFIGURATION_EXIT_REASON, EPT_VIOLATION_EXIT_REASON,
    RDMSR_EXIT_REASON, VM_ENTRY_FAILURE_MSR_LOADING_EXIT_REASON, VMCALL_EXIT_REASON,
    VMX_PREEMPTION_TIMER_EXIT_REASON, WRMSR_EXIT_REASON, XSETBV_EXIT_REASON,
};
use super::msr::{
    AMD_SEV_STATUS_MSR, IA32_APIC_BASE_MSR, IA32_BIOS_SIGN_ID_MSR, IA32_CSTAR_MSR, IA32_EFER_MSR,
    IA32_FEATURE_CONTROL_MSR, IA32_FMASK_MSR, IA32_FS_BASE_MSR, IA32_GS_BASE_MSR,
    IA32_KERNEL_GS_BASE_MSR, IA32_LSTAR_MSR, IA32_MTRR_DEF_TYPE_MSR, IA32_MTRR_FIX4K_C0000_MSR,
    IA32_MTRR_FIX4K_F8000_MSR, IA32_MTRR_FIX16K_80000_MSR, IA32_MTRR_FIX16K_A0000_MSR,
    IA32_MTRR_FIX64K_00000_MSR, IA32_MTRR_PHYSBASE0_MSR, IA32_MTRRCAP_MSR, IA32_PLATFORM_ID_MSR,
    IA32_SPEC_CTRL_MSR, IA32_STAR_MSR, IA32_SYSENTER_CS_MSR, IA32_SYSENTER_EIP_MSR,
    IA32_SYSENTER_ESP_MSR, IA32_TSC_AUX_MSR, IA32_TSC_MSR, IA32_X2APIC_MSR_BASE,
    IA32_X2APIC_MSR_END, IA32_XSS_MSR, MSR_DRAM_ENERGY_STATUS, MSR_PKG_ENERGY_STATUS,
    MSR_PP0_ENERGY_STATUS, MSR_PP1_ENERGY_STATUS, MSR_RAPL_POWER_UNIT, resident_msr_switch_count,
};
use super::nested::{NESTED_GUEST_MSR_LIST_CAPACITY, NESTED_MSR_BITMAP_QWORD_COUNT};
use super::state;
use super::vmcs::*;
use super::vmxon::{VmxInstructionResult, VmxonError};
use crate::arch;
use crate::hyperv::{
    CPUID_HYPERVISOR_PRESENT_BIT, HYPERV_FEATURES_LEAF, HYPERV_GUEST_IDLE_ACCESS_MASK,
    HYPERV_GUEST_IDLE_FEATURE_MASK, HYPERV_GUEST_OS_ID_MSR, HYPERV_HYPERCALL_MSR,
    HYPERV_REFERENCE_COUNT_MSR, HYPERV_REFERENCE_TIME_MSR_SPAN, HYPERV_REFERENCE_TSC_MSR,
    HYPERV_SIMP_MSR, HYPERV_SINT3_MSR, HYPERV_STIMER0_CONFIG_MSR, HYPERV_STIMER0_COUNT_MSR,
    HYPERV_TSC_INVARIANT_CONTROL_MSR, HYPERV_VP_ASSIST_MSR, HYPERV_VP_INDEX_MSR,
    HYPERVISOR_LEAF_END, HYPERVISOR_LEAF_START, native_hyperv_invariant_tsc,
    native_hyperv_reference_tsc,
};
use crate::memory::{
    AddressConstraint, HostPagingError, PAGE_SIZE, RESIDENT_CODE_MEMORY_TYPE,
    RESIDENT_EVENT_MEMORY_TYPE, ResidentPages,
};
use crate::nested::{
    CPUID_OSXSAVE_BIT, CPUID_VMX_BIT, IA32_VMX_BASIC_MSR, IA32_VMX_CR0_FIXED0_MSR,
    IA32_VMX_CR0_FIXED1_MSR, IA32_VMX_CR4_FIXED0_MSR, IA32_VMX_CR4_FIXED1_MSR,
    IA32_VMX_ENTRY_CTLS_MSR, IA32_VMX_EPT_VPID_CAP_MSR, IA32_VMX_EXIT_CTLS_MSR, IA32_VMX_MISC_MSR,
    IA32_VMX_PINBASED_CTLS_MSR, IA32_VMX_PROCBASED_CTLS_MSR, IA32_VMX_PROCBASED_CTLS2_MSR,
    IA32_VMX_TRUE_ENTRY_CTLS_MSR, IA32_VMX_TRUE_EXIT_CTLS_MSR, IA32_VMX_TRUE_PINBASED_CTLS_MSR,
    IA32_VMX_TRUE_PROCBASED_CTLS_MSR, IA32_VMX_VMCS_ENUM_MSR,
    INVALID_OPERAND_TO_INVEPT_INVVPID_ERROR, INVEPT_EXIT_REASON, INVVPID_EXIT_REASON,
    NestedVmcs12State, NestedVmxState, VM_ENTRY_BLOCKED_BY_MOV_SS_ERROR,
    VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR, VM_ENTRY_INVALID_HOST_STATE_FIELD_ERROR,
    VMCLEAR_EXIT_REASON, VMCLEAR_INVALID_PHYSICAL_ADDRESS_ERROR, VMCLEAR_VMXON_POINTER_ERROR,
    VMCS_FIELD_EXIT_QUALIFICATION, VMCS_FIELD_GUEST_RFLAGS, VMCS_FIELD_GUEST_RIP,
    VMCS_FIELD_GUEST_RSP, VMCS_FIELD_HOST_RIP, VMCS_FIELD_HOST_RSP,
    VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN, VMCS_FIELD_VM_EXIT_REASON, VMCS_FIELD_VM_INSTRUCTION_ERROR,
    VMCS_SHADOW_READ_BITMAP_BYTE_OFFSET, VMCS_SHADOW_READ_BYPASS_MASK, VMCS_SHADOW_READ_TRAP_MASK,
    VMCS_UNSUPPORTED_COMPONENT_ERROR, VMCS12_BACKING_MAGIC, VMCS12_BACKING_MAGIC_OFFSET,
    VMCS12_BACKING_QWORD_COUNT, VMCS12_BACKING_STATE_OFFSET, VMCS12_EXTENDED_FIELD_COUNT,
    VMCS12_LAUNCH_STATE_CLEAR, VMCS12_LAUNCH_STATE_LAUNCHED, VMFAIL_INVALID_STATUS,
    VMFAIL_VALID_STATUS, VMLAUNCH_EXIT_REASON, VMLAUNCH_NON_CLEAR_VMCS_ERROR, VMPTRLD_EXIT_REASON,
    VMPTRLD_INCORRECT_REVISION_ERROR, VMPTRLD_INVALID_PHYSICAL_ADDRESS_ERROR,
    VMPTRLD_VMXON_POINTER_ERROR, VMPTRST_EXIT_REASON, VMREAD_EXIT_REASON, VMRESUME_EXIT_REASON,
    VMRESUME_NON_LAUNCHED_VMCS_ERROR, VMWRITE_EXIT_REASON, VMWRITE_READ_ONLY_COMPONENT_ERROR,
    VMX_STATUS_FLAGS_CLEAR_MASK, VMXOFF_EXIT_REASON, VMXON_EXIT_REASON, VMXON_IN_VMX_ROOT_ERROR,
};
use crate::protocol::{
    CONTROL_MAGIC, CONTROL_PROBE_OPERATION, CONTROL_VERSION, ControlProbeSnapshot, ControlRequest,
    ControlStatus, MATRIXHV_STATUS_LEAF, MATRIXHV_STATUS_PROTOCOL, MATRIXHV_STATUS_SIGNATURE_EAX,
    MATRIXHV_STATUS_SIGNATURE_EBX, MATRIXHV_STATUS_SIGNATURE_ECX,
};
use abi::*;
use core::arch::global_asm;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};
use uefi::Status;

pub(crate) const CONTEXT_COMPLETE: u64 = 0x4856_5245_534f_4b21;
const EVENT_CONTEXT_MAGIC: u64 = 0x4856_4556_454e_5431;
const EVENT_CONTEXT_CANARY: u64 = 0x4856_4556_4341_4e59;
const EPT_TEST_READ_ACCESS: u64 = 1;
const VMWARE_HYPERVISOR_MAGIC: u32 = 0x564d_5868;
const VMWARE_HYPERVISOR_PORT: u16 = 0x5658;

const HOST_PAGE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

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
pub(crate) static EPT_TEST_PAGE_GPA: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentProbeError {
    Allocation(Status),
    FirmwareDiscovery(crate::firmware::PciDiscoveryError),
    Vmxon(VmxonError),
    Vmcs(VmcsError),
    Controls(VmxControlsError),
    Ept(EptError),
    Paging(HostPagingError),
    InvalidCodeLayout,
    InvalidEptPoolUsage,
    HostRspVmwriteVmFailValid(u64),
    HostRspVmwriteVmFailInvalid,
    HostRipVmwriteVmFailValid(u64),
    HostRipVmwriteVmFailInvalid,
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
pub struct ResidentEventReport {
    pub code_physical_address: u64,
    pub context_physical_address: u64,
    pub code_memory_type: u32,
    pub data_memory_type: u32,
    pub exit_boot_services_event: u64,
    pub virtual_address_change_event: u64,
}

pub(crate) struct ResidentCode {
    pub(crate) pages: ResidentPages,
    pub(crate) entry: u64,
    pub(crate) fatal: u64,
    pub(crate) gp_handler: u64,
    pub(crate) exception_stubs: u64,
    pub(crate) exit_boot_services_callback: u64,
    pub(crate) virtual_address_change_callback: u64,
    pub(crate) dispatch_entry: u64,
    pub(crate) bridge: VariableBridge,
}

impl ResidentCode {
    pub(crate) fn allocate(event_context: u64) -> Result<Self, ResidentProbeError> {
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
        let get_variable_bridge = core::ptr::addr_of!(matrixhv_resident_get_variable) as u64;
        let set_variable_bridge = core::ptr::addr_of!(matrixhv_resident_set_variable) as u64;
        let original_get_variable_slot =
            core::ptr::addr_of!(matrixhv_resident_original_get_variable) as u64;
        let original_set_variable_slot =
            core::ptr::addr_of!(matrixhv_resident_original_set_variable) as u64;
        let convert_pointer_slot = core::ptr::addr_of!(matrixhv_resident_convert_pointer) as u64;
        let bridge_context_slot = core::ptr::addr_of!(matrixhv_resident_bridge_context) as u64;
        let runtime_get_variable_slot =
            core::ptr::addr_of!(matrixhv_resident_runtime_get_variable) as u64;
        let runtime_set_variable_slot =
            core::ptr::addr_of!(matrixhv_resident_runtime_set_variable) as u64;
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
            || get_variable_bridge < start
            || set_variable_bridge < start
            || original_get_variable_slot < start
            || original_set_variable_slot < start
            || convert_pointer_slot < start
            || bridge_context_slot < start
            || runtime_get_variable_slot < start
            || runtime_set_variable_slot < start
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
            || get_variable_bridge >= end
            || set_variable_bridge >= end
            || original_get_variable_slot + 8 > end
            || original_set_variable_slot + 8 > end
            || convert_pointer_slot + 8 > end
            || bridge_context_slot + 8 > end
            || runtime_get_variable_slot + 8 > end
            || runtime_set_variable_slot + 8 > end
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
                    crate::diagnostics::vmexit_diagnostic as *const () as usize as u64,
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
            bridge: VariableBridge {
                get_variable_bridge: base + (get_variable_bridge - start),
                set_variable_bridge: base + (set_variable_bridge - start),
                original_get_variable_slot: base + (original_get_variable_slot - start),
                original_set_variable_slot: base + (original_set_variable_slot - start),
                convert_pointer_slot: base + (convert_pointer_slot - start),
                bridge_context_slot: base + (bridge_context_slot - start),
                runtime_get_variable_slot: base + (runtime_get_variable_slot - start),
                runtime_set_variable_slot: base + (runtime_set_variable_slot - start),
            },
            pages,
        })
    }
}

pub fn status_from_error(error: &ResidentProbeError) -> Status {
    match error {
        ResidentProbeError::FirmwareDiscovery(crate::firmware::PciDiscoveryError::Allocation(
            status,
        ))
        | ResidentProbeError::Allocation(status)
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
    let mut code = ResidentCode::allocate(0)?;
    let mut native_storage_pages = ResidentPages::allocate_typed(
        (size_of::<ControlNativeStorage>() * 64).div_ceil(PAGE_SIZE),
        AddressConstraint::Any,
        RESIDENT_EVENT_MEMORY_TYPE,
    )
    .map_err(ResidentProbeError::Allocation)?;
    let mut context_pages = ResidentPages::allocate_typed(
        size_of::<ResidentEventContext>().div_ceil(PAGE_SIZE),
        AddressConstraint::Any,
        RESIDENT_EVENT_MEMORY_TYPE,
    )
    .map_err(ResidentProbeError::Allocation)?;
    let context = context_pages
        .pointer()
        .as_ptr()
        .cast::<ResidentEventContext>();
    let (hyperv_tsc_scale, hyperv_tsc_offset) =
        native_hyperv_reference_tsc(crate::firmware::calibrate_reference_tsc);
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
            visual_deadline_tsc: 0,
            control_expected_mask: AtomicU64::new(0),
            control_active_mask: AtomicU64::new(0),
            control_stopped_mask: AtomicU64::new(0),
            control_failed_mask: AtomicU64::new(0),
            control_processor_count: 0,
            control_va_error: 0,
            control_completion_sequences: core::array::from_fn(|_| AtomicU64::new(0)),
            control_rearm_mask: AtomicU64::new(0),
            runtime_get_variable: 0,
            runtime_set_variable: 0,
            runtime_context: 0,
            control_apic_ids: [u32::MAX; 64],
            control_probe_states: [ControlProbeSnapshot::default(); 64],
            control_cpu_states: [ControlCpuState::default(); 64],
            hyperv_tsc_scale,
            hyperv_tsc_offset,
            hyperv_reference_tsc_msr: AtomicU64::new(0),
            hyperv_reference_tsc_lock: AtomicU64::new(0),
            hyperv_reference_tsc_sequence: AtomicU64::new(0),
            hyperv_guest_os_id: AtomicU64::new(0),
            hyperv_hypercall_msr: AtomicU64::new(0),
            hyperv_hypercall_lock: AtomicU64::new(0),
            hyperv_tsc_invariant_supported: u64::from(native_hyperv_invariant_tsc()),
            hyperv_tsc_invariant_control: AtomicU64::new(0),
        });
        for (index, state) in (*context).control_cpu_states.iter_mut().enumerate() {
            let address = native_storage_pages.physical_address()
                + (index * size_of::<ControlNativeStorage>()) as u64;
            state.native_storage_physical = address;
            state.native_storage_runtime = address;
        }
    }
    let serial_lock_address = context_pages.physical_address() + EVENT_CTX_SERIAL_LOCK as u64;
    let (ebs_event, va_event) = unsafe {
        crate::firmware::register_residency_events(
            code.exit_boot_services_callback,
            code.virtual_address_change_callback,
            &code.bridge,
            context as u64,
        )
    }
    .map_err(ResidentProbeError::EventRegistration)?;

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
    native_storage_pages.preserve();
    crate::firmware::publish_events(report.context_physical_address, EVENT_CTX_EBS_SEEN);
    crate::runtime::install_shared_lock(serial_lock_address);
    Ok(report)
}

pub(crate) fn guest_probe_address() -> u64 {
    matrixhv_resident_guest_probe_asm as *const () as usize as u64
}

unsafe extern "efiapi" {
    pub(crate) fn matrixhv_resident_startup_halt_asm() -> !;

    fn matrixhv_resident_guest_probe_asm();
    pub(crate) fn matrixhv_resident_boot_run_asm(
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
    static matrixhv_resident_get_variable: u8;
    static matrixhv_resident_set_variable: u8;
    static matrixhv_resident_original_get_variable: u8;
    static matrixhv_resident_original_set_variable: u8;
    static matrixhv_resident_convert_pointer: u8;
    static matrixhv_resident_bridge_context: u8;
    static matrixhv_resident_runtime_get_variable: u8;
    static matrixhv_resident_runtime_set_variable: u8;
    static matrixhv_resident_island_end: u8;
}

global_asm!(
    include_str!("../../asm/ap_startup.S"),
    include_str!("../../asm/ept_cache.S"),
    include_str!("../../asm/eptp_switch.S"),
    include_str!("../../asm/nested.S"),
    include_str!("../../asm/hyperv.S"),
    include_str!("../../asm/exits.S"),
    include_str!("../../asm/msr.S"),
    include_str!("../../asm/control.S"),
    include_str!("../../asm/diagnostics.S"),
    include_str!("../../asm/island.S"),
    p_root_rsp = const core::mem::offset_of!(ResidentContext, root_rsp),
    p_return_rip = const core::mem::offset_of!(ResidentContext, return_rip),
    p_source_cr3 = const core::mem::offset_of!(ResidentContext, source_cr3),
    p_observed_host_cr3 = const core::mem::offset_of!(ResidentContext, observed_host_cr3),
    p_observed_guest_cr3 = const core::mem::offset_of!(ResidentContext, observed_guest_cr3),
    p_exit_reason = const core::mem::offset_of!(ResidentContext, exit_reason),
    p_guest_rip = const core::mem::offset_of!(ResidentContext, guest_rip),
    p_completed = const core::mem::offset_of!(ResidentContext, completed),
    p_original_gdtr = const core::mem::offset_of!(ResidentContext, original_gdtr),
    p_original_idtr = const core::mem::offset_of!(ResidentContext, original_idtr),
    host_rsp = const HOST_RSP,
    host_rip = const HOST_RIP,
    host_es_selector = const HOST_ES_SELECTOR,
    host_cs_selector = const HOST_CS_SELECTOR,
    host_ss_selector = const HOST_SS_SELECTOR,
    host_ds_selector = const HOST_DS_SELECTOR,
    host_fs_selector = const HOST_FS_SELECTOR,
    host_gs_selector = const HOST_GS_SELECTOR,
    host_tr_selector = const HOST_TR_SELECTOR,
    host_cr0 = const HOST_CR0,
    host_cr3 = const HOST_CR3,
    host_cr4 = const HOST_CR4,
    host_pat = const HOST_IA32_PAT,
    host_efer = const HOST_IA32_EFER,
    host_fs_base = const HOST_FS_BASE,
    host_gs_base = const HOST_GS_BASE,
    host_tr_base = const HOST_TR_BASE,
    host_gdtr_base = const HOST_GDTR_BASE,
    host_idtr_base = const HOST_IDTR_BASE,
    host_sysenter_cs = const HOST_SYSENTER_CS,
    host_sysenter_esp = const HOST_SYSENTER_ESP,
    host_sysenter_eip = const HOST_SYSENTER_EIP,
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
    b_root_vmx_active = const core::mem::offset_of!(ResidentBootContext, root_vmx_active),
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
    ept_misconfiguration_reason = const EPT_MISCONFIGURATION_EXIT_REASON,
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
    vmfunc_reason = const crate::nested::VMFUNC_EXIT_REASON,
    vm_function_control = const VM_FUNCTION_CONTROL,
    eptp_list_address = const EPTP_LIST_ADDRESS,
    b_nested_eptp_shadow_list = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, eptp_shadow_list),
    b_nested_eptp_native_supported = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, eptp_native_supported),
    b_nested_eptp_native_enabled = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, eptp_native_enabled),
    b_nested_eptp_sync_ack = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, eptp_sync_ack),
    b_nested_eptp_sync_safe = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, eptp_sync_safe),
    b_nested_eptp_sync_nmi = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, eptp_sync_nmi),
    b_nested_eptp_sync_apic_id = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, eptp_sync_apic_id),
    b_nested_eptp_admission = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, eptp_admission),
    b_nested_eptp_write_retry = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, eptp_write_retry),
    b_nested_eptp_table_pool = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, eptp_table_pool),
    b_nested_eptp_table_pages = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, eptp_table_pages),
    b_nested_eptp_table_used = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, eptp_table_used),
    vmx_vmfunc_msr = const crate::nested::IA32_VMX_VMFUNC_MSR,
    b_nested_vmcs12_vm_function_control = const BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 118 * 8,
    b_nested_vmcs12_eptp_list_address = const BCTX_NESTED_VMCS12_EXTENDED_FIELDS + 119 * 8,
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
    hv_interface_leaf = const crate::hyperv::HYPERV_INTERFACE_LEAF,
    hv_identity_leaf = const crate::hyperv::HYPERV_IDENTITY_LEAF,
    hv_recommendations_leaf = const crate::hyperv::HYPERV_RECOMMENDATIONS_LEAF,
    hv_limits_leaf = const crate::hyperv::HYPERV_LIMITS_LEAF,
    hv_hardware_leaf = const crate::hyperv::HYPERV_HARDWARE_LEAF,
    hv_nested_features_leaf = const crate::hyperv::HYPERV_NESTED_FEATURES_LEAF,
    hv_vendor_ebx = const crate::hyperv::HYPERV_VENDOR_EBX,
    hv_vendor_ecx = const crate::hyperv::HYPERV_VENDOR_ECX,
    hv_vendor_edx = const crate::hyperv::HYPERV_VENDOR_EDX,
    hv_interface_signature = const crate::hyperv::HYPERV_INTERFACE_SIGNATURE,
    hv_base_access = const crate::hyperv::HYPERV_BASE_ACCESS,
    hv_apic_access = const crate::hyperv::HYPERV_APIC_ACCESS,
    hv_time_access = const crate::hyperv::HYPERV_TIME_ACCESS,
    hv_invariant_tsc_access = const crate::hyperv::HYPERV_INVARIANT_TSC_ACCESS,
    hv_evmcs_recommendation = const crate::hyperv::HYPERV_EVMCS_RECOMMENDATION,
    hv_evmcs_versions = const crate::hyperv::HYPERV_EVMCS_VERSIONS,
    hv_build_number = const crate::hyperv::HYPERV_BUILD_NUMBER,
    hv_product_version = const crate::hyperv::HYPERV_PRODUCT_VERSION,
    hv_hardware_in_use = const crate::hyperv::HYPERV_HARDWARE_IN_USE,
    hv_msr_range_span = const crate::hyperv::HYPERV_MSR_RANGE_SPAN,
    hv_eoi_msr = const crate::hyperv::HYPERV_EOI_MSR,
    hv_icr_msr = const crate::hyperv::HYPERV_ICR_MSR,
    hv_tpr_msr = const crate::hyperv::HYPERV_TPR_MSR,
    hv_notify_long_spin_wait = const crate::hyperv::HYPERV_NOTIFY_LONG_SPIN_WAIT,
    hv_invalid_hypercall_code = const crate::hyperv::HYPERV_INVALID_HYPERCALL_CODE,
    hv_invalid_hypercall_input = const crate::hyperv::HYPERV_INVALID_HYPERCALL_INPUT,
    hv_invalid_alignment = const crate::hyperv::HYPERV_INVALID_ALIGNMENT,
    hv_invalid_parameter = const crate::hyperv::HYPERV_INVALID_PARAMETER,
    hv_processor_limit = const crate::hyperv::HYPERV_PROCESSOR_LIMIT,
    hv_vendor_leaf = const crate::hyperv::HYPERVISOR_LEAF_START,
    hv_msr_base = const crate::hyperv::HYPERV_GUEST_OS_ID_MSR,
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
    hyperv_reference_count_msr = const HYPERV_REFERENCE_COUNT_MSR,
    hyperv_tsc_invariant_control_msr = const HYPERV_TSC_INVARIANT_CONTROL_MSR,
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
    guest_contract_subleaf = const crate::protocol::MATRIXHV_GUEST_CONTRACT_SUBLEAF,
    guest_contract_unsupported = const crate::protocol::MATRIXHV_GUEST_CONTRACT_UNSUPPORTED,
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
    b_flight_sequence = const core::mem::offset_of!(ResidentBootContext, flight_recorder_sequence),
    b_flight_frozen = const core::mem::offset_of!(ResidentBootContext, flight_recorder_frozen),
    b_flight_records = const core::mem::offset_of!(ResidentBootContext, flight_recorder_records),
    flight_capacity_mask = const FLIGHT_RECORDER_CAPACITY - 1,
    flight_record_bytes = const FLIGHT_RECORDER_RECORD_BYTES,
    b_telemetry_enabled = const core::mem::offset_of!(ResidentBootContext, telemetry_enabled),
    b_telemetry_active = const core::mem::offset_of!(ResidentBootContext, telemetry_active),
    b_telemetry_probe_active = const core::mem::offset_of!(ResidentBootContext, telemetry_probe_active),
    b_watchdog_tsc_hz = const core::mem::offset_of!(ResidentBootContext, watchdog_tsc_hz),
    b_hyperv_timing_supported = const core::mem::offset_of!(ResidentBootContext, hyperv_timing_supported),
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
    b_vmresume_status_flags = const core::mem::offset_of!(ResidentBootContext, vmresume_status_flags),
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
    b_nested_host_procbased_ctls2 = const BCTX_NESTED_HOST_PROCBASED_CTLS2,
    b_nested_host_misc = const BCTX_NESTED_HOST_MISC,
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
    b_nested_current_vmcs_is_shadow = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, current_vmcs_is_shadow),
    b_nested_evmcs_enabled = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, evmcs_enabled),
    b_nested_vp_assist_msr = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, vp_assist_msr),
    b_nested_evmcs_active = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, evmcs_active),
    b_nested_evmcs_page_cache = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, evmcs_page_cache),
    event_hyperv_guest_os_id = const core::mem::offset_of!(ResidentEventContext, hyperv_guest_os_id),
    event_hyperv_hypercall_msr = const core::mem::offset_of!(ResidentEventContext, hyperv_hypercall_msr),
    event_hyperv_hypercall_lock = const core::mem::offset_of!(ResidentEventContext, hyperv_hypercall_lock),
    event_hyperv_tsc_invariant_supported = const core::mem::offset_of!(ResidentEventContext, hyperv_tsc_invariant_supported),
    event_hyperv_tsc_invariant_control = const core::mem::offset_of!(ResidentEventContext, hyperv_tsc_invariant_control),
    evmcs_version = const crate::hyperv::EVMCS_VERSION,
    evmcs_guest_rip = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, guest_rip),
    evmcs_guest_rsp = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, guest_rsp),
    evmcs_guest_rflags = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, guest_rflags),
    evmcs_host_rsp = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, host_rsp),
    evmcs_host_rip = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, host_rip),
    evmcs_exit_reason = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, exit_reason),
    evmcs_exit_instruction_error = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, exit_instruction_error),
    evmcs_exit_instruction_length = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, exit_instruction_length),
    evmcs_exit_qualification = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, exit_qualification),
    evmcs_clean_fields = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, clean_fields),
    vp_assist_enlighten_vm_entry = const crate::hyperv::VP_ASSIST_ENLIGHTEN_VM_ENTRY_OFFSET,
    vp_assist_current_nested_vmcs = const crate::hyperv::VP_ASSIST_CURRENT_NESTED_VMCS_OFFSET,
    b_nested_last_operand = const BCTX_NESTED_LAST_OPERAND,
    b_nested_last_vmcs_field = const BCTX_NESTED_LAST_VMCS_FIELD,
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
    b_nested_shadow_vmcs_region = const BCTX_NESTED_SHADOW_VMCS_REGION,
    b_nested_shadow_vmread_bitmap = const BCTX_NESTED_SHADOW_VMREAD_BITMAP,
    vmcs_shadow_read_byte_offset = const VMCS_SHADOW_READ_BITMAP_BYTE_OFFSET,
    vmcs_shadow_read_bypass_mask = const VMCS_SHADOW_READ_BYPASS_MASK,
    vmcs_shadow_read_trap_mask = const VMCS_SHADOW_READ_TRAP_MASK,
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
    b_nested_exit_reason_counts = const core::mem::offset_of!(ResidentBootContext, nested) + core::mem::offset_of!(NestedVmxState, exit_reason_counts),
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
    b_nested_ept02_eviction_cursor = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_eviction_cursor),
    b_nested_ept02_table_eviction_count = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, ept02_table_eviction_count),
    b_nested_failure_trace = const core::mem::offset_of!(ResidentBootContext, nested)
        + core::mem::offset_of!(NestedVmxState, failure_trace),
    nested_failure_trace_capacity = const crate::nested::NESTED_FAILURE_TRACE_CAPACITY,
    nested_failure_trace_limit = const 0x101 + crate::nested::NESTED_FAILURE_TRACE_CAPACITY * 3,
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
    b_nested_current_vmcs_hpa = const core::mem::offset_of!(ResidentBootContext, nested) + core::mem::offset_of!(NestedVmxState, current_vmcs_hpa),
    b_nested_l2_msr_gp_pending = const core::mem::offset_of!(ResidentBootContext, nested) + core::mem::offset_of!(NestedVmxState, l2_msr_gp_pending),
    b_nested_l2_nmi_exit_pending = const core::mem::offset_of!(ResidentBootContext, nested) + core::mem::offset_of!(NestedVmxState, l2_nmi_exit_pending),
    b_nested_entry_msr_prefix_count = const core::mem::offset_of!(ResidentBootContext, nested) + core::mem::offset_of!(NestedVmxState, entry_msr_prefix_count),
    b_nested_captured_msr_store_count = const core::mem::offset_of!(ResidentBootContext, nested) + core::mem::offset_of!(NestedVmxState, captured_msr_store_count),
    b_nested_operand_linear_address = const core::mem::offset_of!(ResidentBootContext, nested) + core::mem::offset_of!(NestedVmxState, operand_linear_address),
    b_nested_operand_data = const core::mem::offset_of!(ResidentBootContext, nested) + core::mem::offset_of!(NestedVmxState, operand_data),
    b_nested_ept_observed_value_after_invept = const BCTX_NESTED_EPT_OBSERVED_VALUE_AFTER_INVEPT,
    nested_invept_descriptor_offset = const crate::hv_core::vcpu::NESTED_INVEPT_DESCRIPTOR_OFFSET,
    nested_invept_rip_offset = const crate::hv_core::vcpu::NESTED_INVEPT_RIP_OFFSET,
    nested_invept_after_rip_offset = const crate::hv_core::vcpu::NESTED_INVEPT_AFTER_RIP_OFFSET,
    nested_invvpid_descriptor_offset = const crate::hv_core::vcpu::NESTED_INVVPID_DESCRIPTOR_OFFSET,
    nested_invvpid_rip_offset = const crate::hv_core::vcpu::NESTED_INVVPID_RIP_OFFSET,
    nested_invvpid_after_rip_offset = const crate::hv_core::vcpu::NESTED_INVVPID_AFTER_RIP_OFFSET,
    nested_ept_target_marker = const crate::hv_core::vcpu::NESTED_EPT_TARGET_MARKER,
    nested_ept_second_target_marker = const crate::hv_core::vcpu::NESTED_EPT_SECOND_TARGET_MARKER,
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
    vmcs_field_exit_reason = const VMCS_FIELD_VM_EXIT_REASON,
    vmcs_field_instruction_error = const VMCS_FIELD_VM_INSTRUCTION_ERROR,
    event_magic_offset = const EVENT_CTX_MAGIC,
    event_ebs_seen = const EVENT_CTX_EBS_SEEN,
    event_va_seen = const EVENT_CTX_VA_SEEN,
    event_canary_offset = const EVENT_CTX_CANARY,
    event_visual_base = const EVENT_CTX_VISUAL_BASE,
    event_visual_stride_bytes = const EVENT_CTX_VISUAL_STRIDE_BYTES,
    event_visual_deadline = const core::mem::offset_of!(ResidentEventContext, visual_deadline_tsc),
    event_tsc_hz = const core::mem::offset_of!(ResidentEventContext, watchdog_tsc_hz),
    event_hyperv_tsc_scale = const core::mem::offset_of!(ResidentEventContext, hyperv_tsc_scale),
    event_hyperv_tsc_offset = const core::mem::offset_of!(ResidentEventContext, hyperv_tsc_offset),
    event_hyperv_reference_tsc_msr = const core::mem::offset_of!(ResidentEventContext, hyperv_reference_tsc_msr),
    event_hyperv_reference_tsc_lock = const core::mem::offset_of!(ResidentEventContext, hyperv_reference_tsc_lock),
    event_hyperv_reference_tsc_sequence = const core::mem::offset_of!(ResidentEventContext, hyperv_reference_tsc_sequence),
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
    event_control_expected_mask = const core::mem::offset_of!(ResidentEventContext, control_expected_mask),
    event_control_active_mask = const core::mem::offset_of!(ResidentEventContext, control_active_mask),
    event_control_stopped_mask = const core::mem::offset_of!(ResidentEventContext, control_stopped_mask),
    event_control_failed_mask = const core::mem::offset_of!(ResidentEventContext, control_failed_mask),
    event_control_processor_count = const core::mem::offset_of!(ResidentEventContext, control_processor_count),
    event_control_va_error = const core::mem::offset_of!(ResidentEventContext, control_va_error),
    event_control_completion_sequences = const core::mem::offset_of!(ResidentEventContext, control_completion_sequences),
    event_control_rearm_mask = const core::mem::offset_of!(ResidentEventContext, control_rearm_mask),
    event_runtime_get_variable = const core::mem::offset_of!(ResidentEventContext, runtime_get_variable),
    event_runtime_set_variable = const core::mem::offset_of!(ResidentEventContext, runtime_set_variable),
    event_runtime_context = const core::mem::offset_of!(ResidentEventContext, runtime_context),
    event_control_apic_ids = const core::mem::offset_of!(ResidentEventContext, control_apic_ids),
    event_control_probe_states = const core::mem::offset_of!(ResidentEventContext, control_probe_states),
    event_control_cpu_states = const core::mem::offset_of!(ResidentEventContext, control_cpu_states),
    control_cpu_state_size = const size_of::<ControlCpuState>(),
    control_cpu_vmxon_region = const core::mem::offset_of!(ControlCpuState, vmxon_region),
    control_cpu_vmcs_region = const core::mem::offset_of!(ControlCpuState, vmcs_region),
    control_cpu_current_vmcs = const core::mem::offset_of!(ControlCpuState, current_vmcs),
    control_cpu_host_fields = const core::mem::offset_of!(ControlCpuState, host_fields),
    control_cpu_pin_based_controls = const core::mem::offset_of!(ControlCpuState, pin_based_controls),
    control_cpu_exit_msr_load_count = const core::mem::offset_of!(ControlCpuState, exit_msr_load_count),
    control_cpu_native_cr4 = const core::mem::offset_of!(ControlCpuState, native_cr4),
    control_cpu_on_original_cr4 = const core::mem::offset_of!(ControlCpuState, on_original_cr4),
    control_cpu_guest_dr7 = const core::mem::offset_of!(ControlCpuState, guest_dr7),
    control_cpu_guest_gdtr_limit = const core::mem::offset_of!(ControlCpuState, guest_gdtr_limit),
    control_cpu_guest_idtr_limit = const core::mem::offset_of!(ControlCpuState, guest_idtr_limit),
    control_cpu_sequence = const core::mem::offset_of!(ControlCpuState, sequence),
    control_cpu_phase = const core::mem::offset_of!(ControlCpuState, phase),
    control_cpu_stage = const core::mem::offset_of!(ControlCpuState, stage),
    control_cpu_native_storage_physical = const core::mem::offset_of!(ControlCpuState, native_storage_physical),
    control_cpu_native_storage_runtime = const core::mem::offset_of!(ControlCpuState, native_storage_runtime),
    control_cpu_native_caller_rsp = const core::mem::offset_of!(ControlCpuState, native_caller_rsp),
    control_cpu_native_snapshot_count = const core::mem::offset_of!(ControlCpuState, native_snapshot_count),
    control_cpu_on_native_cr0 = const core::mem::offset_of!(ControlCpuState, on_native_cr0),
    control_cpu_on_native_cr3 = const core::mem::offset_of!(ControlCpuState, on_native_cr3),
    control_cpu_on_native_dr7 = const core::mem::offset_of!(ControlCpuState, on_native_dr7),
    control_cpu_on_native_msrs = const core::mem::offset_of!(ControlCpuState, on_native_msrs),
    control_cpu_on_failure_reason = const core::mem::offset_of!(ControlCpuState, on_failure_reason),
    control_cpu_on_failure_qualification = const core::mem::offset_of!(ControlCpuState, on_failure_qualification),
    native_stack_bytes = const CONTROL_NATIVE_STACK_BYTES,
    native_recovery_pml4 = const core::mem::offset_of!(ControlNativeStorage, recovery_pml4),
    native_snapshots_offset = const core::mem::offset_of!(ControlNativeStorage, snapshots),
    native_snapshot_size = const size_of::<ControlNativeSnapshot>(),
    native_snapshot_pairs = const size_of::<ControlNativeSnapshot>() / 16,
    native_snapshot_capacity = const CONTROL_NATIVE_SNAPSHOT_CAPACITY,
    native_snapshot_leaf_limit = const 0x4000 + CONTROL_NATIVE_SNAPSHOT_CAPACITY * (size_of::<ControlNativeSnapshot>() / 16),
    native_snapshot_stage = const core::mem::offset_of!(ControlNativeSnapshot, stage),
    native_snapshot_rip = const core::mem::offset_of!(ControlNativeSnapshot, rip),
    native_snapshot_rsp = const core::mem::offset_of!(ControlNativeSnapshot, rsp),
    native_snapshot_rflags = const core::mem::offset_of!(ControlNativeSnapshot, rflags),
    native_snapshot_cr0 = const core::mem::offset_of!(ControlNativeSnapshot, cr0),
    native_snapshot_cr3 = const core::mem::offset_of!(ControlNativeSnapshot, cr3),
    native_snapshot_cr4 = const core::mem::offset_of!(ControlNativeSnapshot, cr4),
    native_snapshot_caller_rsp = const core::mem::offset_of!(ControlNativeSnapshot, caller_rsp),
    native_snapshot_stack_limit = const core::mem::offset_of!(ControlNativeSnapshot, stack_limit),
    native_snapshot_stack_base = const core::mem::offset_of!(ControlNativeSnapshot, stack_base),
    native_snapshot_gprs = const core::mem::offset_of!(ControlNativeSnapshot, gprs),
    native_snapshot_tsc = const core::mem::offset_of!(ControlNativeSnapshot, tsc),
    native_snapshot_stack = const core::mem::offset_of!(ControlNativeSnapshot, stack),
    probe_state_size = const size_of::<ControlProbeSnapshot>(),
    probe_state_qwords = const size_of::<ControlProbeSnapshot>() / size_of::<u64>(),
    probe_sequence = const core::mem::offset_of!(ControlProbeSnapshot, sequence),
    probe_guest_rip = const core::mem::offset_of!(ControlProbeSnapshot, guest_rip),
    probe_guest_rsp = const core::mem::offset_of!(ControlProbeSnapshot, guest_rsp),
    probe_guest_rflags = const core::mem::offset_of!(ControlProbeSnapshot, guest_rflags),
    probe_guest_cr0 = const core::mem::offset_of!(ControlProbeSnapshot, guest_cr0),
    probe_guest_cr3 = const core::mem::offset_of!(ControlProbeSnapshot, guest_cr3),
    probe_guest_cr4 = const core::mem::offset_of!(ControlProbeSnapshot, guest_cr4),
    probe_guest_efer = const core::mem::offset_of!(ControlProbeSnapshot, guest_efer),
    probe_guest_pat = const core::mem::offset_of!(ControlProbeSnapshot, guest_pat),
    probe_guest_gdtr_base = const core::mem::offset_of!(ControlProbeSnapshot, guest_gdtr_base),
    probe_guest_gdtr_limit = const core::mem::offset_of!(ControlProbeSnapshot, guest_gdtr_limit),
    probe_guest_idtr_base = const core::mem::offset_of!(ControlProbeSnapshot, guest_idtr_base),
    probe_guest_idtr_limit = const core::mem::offset_of!(ControlProbeSnapshot, guest_idtr_limit),
    probe_guest_cs_selector = const core::mem::offset_of!(ControlProbeSnapshot, guest_cs_selector),
    probe_guest_ss_selector = const core::mem::offset_of!(ControlProbeSnapshot, guest_ss_selector),
    probe_guest_tr_selector = const core::mem::offset_of!(ControlProbeSnapshot, guest_tr_selector),
    probe_guest_tr_access = const core::mem::offset_of!(ControlProbeSnapshot, guest_tr_access),
    probe_guest_fs_base = const core::mem::offset_of!(ControlProbeSnapshot, guest_fs_base),
    probe_guest_gs_base = const core::mem::offset_of!(ControlProbeSnapshot, guest_gs_base),
    probe_guest_interruptibility = const core::mem::offset_of!(ControlProbeSnapshot, guest_interruptibility),
    probe_idt_vectoring = const core::mem::offset_of!(ControlProbeSnapshot, idt_vectoring),
    probe_vm_entry_intr_info = const core::mem::offset_of!(ControlProbeSnapshot, vm_entry_intr_info),
    probe_runtime_get_variable = const core::mem::offset_of!(ControlProbeSnapshot, runtime_get_variable),
    probe_runtime_set_variable = const core::mem::offset_of!(ControlProbeSnapshot, runtime_set_variable),
    probe_runtime_context = const core::mem::offset_of!(ControlProbeSnapshot, runtime_context),
    probe_guest_es_selector = const core::mem::offset_of!(ControlProbeSnapshot, guest_es_selector),
    probe_guest_ds_selector = const core::mem::offset_of!(ControlProbeSnapshot, guest_ds_selector),
    probe_guest_fs_selector = const core::mem::offset_of!(ControlProbeSnapshot, guest_fs_selector),
    probe_guest_gs_selector = const core::mem::offset_of!(ControlProbeSnapshot, guest_gs_selector),
    probe_guest_ldtr_selector = const core::mem::offset_of!(ControlProbeSnapshot, guest_ldtr_selector),
    probe_guest_dr7 = const core::mem::offset_of!(ControlProbeSnapshot, guest_dr7),
    probe_guest_cr4_read_shadow = const core::mem::offset_of!(ControlProbeSnapshot, guest_cr4_read_shadow),
    probe_guest_tr_base = const core::mem::offset_of!(ControlProbeSnapshot, guest_tr_base),
    probe_guest_tr_limit = const core::mem::offset_of!(ControlProbeSnapshot, guest_tr_limit),
    bridge_magic = const CONTROL_MAGIC,
    bridge_version = const CONTROL_VERSION,
    bridge_status_size = const size_of::<ControlStatus>(),
    bridge_status_magic = const core::mem::offset_of!(ControlStatus, magic),
    bridge_status_version = const core::mem::offset_of!(ControlStatus, version),
    bridge_status_capabilities = const core::mem::offset_of!(ControlStatus, capabilities),
    bridge_status_apic_id = const core::mem::offset_of!(ControlStatus, current_apic_id),
    bridge_status_processor_count = const core::mem::offset_of!(ControlStatus, processor_count),
    bridge_status_expected_mask = const core::mem::offset_of!(ControlStatus, expected_mask),
    bridge_status_active_mask = const core::mem::offset_of!(ControlStatus, active_mask),
    bridge_status_stopped_mask = const core::mem::offset_of!(ControlStatus, stopped_mask),
    bridge_status_failed_mask = const core::mem::offset_of!(ControlStatus, failed_mask),
    bridge_status_ebs_seen = const core::mem::offset_of!(ControlStatus, exit_boot_services_seen),
    bridge_status_va_seen = const core::mem::offset_of!(ControlStatus, virtual_address_change_seen),
    bridge_status_va_error = const core::mem::offset_of!(ControlStatus, virtual_address_error),
    bridge_status_completion_sequence = const core::mem::offset_of!(ControlStatus, completion_sequence),
    bridge_status_apic_ids = const core::mem::offset_of!(ControlStatus, apic_ids),
    bridge_status_probe_snapshot = const core::mem::offset_of!(ControlStatus, probe_snapshot),
    bridge_request_size = const size_of::<ControlRequest>(),
    bridge_request_magic = const core::mem::offset_of!(ControlRequest, magic),
    bridge_request_version = const core::mem::offset_of!(ControlRequest, version),
    bridge_request_operation = const core::mem::offset_of!(ControlRequest, operation),
    bridge_request_sequence = const core::mem::offset_of!(ControlRequest, sequence),
    bridge_request_apic_id = const core::mem::offset_of!(ControlRequest, expected_apic_id),
    bridge_request_reserved = const core::mem::offset_of!(ControlRequest, reserved),
    bridge_probe_operation = const CONTROL_PROBE_OPERATION,
    bridge_probe_vmcall = const CONTROL_PROBE_VMCALL,
    bridge_probe_result = const CONTROL_PROBE_RESULT,
    bridge_off_prepare_vmcall = const CONTROL_OFF_PREPARE_VMCALL,
    bridge_off_prepared_result = const CONTROL_OFF_PREPARED_RESULT,
    bridge_off_commit_vmcall = const CONTROL_OFF_COMMIT_VMCALL,
    visual_marker_step_bytes = const crate::diagnostics::RESIDENT_MARKER_STEP * 4,
    visual_marker_row_step = const crate::diagnostics::RESIDENT_MARKER_ROW_STEP,
    visual_marker_side = const crate::diagnostics::RESIDENT_MARKER_SIZE,
    visual_hex_y = const crate::diagnostics::RESIDENT_HEX_Y,
    visual_hex_row_step = const crate::diagnostics::RESIDENT_HEX_ROW_STEP,
    visual_hex_last_row = const crate::diagnostics::RESIDENT_HEX_ROWS - 1,
    visual_hex_column_step_bytes = const crate::diagnostics::RESIDENT_HEX_COLUMN_STEP * 4,
    post_ebs_exit_message_len = const POST_EBS_EXIT_MESSAGE_LEN,
    post_va_exit_message_len = const POST_VA_EXIT_MESSAGE_LEN,
    first_start_exit_message_len = const FIRST_START_EXIT_MESSAGE_LEN,
    start_checkpoint_message_len = const START_CHECKPOINT_MESSAGE_LEN,
    start_returned_message_len = const START_RETURNED_MESSAGE_LEN,
    post_ebs_stop_message_len = const POST_EBS_STOP_MESSAGE_LEN,
    unsupported_exit_message_len = const UNSUPPORTED_EXIT_MESSAGE_LEN,
    task_switch_excluded_message_len = const b"[MATRIXHV][RESIDENT] HV:L1_CONTRACT_EXCLUDES_HARDWARE_TASK_SWITCH\r\n".len(),
    nested_entry_failure_dump_message_len = const b"[MATRIXHV][NESTED] VM_ENTRY_FAILURE_VMCS12 ".len(),
    nested_vmcs02_failure_dump_message_len = const b"[MATRIXHV][NESTED] VM_ENTRY_FAILURE_VMCS02 ".len(),
    nested_extended_field_count = const crate::nested::VMCS12_EXTENDED_FIELD_COUNT,
    host_cr3_mismatch_message_len = const HOST_CR3_MISMATCH_MESSAGE_LEN,
    event_corrupt_message_len = const EVENT_CORRUPT_MESSAGE_LEN,
    vmread_failed_message_len = const VMREAD_FAILED_MESSAGE_LEN,
    vmwrite_failed_message_len = const VMWRITE_FAILED_MESSAGE_LEN,
    vmresume_failed_message_len = const VMRESUME_FAILED_MESSAGE_LEN,
    vmresume_status_flags_message_len = const b" vmx_status_flags=0x".len(),
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

impl From<state::HostTablesError> for ResidentProbeError {
    fn from(value: state::HostTablesError) -> Self {
        match value {
            state::HostTablesError::Allocation(status) => Self::Allocation(status),
            state::HostTablesError::InvalidCodeLayout => Self::InvalidCodeLayout,
        }
    }
}

impl From<super::nested::NestedHardwareError> for ResidentProbeError {
    fn from(value: super::nested::NestedHardwareError) -> Self {
        match value {
            super::nested::NestedHardwareError::Vmclear(result) => Self::Vmclear(result),
            super::nested::NestedHardwareError::Vmcs(error) => Self::Vmcs(error),
            super::nested::NestedHardwareError::Controls(error) => Self::Controls(error),
            super::nested::NestedHardwareError::Ept(error) => Self::Ept(error),
            super::nested::NestedHardwareError::InvalidEptPoolUsage => Self::InvalidEptPoolUsage,
        }
    }
}

impl From<super::exits::ResidentRunError> for ResidentProbeError {
    fn from(value: super::exits::ResidentRunError) -> Self {
        match value {
            super::exits::ResidentRunError::VmlaunchVmFailInvalid => Self::VmlaunchVmFailInvalid,
            super::exits::ResidentRunError::VmlaunchVmFailValid(error) => {
                Self::VmlaunchVmFailValid(error)
            }
            super::exits::ResidentRunError::HostRspVmwriteVmFailValid(error) => {
                Self::HostRspVmwriteVmFailValid(error)
            }
            super::exits::ResidentRunError::HostRspVmwriteVmFailInvalid => {
                Self::HostRspVmwriteVmFailInvalid
            }
            super::exits::ResidentRunError::HostRipVmwriteVmFailValid(error) => {
                Self::HostRipVmwriteVmFailValid(error)
            }
            super::exits::ResidentRunError::HostRipVmwriteVmFailInvalid => {
                Self::HostRipVmwriteVmFailInvalid
            }
            super::exits::ResidentRunError::UnexpectedRunPath(path) => {
                Self::UnexpectedRunPath(path)
            }
        }
    }
}

impl From<crate::firmware::PciDiscoveryError> for ResidentProbeError {
    fn from(value: crate::firmware::PciDiscoveryError) -> Self {
        Self::FirmwareDiscovery(value)
    }
}
