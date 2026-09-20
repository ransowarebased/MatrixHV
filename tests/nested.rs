#[path = "../src/nested/capabilities.rs"]
mod capabilities;
#[path = "../src/nested/exits.rs"]
mod exits;
#[path = "../src/nested/instructions.rs"]
mod instructions;
#[path = "../src/nested/state.rs"]
mod state;
#[path = "../src/nested/vmcs.rs"]
mod vmcs;

use capabilities::{
    CPUID_HYPERVISOR_PRESENT_BIT, CPUID_OSXSAVE_BIT, CPUID_VMX_BIT, HYPERV_FEATURES_LEAF,
    HYPERVISOR_LEAF_END, HYPERVISOR_LEAF_START, IA32_FEATURE_CONTROL_LOCKED,
    IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX, NestedVmxCapabilities, VMX_MEMORY_TYPE_WRITE_BACK,
    VMX_REGION_SIZE,
};
use instructions::{
    VM_ENTRY_BLOCKED_BY_MOV_SS_ERROR, VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR,
    VMCLEAR_INVALID_PHYSICAL_ADDRESS_ERROR, VMCLEAR_VMXON_POINTER_ERROR,
    VMCS_UNSUPPORTED_COMPONENT_ERROR, VMFAIL_INVALID_STATUS, VMFAIL_VALID_STATUS,
    VMLAUNCH_NON_CLEAR_VMCS_ERROR, VMPTRLD_INCORRECT_REVISION_ERROR,
    VMPTRLD_INVALID_PHYSICAL_ADDRESS_ERROR, VMPTRLD_VMXON_POINTER_ERROR,
    VMRESUME_NON_LAUNCHED_VMCS_ERROR, VMWRITE_READ_ONLY_COMPONENT_ERROR, VMX_STATUS_FLAGS,
    VMX_STATUS_FLAGS_CLEAR_MASK, VMXON_IN_VMX_ROOT_ERROR,
};
use state::{INVALID_VMCS_POINTER, NestedVmxState};
use vmcs::{
    NestedVmcs12State, VMCS_FIELD_GUEST_RIP, VMCS_FIELD_VM_INSTRUCTION_ERROR,
    VMCS12_LAUNCH_STATE_CLEAR, VMCS12_LAUNCH_STATE_LAUNCHED, VMCS12_LAUNCH_STATE_UNINITIALIZED,
};

const HOST_VMX_BASIC: u64 = 0x00da_0400_0000_1234;
const VMXON_REGION: u64 = 0x20_0000;
const VMXON_OPERAND: u64 = 0x21_0000;
const VMCS12_REGION: u64 = 0x30_0000;
const VMCS12_OPERAND: u64 = 0x31_0000;
const VMPTRST_DESTINATION: u64 = VMCS12_OPERAND + 8;

fn vmcs12(region_offset: u64) -> NestedVmcs12State {
    NestedVmcs12State::new(
        HOST_VMX_BASIC as u32 & 0x7fff_ffff,
        VMCS12_OPERAND + region_offset,
        VMCS12_REGION + region_offset,
        VMPTRST_DESTINATION + region_offset,
    )
}

fn nested_state(region_offset: u64) -> NestedVmxState {
    NestedVmxState::new(
        NestedVmxCapabilities::vmxon_vmxoff(HOST_VMX_BASIC),
        VMXON_OPERAND + region_offset,
        VMXON_REGION + region_offset,
        vmcs12(region_offset),
    )
}

#[test]
fn capabilities_normalize_vmx_basic_and_keep_vmx_internal() {
    let capabilities = NestedVmxCapabilities::vmxon_vmxoff(HOST_VMX_BASIC);

    assert_eq!(capabilities.revision_id, 0x1234);
    assert_eq!(capabilities.vmx_basic as u32, 0x1234);
    assert_eq!((capabilities.vmx_basic >> 32) & 0x1fff, VMX_REGION_SIZE);
    assert_eq!(
        (capabilities.vmx_basic >> 50) & 0xf,
        VMX_MEMORY_TYPE_WRITE_BACK
    );
    assert_eq!(
        capabilities.feature_control,
        IA32_FEATURE_CONTROL_LOCKED | IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX
    );
    assert!(!capabilities.expose_vmx);
}

#[test]
fn cpuid_contract_uses_architectural_bits_and_hypervisor_namespace() {
    assert_eq!(CPUID_VMX_BIT, 1 << 5);
    assert_eq!(CPUID_OSXSAVE_BIT, 1 << 27);
    assert_eq!(CPUID_HYPERVISOR_PRESENT_BIT, 1 << 31);
    assert_eq!(HYPERVISOR_LEAF_START, 0x4000_0000);
    assert_eq!(HYPERV_FEATURES_LEAF, 0x4000_0003);
    assert_eq!(HYPERVISOR_LEAF_END, 0x4fff_ffff);
}

#[test]
fn per_cpu_nested_state_starts_independent_and_inactive() {
    let bsp = nested_state(0);
    let ap = nested_state(0x10_0000);

    assert_ne!(bsp.vmxon_operand, ap.vmxon_operand);
    assert_ne!(bsp.vmxon_region, ap.vmxon_region);
    assert_ne!(bsp.vmcs12.operand, ap.vmcs12.operand);
    assert_ne!(bsp.vmcs12.region, ap.vmcs12.region);
    assert_eq!(bsp.current_vmcs, INVALID_VMCS_POINTER);
    assert_eq!(ap.current_vmcs, INVALID_VMCS_POINTER);
    assert_eq!(bsp.expose_vmx, 0);
    assert_eq!(ap.expose_vmx, 0);
    assert_eq!(bsp.active, 0);
    assert_eq!(ap.active, 0);
    assert_eq!(bsp.vmxon_count, 0);
    assert_eq!(bsp.vmxoff_count, 0);
    assert_eq!(bsp.failure_count, 0);
    assert_eq!(bsp.probe_complete, 0);
}

#[test]
fn vmcs12_state_starts_uninitialized_with_zero_observability() {
    let vmcs12 = vmcs12(0);

    assert_eq!(vmcs12.operand, VMCS12_OPERAND);
    assert_eq!(vmcs12.region, VMCS12_REGION);
    assert_eq!(vmcs12.vmptrst_destination, VMPTRST_DESTINATION);
    assert_eq!(vmcs12.last_stored_pointer, 0);
    assert_eq!(vmcs12.revision_id, 0x1234);
    assert_eq!(vmcs12.launch_state, VMCS12_LAUNCH_STATE_UNINITIALIZED);
    assert_ne!(VMCS12_LAUNCH_STATE_CLEAR, VMCS12_LAUNCH_STATE_UNINITIALIZED);
    assert_eq!(vmcs12.guest_rip, 0);
    assert_eq!(vmcs12.vmclear_count, 0);
    assert_eq!(vmcs12.vmptrld_count, 0);
    assert_eq!(vmcs12.vmptrst_count, 0);
    assert_eq!(vmcs12.vmwrite_count, 0);
    assert_eq!(vmcs12.vmread_count, 0);
    assert_eq!(vmcs12.probe_complete, 0);
    assert_eq!(vmcs12.vmlaunch_count, 0);
    assert_eq!(vmcs12.vmresume_count, 0);
    assert_eq!(vmcs12.entry_rejection_count, 0);
}

#[test]
fn nested_exit_reasons_match_intel_basic_exit_reasons() {
    assert_eq!(exits::VMCLEAR_EXIT_REASON, 19);
    assert_eq!(exits::VMLAUNCH_EXIT_REASON, 20);
    assert_eq!(exits::VMPTRLD_EXIT_REASON, 21);
    assert_eq!(exits::VMPTRST_EXIT_REASON, 22);
    assert_eq!(exits::VMREAD_EXIT_REASON, 23);
    assert_eq!(exits::VMRESUME_EXIT_REASON, 24);
    assert_eq!(exits::VMWRITE_EXIT_REASON, 25);
    assert_eq!(exits::VMXOFF_EXIT_REASON, 26);
    assert_eq!(exits::VMXON_EXIT_REASON, 27);
}

#[test]
fn vm_instruction_errors_and_status_flags_match_architecture() {
    assert_eq!(VMCLEAR_INVALID_PHYSICAL_ADDRESS_ERROR, 2);
    assert_eq!(VMCLEAR_VMXON_POINTER_ERROR, 3);
    assert_eq!(VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR, 7);
    assert_eq!(VM_ENTRY_BLOCKED_BY_MOV_SS_ERROR, 26);
    assert_eq!(VMXON_IN_VMX_ROOT_ERROR, 15);
    assert_eq!(VMLAUNCH_NON_CLEAR_VMCS_ERROR, 4);
    assert_eq!(VMRESUME_NON_LAUNCHED_VMCS_ERROR, 5);
    assert_eq!(VMPTRLD_INVALID_PHYSICAL_ADDRESS_ERROR, 9);
    assert_eq!(VMPTRLD_VMXON_POINTER_ERROR, 10);
    assert_eq!(VMPTRLD_INCORRECT_REVISION_ERROR, 11);
    assert_eq!(VMCS_UNSUPPORTED_COMPONENT_ERROR, 12);
    assert_eq!(VMWRITE_READ_ONLY_COMPONENT_ERROR, 13);
    assert_eq!(VMX_STATUS_FLAGS, 0x8d5);
    assert_eq!(VMX_STATUS_FLAGS_CLEAR_MASK, -2262);
    assert_eq!(VMFAIL_INVALID_STATUS, 1);
    assert_eq!(VMFAIL_VALID_STATUS, 1 << 6);
}

#[test]
fn supported_vmcs12_fields_match_intel_encodings() {
    assert_eq!(VMCS_FIELD_VM_INSTRUCTION_ERROR, 0x4400);
    assert_eq!(VMCS_FIELD_GUEST_RIP, 0x681e);
    assert_eq!(VMCS12_LAUNCH_STATE_CLEAR, 0);
    assert_eq!(VMCS12_LAUNCH_STATE_LAUNCHED, 1);
}
