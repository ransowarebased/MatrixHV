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
    HYPERVISOR_LEAF_END, HYPERVISOR_LEAF_START, HostVmxCapabilities, IA32_FEATURE_CONTROL_LOCKED,
    IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX, NestedVmxCapabilities, VMX_BASIC_TRUE_CONTROLS,
    VMX_MEMORY_TYPE_WRITE_BACK, VMX_REGION_SIZE,
};
use instructions::{
    VM_ENTRY_BLOCKED_BY_MOV_SS_ERROR, VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR,
    VM_ENTRY_INVALID_HOST_STATE_FIELD_ERROR, VMCLEAR_INVALID_PHYSICAL_ADDRESS_ERROR,
    VMCLEAR_VMXON_POINTER_ERROR, VMCS_UNSUPPORTED_COMPONENT_ERROR, VMFAIL_INVALID_STATUS,
    VMFAIL_VALID_STATUS, VMLAUNCH_NON_CLEAR_VMCS_ERROR, VMPTRLD_INCORRECT_REVISION_ERROR,
    VMPTRLD_INVALID_PHYSICAL_ADDRESS_ERROR, VMPTRLD_VMXON_POINTER_ERROR,
    VMRESUME_NON_LAUNCHED_VMCS_ERROR, VMWRITE_READ_ONLY_COMPONENT_ERROR, VMX_STATUS_FLAGS,
    VMX_STATUS_FLAGS_CLEAR_MASK, VMXON_IN_VMX_ROOT_ERROR,
};
use state::{INVALID_VMCS_POINTER, NestedVmxState};
use vmcs::{
    NestedVmcs12State, VMCS_FIELD_EXIT_QUALIFICATION, VMCS_FIELD_GUEST_RFLAGS,
    VMCS_FIELD_GUEST_RIP, VMCS_FIELD_GUEST_RSP, VMCS_FIELD_HOST_RIP, VMCS_FIELD_HOST_RSP,
    VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN, VMCS_FIELD_VM_EXIT_REASON, VMCS_FIELD_VM_INSTRUCTION_ERROR,
    VMCS12_LAUNCH_STATE_CLEAR, VMCS12_LAUNCH_STATE_LAUNCHED, VMCS12_LAUNCH_STATE_UNINITIALIZED,
};

const HOST_VMX_BASIC: u64 = 0x00da_0400_0000_1234;
const VMXON_REGION: u64 = 0x20_0000;
const VMXON_OPERAND: u64 = 0x21_0000;
const VMCS12_REGION: u64 = 0x30_0000;
const VMCS12_OPERAND: u64 = 0x31_0000;
const VMPTRST_DESTINATION: u64 = VMCS12_OPERAND + 8;
const VMCS01_REGION: u64 = 0x40_0000;
const VMCS02_REGION: u64 = 0x50_0000;

fn control_capabilities(must_be_one: u32, may_be_one: u32) -> u64 {
    u64::from(must_be_one) | (u64::from(may_be_one) << 32)
}

fn host_vmx_capabilities() -> HostVmxCapabilities {
    HostVmxCapabilities {
        vmx_basic: HOST_VMX_BASIC,
        pinbased_ctls: control_capabilities(0x16, u32::MAX),
        procbased_ctls: control_capabilities(0x0400_6172, u32::MAX),
        exit_ctls: control_capabilities(0x0003_6dfb, u32::MAX),
        entry_ctls: control_capabilities(0x0000_11fb, u32::MAX),
        misc: u64::MAX,
        cr0_fixed0: 0x8000_0021,
        cr0_fixed1: 0xffff_ffff,
        cr4_fixed0: 0x0000_2000,
        cr4_fixed1: 0x003f_ffff,
        vmcs_enum: 31 << 1,
        procbased_ctls2: control_capabilities(0, u32::MAX),
        ept_vpid_cap: u64::MAX,
        true_pinbased_ctls: control_capabilities(0, u32::MAX),
        true_procbased_ctls: control_capabilities(0, u32::MAX),
        true_exit_ctls: control_capabilities(0, u32::MAX),
        true_entry_ctls: control_capabilities(0, u32::MAX),
    }
}

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
        VMCS01_REGION + region_offset,
        VMCS02_REGION + region_offset,
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
    assert_eq!(capabilities.vmx_basic & VMX_BASIC_TRUE_CONTROLS, 0);
    assert_eq!(
        capabilities.feature_control,
        IA32_FEATURE_CONTROL_LOCKED | IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX
    );
    assert_eq!(capabilities.vmx_pinbased_ctls, 0);
    assert_eq!(capabilities.vmx_procbased_ctls, 0);
    assert_eq!(capabilities.vmx_exit_ctls, 0);
    assert_eq!(capabilities.vmx_entry_ctls, 0);
    assert_eq!(capabilities.vmx_cr0_fixed0, 0);
    assert_eq!(capabilities.vmx_cr0_fixed1, 0);
    assert_eq!(capabilities.vmx_cr4_fixed0, 0);
    assert_eq!(capabilities.vmx_cr4_fixed1, 0);
    assert_eq!(capabilities.vmx_vmcs_enum, 0);
    assert_eq!(capabilities.vmx_procbased_ctls2, 0);
    assert_eq!(capabilities.vmx_ept_vpid_cap, 0);
    assert!(!capabilities.expose_vmx);
}

#[test]
fn host_derived_capabilities_expose_only_the_current_nested_contract() {
    let host = host_vmx_capabilities();
    let capabilities = NestedVmxCapabilities::from_host(host);
    let ia32e_control = control_capabilities(
        capabilities::VM_ENTRY_IA32E_MODE_GUEST,
        capabilities::VM_ENTRY_IA32E_MODE_GUEST,
    );
    let host_address_size_control = control_capabilities(
        capabilities::VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
        capabilities::VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
    );
    let primary_control =
        control_capabilities(0, capabilities::VMX_PRIMARY_ACTIVATE_SECONDARY_CONTROLS);
    let secondary_control = control_capabilities(0, capabilities::VMX_SECONDARY_ENABLE_EPT);

    assert_eq!(capabilities.vmx_pinbased_ctls, 0);
    assert_eq!(capabilities.vmx_procbased_ctls, primary_control);
    assert_eq!(capabilities.vmx_exit_ctls, host_address_size_control);
    assert_eq!(capabilities.vmx_entry_ctls, ia32e_control);
    assert_eq!(capabilities.vmx_misc, 0);
    assert_eq!(capabilities.vmx_cr0_fixed0, host.cr0_fixed0);
    assert_eq!(capabilities.vmx_cr0_fixed1, host.cr0_fixed1);
    assert_eq!(capabilities.vmx_cr4_fixed0, host.cr4_fixed0);
    assert_eq!(capabilities.vmx_cr4_fixed1, host.cr4_fixed1);
    assert_eq!(
        capabilities.vmx_vmcs_enum,
        capabilities::VMCS12_MAX_ENUM_INDEX << 1
    );
    assert_eq!(capabilities.vmx_procbased_ctls2, secondary_control);
    assert_eq!(
        capabilities.vmx_ept_vpid_cap,
        capabilities::VMX_EPT_CAPABILITIES
    );
    assert_eq!(capabilities::VMX_EPT_CAPABILITIES, 0x1_4040);
    assert_eq!(capabilities.vmx_ept_vpid_cap & !0x1_4040, 0);
    assert_eq!(capabilities.vmx_true_pinbased_ctls, 0);
    assert_eq!(capabilities.vmx_true_procbased_ctls, primary_control);
    assert_eq!(capabilities.vmx_true_exit_ctls, host_address_size_control);
    assert_eq!(capabilities.vmx_true_entry_ctls, ia32e_control);
    assert!(!capabilities.expose_vmx);
}

#[test]
fn host_derived_controls_never_invent_unsupported_one_settings() {
    let mut host = host_vmx_capabilities();
    let exit_supported = u32::MAX & !capabilities::VM_EXIT_HOST_ADDRESS_SPACE_SIZE;
    let entry_supported = u32::MAX & !capabilities::VM_ENTRY_IA32E_MODE_GUEST;
    host.exit_ctls = control_capabilities(0, exit_supported);
    host.entry_ctls = control_capabilities(0, entry_supported);
    host.true_exit_ctls = control_capabilities(0, exit_supported);
    host.true_entry_ctls = control_capabilities(0, entry_supported);

    let capabilities = NestedVmxCapabilities::from_host(host);

    assert_eq!(capabilities.vmx_exit_ctls, 0);
    assert_eq!(capabilities.vmx_entry_ctls, 0);
    assert_eq!(capabilities.vmx_true_exit_ctls, 0);
    assert_eq!(capabilities.vmx_true_entry_ctls, 0);
}

#[test]
fn nested_ept_is_hidden_when_the_host_contract_is_incomplete() {
    let mut host = host_vmx_capabilities();
    host.ept_vpid_cap &= !capabilities::VMX_EPT_MEMORY_TYPE_WB;

    let capabilities = NestedVmxCapabilities::from_host(host);

    assert_eq!(capabilities.vmx_procbased_ctls, 0);
    assert_eq!(capabilities.vmx_procbased_ctls2, 0);
    assert_eq!(capabilities.vmx_ept_vpid_cap, 0);
    assert_eq!(capabilities.vmx_true_procbased_ctls, 0);
}

#[test]
fn true_control_msrs_follow_vmx_basic_availability() {
    let mut host = host_vmx_capabilities();
    host.vmx_basic &= !VMX_BASIC_TRUE_CONTROLS;
    let capabilities = NestedVmxCapabilities::from_host(host);

    assert_eq!(capabilities.vmx_basic & VMX_BASIC_TRUE_CONTROLS, 0);
    assert_eq!(capabilities.vmx_true_pinbased_ctls, 0);
    assert_eq!(capabilities.vmx_true_procbased_ctls, 0);
    assert_eq!(capabilities.vmx_true_exit_ctls, 0);
    assert_eq!(capabilities.vmx_true_entry_ctls, 0);
    assert_eq!(
        capabilities.vmx_msr(capabilities::IA32_VMX_TRUE_PINBASED_CTLS_MSR),
        None
    );
    assert_eq!(
        capabilities.vmx_msr(capabilities::IA32_VMX_TRUE_ENTRY_CTLS_MSR),
        None
    );
}

#[test]
fn virtual_vmx_msr_map_covers_the_supported_capability_range() {
    let capabilities = NestedVmxCapabilities::from_host(host_vmx_capabilities());
    let expected = [
        (capabilities::IA32_VMX_BASIC_MSR, capabilities.vmx_basic),
        (
            capabilities::IA32_VMX_PINBASED_CTLS_MSR,
            capabilities.vmx_pinbased_ctls,
        ),
        (
            capabilities::IA32_VMX_PROCBASED_CTLS_MSR,
            capabilities.vmx_procbased_ctls,
        ),
        (
            capabilities::IA32_VMX_EXIT_CTLS_MSR,
            capabilities.vmx_exit_ctls,
        ),
        (
            capabilities::IA32_VMX_ENTRY_CTLS_MSR,
            capabilities.vmx_entry_ctls,
        ),
        (capabilities::IA32_VMX_MISC_MSR, capabilities.vmx_misc),
        (
            capabilities::IA32_VMX_CR0_FIXED0_MSR,
            capabilities.vmx_cr0_fixed0,
        ),
        (
            capabilities::IA32_VMX_CR0_FIXED1_MSR,
            capabilities.vmx_cr0_fixed1,
        ),
        (
            capabilities::IA32_VMX_CR4_FIXED0_MSR,
            capabilities.vmx_cr4_fixed0,
        ),
        (
            capabilities::IA32_VMX_CR4_FIXED1_MSR,
            capabilities.vmx_cr4_fixed1,
        ),
        (
            capabilities::IA32_VMX_VMCS_ENUM_MSR,
            capabilities.vmx_vmcs_enum,
        ),
        (
            capabilities::IA32_VMX_PROCBASED_CTLS2_MSR,
            capabilities.vmx_procbased_ctls2,
        ),
        (
            capabilities::IA32_VMX_EPT_VPID_CAP_MSR,
            capabilities.vmx_ept_vpid_cap,
        ),
        (
            capabilities::IA32_VMX_TRUE_PINBASED_CTLS_MSR,
            capabilities.vmx_true_pinbased_ctls,
        ),
        (
            capabilities::IA32_VMX_TRUE_PROCBASED_CTLS_MSR,
            capabilities.vmx_true_procbased_ctls,
        ),
        (
            capabilities::IA32_VMX_TRUE_EXIT_CTLS_MSR,
            capabilities.vmx_true_exit_ctls,
        ),
        (
            capabilities::IA32_VMX_TRUE_ENTRY_CTLS_MSR,
            capabilities.vmx_true_entry_ctls,
        ),
    ];

    for (msr, value) in expected {
        assert_eq!(capabilities.vmx_msr(msr), Some(value));
    }
    assert_eq!(capabilities.vmx_msr(0x491), None);
}

#[test]
fn vmcs_enum_is_bounded_by_host_and_vmcs12_field_indices() {
    let max_vmcs12_index = vmcs::VMCS12_EXTENDED_FIELDS
        .iter()
        .map(|field| (field.encoding >> 1) & 0x1ff)
        .max()
        .unwrap();
    assert_eq!(max_vmcs12_index, capabilities::VMCS12_MAX_ENUM_INDEX);

    let mut host = host_vmx_capabilities();
    host.vmcs_enum = 9 << 1;
    let capabilities = NestedVmxCapabilities::from_host(host);
    assert_eq!(capabilities.vmx_vmcs_enum, 9 << 1);
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
    assert_eq!(bsp.vmcs01_region, VMCS01_REGION);
    assert_eq!(bsp.vmcs02_region, VMCS02_REGION);
    assert_eq!(bsp.l2_active, 0);
    assert_eq!(bsp.l2_entry_count, 0);
    assert_eq!(bsp.l2_exit_count, 0);
    assert_eq!(bsp.l2_last_exit_rsp, 0);
    assert_eq!(bsp.l1_reflection_count, 0);
    assert_eq!(bsp.l2_resume_count, 0);
    assert_eq!(bsp.l2_resume_exit_count, 0);
    assert_eq!(bsp.ept12_pointer, 0);
    assert_eq!(bsp.ept02_pointer, 0);
    assert_eq!(bsp.ept_source_gpa, 0);
    assert_eq!(bsp.ept_target_gpa, 0);
    assert_eq!(bsp.ept_composed_hpa, 0);
    assert_eq!(bsp.ept_permissions, 0);
    assert_eq!(bsp.ept_composition_count, 0);
    assert_eq!(bsp.ept_probe_count, 0);
    assert_eq!(bsp.ept_observed_value, 0);
}

#[test]
fn nested_state_records_ept_composition() {
    let mut state = nested_state(0);

    state.configure_ept(0x60_001e, 0x70_001e, 0x80_0000, 0x90_0000, 0x90_0000, 0x5);

    assert_eq!(state.ept12_pointer, 0x60_001e);
    assert_eq!(state.ept02_pointer, 0x70_001e);
    assert_eq!(state.ept_source_gpa, 0x80_0000);
    assert_eq!(state.ept_target_gpa, 0x90_0000);
    assert_eq!(state.ept_composed_hpa, 0x90_0000);
    assert_eq!(state.ept_permissions, 0x5);
    assert_eq!(state.ept_composition_count, 1);
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
    assert_eq!(vmcs12.guest_rsp, 0);
    assert_eq!(vmcs12.guest_rflags, 0);
    assert_eq!(vmcs12.host_rsp, 0);
    assert_eq!(vmcs12.host_rip, 0);
    assert_eq!(vmcs12.exit_reason, 0);
    assert_eq!(vmcs12.exit_instruction_len, 0);
    assert_eq!(vmcs12.exit_qualification, 0);
    assert_eq!(vmcs12.control_validation_count, 0);
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
    assert_eq!(VM_ENTRY_INVALID_HOST_STATE_FIELD_ERROR, 8);
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
    assert_eq!(VMCS_FIELD_VM_EXIT_REASON, 0x4402);
    assert_eq!(VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN, 0x440c);
    assert_eq!(VMCS_FIELD_EXIT_QUALIFICATION, 0x6400);
    assert_eq!(VMCS_FIELD_GUEST_RSP, 0x681c);
    assert_eq!(VMCS_FIELD_GUEST_RIP, 0x681e);
    assert_eq!(VMCS_FIELD_GUEST_RFLAGS, 0x6820);
    assert_eq!(VMCS_FIELD_HOST_RSP, 0x6c14);
    assert_eq!(VMCS_FIELD_HOST_RIP, 0x6c16);
    assert_eq!(VMCS12_LAUNCH_STATE_CLEAR, 0);
    assert_eq!(VMCS12_LAUNCH_STATE_LAUNCHED, 1);
}

#[test]
fn extended_vmcs12_fields_are_dense_unique_and_cover_entry_state() {
    assert_eq!(
        vmcs::VMCS12_EXTENDED_FIELDS.len(),
        vmcs::VMCS12_EXTENDED_FIELD_COUNT
    );
    for (index, field) in vmcs::VMCS12_EXTENDED_FIELDS.iter().enumerate() {
        assert_eq!(field.index, index);
        assert_eq!(
            vmcs::VMCS12_EXTENDED_FIELDS
                .iter()
                .filter(|candidate| candidate.encoding == field.encoding)
                .count(),
            1
        );
    }
    assert!(
        vmcs::VMCS12_EXTENDED_FIELDS
            .iter()
            .any(|field| field.encoding == vmcs::VMCS_FIELD_EXCEPTION_BITMAP)
    );
    assert!(
        vmcs::VMCS12_EXTENDED_FIELDS
            .iter()
            .any(|field| field.encoding == vmcs::VMCS_FIELD_GUEST_CR3)
    );
    assert!(
        vmcs::VMCS12_EXTENDED_FIELDS
            .iter()
            .any(|field| field.encoding == vmcs::VMCS_FIELD_HOST_CR3)
    );
}
