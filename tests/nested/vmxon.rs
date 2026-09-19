#[path = "../../src/nested/nested_capabilities.rs"]
mod nested_capabilities;
#[path = "../../src/nested/nested_cpuid.rs"]
mod nested_cpuid;
#[path = "../../src/nested/nested_state.rs"]
mod nested_state;
#[path = "../../src/nested/nested_vmxoff.rs"]
mod nested_vmxoff;
#[path = "../../src/nested/nested_vmxon.rs"]
mod nested_vmxon;

use nested_capabilities::{
    IA32_FEATURE_CONTROL_LOCKED, IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX,
    NestedVmxCapabilities, VMX_MEMORY_TYPE_WRITE_BACK, VMX_REGION_SIZE,
};
use nested_cpuid::{
    CPUID_HYPERVISOR_PRESENT_BIT, CPUID_OSXSAVE_BIT, CPUID_VMX_BIT, CpuidRegisters,
};
use nested_state::{INVALID_VMCS_POINTER, NestedVmxState};
use nested_vmxon::{NestedVmxOutcome, VmxonOperand};

const HOST_VMX_BASIC: u64 = 0x00da_0400_0000_1234;
const VMXON_REGION: u64 = 0x20_0000;
const VMXON_OPERAND: u64 = VMXON_REGION + 8;

fn state() -> NestedVmxState {
    NestedVmxState::new(
        NestedVmxCapabilities::vmxon_vmxoff(HOST_VMX_BASIC),
        VMXON_OPERAND,
        VMXON_REGION,
    )
}

fn valid_operand() -> VmxonOperand {
    VmxonOperand {
        physical_address: VMXON_REGION,
        revision_id: HOST_VMX_BASIC as u32 & 0x7fff_ffff,
    }
}

#[test]
fn capabilities_describe_only_the_internal_vmxon_contract() {
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
    assert_eq!(state().expose_vmx, 0);
}

#[test]
fn vmxon_then_vmxoff_transitions_back_to_inactive() {
    let mut state = state();
    assert_eq!(
        nested_vmxon::emulate(&mut state, valid_operand(), 1 << 13, 0),
        NestedVmxOutcome::Succeeded
    );
    assert_eq!(state.active, 1);
    assert_eq!(state.current_vmcs, INVALID_VMCS_POINTER);
    assert_eq!(
        nested_vmxoff::emulate(&mut state, 0),
        NestedVmxOutcome::Succeeded
    );
    assert_eq!(state.active, 0);
    assert_eq!(state.probe_complete, 1);
    assert_eq!(state.vmxon_count, 1);
    assert_eq!(state.vmxoff_count, 1);
    assert_eq!(state.failure_count, 0);
}

#[test]
fn vmxon_rejects_bad_operands_and_missing_enablement() {
    let mut misaligned = state();
    let operand = VmxonOperand {
        physical_address: VMXON_REGION + 1,
        revision_id: valid_operand().revision_id,
    };
    assert_eq!(
        nested_vmxon::emulate(&mut misaligned, operand, 1 << 13, 0),
        NestedVmxOutcome::VmFailInvalid
    );

    let mut wrong_revision = state();
    let operand = VmxonOperand {
        physical_address: VMXON_REGION,
        revision_id: valid_operand().revision_id ^ 1,
    };
    assert_eq!(
        nested_vmxon::emulate(&mut wrong_revision, operand, 1 << 13, 0),
        NestedVmxOutcome::VmFailInvalid
    );

    let mut vmxe_clear = state();
    assert_eq!(
        nested_vmxon::emulate(&mut vmxe_clear, valid_operand(), 0, 0),
        NestedVmxOutcome::InvalidOpcode
    );

    let mut feature_control_disabled = state();
    feature_control_disabled.feature_control = IA32_FEATURE_CONTROL_LOCKED;
    assert_eq!(
        nested_vmxon::emulate(
            &mut feature_control_disabled,
            valid_operand(),
            1 << 13,
            0
        ),
        NestedVmxOutcome::GeneralProtection
    );
}

#[test]
fn repeated_vmxon_and_inactive_vmxoff_fail_architecturally() {
    let mut active_state = state();
    assert_eq!(
        nested_vmxon::emulate(&mut active_state, valid_operand(), 1 << 13, 0),
        NestedVmxOutcome::Succeeded
    );
    assert_eq!(
        nested_vmxon::emulate(&mut active_state, valid_operand(), 1 << 13, 0),
        NestedVmxOutcome::VmFailInvalid
    );

    let mut inactive = state();
    assert_eq!(
        nested_vmxoff::emulate(&mut inactive, 0),
        NestedVmxOutcome::InvalidOpcode
    );
}

#[test]
fn cpuid_presence_is_independent_from_vmx_capability() {
    let input = CpuidRegisters {
        eax: 0,
        ebx: 0,
        ecx: u32::MAX,
        edx: 0,
    };
    let hidden = nested_cpuid::filter(1, input, false, false, true);
    assert_eq!(hidden.ecx & CPUID_HYPERVISOR_PRESENT_BIT, 0);
    assert_eq!(hidden.ecx & CPUID_VMX_BIT, 0);
    assert_ne!(hidden.ecx & CPUID_OSXSAVE_BIT, 0);

    let present = nested_cpuid::filter(1, input, true, false, false);
    assert_ne!(present.ecx & CPUID_HYPERVISOR_PRESENT_BIT, 0);
    assert_eq!(present.ecx & CPUID_VMX_BIT, 0);
    assert_eq!(present.ecx & CPUID_OSXSAVE_BIT, 0);
}

#[test]
fn hidden_presence_zeros_the_hypervisor_namespace() {
    let input = CpuidRegisters {
        eax: 0x4000_0010,
        ebx: 0x6177_4d56,
        ecx: 0x4d56_6572,
        edx: 0x6572_6177,
    };
    assert_eq!(
        nested_cpuid::filter(0x4000_0000, input, false, false, false),
        CpuidRegisters {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        }
    );
}
