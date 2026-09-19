use super::nested_capabilities::{
    IA32_FEATURE_CONTROL_LOCKED, IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX,
};
use super::nested_state::{INVALID_VMCS_POINTER, NestedVmxState};

pub const VMXON_IN_ROOT_OPERATION_ERROR: u64 = 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedVmxOutcome {
    Succeeded,
    VmFailInvalid,
    VmFailValid(u64),
    GeneralProtection,
    InvalidOpcode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmxonOperand {
    pub physical_address: u64,
    pub revision_id: u32,
}

pub fn emulate(
    state: &mut NestedVmxState,
    operand: VmxonOperand,
    guest_cr4: u64,
    guest_cpl: u8,
) -> NestedVmxOutcome {
    state.vmxon_count += 1;
    state.last_operand = operand.physical_address;

    if guest_cr4 & (1 << 13) == 0 {
        state.failure_count += 1;
        return NestedVmxOutcome::InvalidOpcode;
    }
    if guest_cpl != 0
        || state.feature_control & IA32_FEATURE_CONTROL_LOCKED == 0
        || state.feature_control & IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX == 0
    {
        state.failure_count += 1;
        return NestedVmxOutcome::GeneralProtection;
    }
    if state.active != 0 {
        state.failure_count += 1;
        if state.current_vmcs == INVALID_VMCS_POINTER {
            return NestedVmxOutcome::VmFailInvalid;
        }
        state.instruction_error = VMXON_IN_ROOT_OPERATION_ERROR;
        return NestedVmxOutcome::VmFailValid(VMXON_IN_ROOT_OPERATION_ERROR);
    }
    if operand.physical_address & 0xfff != 0
        || operand.physical_address != state.vmxon_region
        || operand.revision_id != state.vmx_basic as u32 & 0x7fff_ffff
    {
        state.failure_count += 1;
        return NestedVmxOutcome::VmFailInvalid;
    }

    state.active = 1;
    state.current_vmcs = INVALID_VMCS_POINTER;
    state.instruction_error = 0;
    NestedVmxOutcome::Succeeded
}
