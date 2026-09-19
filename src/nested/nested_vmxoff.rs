use super::nested_state::{INVALID_VMCS_POINTER, NestedVmxState};
use super::nested_vmxon::NestedVmxOutcome;

pub fn emulate(state: &mut NestedVmxState, guest_cpl: u8) -> NestedVmxOutcome {
    state.vmxoff_count += 1;
    if state.active == 0 {
        state.failure_count += 1;
        return NestedVmxOutcome::InvalidOpcode;
    }
    if guest_cpl != 0 {
        state.failure_count += 1;
        return NestedVmxOutcome::GeneralProtection;
    }

    state.active = 0;
    state.current_vmcs = INVALID_VMCS_POINTER;
    state.instruction_error = 0;
    state.probe_complete = 1;
    NestedVmxOutcome::Succeeded
}
