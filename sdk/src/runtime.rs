//! Read-only L0 diagnostics. CPU slots describe resident L0 state, not L2 processes.
use crate::protocol::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuntimeState {
    pub present: bool,
    pub diagnostic_available: bool,
    pub registered_mask: u64,
    pub nested_mask: u64,
    pub l2_mask: u64,
    pub caller_l2: bool,
    pub l2_memory_advertised: bool,
}

impl RuntimeState {
    pub fn transition_preflight(&self, operation: &str, active_mask: u64) -> Result<(), String> {
        if active_mask == 0 {
            return Ok(());
        }
        if !self.diagnostic_available || active_mask & !self.registered_mask != 0 {
            return Err(format!(
                "MatrixHV {operation} preflight unavailable: active CPU coverage cannot be verified through L0 diagnostics"
            ));
        }
        if self.nested_mask != 0 || self.l2_mask != 0 {
            return Err(format!(
                "MatrixHV {operation} unsupported while nested virtualization is active: nested_mask={:#x} l2_mask={:#x}; preserving Hyper-V/VBS requires a native state handoff",
                self.nested_mask, self.l2_mask
            ));
        }
        Ok(())
    }
}

pub fn query() -> RuntimeState {
    query_with(|subleaf| {
        #[cfg(target_arch = "x86_64")]
        {
            let value = std::arch::x86_64::__cpuid_count(MATRIXHV_STATUS_LEAF, subleaf);
            [value.eax, value.ebx, value.ecx, value.edx]
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = subleaf;
            [0; 4]
        }
    })
}

fn query_with(mut read: impl FnMut(u32) -> [u32; 4]) -> RuntimeState {
    let signature = read(0);
    let present = signature[..3]
        == [
            MATRIXHV_STATUS_SIGNATURE_EAX,
            MATRIXHV_STATUS_SIGNATURE_EBX,
            MATRIXHV_STATUS_SIGNATURE_ECX,
        ];
    let mut state = RuntimeState {
        present,
        ..RuntimeState::default()
    };
    if !present || signature[3] < 4 {
        return state;
    }
    state.diagnostic_available = true;
    state.l2_memory_advertised = read(34)[0] & MATRIXHV_L2_MEMORY_CAPABILITY != 0;
    let registered = read(36);
    state.registered_mask = u64::from(registered[0]) | (u64::from(registered[1]) << 32);
    state.caller_l2 = read(31)[1] != 0;
    for cpu in 0..64 {
        let bit = 1_u64 << cpu;
        if state.registered_mask & bit == 0 {
            continue;
        }
        let nested = read(31 | ((cpu + 1) << 16));
        if nested[0] != 0 {
            state.nested_mask |= bit;
        }
        if nested[1] != 0 {
            state.l2_mask |= bit;
        }
    }
    state
}

#[cfg(test)]
#[path = "../../tests/runtime_diagnostics_tests.rs"]
mod tests;
