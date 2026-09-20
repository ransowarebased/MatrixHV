use super::capabilities::NestedVmxCapabilities;
use super::vmcs::NestedVmcs12State;

pub const INVALID_VMCS_POINTER: u64 = u64::MAX;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedVmxState {
    pub feature_control: u64,
    pub vmx_basic: u64,
    pub expose_vmx: u64,
    pub vmxon_operand: u64,
    pub vmxon_region: u64,
    pub current_vmcs: u64,
    pub last_operand: u64,
    pub instruction_error: u64,
    pub vmxon_count: u64,
    pub vmxoff_count: u64,
    pub failure_count: u64,
    pub active: u64,
    pub probe_complete: u64,
    pub vmcs12: NestedVmcs12State,
    pub vmcs01_region: u64,
    pub vmcs02_region: u64,
    pub l2_active: u64,
    pub l2_entry_count: u64,
    pub l2_exit_count: u64,
    pub l2_last_exit_reason: u64,
    pub l2_last_exit_rip: u64,
    pub l2_last_exit_rsp: u64,
    pub l1_reflection_count: u64,
    pub l2_resume_count: u64,
    pub l2_resume_exit_count: u64,
}

impl NestedVmxState {
    pub fn new(
        capabilities: NestedVmxCapabilities,
        vmxon_operand: u64,
        vmxon_region: u64,
        vmcs12: NestedVmcs12State,
        vmcs01_region: u64,
        vmcs02_region: u64,
    ) -> Self {
        Self {
            feature_control: capabilities.feature_control,
            vmx_basic: capabilities.vmx_basic,
            expose_vmx: u64::from(capabilities.expose_vmx),
            vmxon_operand,
            vmxon_region,
            current_vmcs: INVALID_VMCS_POINTER,
            last_operand: 0,
            instruction_error: 0,
            vmxon_count: 0,
            vmxoff_count: 0,
            failure_count: 0,
            active: 0,
            probe_complete: 0,
            vmcs12,
            vmcs01_region,
            vmcs02_region,
            l2_active: 0,
            l2_entry_count: 0,
            l2_exit_count: 0,
            l2_last_exit_reason: 0,
            l2_last_exit_rip: 0,
            l2_last_exit_rsp: 0,
            l1_reflection_count: 0,
            l2_resume_count: 0,
            l2_resume_exit_count: 0,
        }
    }
}
