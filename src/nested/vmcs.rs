pub const VMCS12_LAUNCH_STATE_CLEAR: u64 = 0;
pub const VMCS12_LAUNCH_STATE_UNINITIALIZED: u64 = u64::MAX;
pub const VMCS_FIELD_VM_INSTRUCTION_ERROR: u64 = 0x4400;
pub const VMCS_FIELD_GUEST_RIP: u64 = 0x681e;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedVmcs12State {
    pub operand: u64,
    pub region: u64,
    pub vmptrst_destination: u64,
    pub last_stored_pointer: u64,
    pub revision_id: u64,
    pub launch_state: u64,
    pub guest_rip: u64,
    pub vmclear_count: u64,
    pub vmptrld_count: u64,
    pub vmptrst_count: u64,
    pub vmwrite_count: u64,
    pub vmread_count: u64,
    pub probe_complete: u64,
}

impl NestedVmcs12State {
    pub fn new(revision_id: u32, operand: u64, region: u64, vmptrst_destination: u64) -> Self {
        Self {
            operand,
            region,
            vmptrst_destination,
            last_stored_pointer: 0,
            revision_id: u64::from(revision_id),
            launch_state: VMCS12_LAUNCH_STATE_UNINITIALIZED,
            guest_rip: 0,
            vmclear_count: 0,
            vmptrld_count: 0,
            vmptrst_count: 0,
            vmwrite_count: 0,
            vmread_count: 0,
            probe_complete: 0,
        }
    }
}
