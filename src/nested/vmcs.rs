pub const VMCS12_LAUNCH_STATE_CLEAR: u64 = 0;
pub const VMCS12_LAUNCH_STATE_LAUNCHED: u64 = 1;
pub const VMCS12_LAUNCH_STATE_UNINITIALIZED: u64 = u64::MAX;
pub const VMCS_FIELD_VM_INSTRUCTION_ERROR: u64 = 0x4400;
pub const VMCS_FIELD_VM_EXIT_REASON: u64 = 0x4402;
pub const VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN: u64 = 0x440c;
pub const VMCS_FIELD_EXIT_QUALIFICATION: u64 = 0x6400;
pub const VMCS_FIELD_GUEST_RSP: u64 = 0x681c;
pub const VMCS_FIELD_GUEST_RIP: u64 = 0x681e;
pub const VMCS_FIELD_GUEST_RFLAGS: u64 = 0x6820;
pub const VMCS_FIELD_HOST_RSP: u64 = 0x6c14;
pub const VMCS_FIELD_HOST_RIP: u64 = 0x6c16;

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
    pub vmlaunch_count: u64,
    pub vmresume_count: u64,
    pub entry_rejection_count: u64,
    pub guest_rsp: u64,
    pub guest_rflags: u64,
    pub host_rsp: u64,
    pub host_rip: u64,
    pub exit_reason: u64,
    pub exit_instruction_len: u64,
    pub exit_qualification: u64,
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
            vmlaunch_count: 0,
            vmresume_count: 0,
            entry_rejection_count: 0,
            guest_rsp: 0,
            guest_rflags: 0,
            host_rsp: 0,
            host_rip: 0,
            exit_reason: 0,
            exit_instruction_len: 0,
            exit_qualification: 0,
        }
    }
}
