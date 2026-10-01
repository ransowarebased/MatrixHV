use crate::memory::PAGE_SIZE;
use core::mem::size_of;

pub const CONTROL_PROBE_VMCALL: u64 = 0x4d41_5452_4958_5042;
pub const CONTROL_PROBE_RESULT: u64 = 0x4d41_5452_4958_4f4b;
pub const CONTROL_OFF_PREPARE_VMCALL: u64 = 0x4d41_5452_4958_4f50;
pub const CONTROL_OFF_PREPARED_RESULT: u64 = 0x4d41_5452_4958_5052;
pub const CONTROL_OFF_COMMIT_VMCALL: u64 = 0x4d41_5452_4958_4f43;
pub const CONTROL_NATIVE_STACK_BYTES: usize = PAGE_SIZE * 4;
pub const CONTROL_NATIVE_SNAPSHOT_CAPACITY: usize = 24;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ControlCpuState {
    pub vmxon_region: u64,
    pub vmcs_region: u64,
    pub current_vmcs: u64,
    pub host_fields: [u64; 22],
    pub pin_based_controls: u64,
    pub exit_msr_load_count: u64,
    pub native_cr4: u64,
    pub on_original_cr4: u64,
    pub guest_dr7: u64,
    pub guest_gdtr_limit: u64,
    pub guest_idtr_limit: u64,
    pub sequence: u64,
    pub phase: u64,
    pub stage: u64,
    pub native_storage_physical: u64,
    pub native_storage_runtime: u64,
    pub native_caller_rsp: u64,
    pub native_snapshot_count: u64,
    pub on_native_cr0: u64,
    pub on_native_cr3: u64,
    pub on_native_dr7: u64,
    pub on_native_msrs: [u64; 9],
    pub on_failure_reason: u64,
    pub on_failure_qualification: u64,
}

#[repr(C, align(16))]
pub struct ControlNativeSnapshot {
    pub stage: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub caller_rsp: u64,
    pub stack_limit: u64,
    pub stack_base: u64,
    pub gprs: [u64; 15],
    pub tsc: u64,
    pub stack: [u8; CONTROL_NATIVE_STACK_BYTES],
}

#[repr(C, align(4096))]
pub struct ControlNativeStorage {
    pub stack: [u8; CONTROL_NATIVE_STACK_BYTES],
    pub recovery_pml4: [u64; PAGE_SIZE / size_of::<u64>()],
    pub snapshots: [ControlNativeSnapshot; CONTROL_NATIVE_SNAPSHOT_CAPACITY],
}

pub struct VariableBridge {
    pub get_variable_bridge: u64,
    pub set_variable_bridge: u64,
    pub original_get_variable_slot: u64,
    pub original_set_variable_slot: u64,
    pub convert_pointer_slot: u64,
    pub bridge_context_slot: u64,
    pub runtime_get_variable_slot: u64,
    pub runtime_set_variable_slot: u64,
}
