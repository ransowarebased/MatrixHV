pub const CONTROL_PROBE_OPERATION: u32 = 3;
pub const CONTROL_VERSION: u32 = 3;
pub const CONTROL_MAGIC: u64 = 0x4d41_5452_4958_4354;
#[repr(C)]
pub struct ControlRequest {
    pub magic: u64,
    pub version: u32,
    pub operation: u32,
    pub sequence: u64,
    pub expected_apic_id: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ControlStatus {
    pub magic: u64,
    pub version: u32,
    pub capabilities: u32,
    pub current_apic_id: u32,
    pub processor_count: u32,
    pub expected_mask: u64,
    pub active_mask: u64,
    pub stopped_mask: u64,
    pub failed_mask: u64,
    pub exit_boot_services_seen: u64,
    pub virtual_address_change_seen: u64,
    pub virtual_address_error: u64,
    pub completion_sequence: u64,
    pub apic_ids: [u32; 64],
    pub probe_snapshot: ControlProbeSnapshot,
}

impl Default for ControlStatus {
    fn default() -> Self {
        Self {
            magic: 0,
            version: 0,
            capabilities: 0,
            current_apic_id: 0,
            processor_count: 0,
            expected_mask: 0,
            active_mask: 0,
            stopped_mask: 0,
            failed_mask: 0,
            exit_boot_services_seen: 0,
            virtual_address_change_seen: 0,
            virtual_address_error: 0,
            completion_sequence: 0,
            apic_ids: [0; 64],
            probe_snapshot: ControlProbeSnapshot::default(),
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ControlProbeSnapshot {
    pub sequence: u64,
    pub guest_rip: u64,
    pub guest_rsp: u64,
    pub guest_rflags: u64,
    pub guest_cr0: u64,
    pub guest_cr3: u64,
    pub guest_cr4: u64,
    pub guest_efer: u64,
    pub guest_pat: u64,
    pub guest_gdtr_base: u64,
    pub guest_gdtr_limit: u64,
    pub guest_idtr_base: u64,
    pub guest_idtr_limit: u64,
    pub guest_cs_selector: u64,
    pub guest_ss_selector: u64,
    pub guest_tr_selector: u64,
    pub guest_tr_access: u64,
    pub guest_fs_base: u64,
    pub guest_gs_base: u64,
    pub guest_interruptibility: u64,
    pub idt_vectoring: u64,
    pub vm_entry_intr_info: u64,
    pub runtime_get_variable: u64,
    pub runtime_set_variable: u64,
    pub runtime_context: u64,
    pub guest_es_selector: u64,
    pub guest_ds_selector: u64,
    pub guest_fs_selector: u64,
    pub guest_gs_selector: u64,
    pub guest_ldtr_selector: u64,
    pub guest_dr7: u64,
    pub guest_cr4_read_shadow: u64,
    pub guest_tr_base: u64,
    pub guest_tr_limit: u64,
}

pub const MATRIXHV_STATUS_LEAF: u32 = 0x4d48_5652;
pub const MATRIXHV_STATUS_SIGNATURE_EAX: u32 = 0x4d48_5631;
pub const MATRIXHV_STATUS_SIGNATURE_EBX: u32 = u32::from_le_bytes(*b"MATR");
pub const MATRIXHV_STATUS_SIGNATURE_ECX: u32 = u32::from_le_bytes(*b"IXHV");
pub const MATRIXHV_STATUS_PROTOCOL: u32 = 7;

// Version-three control buffers use the same C layout in UEFI and Neo.
const _: () = assert!(core::mem::size_of::<ControlRequest>() == 32);
const _: () = assert!(core::mem::align_of::<ControlRequest>() == 8);
const _: () = assert!(core::mem::size_of::<ControlProbeSnapshot>() == 272);
const _: () = assert!(core::mem::offset_of!(ControlStatus, probe_snapshot) == 344);
const _: () = assert!(core::mem::size_of::<ControlStatus>() == 616);
