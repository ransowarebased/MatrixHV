pub const CONTROL_PROBE_OPERATION: u32 = 3;
pub const CONTROL_VERSION: u32 = 4;
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
    pub update_status: [u64; 48],
    pub update_public_key: [u8; 32],
    pub update_abi: [u32; 6],
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
            update_status: [0; 48],
            update_public_key: [0; 32],
            update_abi: [0; 6],
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
// The resident L1 contract excludes legacy hardware task switching and SMX.
// Query this subleaf before booting a guest that requires either facility.
pub const MATRIXHV_GUEST_CONTRACT_SUBLEAF: u32 = 54;
pub const MATRIXHV_GUEST_CONTRACT_UNSUPPORTED: u32 = (1 << 0) | (1 << 1);

// Version-four control buffers append the runtime transaction and boot trust key.
const _: () = assert!(core::mem::size_of::<ControlRequest>() == 32);
const _: () = assert!(core::mem::align_of::<ControlRequest>() == 8);
const _: () = assert!(core::mem::size_of::<ControlProbeSnapshot>() == 272);
const _: () = assert!(core::mem::offset_of!(ControlStatus, probe_snapshot) == 344);
const _: () = assert!(core::mem::size_of::<ControlStatus>() == 1056);

// Memory packet fields are little-endian; offsets refer to the packet buffer.
pub mod memory {
    pub const ROOT_HISTORY_COUNT: usize = 16;
    pub const INFO_BYTES: usize = HEADER_BYTES + ROOT_HISTORY_COUNT * 8;
    pub const MEMORY_LEAF: u32 = 0x4d48_564d;
    pub const MEMORY_SIGNATURE: u32 = 0x4d45_4d31;
    pub const MEMORY_MAGIC: u64 = 0x4d48_564d_454d_3031;
    pub const MEMORY_VERSION: u32 = 1;
    pub const BUFFER_BYTES: usize = 65536;
    pub const MAX_ITEMS: usize = 128;
    pub const HEADER_BYTES: usize = 160;
    pub const ITEM_BYTES: usize = 24;
    pub const INFO: u32 = 0;
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    // A/D requests use GPA at 16 and page count at 32, without item descriptors.
    // Two LSB-first bitmaps follow the header: accessed, then dirty (one bit/4 KiB).
    // Response flags at 72 identify support and conservative large-page coverage.
    // Snapshots observe the shared L1 EPT without clearing bits or stopping CPUs.
    // Only readable identity-mapped WB leaves participate; hidden and MMIO pages are zero.
    pub const AD_BITMAP: u32 = 3;
    pub const AD_ENABLED: u32 = 1 << 0;
    pub const AD_LARGE_PAGE: u32 = 1 << 1;
    pub const AD_MAX_PAGES: usize = (BUFFER_BYTES - HEADER_BYTES) / 2 * 8;
    pub const AD_START: u32 = 4;
    pub const AD_STOP: u32 = 5;
    pub const AD_FETCH: u32 = 6;
    pub const AD_RELEASE: u32 = 7;
    pub const AD_STATUS: u32 = 8;
    pub const AD_ENUMERATE: u32 = 9;
    pub const AD_CANCEL: u32 = 10;
    // Token/T0/T1 occupy 80/88/96; state/count/pool usage occupy 104/108/112.
    // START carries (CR3, GVA) pairs. FETCH uses the first record index at 64.
    // ENUMERATE uses CR3 at 64 and GVA cursor at 16; returns the user limit at 72.
    pub const TRACK_MAX_PAGES: usize = 1024;
    pub const TRACK_TABLE_PAGES: usize = 2048;
    pub const TRACK_TARGET_BYTES: usize = 16;
    // Records: CR3, GVA, initial/current GPA, initial/current PTE fingerprint,
    // flags/status, initial/final SHA-256, and the frozen 4096-byte dirty page.
    pub const TRACK_RECORD_BYTES: usize = 4216;
    pub const TRACK_FETCH_PAGES: usize = (BUFFER_BYTES - HEADER_BYTES) / TRACK_RECORD_BYTES;
    pub const TRACK_ACCESSED: u32 = 1;
    pub const TRACK_DIRTY: u32 = 2;
    pub const TRACK_REMAPPED: u32 = 4;
    pub const TRACK_DUMP_VALID: u32 = 8;
    pub const TRACK_HASH_CHANGED: u32 = 16;
    pub const TRACK_IDLE: u32 = 0;
    pub const TRACK_ACTIVE: u32 = 1;
    pub const TRACK_STOPPED: u32 = 2;

    pub fn ad_bitmap_length(start: u64, page_count: usize) -> Result<usize, Error> {
        if start & 4095 != 0 || page_count == 0 || page_count > AD_MAX_PAGES {
            return Err(Error::Bounds);
        }
        let end = start
            .checked_add(page_count as u64 * 4096)
            .ok_or(Error::Bounds)?;
        if end > 1 << 48 {
            return Err(Error::Bounds);
        }
        Ok(HEADER_BYTES + 2 * page_count.div_ceil(8))
    }
    pub const ROAD_STATUS_DEMAND_ZERO: u32 = 0xe052_0001;

    #[derive(Clone, Copy, Default)]
    pub struct SoftPteLayout {
        pub transition: u64,
        pub prototype: u64,
        pub software_protection: u64,
        pub transition_protection: u64,
        pub transition_frame: u64,
        pub prototype_address: u64,
        pub prototype_read_only: u64,
        pub pagefile: u64,
        pub hardware_copy_on_write: u64,
        pub prototype_protection: u64,
    }

    impl SoftPteLayout {
        pub fn fields(self) -> [u64; 10] {
            [
                self.transition,
                self.prototype,
                self.software_protection,
                self.transition_protection,
                self.transition_frame,
                self.prototype_address,
                self.prototype_read_only,
                self.pagefile,
                self.hardware_copy_on_write,
                self.prototype_protection,
            ]
        }

        pub fn from_packet(bytes: &[u8]) -> Self {
            Self {
                transition: quad(bytes, 80),
                prototype: quad(bytes, 88),
                software_protection: quad(bytes, 96),
                transition_protection: quad(bytes, 104),
                transition_frame: quad(bytes, 112),
                prototype_address: quad(bytes, 120),
                prototype_read_only: quad(bytes, 128),
                pagefile: quad(bytes, 136),
                hardware_copy_on_write: quad(bytes, 144),
                prototype_protection: quad(bytes, 152),
            }
        }

        pub fn validate(self) -> bool {
            if self.fields().iter().all(|field| *field == 0) {
                return true;
            }
            let contiguous = |mask: u64| {
                if mask == 0 {
                    return false;
                }
                let shifted = mask >> mask.trailing_zeros();
                shifted == u64::MAX || shifted.wrapping_add(1).is_power_of_two()
            };
            self.transition.is_power_of_two()
                && self.prototype.is_power_of_two()
                && self.transition != self.prototype
                && (self.transition | self.prototype) & 1 == 0
                && self.hardware_copy_on_write.is_power_of_two()
                && self.prototype_read_only.is_power_of_two()
                && [
                    self.software_protection,
                    self.transition_protection,
                    self.prototype_protection,
                ]
                .iter()
                .all(|mask| contiguous(*mask) && mask.count_ones() == 5)
                && contiguous(self.transition_frame)
                && self.transition_frame.trailing_zeros() >= 12
                && contiguous(self.prototype_address)
                && self.prototype_address.count_ones() >= 48
                && self.pagefile != 0
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u32)]
    pub enum Error {
        Format = 1,
        Bounds = 2,
        Unmapped = 3,
        Permission = 4,
        Unsupported = 5,
        PrototypeUnresolved = 6,
        PagefileBacked = 7,
        CopyOnWrite = 8,
        DemandZeroWrite = 9,
        Busy = 10,
        Session = 11,
        Capacity = 12,
        Remapped = 13,
    }

    pub fn word(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    pub fn quad(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }
}
