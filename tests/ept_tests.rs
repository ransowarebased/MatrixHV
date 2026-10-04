#[cfg(test_harness = "core_audit")]
include!("core_audit_tests.rs");

#[cfg(test_harness = "cache")]
mod cache {
    include!("../builds/ept-cache-tests/definitions.rs");

    use core::arch::global_asm;

    global_asm!(include_str!("../builds/ept-cache-tests/ept-cache.S"));
    global_asm!(include_str!("../builds/ept-cache-tests/ept-transaction.S"));

    const PAGE_SIZE: usize = 4096;

    #[derive(Clone, Copy)]
    struct MemoryDescriptor {
        phys_start: u64,
        page_count: u64,
    }

    #[derive(Debug, PartialEq)]
    enum EptError {
        AddressOverflow,
    }

    unsafe extern "C" {
        fn test_cache_type(state: &MtrrState, address: u64, size: u64) -> u64;
        fn test_cache_update(state: &MtrrState, root: *mut u64, level: u32);
        fn test_cache_transaction(state: &mut CacheTransaction);
    }

    #[repr(C)]
    struct CacheTransaction {
        dirty: u64,
        hardware_cr0: u64,
        shadow_cr0: u64,
        rebuilds: u64,
    }

    #[test]
    fn mtrr_transaction_waits_for_guest_cache_enable_across_vm_exits() {
        let mut transaction = CacheTransaction {
            dirty: 1,
            hardware_cr0: 0x8000_0031,
            shadow_cr0: 0xe000_0031,
            rebuilds: 0,
        };
        // Each MTRR write exits with physical CD clear even while the guest reads CD set.
        for _ in 0..24 {
            unsafe { test_cache_transaction(&mut transaction) };
            assert_eq!(transaction.dirty, 1);
            assert_eq!(transaction.rebuilds, 0);
        }
        transaction.shadow_cr0 &= !(3 << 29);
        unsafe { test_cache_transaction(&mut transaction) };
        assert_eq!(transaction.dirty, 0);
        assert_eq!(transaction.rebuilds, 1);
        unsafe { test_cache_transaction(&mut transaction) };
        assert_eq!(transaction.rebuilds, 1);
    }

    #[test]
    fn clean_cache_transactions_never_rebuild() {
        for shadow_cr0 in [0x8000_0031, 0xe000_0031] {
            let mut transaction = CacheTransaction {
                dirty: 0,
                hardware_cr0: 0x8000_0031,
                shadow_cr0,
                rebuilds: 0,
            };
            unsafe { test_cache_transaction(&mut transaction) };
            assert_eq!(transaction.rebuilds, 0);
        }
    }

    fn state() -> MtrrState {
        MtrrState {
            capability: 0x108,
            default_type: 0x806,
            physical_mask: ((1_u64 << 40) - 1) & !0xfff,
            fixed_types: [0x0606_0606_0606_0606; 11],
            variable_ranges: [[0, 0]; 255],
        }
    }

    fn set_range(state: &mut MtrrState, index: usize, base: u64, size: u64, memory_type: u8) {
        state.variable_ranges[index] = [
            base | u64::from(memory_type),
            (state.physical_mask & !(size - 1)) | 0x800,
        ];
    }

    fn check(state: &MtrrState, address: u64, size: u64, expected: EptMemoryType) {
        assert_eq!(state.memory_type(address, size), expected);
        assert_eq!(
            unsafe { test_cache_type(state, address, size) },
            expected as u64
        );
    }

    #[test]
    fn disabled_mtrrs_force_uncacheable_and_default_is_respected() {
        let mut state = state();
        check(&state, 0x1000_0000, 4096, EptMemoryType::WriteBack);
        state.default_type = 6;
        check(&state, 0x1000_0000, 4096, EptMemoryType::Uncacheable);
        for (value, expected) in [
            (0, EptMemoryType::Uncacheable),
            (1, EptMemoryType::WriteCombining),
            (4, EptMemoryType::WriteThrough),
            (5, EptMemoryType::WriteProtected),
            (6, EptMemoryType::WriteBack),
            (7, EptMemoryType::Uncacheable),
        ] {
            state.default_type = 0x800 | value;
            check(&state, 0x4000_0000, 4096, expected);
        }
    }

    #[test]
    fn fixed_ranges_override_variables_at_every_boundary() {
        let mut state = state();
        state.default_type |= 0x400;
        set_range(&mut state, 0, 0, 0x20_0000, 0);
        for (index, value) in state.fixed_types.iter_mut().enumerate() {
            *value = if index % 2 == 0 {
                0x0605_0401_0006_0504
            } else {
                0x0001_0405_0600_0104
            };
        }
        for page in 0..256 {
            let address = page * 4096;
            let (register, byte) = if address < 0x80000 {
                (0, address / 0x10000)
            } else if address < 0xc0000 {
                (1 + (address - 0x80000) / 0x20000, (address / 0x4000) % 8)
            } else {
                (3 + (address - 0xc0000) / 0x8000, (address / 4096) % 8)
            };
            let expected =
                decode_memory_type((state.fixed_types[register as usize] >> (byte * 8)) as u8);
            check(&state, address, 4096, expected);
        }
        check(&state, 0x100000, 4096, EptMemoryType::Uncacheable);
    }

    #[test]
    fn variable_overlap_precedence_is_order_independent() {
        for types in [[6, 4], [4, 6], [6, 0], [0, 6], [1, 5], [5, 1], [5, 5]] {
            let mut state = state();
            set_range(&mut state, 0, 0x4000_0000, 0x4000_0000, types[0]);
            set_range(&mut state, 1, 0x4000_0000, 0x4000_0000, types[1]);
            let expected = match types {
                [6, 4] | [4, 6] => EptMemoryType::WriteThrough,
                [5, 5] => EptMemoryType::WriteProtected,
                _ => EptMemoryType::Uncacheable,
            };
            check(&state, 0x5000_0000, 0x20_0000, expected);
            check(&state, 0x8000_0000, 0x20_0000, EptMemoryType::WriteBack);
        }
    }

    #[test]
    fn partial_large_leaf_and_high_physical_addresses_are_safe() {
        let mut state = state();
        set_range(&mut state, 0, 0x10_0000_0000, 0x1000, 4);
        check(&state, 0x10_0000_0000, 4096, EptMemoryType::WriteThrough);
        check(
            &state,
            0x10_0000_0000,
            0x20_0000,
            EptMemoryType::Uncacheable,
        );
        check(&state, 0x10_0000_1000, 4096, EptMemoryType::WriteBack);
        state.variable_ranges[0][1] &= !0x800;
        check(&state, 0x10_0000_0000, 4096, EptMemoryType::WriteBack);
    }

    #[test]
    fn all_variable_slots_are_bounded_and_decoded() {
        let mut state = state();
        state.capability = 255;
        set_range(&mut state, 254, 0x2000_0000, 0x1000, 1);
        check(&state, 0x2000_0000, 4096, EptMemoryType::WriteCombining);
    }

    #[repr(C, align(4096))]
    struct Table([u64; 512]);

    #[test]
    fn cache_update_preserves_remaps_permissions_and_can_restore_write_back() {
        let mut state = state();
        let mut leaf = Box::new(Table([0; 512]));
        let mut directory = Box::new(Table([0; 512]));
        directory.0[0] = leaf.0.as_ptr() as u64 | 7;
        leaf.0[3] = 0x3000_0000 | (6 << 52) | (6 << 3) | 1;
        leaf.0[4] = 0x4000_0000 | 7;
        leaf.0[5] = 0x5000_0000 | (6 << 52) | (6 << 3); // Absent protected page.
        directory.0[1] = 0x6000_0000 | (6 << 52) | (6 << 3) | 0x87;
        let original = leaf.0;
        state.default_type = 0;
        unsafe { test_cache_update(&state, directory.0.as_mut_ptr(), 2) };
        assert_eq!(leaf.0[3], original[3] & !0x38);
        assert_eq!(leaf.0[4], original[4]);
        assert_eq!(leaf.0[5], original[5]);
        assert_eq!(directory.0[1], 0x6000_0000 | (6 << 52) | 0x87);
        state.default_type = 0x806;
        unsafe { test_cache_update(&state, directory.0.as_mut_ptr(), 2) };
        assert_eq!(leaf.0, original);
        assert_eq!(directory.0[1], 0x6000_0000 | (6 << 52) | (6 << 3) | 0x87);
        for firmware in [
            EptMemoryType::Uncacheable,
            EptMemoryType::WriteCombining,
            EptMemoryType::WriteThrough,
            EptMemoryType::WriteProtected,
            EptMemoryType::WriteBack,
        ] {
            assert_eq!(
                combine_memory_types(firmware, EptMemoryType::Uncacheable),
                EptMemoryType::Uncacheable
            );
            assert_eq!(
                combine_memory_types(firmware, EptMemoryType::WriteBack),
                firmware
            );
        }
    }

    #[test]
    fn sparse_mapping_skips_terabyte_holes_without_losing_boundary_pages() {
        let descriptors = [
            MemoryDescriptor {
                phys_start: 0,
                page_count: 1024,
            },
            MemoryDescriptor {
                phys_start: 0x100_0000_1000,
                page_count: 1,
            },
        ];
        let mut cursor = 0;
        assert_eq!(next_mapped_chunk(&descriptors, &mut cursor, 0).unwrap(), 0);
        assert_eq!(
            next_mapped_chunk(&descriptors, &mut cursor, 0x1_0000_0000).unwrap(),
            0x100_0000_0000
        );
        assert_eq!(cursor, 1);
        assert_eq!(
            next_mapped_chunk(&descriptors, &mut cursor, 0x100_0020_0000).unwrap(),
            EPT_GUEST_PHYSICAL_LIMIT
        );
        let invalid = [MemoryDescriptor {
            phys_start: u64::MAX - 4095,
            page_count: 1,
        }];
        assert_eq!(
            next_mapped_chunk(&invalid, &mut 0, 0x1_0000_0000),
            Err(EptError::AddressOverflow)
        );
    }

    #[test]
    fn high_address_coverage_includes_relocated_pci_bar() {
        let firmware_bar_end = 0x4000_11c000;
        let relocated_audio_bar = 0x7fff_efcd08;
        let end = high_address_mapping_end(firmware_bar_end, 39).unwrap();
        assert_eq!(end, EPT_512GB_PAGE_SIZE);
        assert!(relocated_audio_bar >= firmware_bar_end);
        assert!(relocated_audio_bar < end);
        assert_eq!(
            high_address_mapping_end(firmware_bar_end, 36).unwrap(),
            1 << 36
        );
        assert_eq!(
            high_address_mapping_end(EPT_512GB_PAGE_SIZE + 1, 48).unwrap(),
            EPT_512GB_PAGE_SIZE + EPT_1GB_PAGE_SIZE
        );
    }
}

#[cfg(test_harness = "high")]
mod high {
    include!("../builds/ept-cache-tests/high-definitions.rs");

    #[derive(Debug, PartialEq)]
    enum EptError {
        AddressOverflow,
        InvalidPageTable,
    }

    #[repr(align(4096))]
    struct AlignedTable([u64; EPT_ENTRY_COUNT]);

    #[derive(Clone, Copy)]
    struct TablePage {
        physical_address: u64,
        entries: NonNull<u64>,
    }

    struct IdentityEpt {
        pages: Vec<Box<AlignedTable>>,
        root: TablePage,
        mapped_end: u64,
        large_pages_supported: bool,
    }

    mod arch {
        use std::cell::Cell;
        pub struct Leaf {
            pub eax: u32,
        }

        pub fn leaf(_selector: u32) -> Leaf {
            Leaf { eax: 39 }
        }

        pub const IA32_VMX_EPT_VPID_CAP: u32 = 0x48c;

        thread_local! {
            static CAPABILITIES: Cell<u64> = const { Cell::new(1 << 17) };
        }

        pub unsafe fn read_msr(_register: u32) -> u64 {
            CAPABILITIES.with(Cell::get)
        }

        pub fn set_capabilities(capabilities: u64) {
            CAPABILITIES.with(|value| value.set(capabilities));
        }
    }

    fn allocate_table(pages: &mut Vec<Box<AlignedTable>>) -> Result<TablePage, EptError> {
        let mut table = Box::new(AlignedTable([0; EPT_ENTRY_COUNT]));
        let entries = NonNull::new(table.0.as_mut_ptr()).unwrap();
        let physical_address = entries.as_ptr() as u64;
        pages.push(table);
        Ok(TablePage {
            physical_address,
            entries,
        })
    }

    #[test]
    fn table_access_rejects_out_of_bounds_indices_in_every_build_profile() {
        let mut pages = Vec::new();
        let table = allocate_table(&mut pages).unwrap();
        write_entry(table, 0, 0x1234);
        write_entry(table, EPT_ENTRY_COUNT - 1, 0x5678);
        for index in [EPT_ENTRY_COUNT, usize::MAX] {
            assert!(std::panic::catch_unwind(|| read_entry(table, index)).is_err());
            assert!(std::panic::catch_unwind(|| write_entry(table, index, 0)).is_err());
        }
        assert_eq!(read_entry(table, 0), 0x1234);
        assert_eq!(read_entry(table, EPT_ENTRY_COUNT - 1), 0x5678);
    }

    #[test]
    fn relocated_pci_bar_is_uc_without_replacing_ram_or_firmware_bar() {
        assert_eq!(
            [
                EptMemoryType::WriteCombining as u64,
                EptMemoryType::WriteThrough as u64,
                EptMemoryType::WriteProtected as u64,
            ],
            [1, 4, 5]
        );
        let mut pages = Vec::new();
        let root = allocate_table(&mut pages).unwrap();
        let pdpt = allocate_table(&mut pages).unwrap();
        write_entry(root, 0, table_entry(pdpt.physical_address));

        let ram_pd = allocate_table(&mut pages).unwrap();
        let ram_leaf = leaf_entry(
            EPT_MINIMUM_MAPPED_END,
            EptMemoryType::WriteBack,
            EptMemoryType::WriteBack,
        ) | EPT_LARGE_PAGE;
        write_entry(pdpt, 4, table_entry(ram_pd.physical_address));
        write_entry(ram_pd, 0, ram_leaf);

        let pci_pd = allocate_table(&mut pages).unwrap();
        let firmware_bar_address = 0x4000_000000;
        let pci_leaf = leaf_entry(
            firmware_bar_address,
            EptMemoryType::Uncacheable,
            EptMemoryType::Uncacheable,
        ) | EPT_LARGE_PAGE;
        write_entry(pdpt, 256, table_entry(pci_pd.physical_address));
        write_entry(pci_pd, 0, pci_leaf);

        let mut ept = IdentityEpt {
            pages,
            root,
            mapped_end: 0x4000_11c000,
            large_pages_supported: true,
        };
        assert_eq!(ept.map_high_address_gaps().unwrap(), EPT_512GB_PAGE_SIZE);
        let pdpt = table_from_entry(read_entry(ept.root, 0)).unwrap();
        assert_eq!(read_entry(pdpt, 3), 0);
        assert_eq!(read_entry(ram_pd, 0), ram_leaf);
        assert_eq!(read_entry(pci_pd, 0), pci_leaf);
        assert_eq!(
            read_entry(pci_pd, 1) & (EPT_PERMISSIONS | EPT_LARGE_PAGE),
            EPT_PERMISSIONS | EPT_LARGE_PAGE
        );

        let relocated_audio_bar = 0x7fff_efcd08;
        let pdpt_index = (relocated_audio_bar / EPT_1GB_PAGE_SIZE) as usize;
        let entry = read_entry(pdpt, pdpt_index);
        assert_eq!(pdpt_index, 511);
        assert_eq!(
            entry & (EPT_PERMISSIONS | EPT_LARGE_PAGE),
            EPT_PERMISSIONS | EPT_LARGE_PAGE
        );
        assert_eq!(
            (entry >> EPT_MEMORY_TYPE_SHIFT) & 7,
            EptMemoryType::Uncacheable as u64
        );
        assert_eq!(
            entry & EPT_ADDRESS_MASK & !(EPT_1GB_PAGE_SIZE - 1),
            511 * EPT_1GB_PAGE_SIZE
        );
        assert_eq!(ept.mapped_end, EPT_512GB_PAGE_SIZE);
    }

    #[test]
    fn two_megabyte_fallback_covers_high_pci_space() {
        arch::set_capabilities(0);
        let mut pages = Vec::new();
        let root = allocate_table(&mut pages).unwrap();
        let mut ept = IdentityEpt {
            pages,
            root,
            mapped_end: EPT_MINIMUM_MAPPED_END,
            large_pages_supported: true,
        };
        assert_eq!(ept.map_high_address_gaps().unwrap(), EPT_512GB_PAGE_SIZE);
        let pdpt = table_from_entry(read_entry(root, 0)).unwrap();
        let pd = table_from_entry(read_entry(pdpt, 511)).unwrap();
        let entry = read_entry(pd, 511);
        assert_eq!(
            entry & (EPT_PERMISSIONS | EPT_LARGE_PAGE),
            EPT_PERMISSIONS | EPT_LARGE_PAGE
        );
        assert_eq!(
            (entry >> EPT_MEMORY_TYPE_SHIFT) & 7,
            EptMemoryType::Uncacheable as u64
        );
        assert_eq!(
            entry & EPT_ADDRESS_MASK & !(EPT_2MB_PAGE_SIZE - 1),
            EPT_512GB_PAGE_SIZE - EPT_2MB_PAGE_SIZE
        );
    }
}

#[cfg(test_harness = "pci_bar")]
mod pci_bar {
    include!("../builds/pci-bar-tests/definitions.rs");

    fn descriptor(start: u64, length: u64, resource_type: u8) -> [u8; PCI_BAR_DESCRIPTOR_SIZE] {
        let mut bytes = [0_u8; PCI_BAR_DESCRIPTOR_SIZE];
        bytes[0] = 0x8a;
        bytes[1..3].copy_from_slice(&0x2b_u16.to_le_bytes());
        bytes[3] = resource_type;
        bytes[14..22].copy_from_slice(&start.to_le_bytes());
        bytes[38..46].copy_from_slice(&length.to_le_bytes());
        bytes
    }

    #[test]
    fn high_usb_controller_bar_covers_observed_fault_address() {
        let bytes = descriptor(0x4000_100000, 0x10000, 0);
        let range = read_pci_bar_range(bytes.as_ptr()).unwrap().unwrap();
        assert_eq!(range, (0x4000_100000, 0x4000_110000));
        assert!(range.0 <= 0x4000_100084 && 0x4000_100084 < range.1);
    }

    #[test]
    fn ignores_io_and_unassigned_bars() {
        let io = descriptor(0x4000_100000, 0x10000, 1);
        assert_eq!(read_pci_bar_range(io.as_ptr()), Ok(None));
        let unassigned = descriptor(0x4000_100000, 0, 0);
        assert_eq!(read_pci_bar_range(unassigned.as_ptr()), Ok(None));
    }

    #[test]
    fn rejects_out_of_range_physical_addresses() {
        let overflow = descriptor(u64::MAX - 15, 32, 0);
        assert_eq!(
            read_pci_bar_range(overflow.as_ptr()),
            Err(EptError::AddressOverflow)
        );
        let too_wide = descriptor(EPT_GUEST_PHYSICAL_LIMIT - 0x1000, 0x2000, 0);
        assert_eq!(
            read_pci_bar_range(too_wide.as_ptr()),
            Err(EptError::GuestPhysicalAddressTooWide(
                EPT_GUEST_PHYSICAL_LIMIT + 0x1000
            ))
        );
    }
}

#[cfg(test_harness = "sync")]
mod sync {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    static SERIAL: Mutex<()> = Mutex::new(());

    #[repr(C)]
    struct Profile { active: AtomicU64, cause: AtomicU64 }
    impl Profile {
        fn new() -> Self {
            Self {
                active: AtomicU64::new(1),
                cause: AtomicU64::new(0),
            }
        }
    }

    #[repr(C)]
    struct Event {
        cpus: [u64; 64],
        interception: u64,
    }

    #[repr(C)]
    struct Context {
        event: u64,
        ack: AtomicU64,
        safe: AtomicU64,
        pending_nmi: AtomicU64,
        reason: AtomicU64,
        exit_info: AtomicU64,
        apic_id: u64,
        guest_nmi: AtomicU64,
        apic_base: AtomicU64,
        sends: AtomicU64,
        destination: AtomicU64,
        icr: AtomicU64,
        fail_send: AtomicU64,
        consume_failed_token: AtomicU64,
        l2_active: u64,
        native_enabled: AtomicU64,
        admission: AtomicU64,
        shadow_list: u64,
        initialized: u64,
        ept01: u64,
        captures: AtomicU64,
        invalidations: AtomicU64,
        swaps: AtomicU64,
        flushes: AtomicU64,
        cache_ept: u64,
        flushed_ept: AtomicU64,
        sync_diagnostics: [AtomicU64; 8],
        processor: AtomicU64,
        tsc_hz: u64,
        runtime_diagnostics: [AtomicU64; 24],
        timer_pin: AtomicU64,
        timer_value: AtomicU64,
        timer_supported: AtomicU64,
        revocations: AtomicU64,
        clock_enabled: AtomicU64,
        clock_ticks: AtomicU64,
        clock_step: AtomicU64,
        cancel_on_send: AtomicU64,
    }

    impl Context {
        fn new(event: &Event, l2_active: bool) -> Self {
            Self {
                event: event as *const Event as u64,
                ack: AtomicU64::new(0),
                safe: AtomicU64::new(0),
                pending_nmi: AtomicU64::new(0),
                reason: AtomicU64::new(0),
                exit_info: AtomicU64::new(0),
                apic_id: 0,
                guest_nmi: AtomicU64::new(0),
                apic_base: AtomicU64::new(0xc00),
                sends: AtomicU64::new(0),
                destination: AtomicU64::new(0),
                icr: AtomicU64::new(0),
                fail_send: AtomicU64::new(0),
                consume_failed_token: AtomicU64::new(0),
                l2_active: u64::from(l2_active),
                native_enabled: AtomicU64::new(1),
                admission: AtomicU64::new(1),
                shadow_list: 0,
                initialized: 1,
                ept01: 0x101e,
                captures: AtomicU64::new(0),
                invalidations: AtomicU64::new(0),
                swaps: AtomicU64::new(0),
                flushes: AtomicU64::new(0),
                cache_ept: 0x205e,
                flushed_ept: AtomicU64::new(0),
                sync_diagnostics: std::array::from_fn(|_| AtomicU64::new(0)),
                processor: AtomicU64::new(0),
                tsc_hz: 1_000_000_000,
                runtime_diagnostics: std::array::from_fn(|_| AtomicU64::new(0)),
                timer_pin: AtomicU64::new(0),
                timer_value: AtomicU64::new(77),
                timer_supported: AtomicU64::new(0),
                revocations: AtomicU64::new(0),
                clock_enabled: AtomicU64::new(0),
                clock_ticks: AtomicU64::new(1),
                clock_step: AtomicU64::new(1),
                cancel_on_send: AtomicU64::new(0),
            }
        }
    }

    core::arch::global_asm!(
        ".text",
        ".macro test_sync_wrapper name, target, reset=1",
        ".globl \\name",
        "\\name:",
        "push rbx", "push rbp", "push rsi", "push rdi",
        "push r12", "push r13", "push r14", "push r15",
        "mov r12, rcx", "cld", "push rdx",
        ".if \\reset", "call .Lresident_nested_eptp_sync_budget_start", ".endif",
        "pop rdx", "call \\target",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop rdi", "pop rsi", "pop rbp", "pop rbx", "ret",
        ".endm",
        "test_sync_wrapper sync_begin, .Lresident_nested_eptp_sync_begin",
        "test_sync_wrapper sync_acquire, .Lresident_nested_eptp_sync_acquire",
        "test_sync_wrapper sync_ready, .Lresident_nested_eptp_sync_ready",
        "test_sync_wrapper sync_end, .Lresident_nested_eptp_sync_end",
        "test_sync_wrapper sync_poll, .Lresident_nested_eptp_sync_poll",
        "test_sync_wrapper sync_poll_retained, .Lresident_nested_eptp_sync_poll, 0",
        "test_sync_wrapper sync_budget_check, .Lresident_nested_eptp_sync_budget_expired, 0",
        "test_sync_wrapper sync_enter, .Lresident_nested_eptp_sync_enter",
        "test_sync_wrapper sync_host_nmi, .Lresident_nested_eptp_sync_host_nmi",
        "test_sync_wrapper sync_host_nmi_retained, .Lresident_nested_eptp_sync_host_nmi, 0",
        "test_sync_wrapper sync_exit_nmi, .Lresident_nested_eptp_sync_exit_nmi",
        "test_sync_wrapper sync_kick, .Lresident_nested_eptp_sync_kick",
        "test_sync_wrapper sync_stall, .Ltest_read_stall",
        ".globl sync_reset",
        "sync_reset:", "push rdi", "cld", "xor eax, eax",
        "lea rdi, [rip + .Lresident_eptp_sync_owner]",
        "lea rcx, [rip + .Lresident_eptp_lists_live + 8]",
        "sub rcx, rdi", "shr rcx, 3",
        "rep stosq", "pop rdi", "ret",
        ".Ltest_read_stall:", "mov rax, [r12 + {b_processor_number}]", "shl rax, 6",
        "lea r9, [rip + .Lresident_interception_stall_records]", "add r9, rax",
        "mov rax, [r9 + rdx * 8]", "ret",
        ".Lresident_guarded_rdmsr:",
        "cmp ecx, 0x1b", "je .Ltest_read_apic",
        "cmp ecx, 0x480", "je .Ltest_read_basic",
        "cmp ecx, 0x485", "je .Ltest_read_misc",
        "xor eax, eax", "mov rdx, [r12 + {test_timer_supported}]", "shl rdx, 6", "clc", "ret",
        ".Ltest_read_basic:", "xor eax, eax", "mov edx, 0x800000", "clc", "ret",
        ".Ltest_read_misc:", "mov eax, 5", "xor edx, edx", "clc", "ret",
        ".Ltest_read_apic:",
        "mov rax, qword ptr [r12 + {test_apic_base}]",
        "mov rdx, rax", "shr rdx, 32", "mov eax, eax", "clc", "ret",
        ".Lresident_guarded_wrmsr:",
        "cmp qword ptr [r12 + {test_fail_send}], 0", "jne .Ltest_send_failed",
        "inc qword ptr [r12 + {test_sends}]",
        "mov qword ptr [r12 + {test_destination}], rdx",
        "mov qword ptr [r12 + {test_icr}], rax",
        "cmp qword ptr [r12 + {test_cancel_on_send}], 0", "je .Ltest_send_done",
        "mov rax, [rip + .Lresident_eptp_sync_epoch]",
        "mov [rip + .Lresident_eptp_sync_failure], rax",
        ".Ltest_send_done:", "clc", "ret",
        ".Ltest_send_failed:",
        "cmp qword ptr [r12 + {test_consume_failed_token}], 0",
        "je .Ltest_send_failed_return",
        "mov qword ptr [r14 + {b_nested_eptp_sync_nmi}], 0",
        ".Ltest_send_failed_return:", "stc", "ret",
        ".Lresident_ept01_host_page_is_mapped:", "mov eax, 1", "ret",
        ".Lresident_nested_capture_native_eptp:",
        "inc qword ptr [r12 + {test_captures}]", "ret",
        ".Lresident_nested_invalidate_ept02:",
        "inc qword ptr [r12 + {test_invalidations}]", "ret",
        ".Lresident_nested_swap_ept02_cache:",
        "inc qword ptr [r12 + {test_swaps}]", "ret",
        ".Lresident_dispatch_halt:", ".Lresident_dispatch_vmread_failed:", "ud2",
        ".Ltest_interception_callback:", "cmp edx, 2", "jne .Ltest_callback_return",
        "inc qword ptr [r12 + {test_revocations}]",
        ".Ltest_callback_return:", "xor eax, eax", "ret",
        include_str!("../builds/eptp-sync-tests/eptp-sync.S"),
        b_processor_number = const std::mem::offset_of!(Context, processor),
        b_watchdog_tsc_hz = const std::mem::offset_of!(Context, tsc_hz),
        b_interception_runtime_diagnostics = const std::mem::offset_of!(Context, runtime_diagnostics),
        b_last_guest_rip = const std::mem::offset_of!(Context, reason),
        b_last_guest_physical_address = const std::mem::offset_of!(Context, exit_info),
        event_interception_context = const std::mem::offset_of!(Event, interception),
        interception_cause = const std::mem::offset_of!(Profile, cause),
        interception_rendezvous_cause = const 3,
        pin_based_vm_exec_control = const 0,
        vmx_preemption_timer_value = const 1,
        test_timer_pin = const std::mem::offset_of!(Context, timer_pin),
        test_timer_supported = const std::mem::offset_of!(Context, timer_supported),
        test_revocations = const std::mem::offset_of!(Context, revocations),
        test_clock_enabled = const std::mem::offset_of!(Context, clock_enabled),
        test_clock_ticks = const std::mem::offset_of!(Context, clock_ticks),
        test_clock_step = const std::mem::offset_of!(Context, clock_step),
        test_cancel_on_send = const std::mem::offset_of!(Context, cancel_on_send),
        b_interception_step = const std::mem::offset_of!(Context, revocations),
        b_event_context = const std::mem::offset_of!(Context, event),
        b_interception_sync_diagnostics = const std::mem::offset_of!(Context, sync_diagnostics),
        event_cpu_contexts = const std::mem::offset_of!(Event, cpus),
        b_nested_eptp_sync_ack = const std::mem::offset_of!(Context, ack),
        b_nested_eptp_sync_safe = const std::mem::offset_of!(Context, safe),
        b_nested_eptp_sync_nmi = const std::mem::offset_of!(Context, pending_nmi),
        b_last_reason = const std::mem::offset_of!(Context, reason),
        exit_intr_info = const 0,
        test_exit_info = const std::mem::offset_of!(Context, exit_info),
        b_nested_eptp_sync_apic_id = const std::mem::offset_of!(Context, apic_id),
        b_nmi_pending = const std::mem::offset_of!(Context, guest_nmi),
        apic_base_msr = const 0x1b,
        host_page_address_mask = const 0x000f_ffff_ffff_f000u64,
        test_apic_base = const std::mem::offset_of!(Context, apic_base),
        test_sends = const std::mem::offset_of!(Context, sends),
        test_destination = const std::mem::offset_of!(Context, destination),
        test_icr = const std::mem::offset_of!(Context, icr),
        test_fail_send = const std::mem::offset_of!(Context, fail_send),
        test_consume_failed_token = const std::mem::offset_of!(Context, consume_failed_token),
        b_nested_l2_active = const std::mem::offset_of!(Context, l2_active),
        b_nested_eptp_native_enabled = const std::mem::offset_of!(Context, native_enabled),
        b_nested_eptp_admission = const std::mem::offset_of!(Context, admission),
        b_nested_eptp_shadow_list = const std::mem::offset_of!(Context, shadow_list),
        b_nested_ept02_cache_initialized = const std::mem::offset_of!(Context, initialized),
        b_cache_ept_pointer = const std::mem::offset_of!(Context, cache_ept),
        test_captures = const std::mem::offset_of!(Context, captures),
        test_invalidations = const std::mem::offset_of!(Context, invalidations),
        test_swaps = const std::mem::offset_of!(Context, swaps),
        test_flushes = const std::mem::offset_of!(Context, flushes),
        test_flushed_ept = const std::mem::offset_of!(Context, flushed_ept),
    );

    unsafe extern "win64" {
        fn sync_reset();
        fn tracking_sync(context: *const Context, operation: u64) -> u64;
        fn sync_begin(context: *const Context) -> u64;
        fn sync_acquire(context: *const Context) -> u64;
        fn sync_ready(context: *const Context) -> u64;
        fn sync_end(context: *const Context);
        fn sync_poll(context: *const Context);
        fn sync_poll_retained(context: *const Context);
        fn sync_budget_check(context: *const Context) -> u64;
        fn sync_enter(context: *const Context);
        fn sync_host_nmi(context: *const Context) -> u64;
        fn sync_host_nmi_retained(context: *const Context) -> u64;
        fn sync_exit_nmi(context: *const Context) -> u64;
        fn sync_kick(context: *const Context) -> u64;
        fn sync_stall(context: *const Context, index: u64) -> u64;
    }

    fn isolate() -> std::sync::MutexGuard<'static, ()> {
        let serial = SERIAL.lock().unwrap();
        // Each fixture models a fresh resident instance, including assembly state.
        // Keep the lock until all scoped peers have returned before another reset.
        unsafe { sync_reset() };
        serial
    }

    #[test]
    fn tracking_callback_acquires_flushes_and_releases_the_shared_barrier() {
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let owner = Box::new(Context::new(&event, false));
        let mut peer = Box::new(Context::new(&event, true));
        peer.ept01 = 0;
        event.cpus[0] = &*owner as *const Context as u64;
        owner.processor.store(0, Ordering::Release);
        event.cpus[1] = &*peer as *const Context as u64;
        peer.processor.store(1, Ordering::Release);
        let returned = AtomicU64::new(0);
        thread::scope(|scope| {
            scope.spawn(|| {
                assert!(until(|| peer.pending_nmi.load(Ordering::Acquire) != 0));
                unsafe { sync_poll(&*peer) };
                returned.store(1, Ordering::Release);
            });
            let acquired = unsafe { tracking_sync(&*owner, 0) };
            let early_return = returned.load(Ordering::Acquire);
            if acquired == 1 {
                assert_eq!(unsafe { tracking_sync(&*owner, 1) }, 1);
                assert_eq!(unsafe { tracking_sync(&*owner, 2) }, 1);
            }
            assert_eq!(acquired, 1);
            assert_eq!(early_return, 0);
            assert_eq!(owner.flushes.load(Ordering::Acquire), 1);
        });
        assert_eq!(returned.load(Ordering::Acquire), 1);
        assert_eq!(peer.flushes.load(Ordering::Acquire), 1);
        assert_eq!(peer.invalidations.load(Ordering::Acquire), 2);
        assert_eq!(owner.flushed_ept.load(Ordering::Acquire), owner.cache_ept);
        assert_eq!(peer.flushed_ept.load(Ordering::Acquire), peer.cache_ept);
        event.cpus[1] = 0;
        assert_eq!(unsafe { tracking_sync(&*owner, 0) }, 1);
        assert_eq!(unsafe { tracking_sync(&*owner, 2) }, 1);
    }

    fn until(mut condition: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            if Instant::now() >= deadline {
                return false;
            }
            thread::yield_now();
        }
        true
    }

    #[test]
    fn peers_park_until_release_then_retire_both_roots_and_local_translations() {
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let owner = Box::new(Context::new(&event, false));
        let peer = Box::new(Context::new(&event, true));
        event.cpus[0] = &*owner as *const Context as u64;
        owner.processor.store(0, Ordering::Release);
        event.cpus[63] = &*peer as *const Context as u64;
        peer.processor.store(63, Ordering::Release);
        for epoch in 0..100 {
            assert_eq!(unsafe { sync_begin(&*owner) }, 1);
            assert_eq!(unsafe { sync_begin(&*peer) }, 0);
            assert_eq!(unsafe { sync_ready(&*owner) }, 0, "stale acknowledgement");
            let returned = AtomicU64::new(0);
            thread::scope(|scope| {
                scope.spawn(|| {
                    unsafe { sync_poll(&*peer) };
                    returned.store(1, Ordering::Release);
                });
                let ready = until(|| unsafe { sync_ready(&*owner) } == 1);
                let early_return = returned.load(Ordering::Acquire);
                let captures = peer.captures.load(Ordering::Acquire);
                // Always release before asserting, so a failed test cannot strand a peer.
                unsafe { sync_end(&*owner) };
                assert!(ready);
                assert_eq!(early_return, 0);
                assert_eq!(captures, epoch + 1);
            });
            assert_eq!(returned.load(Ordering::Acquire), 1);
            assert_eq!(peer.native_enabled.load(Ordering::Acquire), 0);
            assert_eq!(peer.invalidations.load(Ordering::Acquire), 2 * (epoch + 1));
            assert_eq!(peer.swaps.load(Ordering::Acquire), 2 * (epoch + 1));
            assert_eq!(peer.flushes.load(Ordering::Acquire), epoch + 1);
        }
    }

    #[test]
    fn idle_and_owner_gates_do_not_invalidate_or_wait() {
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let owner = Box::new(Context::new(&event, false));
        event.cpus[3] = &*owner as *const Context as u64;
        owner.processor.store(3, Ordering::Release);
        unsafe { sync_poll(&*owner) };
        assert_eq!(unsafe { sync_begin(&*owner) }, 1);
        assert_eq!(unsafe { sync_ready(&*owner) }, 1);
        unsafe { sync_poll(&*owner) };
        unsafe { sync_end(&*owner) };
        assert_ne!(owner.ack.load(Ordering::Acquire), 0);
        assert_eq!(owner.flushes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn cancellation_and_immediate_reacquisition_require_fresh_peer_acknowledgements() {
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let owner = Box::new(Context::new(&event, false));
        let peers = [Context::new(&event, false), Context::new(&event, true)];
        event.cpus[0] = &*owner as *const Context as u64;
        owner.processor.store(0, Ordering::Release);
        for (index, peer) in peers.iter().enumerate() {
            event.cpus[index + 1] = peer as *const Context as u64;
            peer.processor.store((index + 1) as u64, Ordering::Release);
        }
        let stop = AtomicU64::new(0);
        let returns = [AtomicU64::new(0), AtomicU64::new(0)];
        thread::scope(|scope| {
            for (index, peer) in peers.iter().enumerate() {
                let stop = &stop;
                let count = &returns[index];
                scope.spawn(move || {
                    while stop.load(Ordering::Acquire) == 0 {
                        unsafe { sync_poll(peer) };
                        count.fetch_add(1, Ordering::Release);
                    }
                });
            }
            let mut passed = true;
            for _ in 0..1000 {
                assert_eq!(unsafe { sync_begin(&*owner) }, 1);
                unsafe { sync_end(&*owner) };
                assert_eq!(unsafe { sync_begin(&*owner) }, 1);
                if !until(|| unsafe { sync_ready(&*owner) } == 1) {
                    unsafe { sync_end(&*owner) };
                    passed = false;
                    break;
                }
                let before = returns
                    .each_ref()
                    .map(|value| value.load(Ordering::Acquire));
                for _ in 0..32 {
                    std::hint::spin_loop();
                }
                let after = returns
                    .each_ref()
                    .map(|value| value.load(Ordering::Acquire));
                unsafe { sync_end(&*owner) };
                if before != after {
                    passed = false;
                    break;
                }
            }
            stop.store(1, Ordering::Release);
            assert!(
                passed,
                "A peer returned while a later synchronization owned the gate"
            );
        });
    }

    #[test]
    fn nmi_parks_in_the_entry_window_and_defers_when_a_root_handler_is_busy() {
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let owner = Box::new(Context::new(&event, false));
        let peer = Box::new(Context::new(&event, true));
        event.cpus[0] = &*owner as *const Context as u64;
        owner.processor.store(0, Ordering::Release);
        event.cpus[1] = &*peer as *const Context as u64;
        peer.processor.store(1, Ordering::Release);
        for safe in [0, 1] {
            peer.safe.store(safe, Ordering::Release);
            peer.pending_nmi.store(1, Ordering::Release);
            assert_eq!(unsafe { sync_begin(&*owner) }, 1);
            if safe == 0 {
                assert_eq!(unsafe { sync_host_nmi(&*peer) }, 1);
                assert_eq!(peer.pending_nmi.load(Ordering::Acquire), 0);
                assert_eq!(unsafe { sync_ready(&*owner) }, 0);
            }
            let returned = AtomicU64::new(0);
            thread::scope(|scope| {
                scope.spawn(|| {
                    if safe == 0 {
                        unsafe { sync_enter(&*peer) };
                    } else {
                        assert_eq!(unsafe { sync_host_nmi(&*peer) }, 1);
                    }
                    returned.store(1, Ordering::Release);
                });
                let ready = until(|| unsafe { sync_ready(&*owner) } == 1);
                let early_return = returned.load(Ordering::Acquire);
                unsafe { sync_end(&*owner) };
                assert!(ready);
                assert_eq!(early_return, 0);
            });
            assert_eq!(peer.safe.load(Ordering::Acquire), 1);
            assert_eq!(peer.pending_nmi.load(Ordering::Acquire), 0);
            assert_eq!(unsafe { sync_host_nmi(&*peer) }, 0);
        }
    }

    #[test]
    fn only_a_valid_nmi_exit_consumes_the_internal_token() {
        let _serial = isolate();
        let profile = Profile::new();
        let event = Event { cpus: [0; 64], interception: &profile as *const _ as u64 };
        let peer = Context::new(&event, true);
        for (reason, info, consumed) in [
            (10, 0x80000202, 0),
            (0x80000000, 0x80000202, 0),
            (0, 0x202, 0),
            (0, 0x8000030e, 0),
            (0, 0x80000306, 0),
            (0, 0x80000002, 0),
            (0, 0x80000202, 1),
        ] {
            peer.reason.store(reason, Ordering::Release);
            peer.exit_info.store(info, Ordering::Release);
            peer.pending_nmi.store(1, Ordering::Release);
            assert_eq!(unsafe { sync_exit_nmi(&peer) }, consumed);
            assert_eq!(peer.pending_nmi.load(Ordering::Acquire), 1 - consumed);
        }
        assert_eq!(unsafe { sync_exit_nmi(&peer) }, 0);
    }

    #[test]
    fn x2apic_kicks_use_full_destinations_and_preserve_external_nmis_on_send_failure() {
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let owner = Box::new(Context::new(&event, false));
        let mut peer = Box::new(Context::new(&event, true));
        peer.apic_id = 0x12345678;
        event.cpus[0] = &*owner as *const Context as u64;
        owner.processor.store(0, Ordering::Release);
        event.cpus[63] = &*peer as *const Context as u64;
        peer.processor.store(63, Ordering::Release);
        assert_eq!(unsafe { sync_begin(&*owner) }, 1);
        let first = unsafe { sync_kick(&*owner) };
        let second = unsafe { sync_kick(&*owner) };
        unsafe { sync_end(&*owner) };
        assert_eq!((first, second), (1, 1));
        assert_eq!(owner.sends.load(Ordering::Acquire), 1);
        assert_eq!(owner.destination.load(Ordering::Acquire), peer.apic_id);
        assert_eq!(owner.icr.load(Ordering::Acquire), 0x4400);
        assert_eq!(peer.pending_nmi.load(Ordering::Acquire), 1);

        owner.fail_send.store(1, Ordering::Release);
        for consumed in [0, 1] {
            peer.pending_nmi.store(0, Ordering::Release);
            owner
                .consume_failed_token
                .store(consumed, Ordering::Release);
            assert_eq!(unsafe { sync_begin(&*owner) }, 1);
            let result = unsafe { sync_kick(&*owner) };
            unsafe { sync_end(&*owner) };
            assert_eq!(result, 0);
            assert_eq!(peer.pending_nmi.load(Ordering::Acquire), 0);
            assert_eq!(peer.guest_nmi.load(Ordering::Acquire), consumed);
        }
    }

    #[test]
    fn xapic_kicks_validate_destination_and_wait_for_an_idle_icr() {
        #[repr(C, align(4096))]
        struct ApicPage([u32; 1024]);
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let owner = Box::new(Context::new(&event, false));
        let mut peer = Box::new(Context::new(&event, true));
        let mut apic = Box::new(ApicPage([0; 1024]));
        owner.apic_base.store(
            (&*apic as *const ApicPage as u64) | 0x800,
            Ordering::Release,
        );
        event.cpus[0] = &*owner as *const Context as u64;
        owner.processor.store(0, Ordering::Release);
        event.cpus[1] = &*peer as *const Context as u64;
        peer.processor.store(1, Ordering::Release);
        for (destination, busy, expected) in [(7, false, 1), (256, false, 0), (7, true, 0)] {
            peer.apic_id = destination;
            peer.pending_nmi.store(0, Ordering::Release);
            apic.0[0x300 / 4] = if busy { 0x1000 } else { 0 };
            apic.0[0x310 / 4] = 0;
            assert_eq!(unsafe { sync_begin(&*owner) }, 1);
            let result = unsafe { sync_kick(&*owner) };
            unsafe { sync_end(&*owner) };
            assert_eq!(result, expected);
            assert_eq!(peer.pending_nmi.load(Ordering::Acquire), expected);
            if expected == 1 {
                assert_eq!(apic.0[0x310 / 4], 7 << 24);
                assert_eq!(apic.0[0x300 / 4], 0x4400);
            }
        }
    }

    #[test]
    fn acquisition_waits_for_peers_and_releases_ownership_on_transport_or_timeout_failure() {
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let owner = Box::new(Context::new(&event, false));
        let peer = Box::new(Context::new(&event, true));
        event.cpus[0] = &*owner as *const Context as u64;
        owner.processor.store(0, Ordering::Release);
        // No peer requires a functioning APIC when there is only one registered CPU.
        owner.apic_base.store(0, Ordering::Release);
        let acquired = unsafe { sync_acquire(&*owner) };
        if acquired != 0 {
            unsafe { sync_end(&*owner) };
        }
        assert_eq!(acquired, 1);
        event.cpus[1] = &*peer as *const Context as u64;
        peer.processor.store(1, Ordering::Release);
        for base in [0, 0xc00] {
            owner.apic_base.store(base, Ordering::Release);
            assert_eq!(unsafe { sync_acquire(&*owner) }, 0);
            assert_eq!(unsafe { sync_begin(&*peer) }, 0);
            unsafe { sync_poll(&*owner); sync_poll(&*peer); }
            assert_eq!(
                unsafe { sync_begin(&*peer) },
                1,
                "Failed acquisition must release its owner"
            );
            unsafe { sync_end(&*peer) };
        }

        peer.pending_nmi.store(0, Ordering::Release);
        let stop = AtomicU64::new(0);
        thread::scope(|scope| {
            scope.spawn(|| {
                while stop.load(Ordering::Acquire) == 0 {
                    unsafe { sync_poll(&*peer) };
                    thread::yield_now();
                }
            });
            let acquired = unsafe { sync_acquire(&*owner) };
            let ready = unsafe { sync_ready(&*owner) };
            if acquired != 0 {
                unsafe { sync_end(&*owner) };
            }
            stop.store(1, Ordering::Release);
            assert_eq!(acquired, 1);
            assert_eq!(ready, 1);
        });
    }

    #[test]
    fn synchronization_diagnostics_separate_contention_transport_and_both_timeout_phases() {
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let owner = Box::new(Context::new(&event, false));
        let mut peer = Box::new(Context::new(&event, false));
        event.cpus[0] = &*owner as *const Context as u64;
        owner.processor.store(0, Ordering::Release);
        let counters = || owner.sync_diagnostics.each_ref().map(|value| value.load(Ordering::Acquire));
        assert_eq!(unsafe { sync_acquire(&*owner) }, 1);
        unsafe { sync_end(&*owner) };
        assert_eq!(&counters()[..6], &[1, 1, 0, 0, 0, 0]);
        event.cpus[63] = &*peer as *const Context as u64;
        peer.processor.store(63, Ordering::Release);
        assert_eq!(unsafe { sync_begin(&*peer) }, 1);
        assert_eq!(unsafe { sync_acquire(&*owner) }, 0);
        unsafe { sync_end(&*peer) };
        assert_eq!(&counters()[..7], &[2, 1, 1, 0, 0, 0, 1]);
        owner.apic_base.store(0, Ordering::Release);
        assert_eq!(unsafe { sync_acquire(&*owner) }, 0);
        assert_eq!(counters(), [3, 1, 1, 1, 0, 0, 2, 1 << 63]);
        unsafe { sync_poll(&*owner); sync_poll(&*peer); }
        owner.apic_base.store(0xc00, Ordering::Release);
        assert_eq!(unsafe { sync_acquire(&*owner) }, 0);
        assert_eq!(counters(), [4, 1, 1, 1, 1, 0, 4, 1 << 63]);
        #[repr(C, align(4096))]
        struct ApicPage([u32; 1024]);
        let mut apic = Box::new(ApicPage([0; 1024]));
        apic.0[0x300 / 4] = 0x1000;
        peer.apic_id = 7;
        unsafe { sync_poll(&*owner); sync_poll(&*peer); }
        owner.apic_base.store((&*apic as *const ApicPage as u64) | 0x800, Ordering::Release);
        assert_eq!(unsafe { sync_acquire(&*owner) }, 0);
        assert_eq!(counters(), [5, 1, 1, 1, 1, 1, 3, 1 << 63]);
unsafe { sync_poll(&*owner); sync_poll(&*peer); }
                event.cpus[63] = 0;
        assert_eq!(unsafe { sync_acquire(&*owner) }, 1);
        unsafe { sync_end(&*owner) };
        assert_eq!(counters(), [6, 2, 1, 1, 1, 1, 3, 1 << 63]);
    }

    #[test]
    fn a_stalled_owner_cancels_peers_but_keeps_storage_quarantined_until_every_cpu_recovers() {
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let owner = Box::new(Context::new(&event, false));
        let peer = Box::new(Context::new(&event, false));
        peer.processor.store(1, Ordering::Release);
        event.cpus[0] = &*owner as *const Context as u64;
        event.cpus[1] = &*peer as *const Context as u64;
        profile.active.store(1, Ordering::Release);
        assert_eq!(unsafe { sync_begin(&*owner) }, 1);
        let started = Instant::now();
        unsafe { sync_poll(&*peer); }
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(profile.active.load(Ordering::Acquire), 2);
        assert_eq!(profile.cause.load(Ordering::Acquire), 3);
        assert_eq!(peer.sync_diagnostics[6].load(Ordering::Acquire), 5);
        assert_eq!(peer.runtime_diagnostics[21].load(Ordering::Acquire), 7);
        assert_eq!(peer.revocations.load(Ordering::Acquire), 1);
        assert_eq!(unsafe { sync_stall(&*peer, 0) }, 5);
        assert_eq!(unsafe { sync_stall(&*peer, 1) }, &*owner as *const Context as u64);
        assert_eq!(unsafe { sync_stall(&*peer, 2) }, owner.ack.load(Ordering::Acquire));
        assert_eq!(unsafe { sync_stall(&*peer, 3) }, 1);
        assert_eq!(unsafe { sync_begin(&*peer) }, 0);
        unsafe { sync_end(&*owner); }
        assert_eq!(unsafe { sync_begin(&*peer) }, 0);
        unsafe { sync_poll(&*owner); }
        assert_eq!(unsafe { sync_begin(&*peer) }, 1);
        unsafe { sync_end(&*peer); }
        assert_eq!(owner.revocations.load(Ordering::Acquire), 1);
    }

    #[test]
    fn successive_owners_cannot_renew_a_peers_root_entry_budget() {
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let owner = Box::new(Context::new(&event, false));
        let peer = Box::new(Context::new(&event, false));
        peer.processor.store(1, Ordering::Release);
        event.cpus[0] = &*owner as *const Context as u64;
        event.cpus[1] = &*peer as *const Context as u64;
        profile.active.store(1, Ordering::Release);
        unsafe { sync_poll(&*peer); }
        let mut epochs = 0;
        while unsafe { sync_budget_check(&*peer) } == 0 {
            assert_eq!(unsafe { sync_begin(&*owner) }, 1);
            unsafe { sync_end(&*owner); }
            epochs += 1;
            std::thread::sleep(Duration::from_millis(1));
            assert!(epochs < 1000, "owner changes renewed the peer deadline");
        }
        assert!(epochs > 0);
        assert_eq!(unsafe { sync_begin(&*owner) }, 1);
        unsafe { sync_poll_retained(&*peer); }
        assert_eq!(profile.active.load(Ordering::Acquire), 2);
        assert_eq!(peer.sync_diagnostics[6].load(Ordering::Acquire), 5);
        unsafe { sync_end(&*owner); sync_poll(&*owner); sync_poll(&*peer); }
    }

    #[test]
    fn owner_ack_wait_uses_the_root_entry_budget() {
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let mut owner = Box::new(Context::new(&event, false));
        let peer = Box::new(Context::new(&event, false));
        owner.tsc_hz = 10_000;
        owner.clock_enabled.store(1, Ordering::Release);
        peer.processor.store(1, Ordering::Release);
        event.cpus[0] = &*owner as *const Context as u64;
        event.cpus[1] = &*peer as *const Context as u64;
        assert_eq!(unsafe { sync_acquire(&*owner) }, 0);
        assert!(owner.clock_ticks.load(Ordering::Acquire) <= 205,
                "an unresponsive peer held the owner beyond its 20 ms root budget");
        assert_eq!(owner.sends.load(Ordering::Acquire), 1);
        assert_eq!(owner.sync_diagnostics[6].load(Ordering::Acquire), 4);
        unsafe { sync_poll(&*owner); sync_poll(&*peer); }
        assert_eq!(unsafe { sync_begin(&*peer) }, 1);
        unsafe { sync_end(&*peer); }
    }

    #[test]
    fn cancelled_acquisition_stops_before_the_owner_deadline() {
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let mut owner = Box::new(Context::new(&event, false));
        let peer = Box::new(Context::new(&event, false));
        owner.tsc_hz = 1000;
        owner.clock_enabled.store(1, Ordering::Release);
        owner.cancel_on_send.store(1, Ordering::Release);
        peer.processor.store(1, Ordering::Release);
        event.cpus[0] = &*owner as *const Context as u64;
        event.cpus[1] = &*peer as *const Context as u64;
        assert_eq!(unsafe { sync_acquire(&*owner) }, 0);
        assert!(owner.clock_ticks.load(Ordering::Acquire) < 20,
                "the owner kept polling an already cancelled epoch");
        assert_eq!(owner.sync_diagnostics[4].load(Ordering::Acquire), 0);
        unsafe { sync_poll(&*owner); sync_poll(&*peer); }
        assert_eq!(unsafe { sync_begin(&*peer) }, 1);
        unsafe { sync_end(&*peer); }
    }

    #[test]
    fn busy_icr_uses_the_root_entry_budget() {
        #[repr(C, align(4096))]
        struct ApicPage([u32; 1024]);
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let mut owner = Box::new(Context::new(&event, false));
        let peer = Box::new(Context::new(&event, false));
        let mut apic = Box::new(ApicPage([0; 1024]));
        apic.0[0x300 / 4] = 0x1000;
        owner.apic_base.store((&*apic as *const ApicPage as u64) | 0x800, Ordering::Release);
        owner.tsc_hz = 1000;
        owner.clock_enabled.store(1, Ordering::Release);
        peer.processor.store(1, Ordering::Release);
        event.cpus[0] = &*owner as *const Context as u64;
        event.cpus[1] = &*peer as *const Context as u64;
        assert_eq!(unsafe { sync_acquire(&*owner) }, 0);
        assert!(owner.clock_ticks.load(Ordering::Acquire) <= 25,
                "a busy APIC held the owner beyond its 20 ms root budget");
        assert_eq!(owner.sync_diagnostics[6].load(Ordering::Acquire), 3);
        assert_eq!(peer.pending_nmi.load(Ordering::Acquire), 0);
    }

    #[test]
    fn host_nmi_cannot_renew_an_expired_root_budget() {
        let _serial = isolate();
        let profile = Profile::new();
        let mut event = Box::new(Event { cpus: [0; 64], interception: &profile as *const _ as u64 });
        let owner = Box::new(Context::new(&event, false));
        let mut peer = Box::new(Context::new(&event, false));
        peer.processor.store(1, Ordering::Release);
        peer.tsc_hz = 1000;
        peer.clock_enabled.store(1, Ordering::Release);
        event.cpus[0] = &*owner as *const Context as u64;
        event.cpus[1] = &*peer as *const Context as u64;
        unsafe { sync_poll(&*peer); }
        peer.clock_ticks.store(100, Ordering::Release);
        assert_eq!(unsafe { sync_begin(&*owner) }, 1);
        peer.safe.store(1, Ordering::Release);
        peer.pending_nmi.store(1, Ordering::Release);
        assert_eq!(unsafe { sync_host_nmi_retained(&*peer) }, 1);
        assert_eq!(peer.ack.load(Ordering::Acquire), 0,
                   "the NMI reset an expired budget and started another parking interval");
        assert_eq!(peer.sync_diagnostics[6].load(Ordering::Acquire), 5);
        unsafe { sync_end(&*owner); }
    }

    #[test]
    fn frozen_tsc_iteration_budget_stays_exhausted() {
        let _serial = isolate();
        let profile = Profile::new();
        let event = Event { cpus: [0; 64], interception: &profile as *const _ as u64 };
        let cpu = Context::new(&event, false);
        cpu.clock_enabled.store(1, Ordering::Release);
        cpu.clock_step.store(0, Ordering::Release);
        unsafe { sync_poll(&cpu); }
        let mut exhausted = false;
        for _ in 0..1_000_001 {
            if unsafe { sync_budget_check(&cpu) } != 0 {
                exhausted = true;
                break;
            }
        }
        assert!(exhausted);
        for _ in 0..3 {
            assert_eq!(unsafe { sync_budget_check(&cpu) }, 1,
                       "an exhausted fallback counter wrapped and renewed the budget");
        }
    }

    #[test]
    fn periodic_safe_points_do_not_need_a_lease_and_restore_the_timer_they_own() {
        let _serial = isolate();
        let profile = Profile::new();
        let event = Event { cpus: [0; 64], interception: &profile as *const _ as u64 };
        let cpu = Context::new(&event, false);
        cpu.processor.store(30, Ordering::Release);
        cpu.timer_supported.store(1, Ordering::Release);
        profile.active.store(1, Ordering::Release);
        unsafe { sync_enter(&cpu); }
        assert_eq!(cpu.timer_pin.load(Ordering::Acquire), 64);
        assert_eq!(cpu.timer_value.load(Ordering::Acquire), 625_000);
        cpu.timer_value.store(0, Ordering::Release);
        unsafe { sync_enter(&cpu); }
        assert_eq!(cpu.timer_value.load(Ordering::Acquire), 625_000);
        profile.active.store(2, Ordering::Release);
        unsafe { sync_enter(&cpu); }
        assert_eq!(cpu.timer_pin.load(Ordering::Acquire), 0);
        assert_eq!(cpu.timer_value.load(Ordering::Acquire), 77);
    }

    #[test]
    fn periodic_safe_points_preserve_an_earlier_timer_and_skip_unsupported_hardware() {
        let _serial = isolate();
        let profile = Profile::new();
        let event = Event { cpus: [0; 64], interception: &profile as *const _ as u64 };
        let cpu = Context::new(&event, false);
        cpu.processor.store(31, Ordering::Release);
        cpu.timer_supported.store(1, Ordering::Release);
        cpu.timer_pin.store(64, Ordering::Release);
        cpu.timer_value.store(3, Ordering::Release);
        profile.active.store(1, Ordering::Release);
        unsafe { sync_enter(&cpu); }
        assert_eq!(cpu.timer_value.load(Ordering::Acquire), 3);
        profile.active.store(2, Ordering::Release);
        unsafe { sync_enter(&cpu); }
        assert_eq!(cpu.timer_pin.load(Ordering::Acquire), 64);
        let unsupported = Context::new(&event, false);
        unsupported.processor.store(32, Ordering::Release);
        profile.active.store(1, Ordering::Release);
        unsafe { sync_enter(&unsupported); }
        assert_eq!(unsupported.timer_pin.load(Ordering::Acquire), 0);
        assert_eq!(unsupported.timer_value.load(Ordering::Acquire), 77);
    }
}
