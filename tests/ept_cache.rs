use core::arch::global_asm;

global_asm!(include_str!("ept-cache.S"));
global_asm!(include_str!("ept-transaction.S"));

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
