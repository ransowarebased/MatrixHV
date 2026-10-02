#[test]
fn review_edge_ept_nonleaf_reserved_bits_require_misconfiguration() {
    let mut observed = Vec::new();
    for reserved_bits in [0x08, 0x40, 0x80] {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        state.gpa = 0x200000;
        let root_slot = entry_addresses(ept12, state.gpa)[0] as *mut u64;
        unsafe { *root_slot |= reserved_bits };
        let resolved = unsafe { resolve_test_ept(&mut state) };
        observed.push((reserved_bits, resolved, state.exit_reason));
    }
    println!("nonleaf_reserved_bits={observed:?}");
    assert_eq!(observed, vec![(0x08, 0, 49), (0x40, 0, 49), (0x80, 0, 49)]);
}

#[test]
fn review_edge_ept_large_leaf_alignment_requires_misconfiguration() {
    let mut observed = Vec::new();
    for (shift, reserved_address_bit) in [(21, 12), (30, 21)] {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x40000000, 0x80000000, shift, 0xb7);
        arena.map(ept01, 0x80000000, 0xc0000000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        state.gpa = 0x40000000;
        let source_slot = *entry_addresses(ept12, state.gpa).last().unwrap() as *mut u64;
        unsafe { *source_slot |= 1 << reserved_address_bit };
        let resolved = unsafe { resolve_test_ept(&mut state) };
        observed.push((
            shift,
            resolved,
            state.exit_reason,
            leaf(state.ept02, state.gpa).1 & ADDRESS_MASK,
        ));
    }
    println!("large_leaf_alignment={observed:?}");
    assert!(
        observed
            .iter()
            .all(|&(_, resolved, reason, _)| resolved == 0 && reason == 49)
    );
}

#[test]
fn review_edge_ept_address_width_requires_misconfiguration() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12, ept01);
    state.gpa = 0x200000;
    state.physical_address_bits = 48;
    let source_slot = *entry_addresses(ept12, state.gpa).last().unwrap() as *mut u64;
    unsafe { *source_slot |= 1 << 48 };
    let resolved = unsafe { resolve_test_ept(&mut state) };
    println!(
        "physical_address_width={:?}",
        (resolved, state.exit_reason, leaf(state.ept02, state.gpa))
    );
    assert_eq!((resolved, state.exit_reason), (0, 49));
}

#[test]
fn review_edge_ept_execute_only_requires_advertised_support() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0xb4);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12, ept01);
    state.gpa = 0x200000;
    state.qualification = 4;
    state.ept_capabilities = 1 << 16;
    let resolved = unsafe { resolve_test_ept(&mut state) };
    println!(
        "execute_only_without_capability={:?}",
        (resolved, state.exit_reason, leaf(state.ept02, state.gpa))
    );
    assert_eq!((resolved, state.exit_reason), (0, 49));
}

#[test]
fn review_edge_ept_invalid_entries_must_not_survive_revalidation() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12, ept01);
    state.gpa = 0x200000;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    let source_slot = *entry_addresses(ept12, state.gpa).last().unwrap() as *mut u64;
    unsafe {
        *source_slot |= 1 << 12;
        revalidate_test_ept(&mut state);
    }
    let cached_leaf = leaf(state.ept02, state.gpa);
    println!("invalid_entry_after_revalidation={cached_leaf:?}");
    assert_eq!(cached_leaf.1, 0);
}

#[test]
fn review_edge_ept_page_sizes_require_their_advertised_capability() {
    for (shift, capability) in [(21, 16), (30, 17)] {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x40000000, 0x80000000, shift, 0xb7);
        arena.map(ept01, 0x80000000, 0xc0000000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        state.gpa = 0x40000000;
        state.ept_capabilities &= !(1 << capability);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
        assert_eq!(state.exit_reason, 49);
        state.ept_capabilities |= 1 << capability;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    }
}

#[test]
fn review_edge_ept_ignored_bits_remain_usable_and_nonpresent_entries_take_priority() {
    for level in 0..4 {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 12, 0x37);
        arena.map(ept01, 0x400000, 0x600000, 12, 0x37);
        let mut state = context(&mut arena, ept12, ept01);
        state.gpa = 0x200000;
        let source = entry_addresses(ept12, state.gpa)[level] as *mut u64;
        unsafe { *source |= (0xfff_u64 << 52) | 0xe00 };
        if level == 3 {
            unsafe { *source |= 0x80 };
        }
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        unsafe { *source = (1 << 48) | 0x78 };
        state.exit_reason = 48;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
        assert_eq!(state.exit_reason, 48);
    }
}

#[test]
fn review_edge_ept_user_execute_only_obeys_capability_with_mbec_enabled() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 12, 0x430);
    arena.map(ept01, 0x400000, 0x600000, 12, 0x37);
    let mut state = context(&mut arena, ept12, ept01);
    state.gpa = 0x200000;
    state.ept_capabilities &= !1;
    state.mbec = 1;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
    assert_eq!(state.exit_reason, 49);
}

#[test]
fn review_edge_observe_valid_memory_type_composition() {
    let mut observed = Vec::new();
    for memory_type in [0, 1, 4, 5, 6] {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0x87 | (memory_type << 3));
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        state.gpa = 0x200000;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        observed.push((memory_type, (leaf(state.ept02, state.gpa).1 >> 3) & 7));
    }
    println!("valid_memory_type_composition={observed:?}");
    assert_eq!(observed, vec![(0, 0), (1, 0), (4, 0), (5, 0), (6, 6)]);
}

#[repr(C)]
struct ReviewIoPointerContext {
    primary: u64,
    bitmap_a: u64,
    bitmap_b: u64,
    hardware: [u64; 4],
    ept01: u64,
    virtual_apic: u64,
    tpr_threshold: u64,
}

core::arch::global_asm!(
    include_str!("../builds/nested-ept-tests/resident-io.S"),
    b_nested_vmcs12_primary_control = const std::mem::offset_of!(ReviewIoPointerContext, primary),
    b_nested_vmcs12_io_bitmap_a = const std::mem::offset_of!(ReviewIoPointerContext, bitmap_a),
    b_nested_vmcs12_io_bitmap_b = const std::mem::offset_of!(ReviewIoPointerContext, bitmap_b),
    io_bitmap_a = const 0,
    io_bitmap_b = const 1,
    virtual_apic_page_addr = const 2,
    tpr_threshold = const 3,
    b_nested_vmcs12_virtual_apic_page = const std::mem::offset_of!(ReviewIoPointerContext, virtual_apic),
    b_nested_vmcs12_tpr_threshold = const std::mem::offset_of!(ReviewIoPointerContext, tpr_threshold),
    b_cache_ept_pointer = const std::mem::offset_of!(ReviewIoPointerContext, ept01),
    host_page_address_mask = const 0x000ffffffffff000_u64,
    review_hardware = const std::mem::offset_of!(ReviewIoPointerContext, hardware),
);

unsafe extern "win64" {
    fn review_edge_merge_io(context: *mut ReviewIoPointerContext);
}

#[test]
fn review_edge_io_bitmaps_require_ept01_translation() {
    let mut arena = Arena::new();
    let ept01 = arena.pages(1);
    let bitmap_a = arena.pages(1);
    let bitmap_b = arena.pages(1);
    let virtual_apic = arena.pages(1);
    arena.map(ept01, 0x400000, bitmap_a, 12, 0x37);
    arena.map(ept01, 0x401000, bitmap_b, 12, 0x37);
    arena.map(ept01, 0x402000, virtual_apic, 12, 0x37);
    let mut state = ReviewIoPointerContext {
        primary: (1 << 25) | (1 << 21),
        bitmap_a: 0x400000,
        bitmap_b: 0x401000,
        hardware: [0; 4],
        ept01,
        virtual_apic: 0x402000,
        tpr_threshold: 7,
    };
    unsafe { review_edge_merge_io(&mut state) };
    println!(
        "io_bitmap_host_addresses={:?}; expected={:?}",
        state.hardware,
        [bitmap_a, bitmap_b]
    );
    assert_eq!(state.hardware, [bitmap_a, bitmap_b, virtual_apic, 7]);
}
