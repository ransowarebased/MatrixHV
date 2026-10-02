#[test]
fn review_ept_preserves_ignore_pat_for_small_and_large_leaves() {
    let mut observations = Vec::new();
    for shift in [12, 21] {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        let large = if shift == 21 { 0x80 } else { 0 };
        arena.map(ept12, 0x200000, 0x400000, shift, 0x77 | large);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        state.gpa = 0x200000;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        let (actual_shift, actual_entry) = leaf(state.ept02, state.gpa);
        observations.push((shift, actual_shift, actual_entry & 0x40));
    }
    assert_eq!(observations, vec![(12, 12, 0x40), (21, 21, 0x40)]);
}

#[test]
fn review_ept_reserved_memory_types_raise_misconfiguration() {
    let mut observations = Vec::new();
    let mut expected = Vec::new();
    for memory_type in [2, 3, 7] {
        for shift in [12, 21] {
            let mut arena = Arena::new();
            let ept12 = arena.pages(1);
            let ept01 = arena.pages(1);
            let large = if shift == 21 { 0x80 } else { 0 };
            arena.map(
                ept12,
                0x200000,
                0x400000,
                shift,
                7 | (memory_type << 3) | large,
            );
            arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
            let mut state = context(&mut arena, ept12, ept01);
            state.gpa = 0x200000;
            let resolved = unsafe { resolve_test_ept(&mut state) };
            observations.push((memory_type, shift, resolved, state.exit_reason));
            expected.push((memory_type, shift, 0, 49));
        }
    }
    assert_eq!(observations, expected);
}

#[test]
fn ignore_pat_survives_revalidation_and_large_leaf_splitting() {
    for shift in [12, 21, 30] {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(
            ept12,
            0x40000000,
            0x80000000,
            shift,
            0x77 | if shift > 12 { 0x80 } else { 0 },
        );
        arena.map(ept01, 0x80000000, 0xc0000000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        state.gpa = 0x40000000;
        state.cached_ept12 = state.ept12;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        let source = *entry_addresses(ept12, state.gpa).last().unwrap() as *mut u64;
        for ignore_pat in [0x40, 0, 0x40] {
            unsafe {
                *source = (*source & !0x40) | ignore_pat;
                revalidate_test_ept(&mut state);
            }
            assert_eq!(leaf(state.ept02, state.gpa).1 & 0x40, ignore_pat);
        }
        let large_slot = *entry_addresses(ept01, 0x80000000).last().unwrap() as *mut u64;
        unsafe { *large_slot = 0 };
        arena.map(ept01, 0x80000000, 0xc0000000, 12, 0x37);
        unsafe { revalidate_test_ept(&mut state) };
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        let (actual_shift, entry) = leaf(state.ept02, state.gpa);
        assert_eq!((actual_shift, entry & 0x40), (12, 0x40));
    }
}

#[test]
fn reserved_memory_types_invalidate_cached_leaves_and_valid_types_remain_usable() {
    for shift in [12, 21, 30] {
        for memory_type in 0..8 {
            let mut arena = Arena::new();
            let ept12 = arena.pages(1);
            let ept01 = arena.pages(1);
            let large = if shift > 12 { 0x80 } else { 0 };
            arena.map(ept12, 0x40000000, 0x80000000, shift, 0x37 | large);
            arena.map(ept01, 0x80000000, 0xc0000000, 21, 0xb7);
            let mut state = context(&mut arena, ept12, ept01);
            state.gpa = 0x40000000;
            state.cached_ept12 = state.ept12;
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
            let source = *entry_addresses(ept12, state.gpa).last().unwrap() as *mut u64;
            unsafe {
                *source = (*source & !0x38) | (memory_type << 3);
                revalidate_test_ept(&mut state);
            }
            let reserved = [2, 3, 7].contains(&memory_type);
            assert_eq!(leaf(state.ept02, state.gpa).1 != 0, !reserved);
            assert_eq!(
                unsafe { resolve_test_ept(&mut state) },
                u64::from(!reserved)
            );
            if reserved {
                assert_eq!(state.exit_reason, 49);
                assert_eq!(state.qualification, 0);
                unsafe { *source &= !7 };
                state.exit_reason = 48;
                assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
                assert_eq!(state.exit_reason, 48);
            }
        }
    }
}
