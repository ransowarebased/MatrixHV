core::arch::global_asm!(
    ".globl ept_profile_test_slots",
    "ept_profile_test_slots:",
    "lea rax, [rip + .Lresident_ept_profile_slots]",
    "ret",
    ".data",
    ".balign 64",
    ".Lresident_ept_profile_slots:",
    ".zero 32768",
    ".text",
);

unsafe extern "C" {
    fn ept_profile_test_slots() -> *mut u64;
}

#[test]
fn sampled_profile_counts_repeated_entries_changes_and_discarded_work() {
    for leaf_count in [8_u64, 257] {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept01, 0, 0, 30, 0xb7);
        for index in 0..leaf_count {
            let address = 0x200000 + index * 4096;
            arena.map(ept12, address, address + 0x4000000, 12, 0x37);
        }
        let mut state = context(&mut arena, ept12, ept01);
        for index in 0..leaf_count {
            state.gpa = 0x200000 + index * 4096;
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        }
        arena.map(ept12, 0x200000, 0x8000000, 12, 0x31);
        arena.map(ept12, 0x201000, 0, 12, 0);
        let stats = unsafe { std::slice::from_raw_parts_mut(ept_profile_test_slots(), 64) };
        stats.fill(0);
        stats[0] = 63;
        unsafe { revalidate_test_ept(&mut state) };
        assert_eq!(stats[0], 64);
        assert_eq!(stats[1], 1);
        let visited = leaf_count.min(256);
        assert_eq!(stats[4], visited);
        assert_eq!(stats[5], visited - 2);
        assert_eq!(stats[6], 1);
        assert_eq!(stats[7], 1);
        for start in [8, 11, 14] {
            assert_eq!(stats[start], visited);
            assert_eq!(stats[start + 1], visited - 1);
            assert_eq!(stats[start + 2], visited - 1);
        }
        assert_eq!(stats[17], visited);
        assert_eq!(stats[18], 0);
        assert_eq!(stats[19], 0);
        assert!(stats[20] > 0);
        assert_eq!(state.native_invept, 1);
        if leaf_count <= 256 {
            assert_eq!((stats[2], stats[3], stats[21]), (1, 0, 0));
            assert_eq!(leaf(state.ept02, 0x200000), (12, 0x8000031));
            assert_eq!(leaf(state.ept02, 0x201000).1, 0);
        } else {
            assert_eq!((stats[2], stats[3], stats[21]), (0, 1, 256));
            assert_eq!(state.pool_used, 0);
            assert_eq!(leaf(state.ept02, 0x200000).1, 0);
        }
    }
}
