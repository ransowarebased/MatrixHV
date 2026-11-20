use std::arch::global_asm;
global_asm!(include_str!("../builds/l2-kernel-root-tests/observe.S"));
unsafe extern "win64" {
    fn test_l2_observe(context: *mut u64);
}

fn context() -> [u64; 40] {
    let mut state = [0; 40];
    state[1] = 512;
    state[2] = 0x201e;
    state[3] = 0x500a;
    state[5] = 0xffff_f800_1234_0000;
    state
}

#[test]
fn observes_kernel_roots_with_ept_namespace_and_normalized_pcid() {
    let mut state = context();
    unsafe {
        test_l2_observe(state.as_mut_ptr());
    }
    assert_eq!(state[6], 1);
    assert_eq!(&state[7..11], &[0x2000, 0x5000, state[5], 0]);
    assert_eq!(state[39], 1);
    unsafe {
        test_l2_observe(state.as_mut_ptr());
    }
    assert_eq!(state[6], 1);
    state[2] = 0x301e;
    unsafe {
        test_l2_observe(state.as_mut_ptr());
    }
    assert_eq!(state[6], 2);
    assert_eq!(&state[11..15], &[0x3000, 0x5000, state[5], 0]);
}

#[test]
fn rejects_user_nonlongmode_invalid_roots_and_noncanonical_lstar() {
    for (field, value) in [
        (0, 0x60),
        (1, 0),
        (2, 0),
        (3, 0),
        (5, 0x1234),
        (5, 0xffff_0000_1234_0000),
    ] {
        let mut state = context();
        state[field] = value;
        unsafe {
            test_l2_observe(state.as_mut_ptr());
        }
        assert_eq!(state[6], 0, "field={field} value={value:#x}");
        assert!(state[7..39].iter().all(|field| *field == 0));
    }
}

#[test]
fn bounded_history_replaces_old_entries_without_writing_past_allocation() {
    let mut state = context();
    for index in 0..20 {
        state[3] = (index + 1) * 4096;
        unsafe {
            test_l2_observe(state.as_mut_ptr());
        }
    }
    assert_eq!(state[6], 20);
    assert_eq!(state[39], 20);
    for item in state[7..39].chunks_exact(4) {
        assert_eq!(item[0], 0x2000);
        assert!((13 * 4096..=20 * 4096).contains(&item[1]));
        assert_eq!(item[2], state[5]);
    }
}
