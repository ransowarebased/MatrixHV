include!("../builds/nested-host-restore-tests/offsets.rs");
core::arch::global_asm!(include_str!("../builds/nested-host-restore-tests/handlers.S"));

unsafe extern "win64" {
    fn restore_host(context: *mut u64);
    fn restore_host_reference(context: *mut u64);
}

#[test]
fn current_l1_snapshots_skip_only_equal_values_and_preserve_all_host_state() {
    for load_controls in [0, 1 << 19, 1 << 21, (1 << 19) | (1 << 21)] {
        for changed in 0..16 {
            let mut state = vec![0_u64; 0x7100];
            state[offset("b_nested_vmcs12_vm_exit_controls")] = load_controls;
            state[offset("b_nested_l2_saved_pat")] = 0x0007_0406_0007_0406;
            state[offset("b_nested_l2_saved_efer")] = 0x500;
            state[27] = 0x0006_0407_0006_0407;
            state[28] = 0xd01;
            for field in 43..=49 {
                state[field] = if changed & 1 == 0 { field as u64 * 8 } else { 0 };
            }
            let pat = state[if load_controls & (1 << 19) != 0 { 27 }
                            else { offset("b_nested_l2_saved_pat") }];
            let efer = state[if load_controls & (1 << 21) != 0 { 28 }
                             else { offset("b_nested_l2_saved_efer") }] | 0x500;
            for (bit, name, encoding, target) in [
                (0, "b_nested_inherited_l1_pat", 0x2804, pat),
                (1, "b_nested_inherited_l1_efer", 0x2806, efer),
                (2, "b_nested_inherited_l1_dr7", 0x681a, 0x400),
                (3, "b_nested_inherited_l1_debugctl", 0x2802, 0),
            ] {
                let live = target ^ u64::from(changed & (1 << bit) != 0);
                state[offset(name)] = live;
                state[256 + encoding] = live;
            }
            let mut reference = state.clone();
            unsafe {
                restore_host(state.as_mut_ptr());
                restore_host_reference(reference.as_mut_ptr());
            }
            assert_eq!(&state[256..], &reference[256..],
                       "controls={load_controls:#x} changed={changed:#x}");
            assert_eq!(state[256 + 0x2804], pat);
            assert_eq!(state[256 + 0x2806], efer);
            assert_eq!(state[256 + 0x681a], 0x400);
            assert_eq!(state[256 + 0x2802], 0);
            assert_eq!(reference[192] - state[192], 4 - (changed as u32).count_ones() as u64);
        }
    }
}
