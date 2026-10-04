use core::arch::global_asm;

global_asm!(include_str!("../builds/exit-guard-tests/guards.S"));

unsafe extern "C" {
    fn test_guest_privilege(context: *mut u64) -> u32;
    fn test_xsetbv_guard(context: *mut u64) -> u32;
    fn test_vmresume_diagnostic(context: *mut u64);
    fn test_dispatch_canaries(context: *mut u64) -> u32;
}

#[test]
fn dispatcher_rejects_corrupt_canaries_before_its_first_context_write() {
    for bad_canary in [None, Some(1), Some(2)] {
        let mut context = [91, 0x4856424f4f544331, 0x4856424f4f544332, 0, 0, 0];
        if let Some(index) = bad_canary {
            context[index] ^= 1;
        }
        let valid = bad_canary.is_none();
        assert_eq!(
            unsafe { test_dispatch_canaries(context.as_mut_ptr()) },
            u32::from(valid)
        );
        assert_eq!(context[0], if valid { 0 } else { 91 });
        assert_eq!(context[3], u64::from(valid));
    }
}

#[test]
fn timing_sample_follows_canary_validation() {
    for valid in [true, false] {
        let mut context = [91, 0x4856424f4f544331, 0x4856424f4f544332, 0, 1, 77];
        if !valid {
            context[1] = 0;
        }
        assert_eq!(
            unsafe { test_dispatch_canaries(context.as_mut_ptr()) },
            u32::from(valid)
        );
        if valid {
            assert!(context[5] > 77);
        } else {
            assert_eq!(context[5], 77);
        }
    }
}

#[test]
fn privilege_uses_ss_dpl_and_preserves_real_and_vm86_rules() {
    for pe in [0, 1] {
        for vm86 in [0, 1 << 17] {
            for dpl in 0..=3 {
                let mut context = [0_u64; 12];
                context[0] = pe;
                context[1] = vm86;
                context[2] = 0x93 | (dpl << 5);
                let expected = pe == 0 || (vm86 == 0 && dpl == 0);
                assert_eq!(
                    unsafe { test_guest_privilege(context.as_mut_ptr()) },
                    u32::from(expected)
                );
            }
        }
    }
}

#[test]
fn xsetbv_failure_survives_cr4_flag_clobber_and_does_not_complete() {
    for denied in [0, 1] {
        let mut context = [0_u64; 12];
        context[0] = 1;
        context[2] = 0x93;
        context[3] = 1 << 18;
        context[4] = denied;
        context[5] = 0x2020;
        assert_eq!(
            unsafe { test_xsetbv_guard(context.as_mut_ptr()) },
            1 - denied as u32
        );
        assert_eq!(context[5], 0x2020);
        assert_eq!(context[11], 1 - denied);
    }
}

#[test]
fn vmresume_error_field_is_read_only_for_vmfail_valid() {
    for flags in [1, 0x40, 0, 0x41] {
        let mut context = [0_u64; 12];
        context[6] = flags;
        context[7] = 7;
        unsafe { test_vmresume_diagnostic(context.as_mut_ptr()) };
        let valid = flags == 0x40;
        assert_eq!(context[8], u64::from(valid));
        assert_eq!(context[9], if valid { 7 } else { u64::MAX });
    }
}
