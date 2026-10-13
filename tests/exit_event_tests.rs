use std::arch::global_asm;

global_asm!(include_str!("../builds/exit-event-tests/event.S"));

#[repr(C)]
#[derive(Default)]
struct EventContext {
    reason: u64,
    qualification: u64,
    rip: u64,
    instruction_len: u64,
    reserved: [u64; 4],
    vmcs: [u64; 19],
    host_cr3: u64,
    expected_host_cr3: u64,
    log_backend: u64,
    dispatch_vmreads: u64,
    cr2: u64,
}

#[repr(C)]
#[derive(Default)]
struct ArmContext {
    l2_active: u64,
    control_cache_valid: [u64; 2],
    primary_controls: u64,
    root_vmx_active: u64,
}

#[repr(C)]
#[derive(Default)]
struct WindowContext {
    pending: u64,
    l2_active: u64,
    l1_pin_controls: u64,
    nmi_exit_pending: u64,
    vmcs02_launched: u64,
    reason: u64,
    qualification: u64,
    instruction_len: u64,
    control_cache_valid: [u64; 2],
    result: u64,
    primary_controls: u64,
    entry_intr_info: u64,
    interruptibility: u64,
    pending_debug: u64,
    activity: u64,
}

unsafe extern "C" {
    fn test_event_gp(context: &mut EventContext);
    fn test_event_debug(context: &mut EventContext);
    fn test_event_advance(context: &mut EventContext);
    fn test_cpuid_leaf0(context: &mut EventContext, registers: &mut [u64; 4]) -> u64;
    fn test_event_retry(context: &mut EventContext);
    fn test_event_interception_retry(context: &mut EventContext);
    fn test_event_exception(context: &mut EventContext);
    fn test_host_arm_nmi_window(context: &mut ArmContext);
    fn test_nested_nmi_window(context: &mut WindowContext);
    fn test_deliver_pending_nmi(context: &mut WindowContext);
    fn test_nested_l2_launch_entry(context: &mut WindowContext);
    fn test_nested_l2_resume_entry(context: &mut WindowContext);
}

#[test]
fn leaf_zero_uses_each_processor_cache_and_ignores_subleaf_and_high_halves() {
    for cache in [[0x20_u32, 0x756e6547, 0x6c65746e, 0x49656e69], [7, 2, 3, 4]] {
        for subleaf in [0, 1, u64::MAX] {
            let mut context = EventContext {
                reason: 10,
                qualification: u64::MAX,
                rip: 0x1000,
                reserved: [
                    u64::from(cache[0]) | (u64::from(cache[1]) << 32),
                    u64::from(cache[2]) | (u64::from(cache[3]) << 32),
                    0,
                    0,
                ],
                ..Default::default()
            };
            context.vmcs[6] = 3;
            context.vmcs[2] = 3;
            context.vmcs[11] = 0x100;
            let mut registers = [0xffff_ffff_0000_0000, subleaf, u64::MAX, u64::MAX];
            assert_eq!(unsafe { test_cpuid_leaf0(&mut context, &mut registers) }, 1);
            assert_eq!(
                registers,
                [cache[0], cache[2], cache[3], cache[1]].map(u64::from)
            );
            assert_eq!(context.qualification, 0);
            assert_eq!(context.dispatch_vmreads, 1);
            assert_eq!(context.vmcs[14], 0x1003);
            assert_eq!(context.vmcs[2], 0);
            assert_eq!(context.vmcs[13], 1 << 14);
        }
    }
}

#[test]
fn leaf_zero_short_dispatch_excludes_l2_diagnostics_and_other_exits() {
    for (reason, leaf, l2, telemetry, backend) in [
        (10, 0, 1, 0, 0),
        (10, 0, 0, 1, 0),
        (10, 0, 0, 0, 1),
        (10, 0, 0, 0, 2),
        (10, 1, 0, 0, 0),
        (10, 0x4d485652, 0, 0, 0),
        (0x8000_000a, 0, 0, 0, 0),
        (0, 0, 0, 0, 0),
    ] {
        let mut context = EventContext {
            reason,
            reserved: [0, 0, l2, telemetry],
            log_backend: backend,
            ..Default::default()
        };
        let mut registers = [leaf, 1, 2, 3];
        assert_eq!(unsafe { test_cpuid_leaf0(&mut context, &mut registers) }, 0);
        assert_eq!(registers, [leaf, 1, 2, 3]);
        assert_eq!(context.dispatch_vmreads, 0);
    }
}

#[test]
fn leaf_zero_short_dispatch_retains_host_cr3_validation() {
    let mut context = EventContext {
        reason: 10,
        host_cr3: 0x1000,
        expected_host_cr3: 0x2000,
        ..Default::default()
    };
    let mut registers = [0, 1, 2, 3];
    assert_eq!(unsafe { test_cpuid_leaf0(&mut context, &mut registers) }, 2);
    assert_eq!(registers, [0, 1, 2, 3]);
}

#[test]
fn gp_error_code_follows_guest_protection_mode() {
    for (cr0, expected) in [(0, 0x8000_030d), (1, 0x8000_0b0d)] {
        let mut context = EventContext::default();
        context.vmcs[8] = cr0;
        context.vmcs[5] = 123;
        unsafe { test_event_gp(&mut context) };
        assert_eq!(context.vmcs[3], expected);
        assert_eq!(context.vmcs[5], 0);
    }
}

#[test]
fn completion_wraps_rip_and_retires_interrupt_shadow() {
    for (cs_access, efer, rip, expected) in [
        (0, 0, 0xfffe, 0x10000),
        (0, 0, 0x10000, 0x10002),
        (0, 0, 0xffff_fffe, 0),
        (0x4000, 0, 0xffff_fffe, 0),
        (0, 0x500, 0xfffe, 0x10000),
        (0, 0x500, 0x10000, 0x10002),
        (0, 0x500, 0xffff_fffe, 0),
        (0x4000, 0x500, 0xffff_fffe, 0),
        (0x2000, 0, 0xffff_fffe, 0),
        (0x2000, 0x500, 0xffff_fffe, 0x1_0000_0000),
        (0x2000, 0x500, u64::MAX - 1, 0),
    ] {
        let mut context = EventContext {
            rip,
            instruction_len: 2,
            ..Default::default()
        };
        context.vmcs[10] = cs_access;
        context.vmcs[15] = efer;
        context.vmcs[2] = 0xb;
        unsafe { test_event_advance(&mut context) };
        assert_eq!(context.vmcs[14], expected);
        assert_eq!(context.vmcs[2], 8);
    }
}

#[test]
fn completion_preserves_debug_causes_and_adds_single_step_only_without_btf() {
    for (flags, debugctl, expected) in [
        (0x100, 0, 0x5001),
        (0x100, 2, 0x1001),
        (0, 0, 0x1001),
    ] {
        let mut context = EventContext::default();
        context.vmcs[10] = 0x2000;
        context.vmcs[11] = flags;
        context.vmcs[12] = debugctl;
        context.vmcs[13] = 0x1001;
        unsafe { test_event_advance(&mut context) };
        assert_eq!(context.vmcs[13], expected);
    }
    let mut context = EventContext::default();
    context.vmcs[10] = 0x2000;
    context.vmcs[12] = 2;
    context.vmcs[13] = 0x4000;
    unsafe { test_event_advance(&mut context) };
    assert_eq!(context.vmcs[13], 0x4000);
}

#[test]
fn ept_retry_restores_iret_nmi_blocking_only_for_ept() {
    for (reason, vectoring, expected) in [
        (48, 0, 8),
        (10, 0, 0),
        (48, 0x8000_0202, 0),
    ] {
        let mut context = EventContext {
            reason,
            qualification: 0x1000,
            ..Default::default()
        };
        context.vmcs[0] = vectoring;
        context.vmcs[1] = 0x20;
        unsafe { test_event_retry(&mut context) };
        assert_eq!(context.vmcs[2], expected);
    }
}

#[test]
fn retry_preserves_interrupted_event_metadata() {
    let mut context = EventContext {
        reason: 48,
        ..Default::default()
    };
    context.vmcs[0] = 0x8000_0b0e;
    context.vmcs[4] = 0x1234;
    unsafe { test_event_retry(&mut context) };
    assert_eq!(context.vmcs[3], 0x8000_0b0e);
    assert_eq!(context.vmcs[5], 0x1234);

    context.vmcs[0] = 0x8000_0403;
    context.vmcs[3] = 0;
    context.vmcs[6] = 4;
    unsafe { test_event_retry(&mut context) };
    assert_eq!(context.vmcs[3], 0x8000_0403);
    assert_eq!(context.vmcs[7], 4);
}

#[test]
fn interception_retry_restores_nmi_blocking_after_an_ept_exit_during_iret() {
    let mut context = EventContext {
        reason: 48,
        qualification: 0x1000,
        ..Default::default()
    };
    context.vmcs[1] = 0x20;
    unsafe { test_event_interception_retry(&mut context) };
    assert_eq!(context.vmcs[2], 8);
}

#[test]
fn exception_reinjection_preserves_error_codes_and_discards_exit_only_bits() {
    for event in [0x8000_0b0d, 0x8000_0b0e, 0x8000_1b0e] {
        let mut context = EventContext::default();
        context.vmcs[17] = event;
        context.vmcs[16] = 0x1234;
        context.vmcs[5] = 0xdead;
        unsafe { test_event_exception(&mut context) };
        assert_eq!(context.vmcs[3], event & 0x8000_0fff);
        assert_eq!(context.vmcs[5], 0x1234);
    }
}

#[test]
fn intercepted_page_fault_sets_cr2_even_when_delivery_combines_into_double_fault() {
    for vectoring in [0, 0x8000_0b0e] {
        let mut context = EventContext {
            qualification: 0xffff_8000_1234_5000,
            cr2: 0xdead_beef,
            ..Default::default()
        };
        context.vmcs[17] = 0x8000_0b0e;
        context.vmcs[0] = vectoring;
        context.vmcs[8] = 1;
        unsafe { test_event_exception(&mut context) };
        assert_eq!(context.cr2, context.qualification);
        assert_eq!(context.vmcs[3], if vectoring == 0 { 0x8000_0b0e } else { 0x8000_0b08 });
    }
}

#[test]
fn non_page_fault_reinjection_preserves_cr2() {
    for event in [0x8000_0b0d, 0x8000_0301, 0x8000_0603] {
        let mut context = EventContext {
            qualification: u64::MAX,
            cr2: 0x1234_5000,
            ..Default::default()
        };
        context.vmcs[17] = event;
        unsafe { test_event_exception(&mut context) };
        assert_eq!(context.cr2, 0x1234_5000);
    }
}

#[test]
fn software_exception_reinjection_preserves_the_original_instruction_length() {
    for (event, length) in [(0x8000_0603, 1), (0x8000_0501, 1), (0x8000_0604, 2)] {
        let mut context = EventContext::default();
        context.vmcs[17] = event;
        context.vmcs[6] = length;
        context.vmcs[7] = 15;
        unsafe { test_event_exception(&mut context) };
        assert_eq!(context.vmcs[3], event);
        assert_eq!(context.vmcs[7], length);
    }
}

#[test]
fn debug_exception_reinjection_clears_general_detect_and_branch_debug_controls() {
    for event in [0x8000_0301, 0x8000_0501] {
        let mut context = EventContext::default();
        context.vmcs[17] = event;
        context.vmcs[18] = 0xf_2401;
        context.vmcs[12] = 0x5fc3;
        context.vmcs[11] = 0x302;
        unsafe { test_event_exception(&mut context) };
        assert_eq!((context.vmcs[18], context.vmcs[12]), (0xf_0401, 0x5fc0), "event={event:x}");
        assert_eq!(context.vmcs[11], 0x302);
        assert_eq!(context.vmcs[3], event);
    }
}

#[test]
fn other_exception_reinjection_preserves_guest_debug_controls() {
    for event in [0x8000_0b0d, 0x8000_0603, 0x8000_0502] {
        let mut context = EventContext::default();
        context.vmcs[17] = event;
        context.vmcs[18] = 0xf_2401;
        context.vmcs[12] = 0x5fc3;
        unsafe { test_event_exception(&mut context) };
        assert_eq!(context.vmcs[18], 0xf_2401);
        assert_eq!(context.vmcs[12], 0x5fc3);
    }
}

#[test]
fn emulated_general_detect_injects_debug_with_native_controls_and_unretired_rip() {
    let mut context = EventContext::default();
    context.vmcs[18] = 0x2400;
    context.vmcs[12] = 0x5fc3;
    context.vmcs[14] = 0x400000;
    context.vmcs[11] = 0x302;
    unsafe { test_event_debug(&mut context) };
    assert_eq!(context.vmcs[3], 0x8000_0301);
    assert_eq!(context.vmcs[18], 0x400);
    assert_eq!(context.vmcs[12], 0x5fc0);
    assert_eq!(context.vmcs[14], 0x400000);
    assert_eq!(context.vmcs[11], 0x302);
}

#[test]
fn intercepted_fault_during_delivery_uses_the_double_fault_matrix() {
    let mut context = EventContext::default();
    context.vmcs[17] = 0x8000_0b0d;
    context.vmcs[0] = 0x8000_0b0e;
    context.vmcs[8] = 1;
    unsafe { test_event_exception(&mut context) };
    assert_eq!(context.vmcs[3], 0x8000_0b08);
    assert_eq!(context.vmcs[5], 0);
}

#[test]
fn exception_retry_restores_nmi_blocking_only_when_the_exit_reports_it() {
    for (event, vectoring, pin, expected) in [
        (0x8000_1301, 0, 0x20, 8),
        (0x8000_0301, 0, 0x20, 0),
        (0x8000_1301, 0x8000_0303, 0x20, 0),
        (0x8000_1b08, 0, 0x20, 0),
        (0x8000_1301, 0, 0, 0),
    ] {
        let mut context = EventContext::default();
        context.vmcs[17] = event;
        context.vmcs[0] = vectoring;
        context.vmcs[1] = pin;
        unsafe { test_event_exception(&mut context) };
        assert_eq!(context.vmcs[2], expected);
        assert_eq!(context.vmcs[3] & 0x1000, 0);
    }
}

#[test]
fn retry_combines_only_architectural_double_fault_pairs() {
    let cases = [
        (13, 13, 0x8000_0b08, 0),
        (13, 14, 0x8000_0b0e, 0),
        (14, 13, 0x8000_0b08, 0),
        (14, 14, 0x8000_0b08, 0),
        (3, 13, 0x8000_0b0d, 0),
        (8, 13, 0, 2),
    ];
    for (first, second, expected_event, expected_activity) in cases {
        let mut context = EventContext {
            reason: 48,
            ..Default::default()
        };
        context.vmcs[0] = 0x8000_0300 | first;
        context.vmcs[3] = 0x8000_0b00 | second;
        context.vmcs[8] = 1;
        unsafe { test_event_retry(&mut context) };
        assert_eq!((context.vmcs[3], context.vmcs[9]), (expected_event, expected_activity));
    }
}

#[test]
fn late_host_nmi_arms_exit_and_invalidates_l2_control_cache() {
    let mut context = ArmContext {
        l2_active: 1,
        control_cache_valid: [u64::MAX; 2],
        root_vmx_active: 1,
        ..Default::default()
    };
    unsafe { test_host_arm_nmi_window(&mut context) };
    assert_eq!(context.primary_controls, 1 << 22);
    assert_eq!(context.control_cache_valid, [0; 2]);
    let mut inactive = ArmContext::default();
    unsafe { test_host_arm_nmi_window(&mut inactive) };
    assert_eq!(inactive.primary_controls, 0);
}

#[test]
fn nmi_window_reflects_physical_nmi_to_l1_when_requested() {
    let mut context = WindowContext {
        pending: 1,
        l2_active: 1,
        l1_pin_controls: 8,
        reason: 8,
        qualification: 0x1000,
        instruction_len: 5,
        ..Default::default()
    };
    unsafe { test_nested_nmi_window(&mut context) };
    assert_eq!(context.result, 1);
    assert_eq!(context.pending, 0);
    assert_eq!(context.nmi_exit_pending, 1);
    assert_eq!(context.vmcs02_launched, 1);
    assert_eq!((context.reason, context.qualification, context.instruction_len), (0, 0, 0));
}

#[test]
fn nmi_after_vmcs01_snapshot_is_reflected_from_each_l2_entry_path() {
    for (launched, prepare_entry) in [
        (
            0,
            test_nested_l2_launch_entry as unsafe extern "C" fn(&mut WindowContext),
        ),
        (
            1,
            test_nested_l2_resume_entry as unsafe extern "C" fn(&mut WindowContext),
        ),
    ] {
        let mut vmcs01 = ArmContext {
            primary_controls: 1 << 28,
            root_vmx_active: 1,
            ..Default::default()
        };
        let primary_snapshot = vmcs01.primary_controls;
        unsafe { test_host_arm_nmi_window(&mut vmcs01) };
        assert_ne!(vmcs01.primary_controls & (1 << 22), 0);

        let mut vmcs02 = WindowContext {
            pending: 1,
            l2_active: 1,
            l1_pin_controls: 8,
            vmcs02_launched: launched,
            control_cache_valid: [u64::MAX; 2],
            primary_controls: primary_snapshot,
            ..Default::default()
        };
        unsafe { prepare_entry(&mut vmcs02) };
        assert_eq!(vmcs02.pending, 1);
        assert_eq!(vmcs02.entry_intr_info, 0);
        assert_eq!(vmcs02.primary_controls, primary_snapshot | (1 << 22));
        assert_eq!(vmcs02.control_cache_valid, [0; 2]);

        unsafe { test_nested_nmi_window(&mut vmcs02) };
        assert_eq!(vmcs02.result, 1);
        assert_eq!(vmcs02.pending, 0);
        assert_eq!(vmcs02.nmi_exit_pending, 1);
        assert_eq!(vmcs02.vmcs02_launched, 1);
        assert_eq!(vmcs02.primary_controls, primary_snapshot);
    }
}

#[test]
fn intercepted_nmi_preserves_the_event_prepared_by_l1() {
    let mut context = WindowContext {
        pending: 1,
        l2_active: 1,
        l1_pin_controls: 8,
        entry_intr_info: 0x8000_0b0e,
        control_cache_valid: [u64::MAX; 2],
        ..Default::default()
    };
    unsafe { test_deliver_pending_nmi(&mut context) };
    assert_eq!(context.pending, 1);
    assert_eq!(context.entry_intr_info, 0x8000_0b0e);
    assert_eq!(context.primary_controls, 1 << 22);
    assert_eq!(context.control_cache_valid, [0; 2]);
}

#[test]
fn pending_nmi_is_injected_into_a_guest_without_an_l1_intercept() {
    for (l2_active, l1_pin_controls) in [(0, 8), (1, 0)] {
        let mut context = WindowContext {
            pending: 1,
            l2_active,
            l1_pin_controls,
            activity: 1,
            ..Default::default()
        };
        unsafe { test_deliver_pending_nmi(&mut context) };
        assert_eq!(context.pending, 0);
        assert_eq!(context.entry_intr_info, 0x8000_0202);
        assert_eq!(context.activity, 0);
    }
}

#[test]
fn blocked_nmi_preserves_pending_state_and_arms_a_window() {
    for (entry_intr_info, interruptibility, pending_debug) in [
        (0x8000_0b0e, 0, 0),
        (0, 1, 0),
        (0, 2, 0),
        (0, 8, 0),
        (0, 0, 0x1000),
        (0, 0, 0x4000),
    ] {
        let mut context = WindowContext {
            pending: 1,
            l2_active: 1,
            entry_intr_info,
            interruptibility,
            pending_debug,
            control_cache_valid: [u64::MAX; 2],
            ..Default::default()
        };
        unsafe { test_deliver_pending_nmi(&mut context) };
        assert_eq!(context.pending, 1);
        assert_eq!(context.entry_intr_info, entry_intr_info);
        assert_eq!(context.primary_controls, 1 << 22);
        assert_eq!(context.control_cache_valid, [0; 2]);
    }
}

#[test]
fn no_pending_nmi_leaves_entry_state_and_controls_unchanged() {
    let mut context = WindowContext {
        l2_active: 1,
        l1_pin_controls: 8,
        primary_controls: (1 << 28) | (1 << 22),
        control_cache_valid: [u64::MAX; 2],
        ..Default::default()
    };
    unsafe { test_deliver_pending_nmi(&mut context) };
    assert_eq!(context.pending, 0);
    assert_eq!(context.entry_intr_info, 0);
    assert_eq!(context.primary_controls, (1 << 28) | (1 << 22));
    assert_eq!(context.control_cache_valid, [u64::MAX; 2]);
}
