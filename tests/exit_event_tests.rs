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
    vmcs: [u64; 16],
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
    fn test_event_advance(context: &mut EventContext);
    fn test_event_retry(context: &mut EventContext);
    fn test_host_arm_nmi_window(context: &mut ArmContext);
    fn test_nested_nmi_window(context: &mut WindowContext);
    fn test_deliver_pending_nmi(context: &mut WindowContext);
    fn test_nested_l2_launch_entry(context: &mut WindowContext);
    fn test_nested_l2_resume_entry(context: &mut WindowContext);
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
