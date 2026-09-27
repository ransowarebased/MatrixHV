core::arch::global_asm!(include_str!(
    "../builds/resident-telemetry-tests/resident-telemetry.S"
));
include!("../builds/resident-telemetry-tests/offsets.rs");

unsafe extern "win64" {
    fn test_watchdog_begin(context: *mut u64);
    fn test_watchdog_complete(context: *mut u64);
    fn test_counter(context: *mut u64) -> u64;
    fn test_nested_failure_record(context: *mut u64, kind: u64, code: u64);
    fn test_diagnostic(context: *mut u64, shared: *mut u64, subleaf: u32, result: *mut u32);
}

fn diagnostic(context: &mut [u64; 512], shared: &mut [u64; 512], subleaf: u32) -> [u32; 4] {
    let mut result = [0; 4];
    unsafe {
        test_diagnostic(
            context.as_mut_ptr(),
            shared.as_mut_ptr(),
            subleaf,
            result.as_mut_ptr(),
        );
    }
    result
}

#[test]
fn telemetry_queries_do_not_advance_sequence_or_overwrite_last_guest() {
    let mut context = [0; 512];
    context[offset("b_telemetry_enabled")] = 1;
    context[offset("b_last_reason")] = 10;
    context[offset("b_last_rax")] = 0x4d48_5652;
    context[offset("b_watchdog_last_rip")] = 0x1234;
    unsafe {
        test_watchdog_begin(context.as_mut_ptr());
        test_watchdog_complete(context.as_mut_ptr());
    }
    assert_eq!(context[offset("b_watchdog_sequence")], 0);
    assert_eq!(context[offset("b_watchdog_last_rip")], 0x1234);
    assert_eq!(context[offset("b_watchdog_handler_returns")], 0);
}

#[test]
fn exit_transition_captures_three_states_and_counts_access_bits() {
    let mut context = [0; 512];
    context[offset("b_telemetry_enabled")] = 1;
    context[offset("b_last_reason")] = 48;
    context[offset("b_last_qualification")] = 7;
    context[offset("b_last_guest_rip")] = 0x1122;
    context[offset("b_watchdog_deadline")] = 1000;
    context[offset("b_exit_count")] = 123;
    unsafe {
        test_watchdog_begin(context.as_mut_ptr());
    }
    assert_eq!(context[offset("b_watchdog_sequence")], 1);
    assert_eq!(context[offset("b_watchdog_phase")], 3);
    for name in [
        "b_ept_violation_read",
        "b_ept_violation_write",
        "b_ept_violation_execute",
    ] {
        assert_eq!(context[offset(name)], 1);
    }
    unsafe {
        test_watchdog_complete(context.as_mut_ptr());
    }
    assert_eq!(context[offset("b_watchdog_sequence")], 2);
    assert_eq!(context[offset("b_watchdog_phase")], 1);
    assert_eq!(context[offset("b_watchdog_exit_count")], 123);
    for name in ["b_watchdog_before", "b_watchdog_after", "b_watchdog_resume"] {
        assert_eq!(context[offset(name)], 0x123456789abcdef0);
        assert_eq!(context[offset(name) + 1], 0xabcdef0123456780);
        assert_eq!(context[offset(name) + 6], 0x500);
    }
}

#[test]
fn expired_lease_disables_capture_and_first_entry_failure_is_sealed() {
    let mut context = [0; 512];
    context[offset("b_telemetry_enabled")] = 1;
    context[offset("b_watchdog_deadline")] = 99;
    context[offset("b_last_reason")] = 0x8000_0021;
    unsafe {
        test_watchdog_begin(context.as_mut_ptr());
    }
    assert_eq!(context[offset("b_watchdog_deadline")], 0);
    assert_eq!(context[offset("b_watchdog_before")], 0);
    assert_eq!(context[offset("b_entry_failure_state")], 2);
    assert_eq!(context[offset("b_entry_failure_exit")], 0x8000_0021);
    assert_eq!(context[offset("b_entry_failure_tsc")], 100);
    context[offset("b_entry_failure_guest")] = 0xfeed;
    unsafe {
        test_watchdog_begin(context.as_mut_ptr());
    }
    assert_eq!(context[offset("b_entry_failure_guest")], 0xfeed);
}

#[test]
fn remote_cpu_queries_preserve_64_bit_values_and_validate_target() {
    let mut context = [0; 512];
    let mut remote = [0u64; 512];
    let mut shared = [0; 512];
    shared[offset("event_cpu_contexts") + 1] = remote.as_mut_ptr() as u64;
    remote[offset("b_watchdog_last_reason")] = 0x1122334455667788;
    remote[offset("b_watchdog_last_rip")] = 0x8877665544332211;
    std::hint::black_box(&remote);
    assert_eq!(
        diagnostic(&mut context, &mut shared, (2 << 16) | 8),
        [0x55667788, 0x11223344, 0x44332211, 0x88776655]
    );
    assert_eq!(
        diagnostic(&mut context, &mut shared, (65 << 16) | 8),
        [0; 4]
    );
    assert_eq!(diagnostic(&mut context, &mut shared, (3 << 16) | 8), [0; 4]);
    assert_eq!(diagnostic(&mut context, &mut shared, 36), [2, 0, 0, 0]);
}

#[test]
fn nested_failure_trace_exposes_each_record_word_pair() {
    let mut context = [0; 512];
    let mut shared = [0; 512];
    context[offset("b_nested_failure_count")] = 1;
    let trace = offset("b_nested_failure_trace");
    context[trace] = 0x1122334455667788;
    context[trace + 1] = 25;
    context[trace + 2] = 1;
    context[trace + 3] = 12;
    context[trace + 4] = 0x2806;
    context[trace + 5] = 0x1234;
    assert_eq!(diagnostic(&mut context, &mut shared, 0x100), [1, 0, 32, 0]);
    assert_eq!(
        diagnostic(&mut context, &mut shared, 0x101),
        [0x55667788, 0x11223344, 25, 0]
    );
    assert_eq!(diagnostic(&mut context, &mut shared, 0x102), [1, 0, 12, 0]);
    assert_eq!(
        diagnostic(&mut context, &mut shared, 0x103),
        [0x2806, 0, 0x1234, 0]
    );
    assert_eq!(diagnostic(&mut context, &mut shared, 0x104), [0; 4]);
}

#[test]
fn nested_failure_recorder_captures_instruction_context_and_bounds_the_trace() {
    let mut context = [0; 512];
    let trace = offset("b_nested_failure_trace");
    context[offset("b_telemetry_active")] = 1;
    context[offset("b_nested_failure_count")] = 1;
    context[offset("b_nested_current_vmcs")] = 0x3000;
    context[offset("b_last_guest_rip")] = 0x140001234;
    context[offset("b_last_reason")] = 25;
    context[offset("b_nested_last_vmcs_field")] = 0x2806;
    context[offset("b_nested_last_operand")] = 0xabc;
    unsafe { test_nested_failure_record(context.as_mut_ptr(), 1, 12) };
    assert_eq!(
        &context[trace..trace + 6],
        &[0x140001234, 25, 1, 12, 0x2806, 0xabc]
    );
    context[offset("b_nested_failure_count")] = 2;
    context[offset("b_nested_current_vmcs")] = u64::MAX;
    unsafe { test_nested_failure_record(context.as_mut_ptr(), 1, 7) };
    assert_eq!(&context[trace + 6..trace + 10], &[0x140001234, 25, 6, 7]);
    context[offset("b_nested_failure_count")] = 33;
    unsafe { test_nested_failure_record(context.as_mut_ptr(), 1, 8) };
    assert_eq!(&context[trace + 6 * 31..trace + 6 * 32], &[0; 6]);
}

#[test]
fn watchdog_control_uses_a_15_second_lease_on_the_selected_cpu() {
    let mut context = [0; 512];
    let mut remote = [0u64; 512];
    let mut shared = [0; 512];
    shared[offset("event_cpu_contexts")] = remote.as_mut_ptr() as u64;
    remote[offset("b_watchdog_tsc_hz")] = 200;
    remote[offset("b_telemetry_enabled")] = 1;
    diagnostic(&mut context, &mut shared, (1 << 16) | 0x200);
    assert_eq!(remote[offset("b_watchdog_deadline")], 3100);
    assert_eq!(context[offset("b_watchdog_deadline")], 0);
    diagnostic(&mut context, &mut shared, (1 << 16) | 0x201);
    assert_eq!(remote[offset("b_watchdog_deadline")], 0);
}

#[test]
fn collection_is_disabled_until_enabled_and_freezes_existing_records() {
    let mut context = [0; 512];
    let mut shared = [0; 512];
    context[offset("b_last_reason")] = 48;
    context[offset("b_last_qualification")] = 7;
    context[offset("b_last_guest_rip")] = 0x1122;
    let before = context;
    unsafe {
        test_watchdog_begin(context.as_mut_ptr());
        test_watchdog_complete(context.as_mut_ptr());
    }
    assert_eq!(context, before);
    assert_eq!(diagnostic(&mut context, &mut shared, 37), [0; 4]);
    assert_eq!(diagnostic(&mut context, &mut shared, 0x202), [1, 0, 0, 0]);
    unsafe {
        test_watchdog_begin(context.as_mut_ptr());
        test_watchdog_complete(context.as_mut_ptr());
    }
    assert_eq!(context[offset("b_watchdog_sequence")], 2);
    assert_eq!(context[offset("b_watchdog_handler_returns")], 1);
    assert_eq!(context[offset("b_watchdog_last_rip")], 0x1122);
    diagnostic(&mut context, &mut shared, 0x200);
    diagnostic(&mut context, &mut shared, 0x203);
    assert_eq!(context[offset("b_watchdog_deadline")], 0);
    unsafe { test_watchdog_begin(context.as_mut_ptr()) };
    let frozen = context;
    unsafe { test_watchdog_complete(context.as_mut_ptr()) };
    assert_eq!(context, frozen);
    assert_eq!(context[offset("b_watchdog_sequence")], 2);
    assert_eq!(context[offset("b_ept_violation_execute")], 1);
    diagnostic(&mut context, &mut shared, 0x200);
    assert_eq!(context[offset("b_watchdog_deadline")], 0);
}

#[test]
fn remote_toggle_applies_to_selected_cpu_and_finishes_an_inflight_exit() {
    let mut context = [0; 512];
    let mut remote = [0u64; 512];
    let mut shared = [0; 512];
    shared[offset("event_cpu_contexts") + 1] = remote.as_mut_ptr() as u64;
    remote[offset("b_last_reason")] = 28;
    remote[offset("b_last_qualification")] = 3;
    diagnostic(&mut context, &mut shared, (2 << 16) | 0x202);
    assert_eq!(remote[offset("b_telemetry_enabled")], 1);
    assert_eq!(context[offset("b_telemetry_enabled")], 0);
    unsafe { test_watchdog_begin(remote.as_mut_ptr()) };
    diagnostic(&mut context, &mut shared, (2 << 16) | 0x203);
    unsafe { test_watchdog_complete(remote.as_mut_ptr()) };
    assert_eq!(remote[offset("b_watchdog_sequence")], 2);
    assert_eq!(remote[offset("b_cr3_exits")], 1);
    unsafe {
        test_watchdog_begin(remote.as_mut_ptr());
        test_watchdog_complete(remote.as_mut_ptr());
    }
    assert_eq!(remote[offset("b_watchdog_sequence")], 2);
    assert_eq!(
        diagnostic(&mut context, &mut shared, (65 << 16) | 0x202),
        [0; 4]
    );
    assert_eq!(remote[offset("b_telemetry_enabled")], 0);
}

#[test]
fn basic_counters_freeze_when_disabled_and_preserve_carry_flag() {
    let mut context = [0; 512];
    context[offset("b_exit_count")] = 17;
    for active in [0, 1, 0] {
        context[offset("b_telemetry_active")] = active;
        let before = context[offset("b_exit_count")];
        let flags = unsafe { test_counter(context.as_mut_ptr()) };
        assert_eq!(flags & 1, 1);
        assert_eq!(context[offset("b_exit_count")], before + active);
    }
}

#[test]
fn startup_probe_does_not_enable_user_telemetry() {
    let mut context = [0; 512];
    let mut shared = [0; 512];
    context[offset("b_telemetry_probe_active")] = 1;
    context[offset("b_last_reason")] = 10;
    unsafe {
        test_watchdog_begin(context.as_mut_ptr());
        test_watchdog_complete(context.as_mut_ptr());
    }
    assert_eq!(context[offset("b_watchdog_sequence")], 2);
    assert_eq!(diagnostic(&mut context, &mut shared, 37), [0; 4]);
    assert_ne!(diagnostic(&mut context, &mut shared, 34)[0] & (1 << 8), 0);
    context[offset("b_telemetry_probe_active")] = 0;
    unsafe {
        test_watchdog_begin(context.as_mut_ptr());
        test_watchdog_complete(context.as_mut_ptr());
    }
    assert_eq!(context[offset("b_watchdog_sequence")], 2);
}
