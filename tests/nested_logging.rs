core::arch::global_asm!(include_str!("../builds/nested-logging-tests/lifecycle.S"));
core::arch::global_asm!(include_str!("../builds/nested-logging-tests/display.S"));
include!("../builds/nested-logging-tests/offsets.rs");

unsafe extern "win64" {
    fn test_vmx_lifecycle(context: *mut u64, vmxoff: u32) -> u32;
    fn test_resident_display(event: *const u64, hexadecimal: u32);
}

fn lifecycle(probe_active: bool, telemetry_active: bool) -> u64 {
    let revision = 1_u64;
    let mut context = [0_u64; 64];
    context[offset("b_nested_l1_cr4")] = 1 << 13;
    context[offset("b_nested_feature_control")] = 5;
    context[offset("b_nested_vmx_basic")] = revision;
    context[offset("b_test_operand")] = &revision as *const u64 as u64;
    context[offset("b_test_rflags")] = 0x202 | 0x8d5;
    context[offset("b_test_rip")] = 0x1000;
    context[offset("b_telemetry_probe_active")] = u64::from(probe_active);
    context[offset("b_telemetry_active")] = u64::from(telemetry_active);

    assert_eq!(unsafe { test_vmx_lifecycle(context.as_mut_ptr(), 0) }, 0);
    assert_eq!(context[offset("b_nested_active")], 1);
    assert_eq!(context[offset("b_nested_current_vmcs")], u64::MAX);
    assert_eq!(context[offset("b_nested_instruction_error")], 0);
    assert_eq!(context[offset("b_test_rflags")], 0x202);
    assert_eq!(context[offset("b_test_rip")], 0x1003);

    context[offset("b_test_rflags")] |= 0x8d5;
    assert_eq!(unsafe { test_vmx_lifecycle(context.as_mut_ptr(), 1) }, 0);
    assert_eq!(context[offset("b_nested_active")], 0);
    assert_eq!(context[offset("b_nested_current_vmcs")], u64::MAX);
    assert_eq!(context[offset("b_test_stores")], 1);
    assert_eq!(context[offset("b_test_rflags")], 0x202);
    assert_eq!(context[offset("b_test_rip")], 0x1006);
    for name in ["b_nested_vmxon_count", "b_nested_vmxoff_count"] {
        assert_eq!(context[offset(name)], u64::from(telemetry_active));
    }
    context[offset("b_test_serial_bytes")]
}

#[test]
fn runtime_vmx_lifecycle_never_waits_for_uart_even_with_telemetry_enabled() {
    for telemetry_active in [false, true] {
        assert_eq!(lifecycle(false, telemetry_active), 0);
    }
}

#[test]
fn explicit_startup_probe_retains_serial_lifecycle_evidence() {
    assert!(lifecycle(true, true) > 0);
}

#[test]
fn firmware_display_is_writable_only_during_the_post_ebs_window() {
    for hexadecimal in [0, 1] {
        for (ebs_seen, deadline, writable) in [(0, u64::MAX, false), (1, 1001, true), (1, 1000, false)] {
            let mut framebuffer = vec![0x55aa55aa_u32; 512 * 128];
            let event = [ebs_seen, framebuffer.as_mut_ptr() as u64, 512 * 4, deadline];
            unsafe { test_resident_display(event.as_ptr(), hexadecimal) };
            assert_eq!(framebuffer.iter().any(|&pixel| pixel != 0x55aa55aa), writable);
        }
    }
}
