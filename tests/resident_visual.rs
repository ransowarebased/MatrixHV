use core::arch::global_asm;

const WIDTH: usize = 512;
const HEIGHT: usize = 384;
const BACKGROUND: u32 = 0x1234_5678;
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[repr(C)]
#[derive(Default)]
struct TimerContext {
    interval_tsc: u64,
    rate: u64,
    deadline_tsc: u64,
    samples: u64,
    expired: u64,
    pin_controls: u64,
    cached_pin_controls: u64,
    event_context: *mut EventContext,
    snapshots: u64,
}

global_asm!(
    include_str!("resident-timer.S"),
    b_diagnostic_interval = const core::mem::offset_of!(TimerContext, interval_tsc),
    b_diagnostic_rate = const core::mem::offset_of!(TimerContext, rate),
    b_diagnostic_deadline = const core::mem::offset_of!(TimerContext, deadline_tsc),
    b_diagnostic_samples = const core::mem::offset_of!(TimerContext, samples),
    b_diagnostic_expired = const core::mem::offset_of!(TimerContext, expired),
    b_nested_vmcs01_pin_based_controls = const core::mem::offset_of!(TimerContext, cached_pin_controls),
    b_event_context = const core::mem::offset_of!(TimerContext, event_context),
    test_pin_controls = const core::mem::offset_of!(TimerContext, pin_controls),
    test_snapshot_count = const core::mem::offset_of!(TimerContext, snapshots),
    event_ebs_seen = const core::mem::offset_of!(EventContext, exit_boot_services_seen),
    event_diagnostic_halted = const core::mem::offset_of!(EventContext, diagnostic_halted),
    event_visual_deadline = const core::mem::offset_of!(EventContext, visual_deadline),
    pin_based_vm_exec_control = const 0x4000,
    vmx_preemption_timer_value = const 0x482e,
);

#[repr(C)]
struct EventContext {
    telemetry_enabled: u64,
    diagnostic_halted: u64,
    exit_boot_services_seen: u64,
    virtual_address_change_seen: u64,
    visual_base: u64,
    visual_stride_bytes: u64,
    host_fault_vector: u64,
    host_fault_rip: u64,
    host_fault_error_code: u64,
    host_fault_address: u64,
    nmi_pending: u64,
    sync_nmi: u64,
    nmi_count: u64,
    tsc_hz: u64,
    visual_deadline: u64,
}

#[repr(C)]
#[derive(Default)]
struct GpFrameTest {
    fault_rip: u64,
    error_code: u64,
    input_rax: u64,
    input_rdx: u64,
    recovered_rip: u64,
    recovered_rax: u64,
    recovered_rdx: u64,
    unhandled: u64,
}

global_asm!(
    include_str!("resident-visual.S"),
    event_visual_base = const core::mem::offset_of!(EventContext, visual_base),
    event_diagnostic_halted = const core::mem::offset_of!(EventContext, diagnostic_halted),
    event_visual_stride_bytes = const core::mem::offset_of!(EventContext, visual_stride_bytes),
    event_host_fault_vector = const core::mem::offset_of!(EventContext, host_fault_vector),
    event_host_fault_rip = const core::mem::offset_of!(EventContext, host_fault_rip),
    event_host_fault_error_code = const core::mem::offset_of!(EventContext, host_fault_error_code),
    event_host_fault_address = const core::mem::offset_of!(EventContext, host_fault_address),
    b_nmi_pending = const core::mem::offset_of!(EventContext, nmi_pending),
    b_nested_eptp_sync_nmi = const core::mem::offset_of!(EventContext, sync_nmi),
    b_nmi_count = const core::mem::offset_of!(EventContext, nmi_count),
    b_telemetry_enabled = const core::mem::offset_of!(EventContext, telemetry_enabled),
    visual_marker_step_bytes = const MARKER_STEP * 4,
    visual_marker_row_step = const MARKER_ROW_STEP,
    visual_marker_side = const MARKER_SIDE,
    visual_hex_y = const HEX_Y,
    visual_hex_row_step = const HEX_ROW_STEP,
    visual_hex_last_row = const HEX_ROWS - 1,
    visual_hex_column_step_bytes = const HEX_COLUMN_STEP * 4,
    log_framebuffer_sink = const 2,
    log_serial_sink = const 1,
    event_ebs_seen = const core::mem::offset_of!(EventContext, exit_boot_services_seen),
    event_va_seen = const core::mem::offset_of!(EventContext, virtual_address_change_seen),
    event_tsc_hz = const core::mem::offset_of!(EventContext, tsc_hz),
    event_visual_deadline = const core::mem::offset_of!(EventContext, visual_deadline),
);

unsafe extern "win64" {
    fn test_dispatch_timer(context: *mut TimerContext);
    static mut test_visual_tsc: u64;
    fn test_claim_diagnostic(context: *mut EventContext) -> u64;
    fn matrixhv_resident_ebs_callback(event: usize, context: *mut EventContext);
    fn matrixhv_resident_va_callback(event: usize, context: *mut EventContext);
    fn test_set_backend(backend: u8);
    fn test_copy_serial(buffer: *mut u8, capacity: usize) -> usize;
    fn test_emit_value(context: *const EventContext, value: u64, row: u32);
    fn test_reload_timer(context: *const TimerContext, now: u64, result: *mut [u64; 2]);
    fn test_paint_stage(context: *const EventContext, index: u32);
    fn test_paint_byte(context: *const EventContext, value: u32, first_index: u32);
    fn test_paint_hex(context: *const EventContext, value: u64, row: u32);
    fn test_msr_fault_fixup(fault_rip: u64) -> u64;
    fn test_read_fault_rip() -> u64;
    fn test_write_fault_rip() -> u64;
    fn test_xsetbv_fault_rip() -> u64;
    fn test_fault_resume_rip() -> u64;
    fn test_gp_frame(frame: *mut GpFrameTest);
    fn test_exception_frame(
        vector: u32,
        context: *mut EventContext,
        error_code: u64,
        fault_rip: u64,
    );
}

#[test]
fn serial_sink_formats_shared_fields_without_writing_the_framebuffer() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
    let event_context = context(&mut pixels);
    unsafe {
        test_set_backend(1);
        test_emit_value(&event_context, 31, 1);
        test_emit_value(&event_context, 0x1234, 24);
        test_emit_value(&event_context, 0x3456, 33);
        let mut bytes = [0u8; 512];
        let length = test_copy_serial(bytes.as_mut_ptr(), bytes.len());
        assert_eq!(
            std::str::from_utf8(&bytes[..length]).unwrap(),
            " reason=0x000000000000001F rsp=0x0000000000001234 host_cr3=0x0000000000003456"
        );
        test_set_backend(2);
    }
    assert!(pixels.iter().all(|&pixel| pixel == BACKGROUND));
}

#[test]
fn framebuffer_sink_renders_shared_fields_without_serial_output() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut actual = vec![BACKGROUND; WIDTH * HEIGHT];
    let mut expected = actual.clone();
    let actual_context = context(&mut actual);
    let expected_context = context(&mut expected);
    unsafe {
        test_emit_value(&actual_context, 0x1234, 19);
        test_paint_hex(&expected_context, 0x1234, 19);
        let mut bytes = [0u8; 512];
        assert_eq!(test_copy_serial(bytes.as_mut_ptr(), bytes.len()), 0);
    }
    assert_eq!(actual, expected);
    assert!(actual.iter().any(|&pixel| pixel != BACKGROUND));
}

#[test]
fn valid_serial_does_not_disable_framebuffer_diagnostics() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut actual = vec![BACKGROUND; WIDTH * HEIGHT];
    let mut expected = actual.clone();
    let actual_context = context(&mut actual);
    let expected_context = context(&mut expected);
    unsafe {
        test_set_backend(3);
        test_emit_value(&actual_context, 0x1234, 19);
        let mut bytes = [0u8; 512];
        let length = test_copy_serial(bytes.as_mut_ptr(), bytes.len());
        assert_eq!(
            std::str::from_utf8(&bytes[..length]).unwrap(),
            " efer=0x0000000000001234"
        );
        test_set_backend(2);
        test_paint_hex(&expected_context, 0x1234, 19);
    }
    assert_eq!(actual, expected);
    assert!(actual.iter().any(|&pixel| pixel != BACKGROUND));
}

#[test]
fn serial_mirror_does_not_draw_over_the_preboot_password_prompt() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
    let mut event_context = context(&mut pixels);
    event_context.exit_boot_services_seen = 0;
    unsafe {
        test_set_backend(3);
        test_emit_value(&event_context, 0x1234, 19);
        let mut bytes = [0u8; 512];
        let length = test_copy_serial(bytes.as_mut_ptr(), bytes.len());
        assert_eq!(
            std::str::from_utf8(&bytes[..length]).unwrap(),
            " efer=0x0000000000001234"
        );
        test_set_backend(2);
    }
    assert!(pixels.iter().all(|&pixel| pixel == BACKGROUND));
}

#[test]
fn disabled_logger_suppresses_both_sinks_and_serial_mode_suppresses_painting() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
    let event_context = context(&mut pixels);
    unsafe {
        for backend in [0, 1] {
            test_set_backend(backend);
            test_paint_stage(&event_context, 4);
            test_paint_byte(&event_context, 0xff, 5);
            test_paint_hex(&event_context, u64::MAX, 0);
            if backend == 0 {
                test_emit_value(&event_context, u64::MAX, 0);
            }
            let mut bytes = [0u8; 512];
            assert_eq!(test_copy_serial(bytes.as_mut_ptr(), bytes.len()), 0);
        }
        test_set_backend(2);
    }
    assert!(pixels.iter().all(|&pixel| pixel == BACKGROUND));
}

#[test]
fn boot_timer_reload_preserves_deadline_and_clamps_hardware_ticks() {
    let _guard = TEST_LOCK.lock().unwrap();
    for (deadline_tsc, now, rate, expected) in [
        (10_000, 1_000, 3, 1_125),
        (10_000, 8_000, 3, 250),
        (10_000, 9_999, 0, 2),
        (10_000, 10_000, 0, 2),
        (10_000, 10_001, 0, 2),
        (u64::MAX, 0, 0, u64::from(u32::MAX)),
        (0x1_0000_4000, 0x1_0000_0000, 3, 0x800),
    ] {
        let context = TimerContext {
            interval_tsc: 1_000,
            rate,
            deadline_tsc,
            ..Default::default()
        };
        let mut result = [u64::MAX; 2];
        unsafe { test_reload_timer(&context, now, &mut result) };
        assert_eq!(result, [expected, 0x482e]);
        assert_eq!(context.deadline_tsc, deadline_tsc);
    }
}

#[test]
fn disabled_boot_timer_does_not_access_unsupported_vmcs_field() {
    let _guard = TEST_LOCK.lock().unwrap();
    let context = TimerContext {
        interval_tsc: 0,
        rate: 0,
        deadline_tsc: 10_000,
        ..Default::default()
    };
    let mut result = [u64::MAX; 2];
    unsafe { test_reload_timer(&context, 1_000, &mut result) };
    assert_eq!(result, [u64::MAX; 2]);
}

#[test]
fn boot_timer_retires_after_the_visual_deadline() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
    let mut event_context = context(&mut pixels);
    event_context.visual_deadline = 5_000;
    let mut timer = TimerContext {
        interval_tsc: 100,
        pin_controls: 1 << 6,
        cached_pin_controls: 1 << 6,
        event_context: &mut event_context,
        ..Default::default()
    };
    unsafe {
        test_visual_tsc = 4_999;
        test_dispatch_timer(&mut timer);
    }
    assert_eq!(timer.samples, 1);
    assert_eq!(timer.snapshots, 1);
    assert_eq!(timer.expired, 0);
    unsafe {
        test_visual_tsc = 5_000;
        test_dispatch_timer(&mut timer);
    }
    assert_eq!(timer.interval_tsc, 0);
    assert_eq!(timer.pin_controls & (1 << 6), 0);
    assert_eq!(timer.cached_pin_controls & (1 << 6), 0);
    assert_eq!(timer.expired, 1);
    assert_eq!(event_context.visual_base, 0);
    unsafe { test_set_backend(2) };
}

fn context(pixels: &mut [u32]) -> EventContext {
    EventContext {
        telemetry_enabled: 1,
        nmi_pending: 0,
        sync_nmi: 0,
        nmi_count: 0,
        tsc_hz: 100,
        visual_deadline: u64::MAX,
        diagnostic_halted: 0,
        exit_boot_services_seen: 1,
        virtual_address_change_seen: 0,
        visual_base: pixels.as_mut_ptr().wrapping_add(WIDTH * 16 + 16) as u64,
        visual_stride_bytes: (WIDTH * 4) as u64,
        host_fault_vector: 0,
        host_fault_rip: 0,
        host_fault_error_code: 0,
        host_fault_address: 0,
    }
}

#[test]
fn runtime_callbacks_are_idempotent_and_preserve_framebuffer_diagnostics() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
    let mut event_context = context(&mut pixels);
    event_context.exit_boot_services_seen = 0;
    let original_base = event_context.visual_base;
    let original_stride = event_context.visual_stride_bytes;
    for _ in 0..2 {
        unsafe {
            matrixhv_resident_ebs_callback(0, &mut event_context);
            matrixhv_resident_va_callback(0, &mut event_context);
        }
        assert_eq!(event_context.exit_boot_services_seen, 1);
        assert_eq!(event_context.virtual_address_change_seen, 1);
        assert_eq!(event_context.visual_base, original_base);
        assert_eq!(event_context.visual_stride_bytes, original_stride);
        assert!(pixels.iter().all(|&pixel| pixel == BACKGROUND));
    }
    unsafe {
        test_set_backend(2);
        test_emit_value(&event_context, 0x1234, 2);
    }
    assert!(pixels.iter().any(|&pixel| pixel != BACKGROUND));
}

#[test]
fn framebuffer_window_starts_at_ebs_and_expires_after_forty_seconds() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
    let mut event_context = context(&mut pixels);
    event_context.exit_boot_services_seen = 0;
    event_context.visual_deadline = 0;
    unsafe {
        test_visual_tsc = 1000;
        test_set_backend(3);
        test_paint_stage(&event_context, 1);
        test_paint_hex(&event_context, 1, 0);
    }
    assert!(pixels.iter().all(|&pixel| pixel == BACKGROUND));
    unsafe { matrixhv_resident_ebs_callback(0, &mut event_context) };
    assert_eq!(event_context.visual_deadline, 5000);
    unsafe {
        test_visual_tsc = 4999;
        matrixhv_resident_ebs_callback(0, &mut event_context);
        matrixhv_resident_va_callback(0, &mut event_context);
        test_paint_hex(&event_context, u64::MAX, 0);
    }
    assert_eq!(event_context.visual_deadline, 5000);
    assert!(pixels.iter().any(|&pixel| pixel != BACKGROUND));
    pixels.fill(BACKGROUND);
    unsafe {
        test_visual_tsc = 5000;
        test_paint_stage(&event_context, 1);
        test_paint_byte(&event_context, 0xff, 5);
        test_paint_hex(&event_context, u64::MAX, 0);
        test_emit_value(&event_context, 0x1234, 19);
        let mut bytes = [0u8; 512];
        let length = test_copy_serial(bytes.as_mut_ptr(), bytes.len());
        assert_eq!(std::str::from_utf8(&bytes[..length]).unwrap(),
                   " efer=0x0000000000001234");
    }
    assert_eq!(event_context.visual_base, 0);
    assert!(pixels.iter().all(|&pixel| pixel == BACKGROUND));
    unsafe {
        // A repeated notification or a clock rollback must not revive the aperture.
        test_visual_tsc = 1000;
        matrixhv_resident_ebs_callback(0, &mut event_context);
        test_paint_stage(&event_context, 1);
        test_set_backend(2);
    }
    assert_eq!(event_context.visual_base, 0);
    assert_eq!(event_context.visual_deadline, 5000);
    assert!(pixels.iter().all(|&pixel| pixel == BACKGROUND));
}

fn check_pixels(pixels: &[u32], marker_indices: &[usize]) {
    for (offset, &pixel) in pixels.iter().enumerate() {
        let x = offset % WIDTH;
        let y = offset / WIDTH;
        let marked = marker_indices.iter().any(|&index| {
            let (row, column) = if index == 29 {
                (0, 4)
            } else if index <= 4 {
                (0, index - 1)
            } else {
                (1 + (index - 5) / 8, (index - 5) % 8)
            };
            let marker_x = 16 + column * MARKER_STEP;
            let marker_y = 16 + row * MARKER_ROW_STEP;
            (marker_x..marker_x + MARKER_SIDE).contains(&x)
                && (marker_y..marker_y + MARKER_SIDE).contains(&y)
        });
        assert_eq!(
            pixel,
            if marked { u32::MAX } else { BACKGROUND },
            "pixel ({x}, {y})"
        );
    }
}

#[test]
fn all_marker_positions_stay_inside_their_rectangles() {
    let _guard = TEST_LOCK.lock().unwrap();
    for index in 1..=29 {
        let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
        let event_context = context(&mut pixels);
        unsafe { test_paint_stage(&event_context, index) };
        check_pixels(&pixels, &[index as usize]);
    }
}

#[test]
fn invalid_marker_indices_do_not_write_pixels() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
    let event_context = context(&mut pixels);
    for index in [0, 30, u32::MAX] {
        unsafe { test_paint_stage(&event_context, index) };
    }
    check_pixels(&pixels, &[]);
}

#[test]
fn byte_rows_preserve_bit_order_and_ignore_high_bits() {
    let _guard = TEST_LOCK.lock().unwrap();
    for first_index in [5, 13] {
        let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
        let event_context = context(&mut pixels);
        unsafe { test_paint_byte(&event_context, 0xdead_bea5, first_index) };
        let expected = [0, 2, 5, 7].map(|bit| first_index as usize + bit);
        check_pixels(&pixels, &expected);
    }
}

#[test]
fn missing_framebuffer_is_ignored() {
    let _guard = TEST_LOCK.lock().unwrap();
    let event_context = EventContext {
        telemetry_enabled: 1,
        nmi_pending: 0,
        sync_nmi: 0,
        nmi_count: 0,
        tsc_hz: 100,
        visual_deadline: u64::MAX,
        diagnostic_halted: 0,
        exit_boot_services_seen: 1,
        virtual_address_change_seen: 0,
        visual_base: 0,
        visual_stride_bytes: (WIDTH * 4) as u64,
        host_fault_vector: 0,
        host_fault_rip: 0,
        host_fault_error_code: 0,
        host_fault_address: 0,
    };
    unsafe {
        test_paint_stage(&event_context, 4);
        test_paint_byte(&event_context, 0xff, 5);
        test_paint_hex(&event_context, u64::MAX, 0);
    }
}

#[test]
fn hex_rows_render_complete_values_and_clear_previous_pixels() {
    let _guard = TEST_LOCK.lock().unwrap();
    const GLYPHS: [[u8; 5]; 16] = [
        [7, 5, 5, 5, 7],
        [2, 6, 2, 2, 7],
        [7, 1, 7, 4, 7],
        [7, 1, 7, 1, 7],
        [5, 5, 7, 1, 1],
        [7, 4, 7, 1, 7],
        [7, 4, 7, 5, 7],
        [7, 1, 2, 2, 2],
        [7, 5, 7, 5, 7],
        [7, 5, 7, 1, 7],
        [7, 5, 7, 5, 5],
        [6, 5, 6, 5, 6],
        [7, 4, 4, 4, 7],
        [6, 5, 5, 5, 6],
        [7, 4, 7, 4, 7],
        [7, 4, 7, 4, 4],
    ];
    for row in 0..HEX_ROWS {
        for value in [0, u64::MAX, 0x0123_4567_89ab_cdef] {
            let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
            let event_context = context(&mut pixels);
            unsafe {
                test_paint_hex(&event_context, u64::MAX, row as u32);
                test_paint_hex(&event_context, value, row as u32);
            }
            let text = format!("{:X} {value:016X}", row % 16);
            let first_x = 16 + row / 16 * HEX_COLUMN_STEP;
            let first_y = 16 + HEX_Y + row % 16 * HEX_ROW_STEP;
            for (offset, &pixel) in pixels.iter().enumerate() {
                let x = offset % WIDTH;
                let y = offset / WIDTH;
                let expected = if (first_x..first_x + 18 * 8).contains(&x)
                    && (first_y..first_y + 10).contains(&y)
                {
                    let cell = (x - first_x) / 8;
                    let glyph_x = (x - first_x) % 8;
                    let character = text.as_bytes()[cell] as char;
                    let lit = character.to_digit(16).is_some_and(|digit| {
                        glyph_x < 6
                            && GLYPHS[digit as usize][(y - first_y) / 2] & (1 << (2 - glyph_x / 2))
                                != 0
                    });
                    if lit { u32::MAX } else { 0 }
                } else {
                    BACKGROUND
                };
                assert_eq!(
                    pixel, expected,
                    "row {row}, value {value:X}, pixel ({x}, {y})"
                );
            }
        }
    }
}

#[test]
fn invalid_hex_rows_do_not_write_pixels() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
    let event_context = context(&mut pixels);
    for row in [HEX_ROWS as u32, u32::MAX] {
        unsafe { test_paint_hex(&event_context, u64::MAX, row) };
    }
    check_pixels(&pixels, &[]);
}

#[test]
fn msr_fault_recovery_matches_only_guarded_instruction_addresses() {
    let _guard = TEST_LOCK.lock().unwrap();
    unsafe {
        let read_rip = test_read_fault_rip();
        let write_rip = test_write_fault_rip();
        let resume_rip = test_fault_resume_rip();
        assert_ne!(read_rip, write_rip);
        assert_ne!(resume_rip, 0);
        for fault_rip in [read_rip, write_rip, test_xsetbv_fault_rip()] {
            assert_eq!(test_msr_fault_fixup(fault_rip), resume_rip);
        }
        for fault_rip in [0, u64::MAX, read_rip + 1, write_rip + 1, resume_rip] {
            assert_eq!(test_msr_fault_fixup(fault_rip), 0);
        }
    }
}

#[test]
fn gp_frame_recovery_preserves_registers_and_removes_only_the_error_code() {
    let _guard = TEST_LOCK.lock().unwrap();
    unsafe {
        let resume_rip = test_fault_resume_rip();
        for fault_rip in [
            test_read_fault_rip(),
            test_write_fault_rip(),
            test_xsetbv_fault_rip(),
            resume_rip,
        ] {
            let mut frame = GpFrameTest {
                fault_rip,
                error_code: 0,
                input_rax: 0x1122_3344_5566_7788,
                input_rdx: 0x8899_aabb_ccdd_eeff,
                ..GpFrameTest::default()
            };
            test_gp_frame(&mut frame);
            let unhandled = fault_rip == resume_rip;
            assert_eq!(frame.unhandled, u64::from(unhandled));
            assert_eq!(
                frame.recovered_rip,
                if unhandled { fault_rip } else { resume_rip }
            );
            assert_eq!(frame.recovered_rax, frame.input_rax);
            assert_eq!(frame.recovered_rdx, frame.input_rdx);
        }
    }
}

#[test]
fn every_exception_stub_preserves_vector_error_code_and_fault_rip() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
    let mut event_context = context(&mut pixels);
    for vector in 0..32 {
        event_context.diagnostic_halted = 0;
        let has_error_code = [8, 10, 11, 12, 13, 14, 17, 21, 29, 30].contains(&vector);
        let fault_rip = 0x1234_5678_90ab_cdef;
        unsafe { test_exception_frame(vector, &mut event_context, 0x55, fault_rip) };
        if vector == 2 {
            assert_eq!(event_context.nmi_pending, 1);
            assert_eq!(event_context.nmi_count, 1);
            assert_eq!(event_context.diagnostic_halted, 0);
            continue;
        }
        assert_eq!(event_context.host_fault_vector, u64::from(vector));
        assert_eq!(event_context.host_fault_rip, fault_rip);
        assert_eq!(
            event_context.host_fault_error_code,
            if has_error_code { 0x55 } else { 0 }
        );
        assert_eq!(
            event_context.host_fault_address,
            if vector == 14 { 0x1234_5678 } else { 0 }
        );
    }
}

#[test]
fn later_cpu_faults_cannot_overwrite_the_first_diagnostic() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
    let mut event_context = context(&mut pixels);
    unsafe {
        test_exception_frame(14, &mut event_context, 0x55, 0x1234);
        test_exception_frame(6, &mut event_context, 0, 0x5678);
        assert_eq!(test_claim_diagnostic(&mut event_context), 0);
    }
    assert_eq!(event_context.diagnostic_halted, 1);
    assert_eq!(event_context.host_fault_vector, 14);
    assert_eq!(event_context.host_fault_error_code, 0x55);
    assert_eq!(event_context.host_fault_rip, 0x1234);
    assert_eq!(event_context.host_fault_address, 0x1234_5678);
}
