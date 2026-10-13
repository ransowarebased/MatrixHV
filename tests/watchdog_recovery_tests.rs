core::arch::global_asm!(include_str!("../builds/watchdog-recovery-tests/recovery.S"));

static SERIAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[repr(C)]
#[derive(Default)]
struct Serial {
    lock: u64,
    reads: u64,
    writes: u64,
    last_character: u64,
    status: u64,
}

#[repr(C)]
#[derive(Default)]
struct Invalidation {
    root: u64,
    calls: u64,
    fail_mask: u64,
    kinds: [u64; 2],
    roots: [u64; 2],
    terminal: u64,
    carry_failure: u64,
}

#[repr(C)]
struct Reset {
    io: u64,
    keyboard_busy: u64,
    reads: u64,
    writes: u64,
    ports: [u64; 4],
    values: [u64; 4],
    triple_fault: u64,
    magic: u64,
    canary: u64,
    interception: u64,
    tracking: u64,
    update_phase: u64,
    halted: u64,
    event_present: u64,
}

impl Default for Reset {
    fn default() -> Self {
        Self {
            io: 0,
            keyboard_busy: 0,
            reads: 0,
            writes: 0,
            ports: [0; 4],
            values: [0; 4],
            triple_fault: 0,
            magic: 0x4856_4556_454e_5431,
            canary: 0x4856_4556_4341_4e59,
            interception: 0,
            tracking: 0,
            update_phase: 0,
            halted: 0,
            event_present: 1,
        }
    }
}

unsafe extern "win64" {
    fn test_ept_sync(model: &mut Invalidation) -> u64;
    fn test_ept_cache(model: &mut Invalidation) -> u64;
    fn test_ept_nested(model: &mut Invalidation) -> u64;
    fn test_vpid(model: &mut Invalidation) -> u64;
    fn test_reset(model: &mut Reset);
    fn test_reset_cf9(model: &mut Reset);
    fn test_serial(model: &mut Serial, character: u64) -> u64;
    fn test_retired_serial(model: &mut Serial, operation: u64) -> u64;
    fn test_serial_enabled() -> u64;
    fn test_vmxoff_0(failure: u64) -> u64;
    fn test_vmxoff_1(failure: u64) -> u64;
    fn test_vmxoff_2(failure: u64) -> u64;
    fn test_fault_guard_0(active: u64) -> u64;
    fn test_fault_guard_1(active: u64) -> u64;
    fn test_fault_guard_2(active: u64) -> u64;
}

#[test]
fn recursive_host_faults_bypass_diagnostics_and_the_context_dependent_reset_tuple() {
    let _guard = SERIAL_LOCK.lock().unwrap();
    for operation in [test_fault_guard_0, test_fault_guard_1, test_fault_guard_2] {
        assert_eq!(unsafe { operation(0) }, 1);
        for active in [1, 3, u64::MAX] {
            assert_eq!(unsafe { operation(active) }, 0);
        }
    }
}

#[test]
fn every_native_transition_resets_on_either_vmxoff_failure_status() {
    for operation in [test_vmxoff_0, test_vmxoff_1, test_vmxoff_2] {
        for failure in [0, 1, 2] {
            assert_eq!(unsafe { operation(failure) }, u64::from(failure == 0));
        }
    }
}

#[test]
fn serial_lock_contention_and_uart_failure_retire_the_sink_with_bounded_work() {
    let _guard = SERIAL_LOCK.lock().unwrap();
    let mut owner = 0xdead_u64;
    let mut model = Serial { lock: &mut owner as *mut u64 as u64, status: 0x20, ..Default::default() };
    assert_eq!(unsafe { test_serial(&mut model, b'A' as u64) }, 1);
    assert_eq!((owner, model.reads, model.writes), (0xdead, 0, 0));
    assert_eq!(unsafe { test_serial_enabled() }, 0);
    owner = 0;
    model.status = 0;
    assert_eq!(unsafe { test_serial(&mut model, b'A' as u64) }, 1);
    assert_eq!((owner, model.reads, model.writes), (0, 8, 0));
    assert_eq!(unsafe { test_serial_enabled() }, 0);
}

#[test]
fn retiring_a_sink_on_a_peer_releases_every_owned_output_path() {
    let _guard = SERIAL_LOCK.lock().unwrap();
    for operation in 0..3 {
        let mut owner = 0_u64;
        let mut model = Serial { lock: &mut owner as *mut u64 as u64, status: 0x20, ..Default::default() };
        assert_eq!(unsafe { test_serial(&mut model, b'A' as u64) }, 0);
        assert_eq!(owner, &model as *const Serial as u64);
        assert_eq!(unsafe { test_retired_serial(&mut model, operation) }, 1);
        assert_eq!((owner, model.reads, model.writes), (0, 1, 1));
        owner = 0xdead;
        assert_eq!(unsafe { test_retired_serial(&mut model, operation) }, 1);
        assert_eq!(owner, 0xdead);
    }
}

#[test]
fn serial_success_preserves_line_ownership_until_newline_and_clears_failure_status() {
    let _guard = SERIAL_LOCK.lock().unwrap();
    let mut owner = 0_u64;
    let mut model = Serial { lock: &mut owner as *mut u64 as u64, status: 0x20, ..Default::default() };
    assert_eq!(unsafe { test_serial(&mut model, b'A' as u64) }, 0);
    assert_eq!(owner, &model as *const Serial as u64);
    assert_eq!(unsafe { test_serial(&mut model, b'\n' as u64) }, 0);
    assert_eq!((owner, model.reads, model.writes, model.last_character), (0, 2, 2, 10));
    assert_eq!(unsafe { test_serial_enabled() }, 1);
}

#[test]
fn all_resident_invalidation_paths_retry_globally_and_bound_permanent_failure() {
    for operation in [test_ept_sync, test_ept_cache, test_ept_nested, test_vpid] {
        for carry_failure in [0, 1] {
            for fail_mask in [0, 1, 3] {
                let mut model = Invalidation { root: 0x10201e, fail_mask, carry_failure, ..Default::default() };
                let result = unsafe { operation(&mut model) };
                assert_eq!(result, u64::from(fail_mask != 3));
                assert_eq!(model.terminal, u64::from(fail_mask == 3));
                assert_eq!(model.calls, if fail_mask == 0 { 1 } else { 2 });
                assert_eq!(model.kinds[0], 1);
                assert_eq!(model.roots[0], model.root);
                if fail_mask != 0 {
                    assert_eq!((model.kinds[1], model.roots[1]), (2, 0));
                }
            }
        }
    }
}

#[test]
fn reset_uses_the_validated_acpi_port_before_fallbacks() {
    let mut model = Reset { io: 0x60001, ..Default::default() };
    unsafe { test_reset(&mut model) };
    assert_eq!(model.ports, [1, 0xcf9, 0xcf9, 0x64]);
    assert_eq!(model.values, [6, 2, 6, 0xfe]);
    assert_eq!((model.triple_fault, model.halted), (0, 1));
}

#[test]
fn reset_without_acpi_never_waits_forever_for_a_busy_keyboard_controller() {
    let mut model = Reset { keyboard_busy: 2, ..Default::default() };
    unsafe { test_reset(&mut model) };
    assert_eq!(model.reads, 65536);
    assert_eq!(model.writes, 2);
    assert_eq!(&model.ports[..2], &[0xcf9, 0xcf9]);
    assert_eq!((model.triple_fault, model.halted), (0, 1));
}

#[test]
fn inactive_operations_never_authorize_a_triple_fault() {
    for interception_state in [0, 2, u64::MAX] {
        for tracking_state in [0, 2, u64::MAX] {
            for update_phase in [0, 5, 7, 8, u64::from(u32::MAX)] {
                let tracking = [0, 0, 0, tracking_state];
                let mut model = Reset {
                    interception: &interception_state as *const u64 as u64,
                    tracking: tracking.as_ptr() as u64,
                    update_phase,
                    ..Default::default()
                };
                unsafe { test_reset(&mut model) };
                assert_eq!((model.triple_fault, model.halted), (0, 1));
            }
        }
    }
}

#[test]
fn active_operations_retain_the_triple_fault_fallback() {
    for io in [0, 0x60001] {
        for keyboard_busy in [0, 2] {
            let interception = 1_u64;
            let tracking = [0_u64, 0, 0, 1];
            for operation in 0..7 {
                let mut model = Reset { io, keyboard_busy, ..Default::default() };
                match operation {
                    0 => model.interception = &interception as *const u64 as u64,
                    1 => model.tracking = tracking.as_ptr() as u64,
                    _ => model.update_phase = [1, 2, 3, 4, 6][operation - 2],
                }
                unsafe { test_reset(&mut model) };
                assert_eq!((model.triple_fault, model.halted), (1, 0));
            }
        }
    }
}

#[test]
fn missing_or_invalid_event_context_cannot_authorize_a_triple_fault() {
    let active = 1_u64;
    for invalid in 0..3 {
        let mut model = Reset {
            interception: &active as *const u64 as u64,
            tracking: u64::MAX,
            ..Default::default()
        };
        match invalid {
            0 => model.event_present = 0,
            1 => model.magic = 0,
            _ => model.canary = 0,
        }
        unsafe { test_reset(&mut model) };
        assert_eq!((model.triple_fault, model.halted), (0, 1));
        assert_eq!(&model.ports[..2], &[0xcf9, 0xcf9]);
    }
}

#[test]
fn context_independent_reset_discards_any_previous_triple_fault_permission() {
    let mut model = Reset {
        interception: u64::MAX,
        tracking: u64::MAX,
        update_phase: 4,
        ..Default::default()
    };
    unsafe { test_reset_cf9(&mut model) };
    assert_eq!((model.triple_fault, model.halted), (0, 1));
    assert_eq!(&model.ports[..2], &[0xcf9, 0xcf9]);
}

thread_local! {
    static ATTEMPTS: std::cell::RefCell<Vec<(u64, [u64; 2])>> = const { std::cell::RefCell::new(Vec::new()) };
    static FAIL_MASK: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn model_invalidate(kind: u64, descriptor: [u64; 2]) -> u8 {
    ATTEMPTS.with_borrow_mut(|attempts| {
        let index = attempts.len();
        attempts.push((kind, descriptor));
        u8::from(FAIL_MASK.get() & (1 << index) != 0)
    })
}

include!("../builds/watchdog-recovery-tests/invalidation.rs");

#[test]
fn rust_interception_retires_translations_with_the_same_bounded_fallback() {
    for mask in [0, 1, 3] {
        ATTEMPTS.with_borrow_mut(Vec::clear);
        FAIL_MASK.set(mask);
        assert_eq!(invalidate(0x10001e).is_ok(), mask != 3);
        ATTEMPTS.with_borrow(|attempts| {
            assert_eq!(attempts[0], (1, [0x10001e, 0]));
            assert_eq!(attempts.len(), if mask == 0 { 1 } else { 2 });
            if mask != 0 { assert_eq!(attempts[1], (2, [0, 0])); }
        });
    }
}
