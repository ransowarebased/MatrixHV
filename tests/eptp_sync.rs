use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static SERIAL: Mutex<()> = Mutex::new(());

#[repr(C)]
struct Event {
    cpus: [u64; 64],
}

#[repr(C)]
struct Context {
    event: u64,
    ack: AtomicU64,
    safe: AtomicU64,
    pending_nmi: AtomicU64,
    reason: AtomicU64,
    exit_info: AtomicU64,
    apic_id: u64,
    guest_nmi: AtomicU64,
    apic_base: AtomicU64,
    sends: AtomicU64,
    destination: AtomicU64,
    icr: AtomicU64,
    fail_send: AtomicU64,
    consume_failed_token: AtomicU64,
    l2_active: u64,
    native_enabled: AtomicU64,
    admission: AtomicU64,
    shadow_list: u64,
    initialized: u64,
    ept01: u64,
    captures: AtomicU64,
    invalidations: AtomicU64,
    swaps: AtomicU64,
    flushes: AtomicU64,
}

impl Context {
    fn new(event: &Event, l2_active: bool) -> Self {
        Self {
            event: event as *const Event as u64,
            ack: AtomicU64::new(0),
            safe: AtomicU64::new(0),
            pending_nmi: AtomicU64::new(0),
            reason: AtomicU64::new(0),
            exit_info: AtomicU64::new(0),
            apic_id: 0,
            guest_nmi: AtomicU64::new(0),
            apic_base: AtomicU64::new(0xc00),
            sends: AtomicU64::new(0),
            destination: AtomicU64::new(0),
            icr: AtomicU64::new(0),
            fail_send: AtomicU64::new(0),
            consume_failed_token: AtomicU64::new(0),
            l2_active: u64::from(l2_active),
            native_enabled: AtomicU64::new(1),
            admission: AtomicU64::new(1),
            shadow_list: 0,
            initialized: 1,
            ept01: 0x101e,
            captures: AtomicU64::new(0),
            invalidations: AtomicU64::new(0),
            swaps: AtomicU64::new(0),
            flushes: AtomicU64::new(0),
        }
    }
}

core::arch::global_asm!(
    ".text",
    ".macro test_sync_wrapper name, target",
    ".globl \\name",
    "\\name:",
    "push rbx", "push rbp", "push rsi", "push rdi",
    "push r12", "push r13", "push r14", "push r15",
    "mov r12, rcx", "cld", "call \\target",
    "pop r15", "pop r14", "pop r13", "pop r12",
    "pop rdi", "pop rsi", "pop rbp", "pop rbx", "ret",
    ".endm",
    "test_sync_wrapper sync_begin, .Lresident_nested_eptp_sync_begin",
    "test_sync_wrapper sync_acquire, .Lresident_nested_eptp_sync_acquire",
    "test_sync_wrapper sync_ready, .Lresident_nested_eptp_sync_ready",
    "test_sync_wrapper sync_end, .Lresident_nested_eptp_sync_end",
    "test_sync_wrapper sync_poll, .Lresident_nested_eptp_sync_poll",
    "test_sync_wrapper sync_enter, .Lresident_nested_eptp_sync_enter",
    "test_sync_wrapper sync_host_nmi, .Lresident_nested_eptp_sync_host_nmi",
    "test_sync_wrapper sync_exit_nmi, .Lresident_nested_eptp_sync_exit_nmi",
    "test_sync_wrapper sync_kick, .Lresident_nested_eptp_sync_kick",
    ".Lresident_guarded_rdmsr:",
    "mov rax, qword ptr [r12 + {test_apic_base}]",
    "mov rdx, rax", "shr rdx, 32", "mov eax, eax", "clc", "ret",
    ".Lresident_guarded_wrmsr:",
    "cmp qword ptr [r12 + {test_fail_send}], 0", "jne .Ltest_send_failed",
    "inc qword ptr [r12 + {test_sends}]",
    "mov qword ptr [r12 + {test_destination}], rdx",
    "mov qword ptr [r12 + {test_icr}], rax", "clc", "ret",
    ".Ltest_send_failed:",
    "cmp qword ptr [r12 + {test_consume_failed_token}], 0",
    "je .Ltest_send_failed_return",
    "mov qword ptr [r14 + {b_nested_eptp_sync_nmi}], 0",
    ".Ltest_send_failed_return:", "stc", "ret",
    ".Lresident_nested_host_page_is_mapped:", "mov eax, 1", "ret",
    ".Lresident_nested_capture_native_eptp:",
    "inc qword ptr [r12 + {test_captures}]", "ret",
    ".Lresident_nested_invalidate_ept02:",
    "inc qword ptr [r12 + {test_invalidations}]", "ret",
    ".Lresident_nested_swap_ept02_cache:",
    "inc qword ptr [r12 + {test_swaps}]", "ret",
    ".Lresident_dispatch_halt:", ".Lresident_dispatch_vmread_failed:", "ud2",
    include_str!("../builds/eptp-sync-tests/eptp-sync.S"),
    b_event_context = const std::mem::offset_of!(Context, event),
    event_cpu_contexts = const std::mem::offset_of!(Event, cpus),
    b_nested_eptp_sync_ack = const std::mem::offset_of!(Context, ack),
    b_nested_eptp_sync_safe = const std::mem::offset_of!(Context, safe),
    b_nested_eptp_sync_nmi = const std::mem::offset_of!(Context, pending_nmi),
    b_last_reason = const std::mem::offset_of!(Context, reason),
    exit_intr_info = const 0,
    test_exit_info = const std::mem::offset_of!(Context, exit_info),
    b_nested_eptp_sync_apic_id = const std::mem::offset_of!(Context, apic_id),
    b_nmi_pending = const std::mem::offset_of!(Context, guest_nmi),
    apic_base_msr = const 0x1b,
    host_page_address_mask = const 0x000f_ffff_ffff_f000u64,
    test_apic_base = const std::mem::offset_of!(Context, apic_base),
    test_sends = const std::mem::offset_of!(Context, sends),
    test_destination = const std::mem::offset_of!(Context, destination),
    test_icr = const std::mem::offset_of!(Context, icr),
    test_fail_send = const std::mem::offset_of!(Context, fail_send),
    test_consume_failed_token = const std::mem::offset_of!(Context, consume_failed_token),
    b_nested_l2_active = const std::mem::offset_of!(Context, l2_active),
    b_nested_eptp_native_enabled = const std::mem::offset_of!(Context, native_enabled),
    b_nested_eptp_admission = const std::mem::offset_of!(Context, admission),
    b_nested_eptp_shadow_list = const std::mem::offset_of!(Context, shadow_list),
    b_nested_ept02_cache_initialized = const std::mem::offset_of!(Context, initialized),
    b_nested_ept01_pointer = const std::mem::offset_of!(Context, ept01),
    test_captures = const std::mem::offset_of!(Context, captures),
    test_invalidations = const std::mem::offset_of!(Context, invalidations),
    test_swaps = const std::mem::offset_of!(Context, swaps),
    test_flushes = const std::mem::offset_of!(Context, flushes),
);

unsafe extern "win64" {
    fn sync_begin(context: *const Context) -> u64;
    fn sync_acquire(context: *const Context) -> u64;
    fn sync_ready(context: *const Context) -> u64;
    fn sync_end(context: *const Context);
    fn sync_poll(context: *const Context);
    fn sync_enter(context: *const Context);
    fn sync_host_nmi(context: *const Context) -> u64;
    fn sync_exit_nmi(context: *const Context) -> u64;
    fn sync_kick(context: *const Context) -> u64;
}

fn until(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        if Instant::now() >= deadline {
            return false;
        }
        thread::yield_now();
    }
    true
}

#[test]
fn peers_park_until_release_then_retire_both_roots_and_local_translations() {
    let _serial = SERIAL.lock().unwrap();
    let mut event = Box::new(Event { cpus: [0; 64] });
    let owner = Box::new(Context::new(&event, false));
    let peer = Box::new(Context::new(&event, true));
    event.cpus[0] = &*owner as *const Context as u64;
    event.cpus[63] = &*peer as *const Context as u64;
    for epoch in 0..100 {
        assert_eq!(unsafe { sync_begin(&*owner) }, 1);
        assert_eq!(unsafe { sync_begin(&*peer) }, 0);
        assert_eq!(unsafe { sync_ready(&*owner) }, 0, "stale acknowledgement");
        let returned = AtomicU64::new(0);
        thread::scope(|scope| {
            scope.spawn(|| {
                unsafe { sync_poll(&*peer) };
                returned.store(1, Ordering::Release);
            });
            let ready = until(|| unsafe { sync_ready(&*owner) } == 1);
            let early_return = returned.load(Ordering::Acquire);
            let captures = peer.captures.load(Ordering::Acquire);
            // Always release before asserting, so a failed test cannot strand a peer.
            unsafe { sync_end(&*owner) };
            assert!(ready);
            assert_eq!(early_return, 0);
            assert_eq!(captures, epoch + 1);
        });
        assert_eq!(returned.load(Ordering::Acquire), 1);
        assert_eq!(peer.native_enabled.load(Ordering::Acquire), 0);
        assert_eq!(peer.invalidations.load(Ordering::Acquire), 2 * (epoch + 1));
        assert_eq!(peer.swaps.load(Ordering::Acquire), 2 * (epoch + 1));
        assert_eq!(peer.flushes.load(Ordering::Acquire), epoch + 1);
    }
}

#[test]
fn idle_and_owner_gates_do_not_invalidate_or_wait() {
    let _serial = SERIAL.lock().unwrap();
    let mut event = Box::new(Event { cpus: [0; 64] });
    let owner = Box::new(Context::new(&event, false));
    event.cpus[3] = &*owner as *const Context as u64;
    unsafe { sync_poll(&*owner) };
    assert_eq!(unsafe { sync_begin(&*owner) }, 1);
    assert_eq!(unsafe { sync_ready(&*owner) }, 1);
    unsafe { sync_poll(&*owner) };
    unsafe { sync_end(&*owner) };
    assert_eq!(owner.ack.load(Ordering::Acquire), 0);
    assert_eq!(owner.flushes.load(Ordering::Acquire), 0);
}

#[test]
fn cancellation_and_immediate_reacquisition_require_fresh_peer_acknowledgements() {
    let _serial = SERIAL.lock().unwrap();
    let mut event = Box::new(Event { cpus: [0; 64] });
    let owner = Box::new(Context::new(&event, false));
    let peers = [Context::new(&event, false), Context::new(&event, true)];
    event.cpus[0] = &*owner as *const Context as u64;
    for (index, peer) in peers.iter().enumerate() {
        event.cpus[index + 1] = peer as *const Context as u64;
    }
    let stop = AtomicU64::new(0);
    let returns = [AtomicU64::new(0), AtomicU64::new(0)];
    thread::scope(|scope| {
        for (index, peer) in peers.iter().enumerate() {
            let stop = &stop;
            let count = &returns[index];
            scope.spawn(move || {
                while stop.load(Ordering::Acquire) == 0 {
                    unsafe { sync_poll(peer) };
                    count.fetch_add(1, Ordering::Release);
                }
            });
        }
        let mut passed = true;
        for _ in 0..1000 {
            assert_eq!(unsafe { sync_begin(&*owner) }, 1);
            unsafe { sync_end(&*owner) };
            assert_eq!(unsafe { sync_begin(&*owner) }, 1);
            if !until(|| unsafe { sync_ready(&*owner) } == 1) {
                unsafe { sync_end(&*owner) };
                passed = false;
                break;
            }
            let before = returns
                .each_ref()
                .map(|value| value.load(Ordering::Acquire));
            for _ in 0..32 {
                std::hint::spin_loop();
            }
            let after = returns
                .each_ref()
                .map(|value| value.load(Ordering::Acquire));
            unsafe { sync_end(&*owner) };
            if before != after {
                passed = false;
                break;
            }
        }
        stop.store(1, Ordering::Release);
        assert!(
            passed,
            "A peer returned while a later synchronization owned the gate"
        );
    });
}

#[test]
fn nmi_parks_in_the_entry_window_and_defers_when_a_root_handler_is_busy() {
    let _serial = SERIAL.lock().unwrap();
    let mut event = Box::new(Event { cpus: [0; 64] });
    let owner = Box::new(Context::new(&event, false));
    let peer = Box::new(Context::new(&event, true));
    event.cpus[0] = &*owner as *const Context as u64;
    event.cpus[1] = &*peer as *const Context as u64;
    for safe in [0, 1] {
        peer.safe.store(safe, Ordering::Release);
        peer.pending_nmi.store(1, Ordering::Release);
        assert_eq!(unsafe { sync_begin(&*owner) }, 1);
        if safe == 0 {
            assert_eq!(unsafe { sync_host_nmi(&*peer) }, 1);
            assert_eq!(peer.pending_nmi.load(Ordering::Acquire), 0);
            assert_eq!(unsafe { sync_ready(&*owner) }, 0);
        }
        let returned = AtomicU64::new(0);
        thread::scope(|scope| {
            scope.spawn(|| {
                if safe == 0 {
                    unsafe { sync_enter(&*peer) };
                } else {
                    assert_eq!(unsafe { sync_host_nmi(&*peer) }, 1);
                }
                returned.store(1, Ordering::Release);
            });
            let ready = until(|| unsafe { sync_ready(&*owner) } == 1);
            let early_return = returned.load(Ordering::Acquire);
            unsafe { sync_end(&*owner) };
            assert!(ready);
            assert_eq!(early_return, 0);
        });
        assert_eq!(peer.safe.load(Ordering::Acquire), 1);
        assert_eq!(peer.pending_nmi.load(Ordering::Acquire), 0);
        assert_eq!(unsafe { sync_host_nmi(&*peer) }, 0);
    }
}

#[test]
fn only_a_valid_nmi_exit_consumes_the_internal_token() {
    let _serial = SERIAL.lock().unwrap();
    let event = Event { cpus: [0; 64] };
    let peer = Context::new(&event, true);
    for (reason, info, consumed) in [
        (10, 0x80000202, 0),
        (0x80000000, 0x80000202, 0),
        (0, 0x202, 0),
        (0, 0x8000030e, 0),
        (0, 0x80000306, 0),
        (0, 0x80000002, 0),
        (0, 0x80000202, 1),
    ] {
        peer.reason.store(reason, Ordering::Release);
        peer.exit_info.store(info, Ordering::Release);
        peer.pending_nmi.store(1, Ordering::Release);
        assert_eq!(unsafe { sync_exit_nmi(&peer) }, consumed);
        assert_eq!(peer.pending_nmi.load(Ordering::Acquire), 1 - consumed);
    }
    assert_eq!(unsafe { sync_exit_nmi(&peer) }, 0);
}

#[test]
fn x2apic_kicks_use_full_destinations_and_preserve_external_nmis_on_send_failure() {
    let _serial = SERIAL.lock().unwrap();
    let mut event = Box::new(Event { cpus: [0; 64] });
    let owner = Box::new(Context::new(&event, false));
    let mut peer = Box::new(Context::new(&event, true));
    peer.apic_id = 0x12345678;
    event.cpus[0] = &*owner as *const Context as u64;
    event.cpus[63] = &*peer as *const Context as u64;
    assert_eq!(unsafe { sync_begin(&*owner) }, 1);
    let first = unsafe { sync_kick(&*owner) };
    let second = unsafe { sync_kick(&*owner) };
    unsafe { sync_end(&*owner) };
    assert_eq!((first, second), (1, 1));
    assert_eq!(owner.sends.load(Ordering::Acquire), 1);
    assert_eq!(owner.destination.load(Ordering::Acquire), peer.apic_id);
    assert_eq!(owner.icr.load(Ordering::Acquire), 0x4400);
    assert_eq!(peer.pending_nmi.load(Ordering::Acquire), 1);

    owner.fail_send.store(1, Ordering::Release);
    for consumed in [0, 1] {
        peer.pending_nmi.store(0, Ordering::Release);
        owner
            .consume_failed_token
            .store(consumed, Ordering::Release);
        assert_eq!(unsafe { sync_begin(&*owner) }, 1);
        let result = unsafe { sync_kick(&*owner) };
        unsafe { sync_end(&*owner) };
        assert_eq!(result, 0);
        assert_eq!(peer.pending_nmi.load(Ordering::Acquire), 0);
        assert_eq!(peer.guest_nmi.load(Ordering::Acquire), consumed);
    }
}

#[test]
fn xapic_kicks_validate_destination_and_wait_for_an_idle_icr() {
    #[repr(C, align(4096))]
    struct ApicPage([u32; 1024]);
    let _serial = SERIAL.lock().unwrap();
    let mut event = Box::new(Event { cpus: [0; 64] });
    let owner = Box::new(Context::new(&event, false));
    let mut peer = Box::new(Context::new(&event, true));
    let mut apic = Box::new(ApicPage([0; 1024]));
    owner.apic_base.store(
        (&*apic as *const ApicPage as u64) | 0x800,
        Ordering::Release,
    );
    event.cpus[0] = &*owner as *const Context as u64;
    event.cpus[1] = &*peer as *const Context as u64;
    for (destination, busy, expected) in [(7, false, 1), (256, false, 0), (7, true, 0)] {
        peer.apic_id = destination;
        peer.pending_nmi.store(0, Ordering::Release);
        apic.0[0x300 / 4] = if busy { 0x1000 } else { 0 };
        apic.0[0x310 / 4] = 0;
        assert_eq!(unsafe { sync_begin(&*owner) }, 1);
        let result = unsafe { sync_kick(&*owner) };
        unsafe { sync_end(&*owner) };
        assert_eq!(result, expected);
        assert_eq!(peer.pending_nmi.load(Ordering::Acquire), expected);
        if expected == 1 {
            assert_eq!(apic.0[0x310 / 4], 7 << 24);
            assert_eq!(apic.0[0x300 / 4], 0x4400);
        }
    }
}

#[test]
fn acquisition_waits_for_peers_and_releases_ownership_on_transport_or_timeout_failure() {
    let _serial = SERIAL.lock().unwrap();
    let mut event = Box::new(Event { cpus: [0; 64] });
    let owner = Box::new(Context::new(&event, false));
    let peer = Box::new(Context::new(&event, true));
    event.cpus[0] = &*owner as *const Context as u64;
    // No peer requires a functioning APIC when there is only one registered CPU.
    owner.apic_base.store(0, Ordering::Release);
    let acquired = unsafe { sync_acquire(&*owner) };
    if acquired != 0 {
        unsafe { sync_end(&*owner) };
    }
    assert_eq!(acquired, 1);
    event.cpus[1] = &*peer as *const Context as u64;
    for base in [0, 0xc00] {
        owner.apic_base.store(base, Ordering::Release);
        assert_eq!(unsafe { sync_acquire(&*owner) }, 0);
        assert_eq!(
            unsafe { sync_begin(&*peer) },
            1,
            "Failed acquisition must release its owner"
        );
        unsafe { sync_end(&*peer) };
    }

    peer.pending_nmi.store(0, Ordering::Release);
    let stop = AtomicU64::new(0);
    thread::scope(|scope| {
        scope.spawn(|| {
            while stop.load(Ordering::Acquire) == 0 {
                unsafe { sync_poll(&*peer) };
                thread::yield_now();
            }
        });
        let acquired = unsafe { sync_acquire(&*owner) };
        let ready = unsafe { sync_ready(&*owner) };
        if acquired != 0 {
            unsafe { sync_end(&*owner) };
        }
        stop.store(1, Ordering::Release);
        assert_eq!(acquired, 1);
        assert_eq!(ready, 1);
    });
}
