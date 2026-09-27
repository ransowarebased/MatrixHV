use core::arch::global_asm;

struct ResidentPages {
    bytes: [u8; 4096],
}

impl ResidentPages {
    fn new() -> Self {
        Self {
            bytes: [0xff; 4096],
        }
    }

    fn intercepts(&self, index: u32, write: bool) -> bool {
        let offset = (index >> 3) as usize + if write { 2048 } else { 0 };
        self.bytes[offset] & (1 << (index & 7)) != 0
    }
}

#[test]
fn physical_clock_and_deadline_share_native_reads_and_writes() {
    let bitmap = clock_bitmap();
    for index in [0x10, 0x3b, 0x6e0] {
        for write in [false, true] {
            assert!(
                !bitmap.intercepts(index, write),
                "clock MSR {index:#x}, write={write}"
            );
        }
    }
    for index in [0xfe, 0x200, 0x201, 0x250, 0x2ff, 0x480] {
        assert!(bitmap.intercepts(index, false));
        assert!(bitmap.intercepts(index, true));
    }
}

#[test]
fn bitmap_boundaries_keep_read_write_and_address_ranges_separate() {
    let mut bitmap = [0xff; 4096];
    allow_low_msr_read_passthrough(&mut bitmap, 0);
    allow_low_msr_write_passthrough(&mut bitmap, 0x1fff);
    allow_high_msr_passthrough(&mut bitmap, 0xc000_0000);
    allow_high_msr_passthrough(&mut bitmap, 0xc000_1fff);
    for (offset, byte) in bitmap.into_iter().enumerate() {
        let expected = match offset {
            0 | 1024 | 3072 => 0xfe,
            2047 | 3071 | 4095 => 0x7f,
            _ => 0xff,
        };
        assert_eq!(byte, expected, "unexpected bitmap byte at {offset}");
    }
}

#[test]
fn bitmap_helpers_reject_invalid_registers_and_short_buffers() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let mut bitmap = [0xff; 4096];
    for index in [0x2000, u32::MAX] {
        for helper in [
            allow_low_msr_passthrough,
            allow_low_msr_read_passthrough,
            allow_low_msr_write_passthrough,
        ] {
            assert!(catch_unwind(AssertUnwindSafe(|| helper(&mut bitmap, index))).is_err());
            assert_eq!(bitmap, [0xff; 4096]);
        }
    }
    for index in [0, 0xbfff_ffff, 0xc000_2000, u32::MAX] {
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                allow_high_msr_passthrough(&mut bitmap, index);
            }))
            .is_err()
        );
        assert_eq!(bitmap, [0xff; 4096]);
    }
    assert!(catch_unwind(|| allow_low_msr_passthrough(&mut [], 0)).is_err());
    assert!(catch_unwind(|| allow_high_msr_passthrough(&mut [0xff; 1024], 0xc000_0000)).is_err());
}

global_asm!(include_str!("resident-cache-flush.S"));

#[repr(C)]
#[derive(Default)]
struct CacheFlush {
    unprivileged: u64,
    flushes: u64,
    rip: u64,
    fault: u64,
}

unsafe extern "C" {
    fn test_cache_flush(state: &mut CacheFlush);
}

#[test]
fn startup_cache_invalidation_resumes_and_preserves_dirty_data() {
    let mut state = CacheFlush {
        rip: 0x8000,
        ..Default::default()
    };
    unsafe { test_cache_flush(&mut state) };
    assert_eq!(state.flushes, 1);
    assert_eq!(state.rip, 0x8002);
    assert_eq!(state.fault, 0);
}

#[test]
fn unprivileged_cache_invalidation_faults_without_advancing() {
    let mut state = CacheFlush {
        unprivileged: 1,
        rip: 0x8000,
        ..Default::default()
    };
    unsafe { test_cache_flush(&mut state) };
    assert_eq!(state.flushes, 0);
    assert_eq!(state.rip, 0x8000);
    assert_eq!(state.fault, 1);
}

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
struct MsrEntry {
    index: u32,
    reserved: u32,
    value: u64,
}

#[repr(C)]
struct Context {
    exit_store: *const MsrEntry,
    guest: *mut MsrEntry,
    l1_store: *mut MsrEntry,
    l1_store_count: u64,
    l1_load: *const MsrEntry,
    l1_load_count: u64,
    entry: *mut MsrEntry,
}

global_asm!(
    include_str!("resident-msr.S"),
    b_nested_vmcs02_exit_store_msr_list = const core::mem::offset_of!(Context, exit_store),
    b_nested_l0_msr_guest_list = const core::mem::offset_of!(Context, guest),
    b_nested_vmcs12_vm_exit_msr_store_addr = const core::mem::offset_of!(Context, l1_store),
    b_nested_vmcs12_vm_exit_msr_store_count = const core::mem::offset_of!(Context, l1_store_count),
    b_nested_vmcs12_vm_exit_msr_load_addr = const core::mem::offset_of!(Context, l1_load),
    b_nested_vmcs12_vm_exit_msr_load_count = const core::mem::offset_of!(Context, l1_load_count),
    b_nested_vmcs01_entry_msr_list = const core::mem::offset_of!(Context, entry),
);

unsafe extern "C" {
    fn test_complete_msr_exit(context: &mut Context, count: u64, reason: u32);
    fn test_validate_efer(value: &mut u64, old: u64, unused: u64, features: u32, cr0: u64) -> u32;
    fn test_validate_canonical(value: u64, cr4: u64) -> u32;
}

fn entry(index: u32, value: u64) -> MsrEntry {
    MsrEntry {
        index,
        reserved: 0,
        value,
    }
}

#[test]
fn spec_ctrl_requires_an_architectural_feature() {
    assert!(!spec_ctrl_available(0));
    assert!(!spec_ctrl_available((1 << 28) | (1 << 29)));
    for bit in [26, 27, 31] {
        assert!(spec_ctrl_available(1 << bit));
    }
}

#[test]
fn nested_store_and_load_preserve_optional_root_prefix() {
    let _guard = TEST_LOCK.lock().unwrap();
    for root_count in [0, 1] {
        let sentinel = entry(0xdead, 0xbeef);
        let mut guest = [entry(0x48, 1), sentinel];
        let mut store = [entry(0x48, 0), entry(0xc000_0102, 0)];
        let load = [entry(0x48, 5), entry(0xc000_0102, 0x1234)];
        let mut exit_store = Vec::new();
        if root_count != 0 {
            exit_store.push(entry(0x48, 3));
        }
        // The duplicate SPEC_CTRL slot can be stale: the L0 prefix is authoritative.
        exit_store.extend([entry(0x48, 2), entry(0xc000_0102, 0x9876)]);
        let mut composed = [sentinel; 4];
        let mut context = Context {
            exit_store: exit_store.as_ptr(),
            guest: guest.as_mut_ptr(),
            l1_store: store.as_mut_ptr(),
            l1_store_count: 2,
            l1_load: load.as_ptr(),
            l1_load_count: 2,
            entry: composed.as_mut_ptr(),
        };
        unsafe { test_complete_msr_exit(&mut context, root_count, 10) };
        assert_eq!(store[0].value, if root_count == 0 { 2 } else { 3 });
        assert_eq!(store[1].value, 0x9876);
        assert_eq!(guest[0].value, if root_count == 0 { 1 } else { 3 });
        assert_eq!(guest[1], sentinel);
        let offset = root_count as usize;
        assert_eq!(composed[offset..offset + 2], load);
        assert_eq!(composed[offset + 2], sentinel);
        if root_count != 0 {
            assert_eq!(composed[0], guest[0]);
        }
    }
}

#[test]
fn failed_entry_never_copies_an_exit_store_list() {
    let _guard = TEST_LOCK.lock().unwrap();
    for root_count in [0, 1] {
        let mut guest = entry(0x48, 7);
        let load = [entry(0xc000_0102, 0x1234)];
        let mut composed = [entry(0, 0); 2];
        let mut context = Context {
            exit_store: core::ptr::null(),
            guest: &mut guest,
            l1_store: core::ptr::null_mut(),
            l1_store_count: 2,
            l1_load: load.as_ptr(),
            l1_load_count: 1,
            entry: composed.as_mut_ptr(),
        };
        unsafe { test_complete_msr_exit(&mut context, root_count, 0x8000_0021) };
        assert_eq!(guest.value, 7);
        assert_eq!(composed[root_count as usize], load[0]);
    }
}

#[test]
fn zero_counts_do_not_dereference_empty_lists() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut context = Context {
        exit_store: core::ptr::null(),
        guest: core::ptr::null_mut(),
        l1_store: core::ptr::null_mut(),
        l1_store_count: 0,
        l1_load: core::ptr::null(),
        l1_load_count: 0,
        entry: core::ptr::null_mut(),
    };
    unsafe { test_complete_msr_exit(&mut context, 0, 10) };
}

#[test]
fn efer_rejects_reserved_bits_and_unsupported_features() {
    let features = (1 << 11) | (1 << 20) | (1 << 29);
    for bit in 0..64 {
        if 0xd01_u64 & (1 << bit) == 0 {
            let mut value = 1 << bit;
            assert_eq!(
                unsafe { test_validate_efer(&mut value, 0, 0, features, 0) },
                0
            );
        }
    }
    for bit in [0, 8, 11] {
        let mut value = 1 << bit;
        assert_eq!(unsafe { test_validate_efer(&mut value, 0, 0, 0, 0) }, 0);
    }
}

#[test]
fn efer_preserves_read_only_lma_and_observes_paging_transition() {
    let features = (1 << 11) | (1 << 20) | (1 << 29);
    let mut value = 0x901;
    assert_eq!(
        unsafe { test_validate_efer(&mut value, 0x500, 0, features, 1 << 31) },
        1
    );
    assert_eq!(value, 0xd01);
    value = 0;
    assert_eq!(
        unsafe { test_validate_efer(&mut value, 0x500, 0, features, 1 << 31) },
        0
    );
    value = 0x500;
    assert_eq!(
        unsafe { test_validate_efer(&mut value, 0, 0, features, 0) },
        1
    );
    assert_eq!(value, 0x100);
}

#[test]
fn canonical_msr_values_follow_the_guest_paging_width() {
    for value in [0, 0x7fff_ffff_ffff, 0xffff_8000_0000_0000, u64::MAX] {
        assert_eq!(unsafe { test_validate_canonical(value, 0) }, 1);
    }
    for value in [
        0x8000_0000_0000,
        0xffff_7fff_ffff_ffff,
        0x0100_0000_0000_0000,
    ] {
        assert_eq!(unsafe { test_validate_canonical(value, 0) }, 0);
    }
    assert_eq!(
        unsafe { test_validate_canonical(0x00ff_ffff_ffff_ffff, 1 << 12) },
        1
    );
    assert_eq!(
        unsafe { test_validate_canonical(0xff00_0000_0000_0000, 1 << 12) },
        1
    );
    assert_eq!(
        unsafe { test_validate_canonical(0x0100_0000_0000_0000, 1 << 12) },
        0
    );
}

#[repr(C)]
#[derive(Default)]
struct NmiContext {
    pending: u64,
    l2_active: u64,
    l1_pin: u64,
    control_cache: [u64; 2],
    vmcs: [u64; 4],
}

global_asm!(
    include_str!("resident-nmi.S"),
    b_nmi_pending = const core::mem::offset_of!(NmiContext, pending),
    b_nested_l2_active = const core::mem::offset_of!(NmiContext, l2_active),
    b_nested_vmcs12_pin_based_control = const core::mem::offset_of!(NmiContext, l1_pin),
    b_nested_vmcs02_control_cache_valid = const core::mem::offset_of!(NmiContext, control_cache),
    test_vmcs = const core::mem::offset_of!(NmiContext, vmcs),
    vm_entry_intr_info_field = const 0,
    guest_interruptibility_info = const 1,
    guest_activity_state = const 2,
    cpu_based_vm_exec_control = const 3,
);

unsafe extern "C" {
    fn test_deliver_nmi(context: &mut NmiContext);
}

#[test]
fn nmi_delivery_waits_for_blocking_and_preserves_an_existing_event() {
    for (event, blocking) in [(0x8000030e, 0), (0, 1), (0, 2), (0, 8)] {
        let mut context = NmiContext {
            pending: 1,
            vmcs: [event, blocking, 0, 0],
            ..Default::default()
        };
        unsafe { test_deliver_nmi(&mut context) };
        assert_eq!(context.pending, 1);
        assert_eq!(context.vmcs[0], event);
        assert_eq!(context.vmcs[3], 1 << 22);
    }
}

#[test]
fn nmi_delivery_wakes_halted_guests_and_respects_wait_for_sipi() {
    let mut context = NmiContext {
        pending: 1,
        vmcs: [0, 0, 1, 0],
        ..Default::default()
    };
    unsafe { test_deliver_nmi(&mut context) };
    assert_eq!(context.pending, 0);
    assert_eq!(context.vmcs, [0x80000202, 0, 0, 0]);
    context.pending = 1;
    context.vmcs = [0, 0, 3, 0];
    unsafe { test_deliver_nmi(&mut context) };
    assert_eq!(context.pending, 1);
    assert_eq!(context.vmcs, [0, 0, 3, 0]);
}

#[test]
fn root_nmi_waits_for_l1_when_l1_owns_nmi_exits() {
    let mut context = NmiContext {
        pending: 1,
        l2_active: 1,
        l1_pin: 8,
        ..Default::default()
    };
    unsafe { test_deliver_nmi(&mut context) };
    assert_eq!(context.pending, 1);
    assert_eq!(context.vmcs, [0; 4]);
    context.l2_active = 0;
    unsafe { test_deliver_nmi(&mut context) };
    assert_eq!(context.pending, 0);
    assert_eq!(context.vmcs[0], 0x80000202);
}
