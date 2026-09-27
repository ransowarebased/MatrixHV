use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::collections::HashMap;

#[repr(C)]
struct InterceptContext {
    l0_primary: u64,
    l1_primary: u64,
    l0_secondary: u64,
    l1_secondary: u64,
    vpid: u64,
    merged_secondary: u64,
    hardware: [u64; 2],
}

core::arch::global_asm!(
    ".text",
    ".globl merge_test_intercepts",
    "merge_test_intercepts:",
    "push r12", "mov r12, rcx",
    "call .Ltest_merge_intercepts",
    "pop r12", "ret",
    ".Ltest_merge_intercepts:",
    include_str!("../builds/nested-ept-tests/resident-intercepts.S"),
    cpu_based_vm_exec_control = const 0,
    secondary_vm_exec_control = const 1,
    b_nested_vmcs01_primary_controls = const std::mem::offset_of!(InterceptContext, l0_primary),
    b_nested_vmcs12_primary_control = const std::mem::offset_of!(InterceptContext, l1_primary),
    b_nested_vmcs01_secondary_controls = const std::mem::offset_of!(InterceptContext, l0_secondary),
    b_nested_vmcs12_secondary_control = const std::mem::offset_of!(InterceptContext, l1_secondary),
    b_nested_vmcs02_last_vpid = const std::mem::offset_of!(InterceptContext, vpid),
    b_nested_last_merged_secondary_controls = const std::mem::offset_of!(InterceptContext, merged_secondary),
    test_hardware = const std::mem::offset_of!(InterceptContext, hardware),
);

unsafe extern "win64" {
    #[link_name = "merge_test_intercepts"]
    fn merge_test_intercepts_raw(context: *mut InterceptContext);
}

fn merge_test_intercepts(context: &mut InterceptContext) {
    // The trampoline only reads and writes fields of the exclusively borrowed context.
    unsafe { merge_test_intercepts_raw(context) }
}

#[test]
fn l1_monitor_trap_and_wbinvd_controls_reach_vmcs02_and_can_be_cleared() {
    let mut context = InterceptContext {
        l0_primary: 1 << 28,
        l1_primary: 1 << 27,
        l0_secondary: 1 << 1,
        l1_secondary: 1 << 6,
        vpid: 0,
        merged_secondary: 0,
        hardware: [0; 2],
    };
    merge_test_intercepts(&mut context);
    assert_eq!(
        context.hardware,
        [(1 << 28) | (1 << 27), (1 << 1) | (1 << 6)]
    );
    assert_eq!(context.merged_secondary, context.hardware[1]);
    context.l1_primary = 0;
    context.l1_secondary = 0;
    merge_test_intercepts(&mut context);
    assert_eq!(context.hardware, [1 << 28, 1 << 1]);
}

#[test]
fn vmfunc_trapping_follows_l1_secondary_control_activation() {
    let mut context = InterceptContext {
        l0_primary: 1 << 31,
        l1_primary: 1 << 31,
        l0_secondary: 2,
        l1_secondary: 0x2002,
        vpid: 0,
        merged_secondary: 0,
        hardware: [0; 2],
    };
    merge_test_intercepts(&mut context);
    assert_eq!(context.hardware[1], 0x2002);
    context.l1_primary = 0;
    merge_test_intercepts(&mut context);
    assert_eq!(context.hardware[1], 2);
    context.l1_primary = 1 << 31;
    context.l1_secondary = 2;
    merge_test_intercepts(&mut context);
    assert_eq!(context.hardware[1], 2);
}

#[repr(C)]
struct SuccessContext {
    rflags: u64,
    writes: u64,
    advances: u64,
}

core::arch::global_asm!(
    ".text",
    ".globl complete_test_vmx_success",
    "complete_test_vmx_success:",
    "push r12", "mov r12, rcx",
    "call .Ltest_nested_success",
    "pop r12", "ret",
    include_str!("../builds/nested-ept-tests/resident-success.S"),
    guest_rflags = const 0,
    vmx_status_flags_clear_mask = const !0x8d5_i32,
    test_rflags = const std::mem::offset_of!(SuccessContext, rflags),
    test_writes = const std::mem::offset_of!(SuccessContext, writes),
    test_advances = const std::mem::offset_of!(SuccessContext, advances),
);

unsafe extern "win64" {
    #[link_name = "complete_test_vmx_success"]
    fn complete_test_vmx_success_raw(context: *mut SuccessContext);
}

fn complete_test_vmx_success(context: &mut SuccessContext) {
    // All simulated VMCS accesses stay inside the borrowed context.
    unsafe { complete_test_vmx_success_raw(context) }
}

#[test]
fn vmx_success_clears_status_flags_and_preserves_other_guest_flags() {
    for combination in 0..64 {
        let status = [0, 2, 4, 6, 7, 11]
            .iter()
            .enumerate()
            .fold(0, |flags, (index, bit)| {
                flags | (((combination >> index) & 1) << bit)
            });
        for preserved in [2, 0x247702] {
            let mut state = SuccessContext {
                rflags: preserved | status,
                writes: 0,
                advances: 0,
            };
            complete_test_vmx_success(&mut state);
            assert_eq!(state.rflags, preserved);
            assert_eq!(state.writes, u64::from(status != 0));
            assert_eq!(state.advances, 1);
        }
    }
}

core::arch::global_asm!(
    ".text",
    ".globl compose_test_msr_bitmap",
    "compose_test_msr_bitmap:",
    "push rsi",
    "push rdi",
    "mov rsi, rcx",
    "mov rdi, r8",
    "mov ecx, 512",
    "call .Lresident_nested_merge_msr_bitmap_loop",
    "pop rdi",
    "pop rsi",
    "ret",
    include_str!("../builds/nested-ept-tests/resident-msr-bitmap.S"),
);

unsafe extern "win64" {
    #[link_name = "compose_test_msr_bitmap"]
    fn compose_test_msr_bitmap_raw(l0: *const u8, l1: *const u8, output: *mut u8);
}

fn compose_test_msr_bitmap(l0: &[u8; 4096], l1: &[u8; 4096], output: &mut [u8; 4096]) {
    // Array sizes cover all 512 qword accesses; the output borrow excludes aliasing.
    unsafe { compose_test_msr_bitmap_raw(l0.as_ptr(), l1.as_ptr(), output.as_mut_ptr()) }
}

#[test]
fn apic_passthrough_keeps_l1_intercepts_and_tracks_bitmap_changes() {
    let mut l0 = [0xff_u8; 4096];
    let mut l1 = [0_u8; 4096];
    let mut output = [0_u8; 4096];
    for base in [0, 2048] {
        for msr in 0x800..=0x8ff {
            l0[base + msr / 8] &= !(1 << (msr % 8));
        }
        for msr in [0x80b, 0x830] {
            l1[base + msr / 8] |= 1 << (msr % 8);
        }
    }
    for revision in 0..3 {
        if revision == 1 {
            l1[2048 + 0x80b / 8] &= !(1 << (0x80b % 8));
        } else if revision == 2 {
            l1[2048 + 0x808 / 8] |= 1 << (0x808 % 8);
        }
        compose_test_msr_bitmap(&l0, &l1, &mut output);
        for offset in 0..4096 {
            assert_eq!(output[offset], l0[offset] | l1[offset]);
        }
    }
}

#[repr(C)]
struct SnapshotContext {
    values: [u64; 9],
    hardware: [u64; 9],
    reads: u64,
}

core::arch::global_asm!(
    ".text",
    ".globl snapshot_test_vmcs01",
    "snapshot_test_vmcs01:",
    "push r12", "mov r12, rcx",
    "call .Lresident_nested_snapshot_vmcs01_effective_state",
    "pop r12", "ret",
    include_str!("../builds/nested-ept-tests/resident-snapshot.S"),
    guest_pat = const 0,
    guest_efer = const 1,
    tsc_offset = const 2,
    vm_entry_controls = const 3,
    pin_based_vm_exec_control = const 4,
    cpu_based_vm_exec_control = const 5,
    secondary_vm_exec_control = const 6,
    vm_exit_controls = const 7,
    ept_pointer = const 8,
    b_nested_inherited_l1_pat = const 0,
    b_nested_inherited_l1_efer = const 8,
    b_nested_inherited_l1_tsc_offset = const 16,
    b_nested_vmcs01_entry_controls = const 24,
    b_nested_vmcs01_pin_based_controls = const 32,
    b_nested_vmcs01_primary_controls = const 40,
    b_nested_vmcs01_secondary_controls = const 48,
    b_nested_vmcs01_exit_controls = const 56,
    b_nested_ept01_pointer = const 64,
    test_hardware = const std::mem::offset_of!(SnapshotContext, hardware),
    test_reads = const std::mem::offset_of!(SnapshotContext, reads),
);

unsafe extern "win64" {
    #[link_name = "snapshot_test_vmcs01"]
    fn snapshot_test_vmcs01_raw(context: *mut SnapshotContext);
}

fn snapshot_test_vmcs01(context: &mut SnapshotContext) {
    // The nine fixed VMCS selectors index the two inline arrays.
    unsafe { snapshot_test_vmcs01_raw(context) }
}

#[test]
fn vmcs01_snapshot_retains_controls_and_refreshes_live_l1_state() {
    let mut state = SnapshotContext {
        values: [0; 9],
        hardware: [
            0x7040600070406,
            0xd01,
            0,
            0x93fb,
            0x1e,
            0x92006172,
            0xa2,
            0x36ffb,
            0x1234501e,
        ],
        reads: 0,
    };
    snapshot_test_vmcs01(&mut state);
    assert_eq!(state.values, state.hardware);
    assert_eq!(state.reads, 9);
    let controls = state.values[4..].to_vec();
    // Mode changes and TSC adjustment must propagate despite the fixed controls.
    state.hardware[0] = 0x606060606060606;
    state.hardware[1] = 0;
    state.hardware[2] = u64::MAX - 100;
    state.hardware[3] &= !0x200;
    snapshot_test_vmcs01(&mut state);
    assert_eq!(state.values[..4], state.hardware[..4]);
    assert_eq!(state.values[4..], controls);
    assert_eq!(state.reads, 13);
}

core::arch::global_asm!(
    ".text",
    ".globl validate_test_address",
    "validate_test_address:",
    "push r12", "mov r12, rcx", "mov r11, rdx",
    "test r8, r8", "jz .Ltest_unaligned_address",
    "call .Lresident_nested_physical_address_is_valid",
    "pop r12", "ret",
    ".Ltest_unaligned_address:",
    "call .Lresident_nested_address_width_is_valid",
    "pop r12", "ret",
    include_str!("../builds/nested-ept-tests/resident-address.S"),
    b_nested_physical_address_bits = const 0,
);

unsafe extern "win64" {
    #[link_name = "validate_test_address"]
    fn validate_test_address_raw(width: *const u32, address: u64, aligned: u64) -> u64;
}

fn validate_test_address(width: &u32, address: u64, aligned: u64) -> u64 {
    // The address is validated as an integer, never dereferenced.
    unsafe { validate_test_address_raw(width, address, aligned) }
}

#[test]
fn physical_address_validation_honors_cached_width_and_alignment() {
    for width in [36, 39, 48, 52] {
        let last_byte = (1_u64 << width) - 1;
        for (address, aligned, valid) in [
            (last_byte, 0, 1),
            (last_byte, 1, 0),
            (last_byte & !4095, 1, 1),
            (last_byte + 1, 0, 0),
            (last_byte + 1, 1, 0),
            (u64::MAX, 0, 0),
        ] {
            assert_eq!(validate_test_address(&width, address, aligned), valid);
        }
    }
    assert_eq!(validate_test_address(&0, 0, 1), 0);
    assert_eq!(validate_test_address(&64, u64::MAX, 0), 1);
}

#[repr(C)]
struct MsrContext {
    host_cr3: u64,
    host_mapping_cache: [u64; 4],
    exit_store: u64,
    root_guest: u64,
    l1_store: u64,
    l1_store_count: u64,
    l1_load: u64,
    l1_load_count: u64,
    l1_entry: u64,
    composed: u64,
    hardware: [u64; 2],
    writes: u64,
}

core::arch::global_asm!(
    ".text",
    ".globl complete_test_msr_exit",
    "complete_test_msr_exit:",
    "push rbx", "push rbp", "push rdi", "push rsi",
    "push r12", "push r13", "push r14", "push r15",
    "mov r12, rcx", "mov r10, rdx",
    "call .Lresident_nested_complete_vmcs02_msr_exit",
    "pop r15", "pop r14", "pop r13", "pop r12",
    "pop rsi", "pop rdi", "pop rbp", "pop rbx", "ret",
    ".globl activate_test_msr_entry",
    "activate_test_msr_entry:",
    "push r12", "mov r12, rcx",
    "call .Lresident_nested_activate_vmcs01_msr_entry",
    "pop r12", "ret",
    include_str!("../builds/nested-ept-tests/resident-msr-exit.S"),
    b_nested_vmcs02_exit_store_msr_list = const std::mem::offset_of!(MsrContext, exit_store),
    b_nested_l0_msr_guest_list = const std::mem::offset_of!(MsrContext, root_guest),
    b_nested_vmcs12_vm_exit_msr_store_addr = const std::mem::offset_of!(MsrContext, l1_store),
    b_nested_vmcs12_vm_exit_msr_store_count = const std::mem::offset_of!(MsrContext, l1_store_count),
    b_nested_vmcs12_vm_exit_msr_load_addr = const std::mem::offset_of!(MsrContext, l1_load),
    b_nested_vmcs12_vm_exit_msr_load_count = const std::mem::offset_of!(MsrContext, l1_load_count),
    b_nested_vmcs01_entry_msr_list = const std::mem::offset_of!(MsrContext, l1_entry),
    b_nested_vmcs01_msr_entry_composed = const std::mem::offset_of!(MsrContext, composed),
    test_hardware = const std::mem::offset_of!(MsrContext, hardware),
    test_writes = const std::mem::offset_of!(MsrContext, writes),
    vm_entry_msr_load_addr = const 0,
    vm_entry_msr_load_count = const 1,
);

unsafe extern "win64" {
    fn complete_test_msr_exit(context: *mut MsrContext, exit_reason: u64);
    fn activate_test_msr_entry(context: *mut MsrContext);
}

#[test]
fn nested_msr_exit_preserves_l1_lists_and_root_speculation_state() {
    let mut arena = Arena::new();
    let buffers = arena.pages(1);
    let mut state = MsrContext {
        host_cr3: arena.host_map(),
        host_mapping_cache: [0; 4],
        exit_store: buffers,
        root_guest: buffers + 0x100,
        l1_store: buffers + 0x200,
        l1_store_count: 3,
        l1_load: buffers + 0x300,
        l1_load_count: 2,
        l1_entry: buffers + 0x400,
        composed: 0,
        hardware: [buffers + 0x100, 1],
        writes: 0,
    };
    unsafe {
        let source = std::slice::from_raw_parts_mut(state.exit_store as *mut u64, 8);
        source.copy_from_slice(&[0x48, 7, 0xc0000102, 0x1234, 0x48, 7, 0xc0000103, 3]);
        let target = std::slice::from_raw_parts_mut(state.l1_store as *mut u64, 6);
        target.copy_from_slice(&[0xc0000102, 0, 0x48, 0, 0xc0000103, 0]);
        let load = std::slice::from_raw_parts_mut(state.l1_load as *mut u64, 4);
        load.copy_from_slice(&[0x48, 9, 0xc0000102, 0x5678]);
        (state.root_guest as *mut u64).write(0x48);
        complete_test_msr_exit(&mut state, 18);
        assert_eq!(target, &[0xc0000102, 0x1234, 0x48, 7, 0xc0000103, 3]);
        let entry = std::slice::from_raw_parts(state.l1_entry as *const u64, 6);
        assert_eq!(entry, &[0x48, 7, 0x48, 9, 0xc0000102, 0x5678]);
        source[1] = 11;
        complete_test_msr_exit(&mut state, 0x80000021);
        assert_eq!(entry, &[0x48, 7, 0x48, 9, 0xc0000102, 0x5678]);
        activate_test_msr_entry(&mut state);
        assert_eq!(state.hardware, [state.l1_entry, 3]);
        assert_eq!(state.composed, 1);
        assert_eq!(state.writes, 2);
        // The first L1 exit restores this base list before its next nested entry.
        state.hardware = [state.root_guest, 1];
        state.composed = 0;
        state.l1_load_count = 0;
        complete_test_msr_exit(&mut state, 18);
        activate_test_msr_entry(&mut state);
        assert_eq!(state.hardware, [state.root_guest, 1]);
        assert_eq!(state.composed, 0);
        assert_eq!(state.writes, 2);
        assert_eq!((state.root_guest as *const u64).add(1).read(), 11);
    }
}

#[repr(C)]
#[derive(Default)]
struct VpidContext {
    primary: u64,
    secondary: u64,
    hardware_controls: u64,
    virtual_tag: u64,
    last_tag: u64,
    flushes: u64,
    kind: u64,
    hardware_tag: u64,
    cache: u64,
    selected_tag: u64,
}

core::arch::global_asm!(
    ".text",
    ".globl prepare_test_vpid",
    "prepare_test_vpid:",
    "push r12", "mov r12, rcx",
    "call .Lresident_nested_prepare_vpid02",
    "pop r12", "ret",
    ".globl invalidate_test_vpid",
    "invalidate_test_vpid:",
    "push r12", "mov r12, rcx", "mov r9, rdx", "mov r10, r8",
    "call .Lresident_nested_invvpid_validate",
    "pop r12", "ret",
    include_str!("../builds/nested-ept-tests/resident-vpid.S"),
    b_nested_vmcs12_primary_control = const std::mem::offset_of!(VpidContext, primary),
    b_nested_vmcs12_secondary_control = const std::mem::offset_of!(VpidContext, secondary),
    b_nested_vmcs01_secondary_controls = const std::mem::offset_of!(VpidContext, hardware_controls),
    b_nested_vmcs12_vpid = const std::mem::offset_of!(VpidContext, virtual_tag),
    b_nested_vmcs02_last_vpid = const std::mem::offset_of!(VpidContext, last_tag),
    b_nested_vmcs02_vpid_cache = const std::mem::offset_of!(VpidContext, cache),
    virtual_processor_id = const 0,
    test_flushes = const std::mem::offset_of!(VpidContext, flushes),
    test_kind = const std::mem::offset_of!(VpidContext, kind),
    test_tag = const std::mem::offset_of!(VpidContext, hardware_tag),
    test_selected_tag = const std::mem::offset_of!(VpidContext, selected_tag),
);

unsafe extern "win64" {
    #[link_name = "prepare_test_vpid"]
    fn prepare_test_vpid_raw(context: *mut VpidContext);
    #[link_name = "invalidate_test_vpid"]
    fn invalidate_test_vpid_raw(
        context: *mut VpidContext,
        kind: u64,
        descriptor: *const u64,
    ) -> u64;
}

fn invalidate_test_vpid(context: &mut VpidContext, kind: u64, descriptor: &[u64; 2]) -> u64 {
    // The descriptor contains both qwords consumed by the validation routine.
    unsafe { invalidate_test_vpid_raw(context, kind, descriptor.as_ptr()) }
}

fn prepare_test_vpid(context: &mut VpidContext) {
    // VPID tags and the packed cache are integers; hardware operations are mocked.
    unsafe { prepare_test_vpid_raw(context) }
}

#[test]
fn vpid_cache_retains_vtl_translations_and_flushes_before_reassigning_a_tag() {
    let mut state = VpidContext {
        primary: 1 << 31,
        secondary: 1 << 5,
        hardware_controls: 1 << 5,
        virtual_tag: 1,
        cache: 48 << 32,
        ..Default::default()
    };
    for (tag, selected, expected_flushes) in [
        (1, 2, 1),
        (1, 2, 1),
        (2, 3, 2),
        (2, 3, 2),
        (1, 2, 2),
        (3, 3, 3),
        (1, 2, 3),
        (2, 3, 4),
    ] {
        state.virtual_tag = tag;
        prepare_test_vpid(&mut state);
        assert_eq!(state.flushes, expected_flushes);
        assert_eq!(state.selected_tag, selected);
        assert_eq!(state.kind, 1);
        assert_ne!(state.hardware_tag, 1);
    }
    state.secondary = 0;
    prepare_test_vpid(&mut state);
    assert_eq!(state.last_tag, 0);
    assert_eq!(state.flushes, 6);
    assert_eq!(state.cache, 48 << 32);
    state.secondary = 1 << 5;
    prepare_test_vpid(&mut state);
    assert_eq!(state.flushes, 7);
    state.hardware_controls = 0;
    state.virtual_tag = 3;
    prepare_test_vpid(&mut state);
    assert_eq!(state.flushes, 7);
}

#[test]
fn invvpid_preserves_l1_and_validates_only_architectural_operand_bits() {
    let mut state = VpidContext {
        hardware_controls: 1 << 5,
        last_tag: 5,
        cache: 5 | (6 << 16),
        ..Default::default()
    };
    for kind in 0..4 {
        let linear = if kind == 0 {
            0xffff_8000_0000_0000
        } else {
            u64::MAX
        };
        let descriptor = [5, linear];
        assert_eq!(invalidate_test_vpid(&mut state, kind, &descriptor), 0);
        assert_eq!(
            (state.kind, state.hardware_tag),
            (1, if kind == 2 { 3 } else { 2 })
        );
    }
    assert_eq!(state.flushes, 5);
    for (kind, descriptor) in [
        (0, [5, 0x0001_0000_0000_0000]),
        (1, [0, 0]),
        (2, [1 << 16, 0]),
        (3, [0, 0]),
    ] {
        assert_eq!(invalidate_test_vpid(&mut state, kind, &descriptor), 1);
    }
    assert_eq!(state.flushes, 5);
    assert_eq!(invalidate_test_vpid(&mut state, 1, &[7, 0]), 0);
    assert_eq!(state.flushes, 5);
    assert_eq!(invalidate_test_vpid(&mut state, 1, &[6, 0]), 0);
    assert_eq!((state.flushes, state.hardware_tag), (6, 3));
    assert_eq!(invalidate_test_vpid(&mut state, 2, &[0, u64::MAX]), 0);
    assert_eq!(state.flushes, 8);
}

#[repr(C)]
#[derive(Default)]
struct Context {
    host_cr3: u64,
    host_mapping_cache: [u64; 4],
    gpa: u64,
    qualification: u64,
    ept01: u64,
    invalidations: u64,
    native_invept: u64,
    recycles: u64,
    ept02: u64,
    pool: u64,
    pool_pages: u64,
    pool_used: u64,
    compositions: u64,
    ept12: u64,
    secondary_control: u64,
    cache_initialized: u64,
    cached_ept12: u64,
    mbec: u64,
    primary_control: u64,
    initial_ept02: u64,
    alternate_ept12: u64,
    alternate_ept02: u64,
    alternate_pool: u64,
    alternate_pool_pages: u64,
    alternate_pool_used: u64,
    alternate_mbec: u64,
    telemetry_active: u64,
    vm_function_control: u64,
    eptp_list_address: u64,
    physical_address_bits: u64,
    ept_capabilities: u64,
    shadow_list: u64,
    native_supported: u64,
    native_enabled: u64,
    native_vmcs: [u64; 3],
    admission: u64,
    write_retry: u64,
    sync_result: u64,
    sync_requests: u64,
    sync_releases: u64,
    eptp_pool: u64,
    eptp_pages: u64,
    eptp_used: u64,
    event_context: u64,
    lists_live: u64,
}

core::arch::global_asm!(
    ".text",
    ".globl resolve_test_ept",
    "resolve_test_ept:",
    "push rbx", "push rbp", "push rdi", "push rsi",
    "push r12", "push r13", "push r14", "push r15",
    "mov r12, rcx",
    "call .Lresident_nested_resolve_ept02_violation",
    "pop r15", "pop r14", "pop r13", "pop r12",
    "pop rsi", "pop rdi", "pop rbp", "pop rbx",
    "ret",
    ".globl check_test_host_mapping",
    "check_test_host_mapping:",
    "push r12", "mov r12, rcx", "mov r11, rdx",
    "call .Lresident_nested_host_page_is_mapped",
    "pop r12", "ret",
    ".globl discard_test_ept",
    "discard_test_ept:",
    "push rbx", "push rbp", "push rdi", "push rsi",
    "push r12", "push r13", "push r14", "push r15",
    "mov r12, rcx",
    "call .Lresident_nested_invalidate_ept02",
    "pop r15", "pop r14", "pop r13", "pop r12",
    "pop rsi", "pop rdi", "pop rbp", "pop rbx",
    "ret",
    ".globl revalidate_test_ept",
    "revalidate_test_ept:",
    "push rbx", "push rbp", "push rdi", "push rsi",
    "push r12", "push r13", "push r14", "push r15",
    "mov r12, rcx",
    "call .Lresident_nested_revalidate_ept02",
    "pop r15", "pop r14", "pop r13", "pop r12",
    "pop rsi", "pop rdi", "pop rbp", "pop rbx",
    "ret",
    ".globl prepare_test_ept",
    "prepare_test_ept:",
    "push rbx", "push rbp", "push rdi", "push rsi",
    "push r12", "push r13", "push r14", "push r15",
    "mov r12, rcx",
    "call .Lresident_nested_prepare_ept02",
    "pop r15", "pop r14", "pop r13", "pop r12",
    "pop rsi", "pop rdi", "pop rbp", "pop rbx",
    "ret",
    ".globl invalidate_test_ept_context",
    "invalidate_test_ept_context:",
    "push rbx", "push rbp", "push rdi", "push rsi",
    "push r12", "push r13", "push r14", "push r15",
    "mov r12, rcx", "mov r14, rdx",
    "call .Lresident_nested_invalidate_ept12_context",
    "pop r15", "pop r14", "pop r13", "pop r12",
    "pop rsi", "pop rdi", "pop rbp", "pop rbx",
    "ret",
    ".globl switch_test_eptp",
    "switch_test_eptp:",
    "push rbx", "push rbp", "push rdi", "push rsi",
    "push r12", "push r13", "push r14", "push r15",
    "mov r12, rcx", "mov eax, edx", "mov ecx, r8d",
    "call .Lresident_nested_switch_eptp",
    "pop r15", "pop r14", "pop r13", "pop r12",
    "pop rsi", "pop rdi", "pop rbp", "pop rbx", "ret",
    ".globl validate_test_vm_functions",
    "validate_test_vm_functions:",
    "push r12", "mov r12, rcx",
    "call .Lresident_nested_validate_vm_functions",
    "pop r12", "ret",
    ".globl refresh_test_eptp_list",
    "refresh_test_eptp_list:",
    "push rbx", "push rbp", "push rdi", "push rsi",
    "push r12", "push r13", "push r14", "push r15",
    "mov r12, rcx", "call .Lresident_nested_refresh_eptp_list",
    "pop r15", "pop r14", "pop r13", "pop r12",
    "pop rsi", "pop rdi", "pop rbp", "pop rbx", "ret",
    ".globl capture_test_native_eptp",
    "capture_test_native_eptp:",
    "push r12", "mov r12, rcx", "call .Lresident_nested_capture_native_eptp",
    "pop r12", "ret",
    ".globl release_test_eptp_sources",
    "release_test_eptp_sources:",
    "push rbx", "push rbp", "push rdi", "push rsi",
    "push r12", "push r13", "push r14", "push r15",
    "mov r12, rcx", "call .Lresident_nested_eptp_release_sources",
    "pop r15", "pop r14", "pop r13", "pop r12",
    "pop rsi", "pop rdi", "pop rbp", "pop rbx", "ret",
    ".globl root_write_test_eptp",
    "root_write_test_eptp:",
    "push r12", "mov r12, rcx",
    "call .Lresident_nested_eptp_before_root_write",
    "pop r12", "ret",
    include_str!("../builds/nested-ept-tests/resident-ept.S"),
    b_event_context = const std::mem::offset_of!(Context, event_context),
    event_cpu_contexts = const 0,
    test_lists_live = const std::mem::offset_of!(Context, lists_live),
    b_nested_eptp_shadow_list = const std::mem::offset_of!(Context, shadow_list),
    b_nested_eptp_native_supported = const std::mem::offset_of!(Context, native_supported),
    b_nested_eptp_native_enabled = const std::mem::offset_of!(Context, native_enabled),
    b_nested_eptp_admission = const std::mem::offset_of!(Context, admission),
    b_nested_eptp_write_retry = const std::mem::offset_of!(Context, write_retry),
    test_sync_result = const std::mem::offset_of!(Context, sync_result),
    test_sync_requests = const std::mem::offset_of!(Context, sync_requests),
    test_sync_releases = const std::mem::offset_of!(Context, sync_releases),
    b_nested_eptp_table_pool = const std::mem::offset_of!(Context, eptp_pool),
    b_nested_eptp_table_pages = const std::mem::offset_of!(Context, eptp_pages),
    b_nested_eptp_table_used = const std::mem::offset_of!(Context, eptp_used),
    test_native_vmcs = const std::mem::offset_of!(Context, native_vmcs),
    vm_function_control = const 0,
    eptp_list_address = const 1,
    ept_pointer = const 2,
    b_nested_vmcs12_vm_function_control = const std::mem::offset_of!(Context, vm_function_control),
    b_nested_vmcs12_eptp_list_address = const std::mem::offset_of!(Context, eptp_list_address),
    b_nested_physical_address_bits = const std::mem::offset_of!(Context, physical_address_bits),
    b_nested_vmx_ept_vpid_cap = const std::mem::offset_of!(Context, ept_capabilities),
    b_expected_host_cr3 = const std::mem::offset_of!(Context, host_cr3),
    b_telemetry_active = const std::mem::offset_of!(Context, telemetry_active),
    b_nested_host_mapping_cache = const std::mem::offset_of!(Context, host_mapping_cache),
    b_last_guest_physical_address = const std::mem::offset_of!(Context, gpa),
    b_last_qualification = const std::mem::offset_of!(Context, qualification),
    b_nested_ept01_pointer = const std::mem::offset_of!(Context, ept01),
    b_nested_ept02_invalidation_count = const std::mem::offset_of!(Context, invalidations),
    b_invept_exits = const std::mem::offset_of!(Context, native_invept),
    b_nested_ept02_recycle_count = const std::mem::offset_of!(Context, recycles),
    b_nested_ept02_pointer = const std::mem::offset_of!(Context, ept02),
    b_nested_ept02_table_pool = const std::mem::offset_of!(Context, pool),
    b_nested_ept02_table_pool_pages = const std::mem::offset_of!(Context, pool_pages),
    b_nested_ept02_table_pool_used = const std::mem::offset_of!(Context, pool_used),
    b_nested_ept_composition_count = const std::mem::offset_of!(Context, compositions),
    b_nested_vmcs12_ept_pointer = const std::mem::offset_of!(Context, ept12),
    b_nested_vmcs12_secondary_control = const std::mem::offset_of!(Context, secondary_control),
    b_nested_ept02_cache_initialized = const std::mem::offset_of!(Context, cache_initialized),
    b_nested_ept12_pointer = const std::mem::offset_of!(Context, cached_ept12),
    b_nested_ept02_mbec = const std::mem::offset_of!(Context, mbec),
    b_nested_vmcs12_primary_control = const std::mem::offset_of!(Context, primary_control),
    b_nested_ept02_initial_pointer = const std::mem::offset_of!(Context, initial_ept02),
    b_nested_ept02_cached_ept12_pointer = const std::mem::offset_of!(Context, alternate_ept12),
    b_nested_ept02_cached_pointer = const std::mem::offset_of!(Context, alternate_ept02),
    b_nested_ept02_cached_table_pool = const std::mem::offset_of!(Context, alternate_pool),
    b_nested_ept02_cached_table_pool_pages = const std::mem::offset_of!(Context, alternate_pool_pages),
    b_nested_ept02_cached_table_pool_used = const std::mem::offset_of!(Context, alternate_pool_used),
    b_nested_ept02_cached_mbec = const std::mem::offset_of!(Context, alternate_mbec),
    guest_physical_address = const 0x2400,
    host_page_address_mask = const 0x000f_ffff_ffff_f000u64,
);

unsafe extern "win64" {
    fn check_test_host_mapping(context: *mut Context, address: u64) -> u64;
    fn resolve_test_ept(context: *mut Context) -> u64;
    fn discard_test_ept(context: *mut Context);
    fn revalidate_test_ept(context: *mut Context);
    fn prepare_test_ept(context: *mut Context);
    fn invalidate_test_ept_context(context: *mut Context, ept_pointer: u64);
    fn switch_test_eptp(context: *mut Context, function: u64, index: u64) -> u64;
    fn validate_test_vm_functions(context: *mut Context) -> u64;
    fn refresh_test_eptp_list(context: *mut Context);
    fn capture_test_native_eptp(context: *mut Context);
    fn release_test_eptp_sources(context: *mut Context) -> u64;
    fn root_write_test_eptp(context: *mut Context);
}

const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
struct Arena {
    allocations: Vec<(*mut u8, Layout)>,
    ept12_mappings: HashMap<u64, u64>,
}
impl Arena {
    fn new() -> Self {
        Self {
            allocations: Vec::new(),
            ept12_mappings: HashMap::new(),
        }
    }
    fn pages(&mut self, count: usize) -> u64 {
        let layout = Layout::from_size_align(count * 4096, 4096).unwrap();
        let pointer = unsafe { alloc_zeroed(layout) };
        assert!(!pointer.is_null());
        self.allocations.push((pointer, layout));
        pointer as u64
    }
    fn map(&mut self, root: u64, address: u64, target: u64, shift: u32, attributes: u64) {
        let mut table = root;
        for level in [39, 30, 21, 12] {
            let slot = table + ((address >> level) & 511) * 8;
            if level == shift {
                unsafe {
                    (slot as *mut u64).write(target | attributes);
                }
                if let Some(&ept01) = self.ept12_mappings.get(&root) {
                    self.map_ept12_tables(root, ept01, 39);
                }
                return;
            }
            let entry = unsafe { (slot as *const u64).read() };
            if entry & 7 == 0 {
                let child = self.pages(1);
                unsafe {
                    (slot as *mut u64).write(child | 0x407);
                }
                table = child;
            } else {
                assert_eq!(entry & 128, 0);
                table = entry & ADDRESS_MASK;
            }
        }
        panic!("Invalid leaf size");
    }
    fn expose_ept12(&mut self, root: u64, ept01: u64) {
        self.ept12_mappings.insert(root, ept01);
        self.map_ept12_tables(root, ept01, 39);
    }
    fn map_ept12_tables(&mut self, table: u64, ept01: u64, shift: u32) {
        self.map(ept01, table, table, 12, 0x37);
        if shift == 12 {
            return;
        }
        for index in 0..512 {
            let entry = unsafe { (table as *const u64).add(index).read() };
            if entry & 0x407 != 0 && entry & 0x80 == 0 {
                self.map_ept12_tables(entry & ADDRESS_MASK, ept01, shift - 9);
            }
        }
    }
    fn host_map(&mut self) -> u64 {
        let root = self.pages(1);
        let addresses: Vec<_> = self.allocations.iter().map(|(p, _)| *p as u64).collect();
        let mut ranges = HashMap::new();
        for address in addresses.into_iter().chain([0, 0x4000_0000]) {
            let index = (address >> 39) & 511;
            let pdpt = *ranges.entry(index).or_insert_with(|| self.pages(1));
            unsafe {
                ((root + index * 8) as *mut u64).write(pdpt | 3);
            }
            for j in 0..512 {
                unsafe {
                    ((pdpt + j * 8) as *mut u64).write((index << 39) | (j << 30) | 0x83);
                }
            }
        }
        root
    }
}
impl Drop for Arena {
    fn drop(&mut self) {
        for &(pointer, layout) in &self.allocations {
            unsafe {
                dealloc(pointer, layout);
            }
        }
    }
}
fn leaf(root: u64, address: u64) -> (u32, u64) {
    let mut table = root & ADDRESS_MASK;
    for shift in [39, 30, 21, 12] {
        let entry = unsafe { ((table + ((address >> shift) & 511) * 8) as *const u64).read() };
        if entry & 7 == 0 || shift == 12 || entry & 128 != 0 {
            return (shift, entry);
        }
        table = entry & ADDRESS_MASK;
    }
    unreachable!()
}
fn entry_addresses(root: u64, address: u64) -> Vec<u64> {
    let mut table = root & ADDRESS_MASK;
    let mut addresses = Vec::new();
    for shift in [39, 30, 21, 12] {
        let slot = table + ((address >> shift) & 511) * 8;
        addresses.push(slot);
        let entry = unsafe { (slot as *const u64).read() };
        if shift == 12 || entry & 128 != 0 {
            break;
        }
        table = entry & ADDRESS_MASK;
    }
    addresses
}

#[test]
fn accessed_dirty_tracks_first_access_and_write_without_discarding_other_leaves() {
    for shift in [12, 21] {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        let large = if shift == 21 { 0x80 } else { 0 };
        arena.map(ept12, 0x200000, 0x400000, shift, 0x37 | large);
        arena.map(ept12, 0x600000, 0x800000, 21, 0xb7);
        arena.map(ept01, 0x400000, 0x400000, 21, 0xb7);
        arena.map(ept01, 0x800000, 0x800000, 21, 0xb7);
        let mut state = context(&mut arena, ept12 | 0x40, ept01);
        state.cached_ept12 = state.ept12;
        state.gpa = 0x600000;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        let other_leaf = leaf(state.ept02, state.gpa);
        state.gpa = 0x200000;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        let entries = entry_addresses(ept12, state.gpa);
        for address in &entries {
            assert_eq!(unsafe { (*address as *const u64).read() } & 0x300, 0x100);
        }
        assert_eq!(leaf(state.ept02, state.gpa).1 & 0x302, 0x300);
        let used = state.pool_used;
        state.qualification = 2;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(ept12, state.gpa).1 & 0x300, 0x300);
        assert_eq!(leaf(state.ept02, state.gpa).1 & 0x302, 0x302);
        assert_eq!(leaf(state.ept02, 0x600000), other_leaf);
        assert_eq!(state.pool_used, used);
        for address in &entries[..entries.len() - 1] {
            assert_eq!(unsafe { (*address as *const u64).read() } & 0x200, 0);
        }
    }
}

#[test]
fn accessed_dirty_invalidation_preserves_cleared_flags_until_real_access() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
    arena.map(ept01, 0x400000, 0x400000, 21, 0xb7);
    let mut state = context(&mut arena, ept12 | 0x40, ept01);
    state.cached_ept12 = state.ept12;
    state.qualification = 2;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    let entries = entry_addresses(ept12, state.gpa);
    let last = *entries.last().unwrap() as *mut u64;
    unsafe { *last &= !0x200 };
    unsafe { discard_test_ept(&mut state) };
    assert_eq!(unsafe { *last } & 0x300, 0x100);
    assert_eq!(leaf(state.ept02, state.gpa).1 & 2, 0);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(unsafe { *last } & 0x300, 0x300);
    for address in entries {
        unsafe { *(address as *mut u64) &= !0x100 };
        unsafe { discard_test_ept(&mut state) };
        assert_eq!(leaf(state.ept02, state.gpa).1, 0);
        assert_eq!(unsafe { *(address as *const u64) } & 0x100, 0);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_ne!(unsafe { *(address as *const u64) } & 0x100, 0);
    }
}

#[test]
fn accessed_dirty_does_not_mark_denied_writes_or_change_disabled_flags() {
    for (ad, l1, l0) in [(true, 0xb5, 0xb7), (true, 0xb7, 0xb5), (false, 0xb7, 0xb7)] {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, l1);
        arena.map(ept01, 0x400000, 0x400000, 21, l0);
        let mut state = context(&mut arena, ept12 | if ad { 0x40 } else { 0 }, ept01);
        state.qualification = 2;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, u64::from(!ad));
        for address in entry_addresses(ept12, state.gpa) {
            let entry = unsafe { (address as *const u64).read() };
            assert_eq!(entry & 0x200, 0);
            assert_eq!(entry & 0x100, if ad { 0x100 } else { 0 });
        }
    }
}

fn context(arena: &mut Arena, ept12: u64, ept01: u64) -> Context {
    if ept12 & ADDRESS_MASK != 0 && ept01 != 0 {
        arena.expose_ept12(ept12 & ADDRESS_MASK, ept01);
    }
    let ept02 = arena.pages(1);
    let pool = arena.pages(16);
    let alternate_ept02 = arena.pages(1);
    let alternate_pool = arena.pages(16);
    let eptp_pool = arena.pages(4);
    Context {
        eptp_pool,
        eptp_pages: 4,
        lists_live: 1,
        telemetry_active: 1,
        host_cr3: arena.host_map(),
        gpa: 0x203000,
        qualification: 1,
        ept01,
        ept12,
        ept02,
        pool,
        pool_pages: 16,
        secondary_control: 2,
        cache_initialized: 1,
        cached_ept12: ept12,
        primary_control: 1 << 31,
        initial_ept02: ept02,
        alternate_ept02,
        alternate_pool,
        alternate_pool_pages: 16,
        ..Default::default()
    }
}

#[test]
fn disabled_telemetry_keeps_ept_composition_and_invalidation_operational() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12, ept01);
    state.telemetry_active = 0;
    unsafe {
        assert_eq!(resolve_test_ept(&mut state), 1);
        discard_test_ept(&mut state);
        assert_eq!(resolve_test_ept(&mut state), 1);
    }
    assert_eq!(state.compositions, 0);
    assert_eq!(state.invalidations, 0);
    assert_eq!(state.native_invept, 0);
    assert!(state.pool_used > 0);
}

#[test]
fn vmfunc_switches_remapped_list_entries_and_retains_both_cached_roots() {
    let mut arena = Arena::new();
    let first = arena.pages(1) | 0x1e;
    let second = arena.pages(1) | 0x1e;
    let ept01 = arena.pages(1);
    let list = arena.pages(1);
    arena.map(ept01, 0x9000, list, 12, 0x31);
    arena.map(first & ADDRESS_MASK, 0x200000, 0x400000, 21, 0xb7);
    arena.map(second & ADDRESS_MASK, 0x200000, 0x600000, 21, 0xb7);
    arena.expose_ept12(second & ADDRESS_MASK, ept01);
    arena.map(ept01, 0x400000, 0x800000, 21, 0xb7);
    arena.map(ept01, 0x600000, 0xa00000, 21, 0xb7);
    unsafe {
        (list as *mut u64).write(first);
        (list as *mut u64).add(511).write(second);
    }
    let mut state = context(&mut arena, first, ept01);
    state.secondary_control |= 1 << 13;
    state.vm_function_control = 1;
    state.eptp_list_address = 0x9000;
    state.physical_address_bits = 52;
    let first_root = state.ept02;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    let first_leaf = leaf(state.ept02, state.gpa);
    assert_eq!(first_leaf.1 & ADDRESS_MASK, 0x800000);
    assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 511) }, 1);
    assert_eq!(state.ept12, second);
    assert_ne!(state.ept02, first_root);
    assert_eq!(state.invalidations, 1);
    let second_root = state.ept02;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    let second_leaf = leaf(state.ept02, state.gpa);
    assert_eq!(second_leaf.1 & ADDRESS_MASK, 0xa00000);
    for _ in 0..8 {
        assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 0) }, 1);
        assert_eq!(state.ept02, first_root);
        assert_eq!(leaf(state.ept02, state.gpa), first_leaf);
        assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 511) }, 1);
        assert_eq!(state.ept02, second_root);
        assert_eq!(leaf(state.ept02, state.gpa), second_leaf);
    }
    assert_eq!(state.invalidations, 1);
    assert_eq!(state.compositions, 2);
    assert_eq!(unsafe { switch_test_eptp(&mut state, 1 << 32, 1 << 32) }, 1);
    assert_eq!(state.ept12, first);
}

#[test]
fn vmfunc_invalid_requests_preserve_the_active_ept() {
    let mut arena = Arena::new();
    let first = arena.pages(1) | 0x1e;
    let ept01 = arena.pages(1);
    let list = arena.pages(1);
    arena.map(ept01, 0x9000, list, 12, 0x31);
    let mut state = context(&mut arena, first, ept01);
    state.secondary_control |= 1 << 13;
    state.vm_function_control = 1;
    state.eptp_list_address = 0x9000;
    state.physical_address_bits = 48;
    let root = state.ept02;
    for entry in [0, first | 0x80, first | (1 << 48), first ^ 1, first | 0x40] {
        unsafe { (list as *mut u64).write(entry) };
        assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 0) }, 0);
        assert_eq!(state.ept12, first);
        assert_eq!(state.ept02, root);
        assert_eq!(state.invalidations, 0);
    }
    unsafe { (list as *mut u64).write(first) };
    for (function, index) in [(1, 0), (63, 0), (0, 512), (0, u32::MAX as u64)] {
        assert_eq!(unsafe { switch_test_eptp(&mut state, function, index) }, 0);
    }
    state.vm_function_control = 0;
    assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 0) }, 0);
    state.vm_function_control = 1;
    state.primary_control = 0;
    assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 0) }, 0);
    state.primary_control = 1 << 31;
    state.secondary_control = 2;
    assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 0) }, 0);
    state.secondary_control = 0x2002;
    arena.map(ept01, 0x9000, list, 12, 0x34);
    assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 0) }, 0);
    assert_eq!(state.ept12, first);
    assert_eq!(state.ept02, root);
    assert_eq!(state.invalidations, 0);
}

#[test]
fn native_eptp_list_publishes_composed_roots_and_recovers_hardware_selection() {
    let mut arena = Arena::new();
    let first = arena.pages(1) | 0x1e;
    let second = arena.pages(1) | 0x1e;
    let cold = arena.pages(1) | 0x1e;
    let list = arena.pages(1);
    let shadow = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept01, 0x9000, list, 12, 0x31);
    unsafe {
        (list as *mut u64).write(first);
        (list as *mut u64).add(1).write(second);
        (list as *mut u64).add(2).write(cold);
        (list as *mut u64).add(3).write(u64::MAX);
        (list as *mut u64).add(511).write(second);
    }
    let mut state = context(&mut arena, first, ept01);
    state.secondary_control = 0x2002;
    state.vm_function_control = 1;
    state.eptp_list_address = 0x9000;
    state.physical_address_bits = 52;
    state.shadow_list = shadow;
    state.native_supported = 1;
    assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 1) }, 1);
    let second_root = state.ept02;
    let first_root = state.alternate_ept02;
    unsafe { refresh_test_eptp_list(&mut state) };
    assert_eq!(state.native_enabled, 1);
    assert_eq!(state.native_vmcs[..2], [1, shadow]);
    let published = unsafe { std::slice::from_raw_parts(shadow as *const u64, 512) };
    assert_eq!(published[0], first_root);
    assert_eq!(published[1], second_root);
    assert_eq!(published[511], second_root);
    assert!(published[2..511].iter().all(|entry| *entry == 0));

    let old_pool = state.pool;
    let old_alternate_pool = state.alternate_pool;
    state.native_vmcs[2] = published[0];
    unsafe { capture_test_native_eptp(&mut state) };
    assert_eq!(state.ept12, first);
    assert_eq!(state.ept02, first_root);
    assert_eq!(state.pool, old_alternate_pool);
    assert_eq!(state.alternate_pool, old_pool);
    state.native_vmcs[2] = published[511];
    unsafe { capture_test_native_eptp(&mut state) };
    assert_eq!(state.ept12, second);
    assert_eq!(state.ept02, second_root);
    assert_eq!(state.pool, old_pool);
    assert_eq!(state.invalidations, 1);

    assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 2) }, 1);
    unsafe { refresh_test_eptp_list(&mut state) };
    assert_eq!(
        published[0], 0,
        "A recycled root must lose its old list aliases"
    );
    assert_eq!(published[1], second_root);
    assert_eq!(published[2], state.ept02);
    state.vm_function_control = 0;
    unsafe { refresh_test_eptp_list(&mut state) };
    assert_eq!(state.native_enabled, 0);
    assert_eq!(state.native_vmcs[0], 0);
}

#[test]
fn native_eptp_list_requires_stable_source_and_matching_execution_mode() {
    let mut arena = Arena::new();
    let first = arena.pages(1) | 0x5e;
    let list = arena.pages(1);
    let shadow = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept01, 0x9000, list, 12, 0x33);
    unsafe { (list as *mut u64).write(first) };
    let mut state = context(&mut arena, first, ept01);
    state.ept02 |= 0x1e;
    state.secondary_control = 0x2002;
    state.vm_function_control = 1;
    state.eptp_list_address = 0x9000;
    state.physical_address_bits = 52;
    state.ept_capabilities = 1 << 21;
    state.shadow_list = shadow;
    state.native_supported = 1;
    unsafe { refresh_test_eptp_list(&mut state) };
    assert_eq!(state.native_enabled, 0);
    arena.map(ept01, 0x9000, list, 12, 0x31);
    unsafe { refresh_test_eptp_list(&mut state) };
    assert_eq!(state.native_enabled, 1);
    assert_eq!(unsafe { (shadow as *const u64).read() }, state.ept02 | 0x40);
    state.native_vmcs[2] = state.ept02 | 0x40;
    unsafe { capture_test_native_eptp(&mut state) };
    assert_eq!(state.ept12, first);
    state.secondary_control |= 1 << 22;
    unsafe { refresh_test_eptp_list(&mut state) };
    assert_eq!(unsafe { (shadow as *const u64).read() }, 0);
    state.native_supported = 0;
    state.native_vmcs = [0xfeed; 3];
    unsafe { refresh_test_eptp_list(&mut state) };
    assert_eq!(state.native_vmcs, [0xfeed; 3]);
}

#[test]
fn native_eptp_list_rejects_writable_physical_aliases_at_every_leaf_size() {
    for shift in [12, 21, 30] {
        let mut arena = Arena::new();
        let first = arena.pages(1) | 0x1e;
        let list = arena.pages(1);
        let shadow = arena.pages(1);
        let ept01 = arena.pages(1);
        let alias = (1_u64 << 39) + (5_u64 << 30);
        let size = 1_u64 << shift;
        let target = list & !(size - 1);
        let large = if shift == 12 { 0 } else { 0x80 };
        arena.map(ept01, 0x9000, list, 12, 0x31);
        arena.map(ept01, alias, target, shift, 0x31 | large);
        unsafe { (list as *mut u64).write(first) };
        let mut state = context(&mut arena, first, ept01);
        state.ept02 |= 0x1e;
        state.secondary_control = 0x2002;
        state.vm_function_control = 1;
        state.eptp_list_address = 0x9000;
        state.physical_address_bits = 52;
        state.shadow_list = shadow;
        state.native_supported = 1;
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_enabled, 1);

        arena.map(ept01, alias, target, shift, 0x33 | large);
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_enabled, 0, "Writable alias with shift {shift}");
        assert_eq!(state.native_vmcs[0], 0);

        // A denial at any ancestor removes effective write access to the alias.
        let entries = entry_addresses(ept01, alias);
        for &address in &entries[..entries.len() - 1] {
            unsafe { *(address as *mut u64) &= !2 };
            unsafe { refresh_test_eptp_list(&mut state) };
            assert_eq!(state.native_enabled, 1);
            unsafe { *(address as *mut u64) |= 2 };
        }

        arena.map(ept01, alias, target ^ size, shift, 0x33 | large);
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(
            state.native_enabled, 1,
            "Unrelated writable leaf with shift {shift}"
        );
        assert_eq!(unsafe { (shadow as *const u64).read() }, state.ept02);
    }
}

#[test]
fn writable_lists_are_protected_before_publication_and_deoptimized_before_a_write() {
    const TRACKED: u64 = 1 << 55;
    for shift in [12, 21, 30] {
        let mut arena = Arena::new();
        let first = arena.pages(1) | 0x1e;
        let list = arena.pages(1);
        let shadow = arena.pages(1);
        let ept01 = arena.pages(1);
        let alias = 1_u64 << 39;
        let size = 1_u64 << shift;
        let alias_page = alias + (list & (size - 1));
        let large = if shift == 12 { 0 } else { 0x80 };
        arena.map(ept01, 0x9000, list, 12, 0x37);
        arena.map(ept01, alias, list & !(size - 1), shift, 0x33 | large);
        arena.map(ept01, 0xa000, list, 12, 0x31);
        arena.map(first & ADDRESS_MASK, 0x200000, 0x9000, 12, 0x37);
        unsafe { (list as *mut u64).write(first) };
        let mut state = context(&mut arena, first, ept01);
        state.ept02 |= 0x1e;
        state.secondary_control = 0x2002;
        state.vm_function_control = 1;
        state.eptp_list_address = 0x9000;
        state.physical_address_bits = 52;
        state.shadow_list = shadow;
        state.native_supported = 1;
        state.admission = 1;
        let original = [leaf(ept01, 0x9000), leaf(ept01, alias), leaf(ept01, 0xa000)];

        // Failed quiescence must leave permissions and native execution unchanged.
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_enabled, 0);
        assert_eq!(leaf(ept01, 0x9000), original[0]);
        assert_eq!(state.sync_releases, 0);
        state.admission = 1;
        state.sync_result = 1;
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_enabled, 1);
        assert_eq!(state.admission, 0);
        assert_eq!(state.sync_releases, 1);
        assert_eq!(leaf(ept01, 0x9000).1, (original[0].1 & !2) | TRACKED);
        assert_eq!(leaf(ept01, alias_page), (12, list | 0x31 | TRACKED));
        if shift != 12 {
            let neighbor = alias_page ^ 4096;
            let neighbor_leaf = leaf(ept01, neighbor);
            assert_eq!(neighbor_leaf, (12, (list ^ 4096) | 0x33));
        }
        assert_eq!(state.eptp_used, u64::from((shift - 12) / 9));
        assert_eq!(leaf(ept01, 0xa000), original[2]);
        assert_eq!(unsafe { (shadow as *const u64).read() }, state.ept02);
        state.gpa = 0x200000;
        state.qualification = 2;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
        assert_eq!(state.write_retry, 1);

        state.sync_result = 0;
        assert_eq!(unsafe { release_test_eptp_sources(&mut state) }, 0);
        assert_ne!(leaf(ept01, 0x9000).1 & TRACKED, 0);
        state.sync_result = 1;
        assert_eq!(unsafe { release_test_eptp_sources(&mut state) }, 1);
        assert_eq!(state.native_enabled, 0);
        assert_eq!(leaf(ept01, 0x9000), original[0]);
        assert_eq!(leaf(ept01, alias_page), (12, list | 0x33));
        assert_eq!(leaf(ept01, 0xa000), original[2]);
        assert!(
            unsafe { std::slice::from_raw_parts(shadow as *const u64, 512) }
                .iter()
                .all(|entry| *entry == 0)
        );
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(
            state.native_enabled, 0,
            "Internal retry must not reprotect the pending store"
        );
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(state.write_retry, 0);
        assert_eq!(leaf(state.ept02, state.gpa).1 & 2, 2);
        let used = state.eptp_used;
        state.admission = 1;
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_enabled, 1);
        assert_eq!(
            state.eptp_used, used,
            "Readmission reuses permanent split tables"
        );
    }
}

#[test]
fn protection_pool_exhaustion_restores_earlier_aliases_without_publishing() {
    for pages in [0, 1] {
        let mut arena = Arena::new();
        let first = arena.pages(1) | 0x1e;
        let list = arena.pages(1);
        let shadow = arena.pages(1);
        let ept01 = arena.pages(1);
        let alias = 1_u64 << 39;
        let attributes = (1_u64 << 63) | (3 << 52) | 0x3b7;
        arena.map(ept01, 0x9000, list, 12, 0x37);
        arena.map(ept01, alias, list & !((1 << 30) - 1), 30, attributes);
        unsafe { (list as *mut u64).write(first) };
        let mut state = context(&mut arena, first, ept01);
        state.ept02 |= 0x1e;
        state.secondary_control = 0x2002;
        state.vm_function_control = 1;
        state.eptp_list_address = 0x9000;
        state.physical_address_bits = 52;
        state.shadow_list = shadow;
        state.native_supported = 1;
        state.admission = 1;
        state.sync_result = 1;
        state.eptp_pages = pages;
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_enabled, 0);
        assert_eq!(state.lists_live, 0);
        assert_eq!(state.eptp_used, pages);
        assert_eq!(state.sync_releases, 1);
        assert_eq!(leaf(ept01, 0x9000), (12, list | 0x37));
        let address = alias + (list & ((1 << 30) - 1));
        let (shift, entry) = leaf(ept01, address);
        let mask = (1_u64 << shift) - 1;
        assert_eq!(entry, (list & !mask) | attributes);
        assert!(
            unsafe { std::slice::from_raw_parts(shadow as *const u64, 512) }
                .iter()
                .all(|entry| *entry == 0)
        );
    }
}

#[test]
fn root_writes_retire_readonly_sources_and_tpr_shadow_prevents_publication() {
    let mut arena = Arena::new();
    let first = arena.pages(1) | 0x1e;
    let list = arena.pages(1);
    let shadow = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept01, 0x9000, list, 12, 0x31);
    unsafe { (list as *mut u64).write(first) };
    let mut state = context(&mut arena, first, ept01);
    state.ept02 |= 0x1e;
    state.secondary_control = 0x2002;
    state.vm_function_control = 1;
    state.eptp_list_address = 0x9000;
    state.physical_address_bits = 52;
    state.shadow_list = shadow;
    state.native_supported = 1;
    state.lists_live = 0;
    unsafe { root_write_test_eptp(&mut state) };
    assert_eq!(state.sync_requests, 0);
    unsafe { refresh_test_eptp_list(&mut state) };
    assert_eq!(
        state.native_enabled, 0,
        "Initial publication requires quiescence"
    );
    state.sync_result = 1;
    unsafe { refresh_test_eptp_list(&mut state) };
    assert_eq!(state.native_enabled, 1);
    assert_eq!(state.lists_live, 1);
    unsafe { root_write_test_eptp(&mut state) };
    assert_eq!(state.lists_live, 0);
    assert_eq!(state.native_enabled, 0);
    assert_eq!(leaf(ept01, 0x9000), (12, list | 0x31));
    assert_eq!(unsafe { (shadow as *const u64).read() }, 0);
    let requests = state.sync_requests;
    unsafe { root_write_test_eptp(&mut state) };
    assert_eq!(state.sync_requests, requests);

    let peer = Context {
        primary_control: 1 << 21,
        ..Default::default()
    };
    let mut peers = [0_u64; 64];
    peers[63] = &peer as *const Context as u64;
    state.event_context = peers.as_ptr() as u64;
    unsafe { refresh_test_eptp_list(&mut state) };
    assert_eq!(state.native_enabled, 0);
    unsafe { peers.as_mut_ptr().add(63).write_volatile(0) };
    unsafe { refresh_test_eptp_list(&mut state) };
    assert_eq!(state.native_enabled, 1);
    state.primary_control |= 1 << 21;
    unsafe { refresh_test_eptp_list(&mut state) };
    assert_eq!(state.native_enabled, 0);
}

#[test]
fn vm_function_entry_validation_checks_reserved_bits_ept_and_list_alignment() {
    let mut arena = Arena::new();
    let mut state = context(&mut arena, 0, 0);
    state.secondary_control = 0x2002;
    state.physical_address_bits = 48;
    state.vm_function_control = 1;
    state.eptp_list_address = 0x9000;
    assert_eq!(unsafe { validate_test_vm_functions(&mut state) }, 1);
    for list in [0x9001, 1 << 48, u64::MAX] {
        state.eptp_list_address = list;
        assert_eq!(unsafe { validate_test_vm_functions(&mut state) }, 0);
    }
    state.eptp_list_address = 0x9000;
    for function_mask in [2, 3, 1 << 63] {
        state.vm_function_control = function_mask;
        assert_eq!(unsafe { validate_test_vm_functions(&mut state) }, 0);
    }
    state.vm_function_control = 1;
    state.secondary_control = 1 << 13;
    assert_eq!(unsafe { validate_test_vm_functions(&mut state) }, 0);
    state.vm_function_control = 0;
    assert_eq!(unsafe { validate_test_vm_functions(&mut state) }, 1);
    state.vm_function_control = u64::MAX;
    state.secondary_control = 2;
    assert_eq!(unsafe { validate_test_vm_functions(&mut state) }, 1);
    state.primary_control = 0;
    state.secondary_control = 0x2002;
    assert_eq!(unsafe { validate_test_vm_functions(&mut state) }, 1);
}

#[test]
fn host_mapping_cache_respects_large_page_boundaries_and_small_page_holes() {
    let mut arena = Arena::new();
    let root = arena.pages(1);
    let pdpt = arena.pages(1);
    let directory = arena.pages(1);
    let small_pages = arena.pages(1);
    unsafe {
        (root as *mut u64).write(pdpt | 3);
        (pdpt as *mut u64).write(directory | 3);
        (pdpt as *mut u64).add(1).write(0x40000083);
        (directory as *mut u64).write(0x83);
        (directory as *mut u64).add(1).write(small_pages | 3);
        (directory as *mut u64).add(4).write(0x800083);
        (small_pages as *mut u64).write(0x200003);
        (small_pages as *mut u64).add(511).write(0x3ff003);
    }
    let mut state = Context {
        host_cr3: root,
        ..Default::default()
    };
    for (address, expected) in [
        (0, 1),
        (0x1fffff, 1),
        (0x200000, 1),
        (0x201000, 0),
        (0x3ff000, 1),
        (0x400000, 0),
        (0x800000, 1),
        (0, 1),
        (0x40000000, 1),
        (0x7fffffff, 1),
        (0x80000000, 0),
    ] {
        assert_eq!(
            unsafe { check_test_host_mapping(&mut state, address) },
            expected,
            "{address:#x}"
        );
    }
    assert_eq!(state.host_mapping_cache[1], 0);
}

#[test]
fn ept_cache_retains_each_execution_mode_and_invalidates_both_by_root() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0x4b7);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12 | 0x1e, ept01);
    let supervisor_root = state.ept02;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    state.secondary_control |= 1 << 22;
    unsafe { prepare_test_ept(&mut state) };
    let mbec_root = state.ept02;
    assert_ne!(supervisor_root, mbec_root);
    assert_eq!(state.mbec, 1);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(leaf(supervisor_root, state.gpa).1 & 0x407, 7);
    assert_eq!(leaf(mbec_root, state.gpa).1 & 0x407, 0x407);
    let invalidations = state.invalidations;
    for mode in [0, 1, 0, 1] {
        state.secondary_control = 2 | (mode << 22);
        unsafe { prepare_test_ept(&mut state) };
        assert_eq!(state.mbec, mode);
        assert_eq!(state.invalidations, invalidations);
        assert_eq!(
            state.ept02,
            if mode == 0 {
                supervisor_root
            } else {
                mbec_root
            }
        );
    }
    arena.map(ept12, 0x200000, 0x400000, 21, 0x4b3);
    unsafe { invalidate_test_ept_context(&mut state, ept12 | 0x5e) };
    assert_eq!(state.ept02, mbec_root);
    assert_eq!(state.mbec, 1);
    assert_eq!(state.invalidations, invalidations + 2);
    assert_eq!(leaf(supervisor_root, state.gpa).1 & 0x407, 3);
    assert_eq!(leaf(mbec_root, state.gpa).1 & 0x407, 0x403);
    state.secondary_control = 2;
    unsafe { prepare_test_ept(&mut state) };
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(leaf(supervisor_root, state.gpa).1 & 0x407, 3);
    assert_eq!(leaf(mbec_root, state.gpa).1 & 0x407, 0x403);
    arena.map(ept12, 0x200000, 0, 21, 0);
    unsafe { invalidate_test_ept_context(&mut state, ept12 | 0x1e) };
    assert_eq!(leaf(supervisor_root, state.gpa).1, 0);
    assert_eq!(leaf(mbec_root, state.gpa).1, 0);
}
#[test]
fn composition_translates_every_ept12_table_and_honors_table_write_protection() {
    let mut arena = Arena::new();
    let tables = [
        arena.pages(1),
        arena.pages(1),
        arena.pages(1),
        arena.pages(1),
    ];
    let table_gpas = [0, 0x101000, 0x102000, 0x103000];
    let slots = [tables[0], tables[1], tables[2] + 8, tables[3] + 3 * 8];
    let entries = [
        table_gpas[1] | 7,
        table_gpas[2] | 7,
        table_gpas[3] | 7,
        0x403037,
    ];
    let ept01 = arena.pages(1);
    for (gpa, hpa) in table_gpas.into_iter().zip(tables) {
        arena.map(ept01, gpa, hpa, 12, 0x37);
    }
    arena.map(ept01, 0x403000, 0x803000, 12, 0x37);
    for (slot, entry) in slots.into_iter().zip(entries) {
        unsafe { (slot as *mut u64).write(entry) };
    }
    let mut state = context(&mut arena, 0, ept01);
    state.ept12 = table_gpas[0] | 0x1e;
    state.cached_ept12 = state.ept12;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(leaf(state.ept02, state.gpa), (12, 0x803037));

    arena.map(ept01, 0x405000, 0xa05000, 12, 0x37);
    unsafe { (slots[3] as *mut u64).write(0x405031) };
    let eptp = state.ept12;
    unsafe { invalidate_test_ept_context(&mut state, eptp) };
    assert_eq!(leaf(state.ept02, state.gpa), (12, 0xa05031));
    unsafe { (slots[3] as *mut u64).write(entries[3]) };

    for index in 0..4 {
        // Deny reads through EPT01 even though all host backing pages are mapped.
        arena.map(ept01, table_gpas[index], tables[index], 12, 0x34);
        unsafe { discard_test_ept(&mut state) };
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
        assert_eq!(leaf(state.ept02, state.gpa).1, 0);
        arena.map(ept01, table_gpas[index], tables[index], 12, 0x37);
    }

    state.ept12 |= 0x40;
    state.cached_ept12 = state.ept12;
    for index in 0..4 {
        for (slot, entry) in slots.into_iter().zip(entries) {
            unsafe { (slot as *mut u64).write(entry) };
        }
        arena.map(ept01, table_gpas[index], tables[index], 12, 0x35);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
        assert_eq!(
            unsafe { (slots[index] as *const u64).read() },
            entries[index]
        );
        arena.map(ept01, table_gpas[index], tables[index], 12, 0x37);
    }
    for (slot, entry) in slots.into_iter().zip(entries) {
        unsafe { (slot as *mut u64).write(entry | 0x100) };
    }
    arena.map(ept01, table_gpas[3], tables[3], 12, 0x35);
    // Already-accessed, read-only table pages can be walked without any update.
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    state.qualification = 2;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
    assert_eq!(unsafe { (slots[3] as *const u64).read() } & 0x200, 0);
    arena.map(ept01, table_gpas[3], tables[3], 12, 0x37);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(unsafe { (slots[3] as *const u64).read() } & 0x300, 0x300);

    // L0's software A/D writes must take the same deoptimization path as a
    // guest store when an EPT12 table shares the protected list page/range.
    state.sync_result = 1;
    for index in 0..4 {
        for (slot, entry) in slots.into_iter().zip(entries) {
            unsafe { (slot as *mut u64).write(entry) };
        }
        arena.map(
            ept01,
            table_gpas[index],
            tables[index],
            12,
            (1 << 55) | 0x35,
        );
        state.qualification = 1;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
        assert_eq!(state.write_retry, 1);
        assert_eq!(
            unsafe { (slots[index] as *const u64).read() },
            entries[index]
        );
        assert_eq!(unsafe { release_test_eptp_sources(&mut state) }, 1);
        assert_eq!(leaf(ept01, table_gpas[index]).1 & ((1 << 55) | 2), 2);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(state.write_retry, 0);
    }
}

#[test]
fn composes_large_leaves_with_remapping_and_restricted_permissions() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0xb5);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12, ept01);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(leaf(state.ept02, state.gpa), (21, 0x6000b5));
    assert_eq!(state.pool_used, 2);
}
#[test]
fn preserves_four_kib_l0_remaps_inside_a_large_l1_leaf() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
    arena.map(ept01, 0x403000, 0xa00000, 12, 0x31);
    let mut state = context(&mut arena, ept12, ept01);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(leaf(state.ept02, state.gpa), (12, 0xa00031));
    assert_eq!(leaf(state.ept02, state.gpa + 4096), (12, 0));
}
#[test]
fn keeps_four_kib_l1_permissions_and_uncacheable_memory() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x203000, 0x403000, 12, 3);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12, ept01);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(leaf(state.ept02, state.gpa), (12, 0x603003));
    assert_eq!(leaf(state.ept02, state.gpa + 4096), (12, 0));
}
#[test]
fn rejects_writes_denied_by_either_level() {
    for (l1, l0) in [(0xb5, 0xb7), (0xb7, 0xb5)] {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, l1);
        arena.map(ept01, 0x400000, 0x600000, 21, l0);
        let mut state = context(&mut arena, ept12, ept01);
        state.qualification = 2;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
        assert_eq!(state.compositions, 0);
    }
}
#[test]
fn recycles_exhausted_tables_without_reflecting_a_false_violation() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x203000, 0x403000, 12, 0x37);
    arena.map(ept12, 0x40003000, 0x405000, 12, 0x37);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12, ept01);
    state.pool_pages = 3;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    state.gpa = 0x40003000;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(state.invalidations, 1);
    assert_eq!(state.recycles, 1);
    assert_eq!(leaf(state.ept02, state.gpa), (12, 0x605037));
    assert_eq!(leaf(state.ept02, 0x203000).1, 0);
}

#[test]
fn replaces_a_cached_large_leaf_after_l1_relaxes_permissions() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0xb5);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12, ept01);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
    state.qualification = 2;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(leaf(state.ept02, state.gpa), (21, 0x6000b7));
    assert_eq!(state.invalidations, 1);
}

#[test]
fn invalidation_rebuilds_remaps_permissions_and_memory_type_on_demand() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
    arena.map(ept12, 0x400000, 0x800000, 21, 0xb7);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    arena.map(ept01, 0x800000, 0xa00000, 21, 0xb7);
    arena.map(ept01, 0xc00000, 0xe00000, 21, 0xb1);
    let mut state = context(&mut arena, ept12, ept01);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    state.gpa = 0x403000;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    let pool_before = unsafe {
        std::slice::from_raw_parts(state.pool as *const u64, state.pool_used as usize * 512)
            .to_vec()
    };
    arena.map(ept12, 0x200000, 0xc00000, 21, 0x87);
    unsafe {
        discard_test_ept(&mut state);
    }
    assert_eq!(leaf(state.ept02, 0x203000).1, 0);
    assert_eq!(leaf(state.ept02, 0x403000).1, 0);
    assert_eq!(state.pool_used, 0);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(state.pool as *const u64, pool_before.len()) },
        pool_before
    );
    state.gpa = 0x203000;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(leaf(state.ept02, state.gpa), (21, 0xe00081));
    // Reused pages must not make an old sibling mapping reachable again.
    assert_eq!(leaf(state.ept02, 0x403000).1, 0);
    state.gpa = 0x403000;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(leaf(state.ept02, 0x403000), (21, 0xa000b7));
    arena.map(ept12, 0x200000, 0, 21, 0);
    unsafe {
        discard_test_ept(&mut state);
    }
    assert_eq!(leaf(state.ept02, 0x203000).1, 0);
    state.gpa = 0x203000;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
    state.gpa = 0x403000;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(leaf(state.ept02, 0x403000), (21, 0xa000b7));
}
#[test]
fn invalidation_removes_a_large_mapping_when_l1_splits_it() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12, ept01);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    arena.map(ept12, 0x200000, 0, 21, 0);
    arena.map(ept12, 0x203000, 0x403000, 12, 0x31);
    unsafe {
        discard_test_ept(&mut state);
    }
    assert_eq!(leaf(state.ept02, state.gpa).1, 0);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(leaf(state.ept02, state.gpa), (12, 0x603031));
    assert_eq!(leaf(state.ept02, 0x204000), (12, 0));
}
#[test]
fn invalidation_applies_four_kib_remaps_and_upper_level_revocations() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x203000, 0x403000, 12, 0x37);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12, ept01);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    arena.map(ept12, 0x203000, 0x405000, 12, 0x31);
    unsafe {
        discard_test_ept(&mut state);
    }
    assert_eq!(leaf(state.ept02, state.gpa).1, 0);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(leaf(state.ept02, state.gpa), (12, 0x605031));
    unsafe {
        (ept12 as *mut u64).write(0);
        discard_test_ept(&mut state);
    }
    assert_eq!(leaf(state.ept02, state.gpa).1, 0);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
}

#[test]
fn revalidation_updates_remaps_permissions_and_memory_type() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
    arena.map(ept12, 0x400000, 0x800000, 21, 0xb7);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    arena.map(ept01, 0x800000, 0xa00000, 21, 0xb7);
    arena.map(ept01, 0xc00000, 0xe00000, 21, 0xb1);
    let mut state = context(&mut arena, ept12, ept01);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    state.gpa = 0x403000;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    let used = state.pool_used;
    arena.map(ept12, 0x200000, 0xc00000, 21, 0x87);
    unsafe {
        revalidate_test_ept(&mut state);
    }
    assert_eq!(leaf(state.ept02, 0x203000), (21, 0xe00081));
    assert_eq!(leaf(state.ept02, 0x403000), (21, 0xa000b7));
    assert_eq!(state.pool_used, used);
    arena.map(ept12, 0x200000, 0, 21, 0);
    unsafe {
        revalidate_test_ept(&mut state);
    }
    assert_eq!(leaf(state.ept02, 0x203000), (21, 0));
    assert_eq!(leaf(state.ept02, 0x403000), (21, 0xa000b7));
}
#[test]
fn revalidation_removes_a_large_mapping_when_l1_splits_it() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12, ept01);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    arena.map(ept12, 0x200000, 0, 21, 0);
    arena.map(ept12, 0x203000, 0x403000, 12, 0x31);
    unsafe {
        revalidate_test_ept(&mut state);
    }
    assert_eq!(leaf(state.ept02, state.gpa), (21, 0));
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(leaf(state.ept02, state.gpa), (12, 0x603031));
    assert_eq!(leaf(state.ept02, 0x204000), (12, 0));
}
#[test]
fn revalidation_visits_four_kib_leaves_and_upper_level_revocations() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x203000, 0x403000, 12, 0x37);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12, ept01);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    arena.map(ept12, 0x203000, 0x405000, 12, 0x31);
    unsafe {
        revalidate_test_ept(&mut state);
    }
    assert_eq!(leaf(state.ept02, state.gpa), (12, 0x605031));
    unsafe {
        (ept12 as *mut u64).write(0);
        revalidate_test_ept(&mut state);
    }
    assert_eq!(leaf(state.ept02, state.gpa), (12, 0));
}

#[repr(C)]
struct ExitMsrContext {
    values: [u64; 117],
    hardware: [u64; 117],
    saved_pat: u64,
    saved_efer: u64,
    exit_reason: u64,
    exit_controls: u64,
    vmx_misc: u64,
    entry_controls: u64,
}
core::arch::global_asm!(
    ".text",
    ".globl capture_test_exit_msrs",
    "capture_test_exit_msrs:",
    "push r12", "mov r12, rcx",
    "call .Lresident_nested_capture_vmcs02_guest_state",
    "pop r12", "ret",
    include_str!("../builds/nested-ept-tests/resident-exit-msrs.S"),
    guest_pat = const 25,
    guest_efer = const 26,
    test_hardware = const std::mem::offset_of!(ExitMsrContext, hardware),
    b_nested_l2_saved_pat = const std::mem::offset_of!(ExitMsrContext, saved_pat),
    b_nested_l2_saved_efer = const std::mem::offset_of!(ExitMsrContext, saved_efer),
    b_nested_vmcs12_exit_reason = const std::mem::offset_of!(ExitMsrContext, exit_reason),
    b_nested_vmcs12_vm_exit_controls = const std::mem::offset_of!(ExitMsrContext, exit_controls),
    b_nested_vmcs12_extended_fields = const std::mem::offset_of!(ExitMsrContext, values),
    b_nested_vmx_misc = const std::mem::offset_of!(ExitMsrContext, vmx_misc),
    b_nested_vmcs12_vm_entry_controls = const std::mem::offset_of!(ExitMsrContext, entry_controls),
);
unsafe extern "win64" {
    #[link_name = "capture_test_exit_msrs"]
    fn capture_test_exit_msrs_raw(context: *mut ExitMsrContext);
}

fn capture_test_exit_msrs(context: &mut ExitMsrContext) {
    // Fixed PAT and EFER indices are within both inline arrays.
    unsafe { capture_test_exit_msrs_raw(context) }
}
#[test]
fn exit_saves_efer_only_when_requested_after_successful_entry() {
    for save_efer in [false, true] {
        for entry_failed in [false, true] {
            for update_entry_mode in [false, true] {
                let mut state = ExitMsrContext {
                    values: [0xfeed; 117],
                    hardware: [0; 117],
                    saved_pat: 0,
                    saved_efer: 0,
                    exit_reason: if entry_failed { 0x80000021 } else { 10 },
                    exit_controls: if save_efer { 1 << 20 } else { 0 },
                    vmx_misc: if update_entry_mode { 1 << 5 } else { 0 },
                    entry_controls: 0,
                };
                state.hardware[25] = 0x0007040600070406;
                state.hardware[26] = 0x500;
                capture_test_exit_msrs(&mut state);
                assert_eq!(state.saved_efer, 0x500);
                assert_eq!(state.saved_pat, state.hardware[25]);
                assert_eq!(state.values[25], 0xfeed);
                assert_eq!(
                    state.values[26],
                    if save_efer && !entry_failed {
                        0x500
                    } else {
                        0xfeed
                    }
                );
                assert_eq!(
                    state.entry_controls,
                    if update_entry_mode && !entry_failed {
                        1 << 9
                    } else {
                        0
                    }
                );
            }
        }
    }
}

#[repr(C)]
struct GuestContext {
    valid: u64,
    control_valid: [u64; 2],
    values: [u64; 117],
    cache: [u64; 117],
    hardware: [u64; 117],
    writes: u64,
    rare_pending: [u64; 2],
    vmcs01: u64,
    vmcs02: u64,
    selected_vmcs: u64,
    switches: u64,
    reads: u64,
}
core::arch::global_asm!(
    ".text",
    ".globl sync_test_guest",
    "sync_test_guest:",
    "push r12", "push rsi",
    "mov r12, rcx",
    "call .Lresident_nested_sync_vmcs02_guest_fields",
    "pop rsi", "pop r12", "ret",
    ".globl capture_test_guest",
    "capture_test_guest:",
    "push r12", "push rsi", "mov r12, rcx",
    "lea rsi, [rip + .Lresident_nested_guest_state_table]", "mov ecx, 50",
    "call .Lresident_nested_capture_vmcs02_guest_state_loop",
    "pop rsi", "pop r12", "ret",
    ".globl materialize_test_guest",
    "materialize_test_guest:",
    "push r12", "mov r12, rcx", "mov rax, rdx",
    "mov r11, r8", "mov r10, r9",
    "push rdx", "mov rdx, r9",
    "call .Lresident_nested_materialize_guest_field",
    "cmp rax, qword ptr [rsp]", "jne .Lresident_dispatch_halt",
    "cmp rdx, r9", "jne .Lresident_dispatch_halt", "pop rdx",
    "cmp r11, r8", "jne .Lresident_dispatch_halt",
    "cmp r10, r9", "jne .Lresident_dispatch_halt",
    "pop r12", "ret",
    ".globl materialize_test_all_guest",
    "materialize_test_all_guest:",
    "push r12", "mov r12, rcx",
    "call .Lresident_nested_materialize_vmcs02_rare_state",
    "pop r12", "ret",
    include_str!("../builds/nested-ept-tests/resident-guest.S"),
    b_nested_vmcs02_guest_cache_valid = const std::mem::offset_of!(GuestContext,valid),
    b_nested_vmcs02_field_cache = const std::mem::offset_of!(GuestContext,cache),
    b_nested_vmcs12_extended_fields = const std::mem::offset_of!(GuestContext,values),
    test_hardware = const std::mem::offset_of!(GuestContext,hardware),
    test_writes = const std::mem::offset_of!(GuestContext,writes),
    test_reads = const std::mem::offset_of!(GuestContext,reads),
    test_selected_vmcs = const std::mem::offset_of!(GuestContext,selected_vmcs),
    test_switches = const std::mem::offset_of!(GuestContext,switches),
    b_nested_vmcs01_region = const std::mem::offset_of!(GuestContext,vmcs01),
    b_nested_vmcs02_region = const std::mem::offset_of!(GuestContext,vmcs02),
    b_nested_vmcs02_rare_state_pending = const std::mem::offset_of!(GuestContext,rare_pending),
    nested_rare_guest_fields_low = const (0xff_u64 << 35) | (0x3ff_u64 << 50),
    nested_rare_guest_fields_high = const (0xffff_u64 << 1) | (1_u64 << 28),
    nested_guest_state_table_count = const 50,
);
unsafe extern "win64" {
    #[link_name = "sync_test_guest"]
    fn sync_test_guest_raw(context: *mut GuestContext);
    #[link_name = "capture_test_guest"]
    fn capture_test_guest_raw(context: *mut GuestContext);
    #[link_name = "materialize_test_guest"]
    fn materialize_test_guest_raw(
        context: *mut GuestContext,
        field: u64,
        value: u64,
        encoding: u64,
    );
    #[link_name = "materialize_test_all_guest"]
    fn materialize_test_all_guest_raw(context: *mut GuestContext);
}

fn materialize_test_all_guest(context: &mut GuestContext) {
    assert_eq!(context.vmcs01, 1);
    assert_eq!(context.vmcs02, 2);
    // Deferred fields come from the bounded static table; VMCS identifiers are mocked.
    unsafe { materialize_test_all_guest_raw(context) }
}

fn materialize_test_guest(context: &mut GuestContext, field: u64, value: u64, encoding: u64) {
    assert!(
        field < context.values.len() as u64,
        "guest field index is out of bounds"
    );
    assert_eq!(context.vmcs01, 1);
    assert_eq!(context.vmcs02, 2);
    // The checked field bounds the bitmap and array accesses; VMCS identifiers are mocked.
    unsafe { materialize_test_guest_raw(context, field, value, encoding) }
}

fn capture_test_guest(context: &mut GuestContext) {
    assert_eq!(context.selected_vmcs, 2);
    // The static guest-field table indexes only the inline context arrays.
    unsafe { capture_test_guest_raw(context) }
}

fn sync_test_guest(context: &mut GuestContext) {
    // The static guest-field table indexes only the inline context arrays.
    unsafe { sync_test_guest_raw(context) }
}
#[test]
fn guest_sync_retains_hardware_state_and_applies_l1_changes() {
    let mut state = GuestContext {
        valid: 0,
        control_valid: [0; 2],
        values: [0; 117],
        cache: [0; 117],
        hardware: [u64::MAX; 117],
        writes: 0,
        rare_pending: [0; 2],
        vmcs01: 1,
        vmcs02: 2,
        selected_vmcs: 2,
        switches: 0,
        reads: 0,
    };
    sync_test_guest(&mut state);
    assert_eq!(state.writes, 50);
    state.values[30] = 0x12345000;
    sync_test_guest(&mut state);
    assert_eq!(state.writes, 55);
    assert_eq!(state.hardware[30], 0x12345000);
    state.hardware[30] = 0x87654000;
    state.cache[30] = state.hardware[30];
    state.values[30] = state.hardware[30];
    sync_test_guest(&mut state);
    assert_eq!(state.writes, 59);
    assert_eq!(state.hardware[30], 0x87654000);
    state.valid = 0;
    sync_test_guest(&mut state);
    assert_eq!(state.writes, 109);
}

#[test]
fn deferred_guest_state_survives_resume_and_materializes_before_l1_access() {
    let mut state = GuestContext {
        valid: 0,
        control_valid: [0; 2],
        values: [0; 117],
        cache: [0; 117],
        hardware: [u64::MAX; 117],
        writes: 0,
        rare_pending: [0; 2],
        vmcs01: 1,
        vmcs02: 2,
        selected_vmcs: 2,
        switches: 0,
        reads: 0,
    };
    let rare = |index| {
        (35..=42).contains(&index)
            || (50..=59).contains(&index)
            || (65..=80).contains(&index)
            || index == 92
    };
    sync_test_guest(&mut state);
    let fields: Vec<usize> = state
        .hardware
        .iter()
        .enumerate()
        .filter_map(|(index, value)| (*value != u64::MAX).then_some(index))
        .collect();
    assert_eq!(fields.len(), 50);
    for &index in &fields {
        state.hardware[index] = 0x10000 + index as u64;
    }
    capture_test_guest(&mut state);
    assert_eq!(state.reads, 15);
    let pending = [
        (0xff_u64 << 35) | (0x3ff_u64 << 50),
        (0xffff_u64 << 1) | (1_u64 << 28),
    ];
    assert_eq!(state.rare_pending, pending);
    for &index in &fields {
        assert_eq!(
            state.values[index],
            if rare(index) {
                0
            } else {
                state.hardware[index]
            }
        );
    }
    state.selected_vmcs = 1;
    materialize_test_guest(&mut state, 30, u64::MAX, 0x6802);
    assert_eq!(state.switches, 0);
    assert_eq!(state.rare_pending, pending);
    state.selected_vmcs = 2;
    sync_test_guest(&mut state);
    assert_eq!(state.writes, 54);
    for &index in &fields {
        assert_eq!(state.hardware[index], 0x10000 + index as u64);
    }
    state.selected_vmcs = 1;
    materialize_test_guest(&mut state, 50, 0xfeed_dead_beef, 0x6806);
    assert_eq!(state.reads, 16);
    assert_eq!(state.switches, 2);
    assert_eq!(state.selected_vmcs, 1);
    assert_eq!(state.rare_pending, [pending[0] & !(1 << 50), pending[1]]);
    for &index in &fields {
        let expected = if rare(index) && index != 50 {
            0
        } else {
            state.hardware[index]
        };
        assert_eq!(state.values[index], expected);
        assert_eq!(state.cache[index], expected);
    }
    materialize_test_guest(&mut state, 50, 0, 0x6806);
    assert_eq!(state.reads, 16);
    assert_eq!(state.switches, 2);
    state.values[50] = 0x87654000;
    state.selected_vmcs = 2;
    sync_test_guest(&mut state);
    assert_eq!(state.hardware[50], 0x87654000);
    assert_eq!(state.writes, 59);
    // A VMCS switch or clear must save even fields L1 has not read.
    for &index in &fields {
        state.hardware[index] = 0x20000 + index as u64;
    }
    capture_test_guest(&mut state);
    state.selected_vmcs = 1;
    materialize_test_all_guest(&mut state);
    materialize_test_all_guest(&mut state);
    assert_eq!(state.reads, 66);
    assert_eq!(state.switches, 4);
    assert_eq!(state.selected_vmcs, 1);
    assert_eq!(state.rare_pending, [0; 2]);
    for &index in &fields {
        assert_eq!(state.values[index], state.hardware[index]);
    }
}

core::arch::global_asm!(
    ".text",
    ".globl sync_test_control",
    "sync_test_control:",
    "push r12",
    "mov r12, rcx",
    "mov rax, rdx",
    "mov r11, r8",
    "call .Lresident_nested_write_vmcs02_control",
    "pop r12", "ret",
    ".globl lookup_test_field",
    "lookup_test_field:",
    "push rsi", "mov rdx, rcx",
    "call .Lresident_vmcs12_field_index",
    "pop rsi", "ret",
    include_str!("../builds/nested-ept-tests/resident-controls.S"),
    b_nested_vmcs02_control_cache_valid = const std::mem::offset_of!(GuestContext,control_valid),
    b_nested_vmcs02_field_cache = const std::mem::offset_of!(GuestContext,cache),
    test_hardware = const std::mem::offset_of!(GuestContext,hardware),
    test_writes = const std::mem::offset_of!(GuestContext,writes),
    vmcs12_extended_field_count = const 117,
);
unsafe extern "win64" {
    #[link_name = "sync_test_control"]
    fn sync_test_control_raw(context: *mut GuestContext, field: u64, value: u64);
    #[link_name = "lookup_test_field"]
    fn lookup_test_field_raw(encoding: u64) -> u64;
}

fn lookup_test_field(encoding: u64) -> u64 {
    // The assembly rejects reserved bits before indexing its static lookup table.
    unsafe { lookup_test_field_raw(encoding) }
}

fn sync_test_control(context: &mut GuestContext, field: u64, value: u64) {
    assert!(
        lookup_test_field(field) < context.cache.len() as u64,
        "unknown VMCS field"
    );
    // The validated encoding maps to an in-bounds context array index.
    unsafe { sync_test_control_raw(context, field, value) }
}

#[test]
fn guest_wrappers_reject_invalid_indices_before_entering_assembly() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let mut context = GuestContext {
        valid: 0,
        control_valid: [0; 2],
        values: [0; 117],
        cache: [0; 117],
        hardware: [0; 117],
        writes: 0,
        rare_pending: [u64::MAX; 2],
        vmcs01: 1,
        vmcs02: 2,
        selected_vmcs: 2,
        switches: 0,
        reads: 0,
    };
    for field in [117, 128, u64::MAX] {
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                materialize_test_guest(&mut context, field, 0, 0x6806);
            }))
            .is_err()
        );
    }
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            sync_test_control(&mut context, u64::MAX, 0);
        }))
        .is_err()
    );
    assert_eq!((context.reads, context.writes, context.switches), (0, 0, 0));
}
#[test]
fn vmcs_lookup_rejects_reserved_bits_and_resolves_every_index() {
    let source = include_str!("../src/asm/resident_island.S");
    let table = source
        .split(".Lresident_vmcs12_field_index_table:")
        .nth(1)
        .unwrap()
        .split(".balign 8")
        .next()
        .unwrap();
    let indices: Vec<u64> = table
        .lines()
        .filter_map(|line| line.split(".byte ").nth(1))
        .flat_map(|line| line.trim().split(", "))
        .map(|value| value.parse().unwrap())
        .collect();
    for encoding in 0_u64..0x10000 {
        let expected = if encoding & !0x6c3e == 0 {
            indices[(((encoding & 0x6c00) >> 5) | ((encoding & 0x3e) >> 1)) as usize]
        } else {
            255
        };
        assert_eq!(lookup_test_field(encoding), expected, "{encoding:#x}");
    }
    for encoding in [0x1_0000_6802, u64::MAX, 0x8000_0000_0000_0000] {
        assert_eq!(lookup_test_field(encoding), 255);
    }
}
#[test]
fn control_cache_writes_zero_initially_and_tracks_high_indices() {
    let mut state = GuestContext {
        valid: 0,
        control_valid: [0; 2],
        values: [0; 117],
        cache: [0; 117],
        hardware: [u64::MAX; 117],
        writes: 0,
        rare_pending: [0; 2],
        vmcs01: 1,
        vmcs02: 2,
        selected_vmcs: 2,
        switches: 0,
        reads: 0,
    };
    sync_test_control(&mut state, 0x4000, 0);
    assert_eq!(state.hardware[1], 0);
    assert_eq!(state.writes, 1);
    sync_test_control(&mut state, 0x4000, 0);
    assert_eq!(state.writes, 1);
    sync_test_control(&mut state, 0x2012, 0x100000000);
    assert_eq!(state.hardware[101], 0x100000000);
    assert_eq!(state.writes, 2);
    sync_test_control(&mut state, 0x2012, 0x100000000);
    assert_eq!(state.writes, 2);
    sync_test_control(&mut state, 0x2012, 0x200000000);
    assert_eq!(state.hardware[101], 0x200000000);
    assert_eq!(state.writes, 3);
    state.control_valid = [0; 2];
    sync_test_control(&mut state, 0x2012, 0x200000000);
    assert_eq!(state.writes, 4);
}

#[test]
fn mbec_enforces_distinct_user_and_supervisor_execute_permissions() {
    for (attributes, user_allowed, supervisor_allowed) in [
        (0x4b3, true, false),
        (0xb7, false, true),
        (0x4b7, true, true),
        (0x4b0, true, false),
    ] {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, attributes);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        state.mbec = 1;
        state.qualification = 0x384;
        assert_eq!(
            unsafe { resolve_test_ept(&mut state) },
            u64::from(user_allowed)
        );
        if user_allowed {
            assert_eq!(leaf(state.ept02, state.gpa), (21, 0x600000 | attributes));
        }
        state.qualification = 0x184;
        assert_eq!(
            unsafe { resolve_test_ept(&mut state) },
            u64::from(supervisor_allowed)
        );
        if !supervisor_allowed {
            assert_eq!(state.qualification & 0x60, 0x40);
            assert_eq!(state.qualification & !0xfff, 0);
        }
    }
}
#[test]
fn mbec_respects_l0_execute_denials_after_user_only_leaf_invalidation() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0x4b0);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12, ept01);
    state.mbec = 1;
    state.qualification = 0x384;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb3);
    unsafe {
        discard_test_ept(&mut state);
    }
    assert_eq!(leaf(state.ept02, state.gpa).1 & 0x407, 0);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
    assert_eq!(state.qualification & 0x60, 0);
}
#[test]
fn disabled_mbec_ignores_the_user_execute_bit() {
    let mut arena = Arena::new();
    let ept12 = arena.pages(1);
    let ept01 = arena.pages(1);
    arena.map(ept12, 0x200000, 0x400000, 21, 0x4b3);
    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
    let mut state = context(&mut arena, ept12, ept01);
    state.qualification = 0x384;
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
    assert_eq!(state.qualification & 0x60, 0);
}
