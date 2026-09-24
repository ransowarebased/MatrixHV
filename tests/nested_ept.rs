use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::collections::HashMap;

#[repr(C)]
struct MsrContext {
    host_cr3: u64,
    exit_store: u64,
    root_guest: u64,
    l1_store: u64,
    l1_store_count: u64,
    l1_load: u64,
    l1_load_count: u64,
    l1_entry: u64,
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
    include_str!("../builds/nested-ept-tests/resident-msr-exit.S"),
    b_nested_vmcs02_exit_store_msr_list = const std::mem::offset_of!(MsrContext, exit_store),
    b_nested_l0_msr_guest_list = const std::mem::offset_of!(MsrContext, root_guest),
    b_nested_vmcs12_vm_exit_msr_store_addr = const std::mem::offset_of!(MsrContext, l1_store),
    b_nested_vmcs12_vm_exit_msr_store_count = const std::mem::offset_of!(MsrContext, l1_store_count),
    b_nested_vmcs12_vm_exit_msr_load_addr = const std::mem::offset_of!(MsrContext, l1_load),
    b_nested_vmcs12_vm_exit_msr_load_count = const std::mem::offset_of!(MsrContext, l1_load_count),
    b_nested_vmcs01_entry_msr_list = const std::mem::offset_of!(MsrContext, l1_entry),
    resident_msr_switch_count = const 1,
    resident_msr_switch_qword_count = const 2,
    resident_msr_switch_byte_count = const 16,
);

unsafe extern "win64" {
    fn complete_test_msr_exit(context: *mut MsrContext, exit_reason: u64);
}

#[test]
fn nested_msr_exit_preserves_l1_lists_and_root_speculation_state() {
    let mut arena = Arena::new();
    let buffers = arena.pages(1);
    let mut state = MsrContext {
        host_cr3: arena.host_map(),
        exit_store: buffers,
        root_guest: buffers + 0x100,
        l1_store: buffers + 0x200,
        l1_store_count: 3,
        l1_load: buffers + 0x300,
        l1_load_count: 2,
        l1_entry: buffers + 0x400,
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
    test_flushes = const std::mem::offset_of!(VpidContext, flushes),
    test_kind = const std::mem::offset_of!(VpidContext, kind),
    test_tag = const std::mem::offset_of!(VpidContext, hardware_tag),
);

unsafe extern "win64" {
    fn prepare_test_vpid(context: *mut VpidContext);
    fn invalidate_test_vpid(context: *mut VpidContext, kind: u64, descriptor: *const u64) -> u64;
}

#[test]
fn vpid_reuse_flushes_on_virtual_tag_changes_and_reenable() {
    let mut state = VpidContext {
        primary: 1 << 31,
        secondary: 1 << 5,
        hardware_controls: 1 << 5,
        virtual_tag: 1,
        ..Default::default()
    };
    for (tag, expected_flushes) in [(1, 1), (1, 1), (2, 2), (2, 2), (1, 3)] {
        state.virtual_tag = tag;
        unsafe { prepare_test_vpid(&mut state) };
        assert_eq!(state.flushes, expected_flushes);
        assert_eq!((state.kind, state.hardware_tag), (1, 2));
    }
    state.secondary = 0;
    unsafe { prepare_test_vpid(&mut state) };
    assert_eq!(state.last_tag, 0);
    assert_eq!(state.flushes, 3);
    state.secondary = 1 << 5;
    unsafe { prepare_test_vpid(&mut state) };
    assert_eq!(state.flushes, 4);
    state.hardware_controls = 0;
    state.virtual_tag = 3;
    unsafe { prepare_test_vpid(&mut state) };
    assert_eq!(state.flushes, 4);
}

#[test]
fn invvpid_preserves_l1_and_validates_only_architectural_operand_bits() {
    let mut state = VpidContext {
        hardware_controls: 1 << 5,
        last_tag: 5,
        ..Default::default()
    };
    for kind in 0..4 {
        let linear = if kind == 0 {
            0xffff_8000_0000_0000
        } else {
            u64::MAX
        };
        let descriptor = [5, linear];
        assert_eq!(
            unsafe { invalidate_test_vpid(&mut state, kind, descriptor.as_ptr()) },
            0
        );
        assert_eq!((state.kind, state.hardware_tag), (1, 2));
    }
    assert_eq!(state.flushes, 4);
    for (kind, descriptor) in [
        (0, [5, 0x0001_0000_0000_0000]),
        (1, [0, 0]),
        (2, [1 << 16, 0]),
        (3, [0, 0]),
    ] {
        assert_eq!(
            unsafe { invalidate_test_vpid(&mut state, kind, descriptor.as_ptr()) },
            1
        );
    }
    assert_eq!(state.flushes, 4);
    assert_eq!(
        unsafe { invalidate_test_vpid(&mut state, 1, [6, 0].as_ptr()) },
        0
    );
    assert_eq!(state.flushes, 4);
    assert_eq!(
        unsafe { invalidate_test_vpid(&mut state, 2, [0, u64::MAX].as_ptr()) },
        0
    );
    assert_eq!(state.flushes, 5);
}

#[repr(C)]
#[derive(Default)]
struct Context {
    host_cr3: u64,
    gpa: u64,
    qualification: u64,
    ept01: u64,
    invalidations: u64,
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
    include_str!("../builds/nested-ept-tests/resident-ept.S"),
    b_expected_host_cr3 = const std::mem::offset_of!(Context, host_cr3),
    b_last_guest_physical_address = const std::mem::offset_of!(Context, gpa),
    b_last_qualification = const std::mem::offset_of!(Context, qualification),
    b_nested_ept01_pointer = const std::mem::offset_of!(Context, ept01),
    b_nested_ept02_invalidation_count = const std::mem::offset_of!(Context, invalidations),
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
    fn resolve_test_ept(context: *mut Context) -> u64;
    fn revalidate_test_ept(context: *mut Context);
    fn prepare_test_ept(context: *mut Context);
    fn invalidate_test_ept_context(context: *mut Context, ept_pointer: u64);
}

const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
struct Arena {
    allocations: Vec<(*mut u8, Layout)>,
}
impl Arena {
    fn new() -> Self {
        Self {
            allocations: Vec::new(),
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
fn accessed_dirty_revalidation_preserves_cleared_flags_until_real_access() {
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
    unsafe { revalidate_test_ept(&mut state) };
    assert_eq!(unsafe { *last } & 0x300, 0x100);
    assert_eq!(leaf(state.ept02, state.gpa).1 & 2, 0);
    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
    assert_eq!(unsafe { *last } & 0x300, 0x300);
    for address in entries {
        unsafe { *(address as *mut u64) &= !0x100 };
        unsafe { revalidate_test_ept(&mut state) };
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
    let ept02 = arena.pages(1);
    let pool = arena.pages(16);
    let alternate_ept02 = arena.pages(1);
    let alternate_pool = arena.pages(16);
    Context {
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
    arena.map(ept12, 0x200000, 0, 21, 0);
    unsafe { invalidate_test_ept_context(&mut state, ept12 | 0x1e) };
    assert_eq!(leaf(supervisor_root, state.gpa).1, 0);
    assert_eq!(leaf(mbec_root, state.gpa).1, 0);
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
struct GuestContext {
    valid: u64,
    control_valid: [u64; 2],
    values: [u64; 117],
    cache: [u64; 117],
    hardware: [u64; 117],
    writes: u64,
}
core::arch::global_asm!(
    ".text",
    ".globl sync_test_guest",
    "sync_test_guest:",
    "push r12", "push rsi",
    "mov r12, rcx",
    "call .Lresident_nested_sync_vmcs02_guest_fields",
    "pop rsi", "pop r12", "ret",
    include_str!("../builds/nested-ept-tests/resident-guest.S"),
    b_nested_vmcs02_guest_cache_valid = const std::mem::offset_of!(GuestContext,valid),
    b_nested_vmcs02_field_cache = const std::mem::offset_of!(GuestContext,cache),
    b_nested_vmcs12_extended_fields = const std::mem::offset_of!(GuestContext,values),
    test_hardware = const std::mem::offset_of!(GuestContext,hardware),
    test_writes = const std::mem::offset_of!(GuestContext,writes),
    nested_guest_state_table_count = const 50,
);
unsafe extern "win64" {
    fn sync_test_guest(context: *mut GuestContext);
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
    };
    unsafe {
        sync_test_guest(&mut state);
    }
    assert_eq!(state.writes, 50);
    state.values[30] = 0x12345000;
    unsafe {
        sync_test_guest(&mut state);
    }
    assert_eq!(state.writes, 55);
    assert_eq!(state.hardware[30], 0x12345000);
    state.hardware[30] = 0x87654000;
    state.cache[30] = state.hardware[30];
    state.values[30] = state.hardware[30];
    unsafe {
        sync_test_guest(&mut state);
    }
    assert_eq!(state.writes, 59);
    assert_eq!(state.hardware[30], 0x87654000);
    state.valid = 0;
    unsafe {
        sync_test_guest(&mut state);
    }
    assert_eq!(state.writes, 109);
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
    fn sync_test_control(context: *mut GuestContext, field: u64, value: u64);
    fn lookup_test_field(encoding: u64) -> u64;
}
#[test]
fn vmcs_lookup_rejects_reserved_bits_and_resolves_every_index() {
    let source = include_str!("../src/core/vt_resident.rs");
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
        .flat_map(|line| line.trim_end_matches(['\"', ',']).split(", "))
        .map(|value| value.parse().unwrap())
        .collect();
    for encoding in 0_u64..0x10000 {
        let expected = if encoding & !0x6c3e == 0 {
            indices[(((encoding & 0x6c00) >> 5) | ((encoding & 0x3e) >> 1)) as usize]
        } else {
            255
        };
        assert_eq!(
            unsafe { lookup_test_field(encoding) },
            expected,
            "{encoding:#x}"
        );
    }
    for encoding in [0x1_0000_6802, u64::MAX, 0x8000_0000_0000_0000] {
        assert_eq!(unsafe { lookup_test_field(encoding) }, 255);
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
    };
    unsafe {
        sync_test_control(&mut state, 0x4000, 0);
    }
    assert_eq!(state.hardware[1], 0);
    assert_eq!(state.writes, 1);
    unsafe {
        sync_test_control(&mut state, 0x4000, 0);
    }
    assert_eq!(state.writes, 1);
    unsafe {
        sync_test_control(&mut state, 0x2012, 0x100000000);
    }
    assert_eq!(state.hardware[101], 0x100000000);
    assert_eq!(state.writes, 2);
    unsafe {
        sync_test_control(&mut state, 0x2012, 0x100000000);
    }
    assert_eq!(state.writes, 2);
    unsafe {
        sync_test_control(&mut state, 0x2012, 0x200000000);
    }
    assert_eq!(state.hardware[101], 0x200000000);
    assert_eq!(state.writes, 3);
    state.control_valid = [0; 2];
    unsafe {
        sync_test_control(&mut state, 0x2012, 0x200000000);
    }
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
fn mbec_respects_l0_execute_denials_and_revalidates_user_only_leaves() {
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
        revalidate_test_ept(&mut state);
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
