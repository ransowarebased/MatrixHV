include!("../builds/interception-runtime-tests/definitions.rs");

use memory::interception::runtime::interception_entry;
use memory::interception::{DebugTarget, Session};
use memory::interception::{CpuidProfile, CpuidRecord};
use memory::interception::SyscallProfile;
use protocol::memory::{INTERCEPT_ACTIVE, INTERCEPT_CONCURRENT_WRITES, INTERCEPT_REVOKED};
use std::sync::atomic::Ordering;
use vmx::resident::abi::{ResidentBootContext, ResidentEventContext};
use vmx::vmcs::*;

const SHADOW: u64 = 0x8000 + protocol::memory::INTERCEPT_TABLE_PAGES as u64 * 4096;

fn syscall_scenario() -> Scenario {
    let mut scenario = Scenario::new();
    let entry = 0xffff800000400000;
    *scenario.session.syscall.get_mut() = SyscallProfile {
        entry, callback: 0x402000, token: 1,
    };
    scenario.session.configuration.get_mut().debug[0] = DebugTarget { address: entry, redirect: 0x402000 };
    hardware::STATE.with(|state| state.borrow_mut().syscall_msrs = [(0x23 << 48) | (0x10 << 32), entry]);
    for (field, value) in [
        (GUEST_IA32_EFER, 0x401), (GUEST_CS_SELECTOR, 0x10), (GUEST_SS_SELECTOR, 0x18),
        (GUEST_CS_AR_BYTES, 0xa09b), (GUEST_SS_AR_BYTES, 0xc093),
        (GUEST_CS_LIMIT, 0xffffffff), (GUEST_SS_LIMIT, 0xffffffff),
        (GUEST_RIP, entry), (GUEST_RFLAGS, 0x46), (GUEST_RSP, 0x700000),
        (GUEST_GS_BASE, 0x7fff1000), (GUEST_FS_BASE, 0x7fff2000),
        (GUEST_DR7, 0xf0440), (VM_EXIT_INTR_INFO, 0x80000301),
    ] {
        hardware::write(field, value).unwrap();
    }
    hardware::load_debug(&[11, 22, 33, 0x7ffe0ff0, 0xffff0ff0]);
    scenario.frame = core::array::from_fn(|index| 0x12340000 + index as u64);
    scenario.frame[0] = 0xffffffff00000026;
    scenario.frame[1] = 0x400122;
    scenario.frame[10] = 0xffffffffffffffff;
    scenario.fx_state.fill(0xaa);
    scenario
}

#[test]
fn syscall_return_restores_full_sysret64_state_and_preserves_user_stack_and_gs() {
    let mut scenario = syscall_scenario();
    let frame = scenario.frame;
    assert_eq!(scenario.call(1), 0);
    assert_eq!(hardware::debug_registers(), [0xffff800000400000, 22, 33, 0x7ffe0ff0, 0xffff0ff0]);
    assert_eq!(hardware::read(GUEST_DR7), Ok(0x442));
    assert_eq!(scenario.exit(0, 1), 1);
    for (field, expected) in [
        (GUEST_RIP, 0x402000), (GUEST_CS_SELECTOR, 0x33), (GUEST_SS_SELECTOR, 0x2b),
        (GUEST_CS_AR_BYTES, 0xa0fb), (GUEST_SS_AR_BYTES, 0xc0f3),
        (GUEST_CS_BASE, 0), (GUEST_SS_BASE, 0),
        (GUEST_CS_LIMIT, 0xffffffff), (GUEST_SS_LIMIT, 0xffffffff),
        (GUEST_RFLAGS, 0x3c7fd7 | 2), (GUEST_RSP, 0x700000),
        (GUEST_GS_BASE, 0x7fff1000), (GUEST_FS_BASE, 0x7fff2000),
    ] {
        assert_eq!(hardware::read(field), Ok(expected), "field={field:x}");
    }
    assert_eq!(scenario.frame[0], frame[1]);
    assert_eq!(scenario.frame[1], 0x402000);
    assert_eq!(&scenario.frame[2..], &frame[2..]);
    assert_eq!(&scenario.fx_state[224..228], &0x26_u32.to_le_bytes());
    assert_eq!(&scenario.fx_state[228..240], &[0; 12]);
    assert!(scenario.fx_state[..224].iter().chain(&scenario.fx_state[240..]).all(|byte| *byte == 0xaa));
    assert_eq!(hardware::read(GUEST_DR7), Ok(0xf0440));
    assert_eq!(hardware::debug_registers()[3], 0x7ffe0ff0);
}

#[test]
fn syscall_bypass_records_the_native_selector_consumes_xmm5_and_retries_with_rf() {
    let mut scenario = syscall_scenario();
    scenario.fx_state[240..248].copy_from_slice(&0x1337133713371337_u64.to_le_bytes());
    let frame = scenario.frame;
    let before = scenario.fx_state;
    scenario.call(1);
    assert_eq!(scenario.exit(0, 1), 1);
    assert_eq!(hardware::read(GUEST_RIP), Ok(0xffff800000400000));
    assert_eq!(hardware::read(GUEST_CS_SELECTOR), Ok(0x10));
    assert_eq!(hardware::read(GUEST_SS_SELECTOR), Ok(0x18));
    assert_eq!(hardware::read(GUEST_RFLAGS), Ok(0x10046));
    assert_eq!(scenario.frame, frame);
    assert_eq!(&scenario.fx_state[..224], &before[..224]);
    assert_eq!(&scenario.fx_state[224..228], &0x26_u32.to_le_bytes());
    assert_eq!(&scenario.fx_state[228..240], &[0; 12]);
    assert_eq!(&scenario.fx_state[240..256], &[0; 16]);
    assert_eq!(&scenario.fx_state[256..], &before[256..]);
}

#[test]
fn syscall_overlay_preserves_foreign_breakpoints_and_forwards_their_debug_causes() {
    let mut scenario = syscall_scenario();
    hardware::write(GUEST_DR7, 0xf0444).unwrap();
    scenario.call(1);
    assert_eq!(hardware::read(GUEST_DR7), Ok(0x446));
    assert_eq!(scenario.exit(0, 3), 0);
    assert_eq!(hardware::read(GUEST_RIP), Ok(0xffff800000400000));
    assert_eq!(hardware::debug_registers()[4] & 15, 2);
    assert_eq!(scenario.frame[0], 0xffffffff00000026);
}

#[test]
fn syscall_overlay_requires_the_exact_gate_free_dr0_root_and_supported_entry() {
    for rejected in 0..7 {
        let mut scenario = syscall_scenario();
        match rejected {
            0 => hardware::write(GUEST_CR3, 0x5000).unwrap(),
            1 => hardware::load_debug(&[11, 22, 33, 0x7ffe0ff1, 0xffff0ff0]),
            2 => hardware::write(GUEST_DR7, 0xf0441).unwrap(),
            3 => hardware::write(GUEST_DR7, 0xf2440).unwrap(),
            4 => hardware::write(GUEST_CR4, 1 << 23).unwrap(),
            5 => hardware::write(GUEST_CR4, 1 << 12).unwrap(),
            _ => hardware::STATE.with(|state| state.borrow_mut().syscall_msrs[1] += 16),
        }
        let debug = hardware::debug_registers();
        scenario.call(1);
        assert_eq!(scenario.boot.interception.debug_armed, 0, "case={rejected}");
        assert_eq!(hardware::debug_registers(), debug);
    }
}

#[test]
fn in_flight_syscall_fault_after_clear_rotation_or_lease_retries_native_privilege_state() {
    for retired in 0..5 {
        let mut scenario = syscall_scenario();
        scenario.call(1);
        match retired {
            0 => *scenario.session.syscall.get_mut() = SyscallProfile::default(),
            1 => scenario.session.configuration.get_mut().token += 1,
            2 => scenario.session.configuration.get_mut().generation += 1,
            3 => scenario.session.active.store(u64::from(INTERCEPT_REVOKED), Ordering::Release),
            _ => {
                scenario.session.tsc_hz.store(1000, Ordering::Release);
                scenario.session.lease_deadline.store(1000, Ordering::Release);
                hardware::STATE.with(|state| state.borrow_mut().clock = 1001);
            }
        }
        assert_eq!(scenario.exit(0, 1), 1, "case={retired}");
        assert_eq!(hardware::read(GUEST_RIP), Ok(0xffff800000400000));
        assert_eq!(hardware::read(GUEST_CS_SELECTOR), Ok(0x10));
        assert_eq!(hardware::read(GUEST_SS_SELECTOR), Ok(0x18));
        assert_eq!(hardware::read(GUEST_RFLAGS), Ok(0x10046));
        assert_eq!(scenario.fx_state, [0xaa; 512]);
    }
}

#[test]
fn unsupported_syscall_entry_state_never_performs_a_partial_user_return() {
    for rejected in 0..5 {
        let mut scenario = syscall_scenario();
        scenario.call(1);
        match rejected {
            0 => hardware::write(GUEST_CS_SELECTOR, 0x20).unwrap(),
            1 => hardware::write(GUEST_SS_SELECTOR, 0x28).unwrap(),
            2 => hardware::write(GUEST_INTERRUPTIBILITY_INFO, 1).unwrap(),
            3 => scenario.frame[1] = 0x800000000000,
            _ => hardware::write(GUEST_IA32_EFER, 0x400).unwrap(),
        }
        let cs = hardware::read(GUEST_CS_SELECTOR);
        let frame = scenario.frame;
        assert_eq!(scenario.exit(0, 1), 1);
        assert_eq!(hardware::read(GUEST_CS_SELECTOR), cs);
        assert_eq!(hardware::read(GUEST_RIP), Ok(0xffff800000400000));
        assert_eq!(scenario.frame, frame);
        assert_eq!(scenario.fx_state, [0xaa; 512]);
    }
}

#[test]
fn syscall_vmcs_failure_rolls_back_every_completed_privilege_write_before_retiring() {
    for failed in [GUEST_CS_SELECTOR, GUEST_SS_SELECTOR, GUEST_CS_BASE, GUEST_SS_BASE,
        GUEST_CS_LIMIT, GUEST_SS_LIMIT, GUEST_CS_AR_BYTES, GUEST_SS_AR_BYTES,
        GUEST_RFLAGS, GUEST_RIP] {
        let mut scenario = syscall_scenario();
        scenario.call(1);
        let frame = scenario.frame;
        hardware::STATE.with(|state| { state.borrow_mut().fail_writes.insert(failed, 1); });
        assert_eq!(scenario.exit(0, 1), 0, "field={failed:x}");
        assert_eq!(hardware::read(GUEST_CS_SELECTOR), Ok(0x10));
        assert_eq!(hardware::read(GUEST_SS_SELECTOR), Ok(0x18));
        assert_eq!(hardware::read(GUEST_CS_AR_BYTES), Ok(0xa09b));
        assert_eq!(hardware::read(GUEST_SS_AR_BYTES), Ok(0xc093));
        assert_eq!(hardware::read(GUEST_RIP), Ok(0xffff800000400000));
        assert_eq!(hardware::read(GUEST_RFLAGS), Ok(0x46));
        assert_eq!(scenario.frame, frame);
        assert_eq!(scenario.fx_state, [0xaa; 512]);
        assert!(!scenario.session.is_active());
        assert_eq!(hardware::debug_registers()[0], 11);
    }
}

#[test]
fn failed_privilege_rollback_halts_and_records_failure_without_touching_guest_registers() {
    let mut scenario = syscall_scenario();
    scenario.boot.telemetry_active = 1;
    scenario.call(1);
    let frame = scenario.frame;
    hardware::STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.write_plan.insert(GUEST_CS_SELECTOR, [true, false].into());
        state.fail_writes.insert(GUEST_SS_SELECTOR, 1);
    });
    assert_eq!(scenario.exit(0, 1), u64::MAX);
    assert_eq!(scenario.frame, frame);
    assert_eq!(scenario.fx_state, [0xaa; 512]);
    assert_eq!(scenario.session.cause.load(Ordering::Acquire), u64::from(protocol::memory::INTERCEPT_CAUSE_RUNTIME));
    assert_eq!(scenario.boot.interception.runtime_diagnostics[..3], [1, 0, 1]);
    assert_eq!(scenario.boot.interception.runtime_diagnostics[protocol::memory::INTERCEPT_RUNTIME_PHASES * 3], 1);
    assert!(!scenario.session.is_active());
}

#[test]
fn private_shared_data_survives_code_write_windows_and_refreshes_at_any_page_index() {
    let mut scenario = Scenario::new();
    let configuration = scenario.session.configuration.get_mut();
    configuration.options = protocol::memory::INTERCEPT_PRIVATE_SHARED_DATA;
    configuration.hook_count = 2;
    configuration.debug_count = 0;
    configuration.pages[1] = 0x900000;
    configuration.base_leaves[1] = 0;
    configuration.data_leaves[1] = 0xb000;
    let private_shadow = SHADOW + 4096;
    hardware::original_value(private_shadow + 0xffc, 4, Some(0x13371337));
    hardware::entry_bits(0xb000, 0x900030, 0);
    assert_eq!(scenario.call(1), 0);
    hardware::write(GUEST_RIP, 0x401000).unwrap();
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800009).unwrap();
    assert_eq!(scenario.exit(48, 2), 1);
    assert_eq!(scenario.call(1), 0);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x905e));
    hardware::original_value(0x800009, 1, Some(0x42));
    hardware::write(GUEST_RIP, 0x401003).unwrap();
    assert_eq!(scenario.exit(37, 0), 1);
    assert_eq!(scenario.call(1), 0);
    assert_eq!(hardware::original_value(SHADOW + 9, 1, None), 0x42);
    assert_eq!(hardware::original_value(private_shadow + 0xffc, 4, None), 0x13371337);
    hardware::original_value(0x900008, 4, Some(123));
    hardware::original_value(0x90000c, 4, Some(7));
    hardware::original_value(0x900010, 4, Some(7));
    scenario.boot.interception.exit_timer = 1;
    scenario.boot.last_reason = 52;
    assert_eq!(scenario.call(0), 1);
    assert_eq!(hardware::original_value(private_shadow + 8, 4, None), 123);
    assert_eq!(hardware::original_value(private_shadow + 12, 4, None), 7);
    hardware::STATE.with(|state| {
        assert_eq!(state.borrow().entries[&0xb000], 0x900030);
        assert!(!state.borrow().entries.contains_key(&0));
    });
    scenario.session.active.store(0, Ordering::Release);
    assert_eq!(scenario.call(1), 0);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
}

#[test]
fn private_shared_data_refreshes_clocks_preserves_identity_and_releases_without_zero_pointer_writes() {
    let mut scenario = Scenario::new();
    let configuration = scenario.session.configuration.get_mut();
    configuration.options = protocol::memory::INTERCEPT_PRIVATE_SHARED_DATA;
    configuration.base_leaves[0] = 0;
    configuration.debug_count = 0;
    hardware::original_value(SHADOW + 0xffc, 4, Some(0x13371337));
    for offset in [0x8, 0x14, 0x320] {
        hardware::original_value(0x800000 + offset, 4, Some(0x12345678));
        hardware::original_value(0x800000 + offset + 4, 4, Some(0xabcdef01));
        hardware::original_value(0x800000 + offset + 8, 4, Some(0xabcdef01));
    }
    for (offset, width, value) in [(0x2e4, 4, 123), (0x340, 8, 456), (0x348, 8, 789), (0x350, 8, 999)] {
        hardware::original_value(0x800000 + offset, width, Some(value));
    }
    scenario.boot.interception.exit_timer = 1;
    scenario.boot.last_reason = 52;
    assert_eq!(scenario.call(0), 1);
    for offset in [0x8, 0x14, 0x320] {
        assert_eq!(hardware::original_value(SHADOW + offset, 8, None), 0xabcdef0112345678);
        assert_eq!(hardware::original_value(SHADOW + offset + 8, 4, None), 0xabcdef01);
    }
    for (offset, width, value) in [(0x2e4, 4, 123), (0x340, 8, 456), (0x348, 8, 789), (0x350, 8, 789), (0xffc, 4, 0x13371337)] {
        assert_eq!(hardware::original_value(SHADOW + offset, width, None), value);
    }
    assert_eq!(hardware::original_value(0x800350, 8, None), 999);
    scenario.session.active.store(0, Ordering::Release);
    assert_eq!(scenario.call(1), 0);
    hardware::STATE.with(|state| assert!(!state.borrow().entries.contains_key(&0)));
}

#[test]
fn cpuid_dispatch_matches_the_intel_gate_and_zero_extends_only_output_registers() {
    for (cr3, cpl, dr3, dr7, active, nested, matched) in [
        (0x3007, 3, 0x7ffe0ff0, 0x440, true, false, true),
        (0x5000, 3, 0x7ffe0ff0, 0x440, true, false, false),
        (0x3007, 0, 0x7ffe0ff0, 0x440, true, false, false),
        (0x3007, 3, 0x7ffe0ff1, 0x440, true, false, false),
        (0x3007, 3, 0x7ffe0ff0, 0x400, true, false, false),
        (0x3007, 3, 0x7ffe0ff0, 0x440, false, false, false),
        (0x3007, 3, 0x7ffe0ff0, 0x440, true, true, false),
    ] {
        let mut scenario = Scenario::new();
        scenario.session.configuration.get_mut().debug_count = 0;
        scenario.session.configuration.get_mut().hook_count = 0;
        let profile = scenario.session.cpuid.get_mut();
        *profile = CpuidProfile {
            count: 1, dr3: 0x7ffe0ff0, dr7_mask: 0xffff_ffff_f000_0040,
            dr7_value: 0x40, token: 1, ..CpuidProfile::default()
        };
        profile.records[0] = CpuidRecord {
            leaf: 1, values: [656981, 0x200800, 33221631, 3219913727],
            keep_masks: [0, 0xff00_0000, 0, 0], ..CpuidRecord::default()
        };
        scenario.session.active.store(u64::from(active), Ordering::Release);
        scenario.boot.nested.active = u64::from(nested);
        hardware::write(GUEST_CR3, cr3).unwrap();
        hardware::write(GUEST_CS_SELECTOR, cpl).unwrap();
        hardware::write(GUEST_DR7, dr7).unwrap();
        hardware::load_debug(&[11, 22, 33, dr3, 0xffff0ff0]);
        scenario.frame.fill(0xfeed_cafe_0000_0000);
        scenario.frame[0] |= 1;
        let before = scenario.frame;
        scenario.boot.last_reason = 10;
        let outcome = scenario.call(0);
        assert_eq!(outcome, if matched { 2 } else { 0 });
        if matched {
            let native = core::arch::x86_64::__cpuid_count(1, 0);
            assert_eq!(&scenario.frame[..4], &[656981, 33221631, 3219913727,
                         u64::from(native.ebx & 0xff00_0000 | 0x200800)]);
            assert_eq!(&scenario.frame[4..], &before[4..]);
            assert_eq!(scenario.session.hits.load(Ordering::Acquire), 1);
        } else {
            assert_eq!(scenario.frame, before);
            assert_eq!(scenario.session.hits.load(Ordering::Acquire), 0);
        }
    }
}

#[test]
fn private_shared_data_keeps_kernel_xstate_native_and_closes_each_cpu_window() {
    for (cpl, linear, target, access) in [
        (3, 0x7ffe03d8, SHADOW, 1),
        (0, 0xfffff780000003d8, 0x800000, 1),
        (0, 0xfffff78000000718, 0x800000, 1),
        (0, 0xfffff780000003d8, 0x800000, 2),
    ] {
        for (exit_reason, cancelled) in [(37, false), (1, false), (37, true)] {
            let mut scenario = Scenario::new();
            let configuration = scenario.session.configuration.get_mut();
            configuration.options = protocol::memory::INTERCEPT_PRIVATE_SHARED_DATA;
            configuration.base_leaves[0] = 0;
            configuration.debug_count = 0;
            configuration.cpu_data[0] = 0xa05e;
            configuration.cpu_leaves[0][0] = 0xb000;
            configuration.cpu_data[1] = 0xc05e;
            configuration.cpu_leaves[1][0] = 0xd000;
            hardware::shared_entry(0xb000, 0x800000, 0);
            hardware::shared_entry(0xd000, 0x800000, 0);
            let mut instruction = [0x90; 15];
            instruction[..2].copy_from_slice(&[0x8b, 0x01]);
            hardware::STATE.with(|state| state.borrow_mut().instruction = Some((instruction, instruction)));
            for (field, value) in [
                (GUEST_CS_SELECTOR, cpl), (GUEST_RIP, 0x401000),
                (GUEST_PHYSICAL_ADDRESS, 0x8003d8), (GUEST_LINEAR_ADDRESS, linear),
            ] {
                hardware::write(field, value).unwrap();
            }
            assert_eq!(scenario.call(1), 0);
            assert_eq!(scenario.exit(48, 0x180 | access), 1);
            assert_eq!(scenario.boot.interception.step_active, 5);
            assert_eq!(scenario.call(1), 0);
            assert_eq!(hardware::read(EPT_POINTER), Ok(0xa05e));
            assert_ne!(hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27), 0);
            hardware::STATE.with(|state| {
                assert_eq!(state.borrow().entries[&0xb000] & 0x000f_ffff_ffff_f007, target | if access == 2 { 3 } else { 1 });
                assert_eq!(state.borrow().entries[&0xd000], 0x800000);
            });
            if cancelled {
                scenario.session.active.store(0, Ordering::Release);
            }
            scenario.exit(exit_reason, 0);
            assert_eq!(scenario.boot.interception.step_active, 0);
            assert_eq!(scenario.call(1), 0);
            assert_eq!(hardware::read(EPT_POINTER), Ok(if cancelled { 0x105e } else { 0x805e }));
            assert_eq!(hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27), 0);
            hardware::STATE.with(|state| {
                assert_eq!(state.borrow().entries[&0xb000], 0x800000);
                assert_eq!(state.borrow().entries[&0xd000], 0x800000);
                assert!(!state.borrow().entries.contains_key(&0));
            });
            assert_eq!(scenario.session.is_active(), !cancelled);
        }
    }
}

mod hardware {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Default)]
    pub struct State {
        pub fields: BTreeMap<u64, u64>,
        pub debug: [u64; 5],
        pub invalidated_epts: Vec<u64>,
        pub invalidated_vpids: Vec<u64>,
        pub sync: Vec<u64>,
        pub sync_busy: bool,
        pub entries: BTreeMap<u64, u64>,
        pub bytes: BTreeMap<u64, u8>,
        pub clock: u64,
        pub syscall_msrs: [u64; 2],
        pub instruction: Option<([u8; 15], [u8; 15])>,
        pub fail_reads: BTreeMap<u64, u32>,
        pub fail_writes: BTreeMap<u64, u32>,
        pub write_plan: BTreeMap<u64, std::collections::VecDeque<bool>>,
        pub fail_invalidations: BTreeMap<u64, u32>,
    }
    thread_local! { pub static STATE: RefCell<State> = RefCell::new(State::default()); }
    pub fn clock() -> u64 {
        STATE.with(|state| state.borrow().clock)
    }
    pub fn syscall_msrs() -> [u64; 2] {
        STATE.with(|state| state.borrow().syscall_msrs)
    }
    pub fn fetch_instruction(_: u64, execution: &mut [u8; 15], original: &mut [u8; 15]) -> usize {
        STATE.with(|state| {
            if let Some((code, data)) = state.borrow().instruction {
                *execution = code;
                *original = data;
                15
            } else {
                0
            }
        })
    }
    pub fn original_value(address: u64, width: usize, value: Option<u64>) -> u64 {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            let mut bytes = [0; 8];
            for (index, byte) in bytes[..width].iter_mut().enumerate() {
                if let Some(value) = value {
                    state
                        .bytes
                        .insert(address + index as u64, (value >> (index * 8)) as u8);
                }
                *byte = *state.bytes.get(&(address + index as u64)).unwrap_or(&0x90);
            }
            u64::from_le_bytes(bytes)
        })
    }
    pub fn read(field: u64) -> Result<u64, ()> {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            if let Some(remaining) = state.fail_reads.get_mut(&field) {
                if *remaining != 0 {
                    *remaining -= 1;
                    return Err(());
                }
            }
            Ok(*state.fields.get(&field).unwrap_or(&0))
        })
    }
    pub fn write(field: u64, value: u64) -> Result<(), ()> {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.write_plan.get_mut(&field).and_then(|plan| plan.pop_front()) == Some(false) {
                return Err(());
            }
            if let Some(remaining) = state.fail_writes.get_mut(&field) {
                if *remaining != 0 {
                    *remaining -= 1;
                    return Err(());
                }
            }
            state.fields.insert(field, value);
            Ok(())
        })
    }
    pub fn debug_registers() -> [u64; 5] {
        STATE.with(|state| state.borrow().debug)
    }
    pub fn load_debug(registers: &[u64; 5]) {
        STATE.with(|state| state.borrow_mut().debug = *registers);
    }
    pub fn invalidate(ept: u64) -> Result<(), ()> {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.invalidated_epts.push(ept);
            if let Some(remaining) = state.fail_invalidations.get_mut(&ept) {
                if *remaining != 0 {
                    *remaining -= 1;
                    return Err(());
                }
            }
            Ok(())
        })
    }
    pub fn invalidate_vpid(vpid: u64) -> Result<(), ()> {
        STATE.with(|state| state.borrow_mut().invalidated_vpids.push(vpid));
        Ok(())
    }
    pub fn entry_bits(pointer: u64, set: u64, clear: u64) {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            let value = *state.entries.get(&pointer).unwrap_or(&0);
            state.entries.insert(pointer, (value | set) & !clear);
        });
    }
    pub fn shared_entry(pointer: u64, target: u64, permissions: u64) {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            let value = *state.entries.get(&pointer).unwrap_or(&0);
            state.entries.insert(pointer, target | (value & !0x000f_ffff_ffff_f000 & !7) | permissions);
        });
    }
    pub fn page_byte(address: u64, value: Option<u8>) -> u8 {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            if let Some(value) = value {
                state.bytes.insert(address, value);
            }
            *state.bytes.get(&address).unwrap_or(&0x90)
        })
    }
    // Model the SDM's no-exit path: the instruction reads the physical list
    // and writes VMCS EPTP directly, without calling resident interception.
    pub fn vmfunc(function: u32, slot: u32) -> u64 {
        use crate::vmx::vmcs::*;
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.fields[&SECONDARY_VM_EXEC_CONTROL] & (1 << 13) == 0 || function > 63 {
                return 4;
            }
            if state.fields[&VM_FUNCTION_CONTROL] & (1 << function) == 0 || slot >= 512 {
                return 59;
            }
            let list = state.fields[&EPTP_LIST_ADDRESS];
            let ept = *state
                .entries
                .get(&(list + u64::from(slot) * 8))
                .unwrap_or(&0);
            if ept & 0x3f != 0x1e || ept & 0xfff & !0x7f != 0 {
                return 59;
            }
            state.fields.insert(EPT_POINTER, ept);
            0
        })
    }
    pub unsafe extern "efiapi" fn synchronize(_: u64, operation: u64) -> u64 {
        STATE.with(|state| state.borrow_mut().sync.push(operation));
        STATE.with(|state| u64::from(operation != 0 || !state.borrow().sync_busy))
    }
}

struct Scenario {
    session: Box<Session>,
    event: Box<ResidentEventContext>,
    boot: ResidentBootContext,
    frame: [u64; 15],
    fx_state: [u8; 512],
}

impl Scenario {
    fn new() -> Self {
        hardware::STATE.with(|state| *state.borrow_mut() = hardware::State::default());
        for (field, value) in [
            (GUEST_CR3, 0x3007),
            (GUEST_CR4, 1 << 17),
            (GUEST_IA32_EFER, 0x400),
            (GUEST_CS_AR_BYTES, 0x2000),
            (GUEST_DR7, 0x400),
            (EPT_POINTER, 0x105e),
            (SECONDARY_VM_EXEC_CONTROL, 1 << 5),
            (VIRTUAL_PROCESSOR_ID, 7),
        ] {
            hardware::write(field, value).unwrap();
        }
        hardware::load_debug(&[11, 22, 33, 44, 0xffff0ff0]);
        let layout = std::alloc::Layout::new::<Session>();
        let mut session =
            unsafe { Box::from_raw(std::alloc::alloc_zeroed(layout).cast::<Session>()) };
        session.initialize(0x8000, u64::MAX);
        let configuration = session.configuration.get_mut();
        configuration.roots = [0x3000, 0x4000];
        configuration.token = 1;
        configuration.ept = 0x805e;
        configuration.data_ept = 0x905e;
        configuration.hook_count = 1;
        configuration.pages[0] = 0x80_0000;
        configuration.base_leaves[0] = 0x2000;
        configuration.data_leaves[0] = 0xa000;
        configuration.patch_mask[0][0] = 1 << 8;
        hardware::STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.entries.insert(0x2000, 0x800035);
            state.entries.insert(0xa000, 0x800031);
            state.bytes.insert(SHADOW + 0x008, 0xcc);
        });
        configuration.debug_count = 1;
        configuration.debug[0] = DebugTarget {
            address: 0x40_0000,
            redirect: 0x40_0100,
        };
        session.active.store(
            u64::from(INTERCEPT_ACTIVE),
            std::sync::atomic::Ordering::Release,
        );
        let event = Box::new(ResidentEventContext {
            interception_context_physical: &*session as *const _ as u64,
        });
        let boot = ResidentBootContext {
            event_context: &*event as *const _ as u64,
            cache_ept_pointer: 0x105e,
            ..Default::default()
        };
        Self {
            session,
            event,
            boot,
            frame: [0; 15],
            fx_state: [0; 512],
        }
    }
    fn call(&mut self, phase: u64) -> u64 {
        assert_eq!(self.boot.event_context, &*self.event as *const _ as u64);
        unsafe {
            interception_entry(
                &mut self.boot,
                phase,
                self.frame.as_mut_ptr(),
                hardware::synchronize,
                self.fx_state.as_mut_ptr(),
            )
        }
    }
    fn enable_vmfunc(&mut self) {
        let configuration = self.session.configuration.get_mut();
        configuration.vmfunc = 1;
        configuration.eptp_list = 0xb000;
        hardware::STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.entries.insert(0xb000, configuration.ept);
            state.entries.insert(0xb008, configuration.data_ept);
        });
    }
    fn exit(&mut self, reason: u64, qualification: u64) -> u64 {
        self.boot.interception.exit_ept = self.boot.interception.applied_ept;
        self.boot.interception.exit_step = self.boot.interception.step_active;
        self.boot.interception.exit_vmfunc = self.boot.interception.vmfunc_armed;
        self.boot.last_reason = reason;
        self.boot.last_qualification = qualification;
        assert_eq!(self.call(4), 0);
        self.call(0)
    }
}

#[test]
fn target_and_alternate_cr3_select_patched_ept_and_other_processes_restore_original_debug_state() {
    let mut scenario = Scenario::new();
    assert_eq!(scenario.call(1), 0);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x805e));
    assert_eq!(hardware::debug_registers()[0], 0x400000);
    assert_eq!(hardware::read(GUEST_DR7), Ok(0x402));
    assert_eq!(scenario.exit(10, 0), 0);
    assert_eq!(hardware::debug_registers(), [11, 22, 33, 44, 0xffff0ff0]);
    assert_eq!(hardware::read(GUEST_DR7), Ok(0x400));
    hardware::write(GUEST_CR3, 0x400f).unwrap();
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x805e));
    scenario.exit(10, 0);
    hardware::write(GUEST_CR3, 0x5000).unwrap();
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    assert_eq!(hardware::debug_registers()[0], 11);
}

#[test]
fn runtime_diagnostics_count_phase_outcomes_and_successful_recovery_separately() {
    let mut scenario = Scenario::new();
    scenario.boot.telemetry_active = 1;
    hardware::write(GUEST_RIP, 0x401234).unwrap();
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
    assert_eq!(scenario.call(1), 0);
    assert_eq!(
        &scenario.boot.interception.runtime_diagnostics[3..6],
        &[1, 1, 0]
    );
    scenario.boot.last_reason = 48;
    hardware::STATE.with(|state| {
        state.borrow_mut().fail_reads.insert(GUEST_CR3, 1);
    });
    assert_eq!(scenario.call(1), 0);
    let counters = &scenario.boot.interception.runtime_diagnostics;
    assert_eq!(&counters[3..6], &[2, 1, 1]);
    assert_eq!(&counters[18..21], &[1, 1, 0]);
    assert_eq!(&counters[21..], &[2, 0x401234, 0x800008]);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    assert_eq!(
        scenario.session.active.load(Ordering::Acquire),
        u64::from(INTERCEPT_REVOKED)
    );
    let mut other = Scenario::new();
    other.boot.telemetry_active = 1;
    assert_eq!(other.call(1), 0);
    assert_eq!(
        &other.boot.interception.runtime_diagnostics[3..6],
        &[1, 1, 0]
    );
    assert_eq!(
        &scenario.boot.interception.runtime_diagnostics[3..6],
        &[2, 1, 1]
    );
}

#[test]
fn disabled_telemetry_keeps_phase_counters_idle_but_retains_failure_details() {
    let mut scenario = Scenario::new();
    assert_eq!(scenario.call(1), 0);
    hardware::write(GUEST_RIP, 0x401234).unwrap();
    hardware::STATE.with(|state| {
        state.borrow_mut().fail_reads.insert(GUEST_CR3, 1);
    });
    assert_eq!(scenario.call(1), 0);
    assert_eq!(
        scenario.boot.interception.runtime_diagnostics[..21],
        [0; 21]
    );
    assert_eq!(
        &scenario.boot.interception.runtime_diagnostics[21..],
        &[2, 0x401234, 0]
    );
}

#[test]
fn failed_recovery_is_counted_and_never_reports_a_safe_guest_reentry() {
    let mut scenario = Scenario::new();
    scenario.boot.telemetry_active = 1;
    hardware::STATE.with(|state| {
        state.borrow_mut().fail_reads.insert(GUEST_DR7, 2);
    });
    assert_eq!(scenario.call(1), u64::MAX);
    let counters = &scenario.boot.interception.runtime_diagnostics;
    assert_eq!(&counters[3..6], &[1, 0, 1]);
    assert_eq!(&counters[18..21], &[1, 0, 1]);
    assert_eq!(counters[21], 7);
    assert_eq!(
        scenario.session.active.load(Ordering::Acquire),
        u64::from(INTERCEPT_REVOKED)
    );
}

#[test]
fn cpu_63_selects_its_private_write_view_and_an_unreserved_cpu_retires_safely() {
    let mut scenario = Scenario::new();
    let configuration = scenario.session.configuration.get_mut();
    configuration.cpu_mask = 1 | (1 << 63);
    configuration.options = INTERCEPT_CONCURRENT_WRITES;
    configuration.cpu_data[63] = 0xc05e;
    configuration.cpu_leaves[63][0] = 0xe000;
    scenario.boot.processor_number = 63;
    hardware::entry_bits(0xe000, 0x800031, 0);
    assert_eq!(scenario.call(1), 0);
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800009).unwrap();
    assert_eq!(scenario.exit(48, 2), 1);
    assert_eq!(scenario.call(1), 0);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0xc05e));
    assert_eq!(scenario.exit(37, 0), 1);
    assert_eq!(scenario.call(1), 0);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x805e));
    scenario.boot.processor_number = 7;
    assert_eq!(scenario.call(1), 0);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    assert_eq!(
        scenario.session.active.load(Ordering::Acquire),
        u64::from(INTERCEPT_REVOKED)
    );
}

#[test]
fn cr3_writes_validate_pcid_reserved_bits_privilege_and_no_flush_before_commit() {
    let mut scenario = Scenario::new();
    scenario.call(1);
    scenario.frame[0] = 0x5009 | (1 << 63);
    assert_eq!(scenario.exit(28, 3), 2);
    assert_eq!(hardware::read(GUEST_CR3), Ok(0x5009));
    hardware::STATE.with(|state| assert!(state.borrow().invalidated_vpids.is_empty()));
    scenario.frame[0] = 0x3005;
    assert_eq!(scenario.exit(28, 3), 2);
    hardware::STATE.with(|state| assert_eq!(state.borrow().invalidated_vpids, [7]));
    scenario.frame[0] = 1 << 48;
    assert_eq!(scenario.exit(28, 3), 3);
    assert_eq!(hardware::read(GUEST_CR3), Ok(0x3005));
    hardware::write(GUEST_CR4, 0).unwrap();
    scenario.frame[0] = 0x5001;
    assert_eq!(scenario.exit(28, 3), 3);
    hardware::write(GUEST_SS_AR_BYTES, 0x60).unwrap();
    scenario.frame[0] = 0x5000;
    assert_eq!(scenario.exit(28, 3), 3);
}

#[test]
fn owned_debug_fault_redirects_without_advancing_and_guest_single_step_is_preserved() {
    let mut scenario = Scenario::new();
    scenario.call(1);
    hardware::write(VM_EXIT_INTR_INFO, 0x80000301).unwrap();
    hardware::write(GUEST_RIP, 0x400000).unwrap();
    hardware::load_debug(&[0x400000, 0, 0, 0, 0xffff0ff0]);
    assert_eq!(scenario.exit(0, 1), 1);
    assert_eq!(hardware::read(GUEST_RIP), Ok(0x400100));
    assert_eq!(
        scenario
            .session
            .hits
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    scenario.call(1);
    hardware::write(GUEST_RIP, 0x400000).unwrap();
    hardware::load_debug(&[0x400000, 0, 0, 0, 0xffff0ff0]);
    assert_eq!(scenario.exit(0, 0x4001), 0);
    assert_eq!(hardware::read(GUEST_RIP), Ok(0x400000));
    assert_ne!(hardware::debug_registers()[4] & (1 << 14), 0);
}

#[test]
fn guest_owned_debug_exceptions_update_dr6_from_qualification_without_redirecting() {
    let mut scenario = Scenario::new();
    hardware::write(GUEST_DR7, 0x401).unwrap();
    scenario.call(1);
    assert_eq!(scenario.boot.interception.debug_armed, 0);
    hardware::write(VM_EXIT_INTR_INFO, 0x80000301).unwrap();
    hardware::write(GUEST_RIP, 0x400000).unwrap();
    assert_eq!(scenario.exit(0, 1 | (1 << 14) | (1 << 11) | (1 << 16)), 0);
    assert_eq!(hardware::read(GUEST_RIP), Ok(0x400000));
    let dr6 = hardware::debug_registers()[4];
    assert_eq!(dr6 & 0x4001, 0x4001);
    assert_eq!(dr6 & ((1 << 11) | (1 << 16)), 0);
    assert_eq!(
        scenario
            .session
            .hits
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
}

#[test]
fn conflicting_guest_writes_revoke_the_profile_and_preserve_original_data() {
    let mut scenario = Scenario::new();
    scenario.call(1);
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
    assert_eq!(scenario.exit(48, 2), 1);
    assert!(scenario.session.is_active());
    assert_eq!(scenario.boot.interception.step_active, 2);
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x905e));
    assert_ne!(
        hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27),
        0
    );
    hardware::STATE.with(|state| {
        let mut state = state.borrow_mut();
        assert_eq!(state.sync, [0]);
        assert_eq!(state.entries[&0xa000] & 7, 3);
        state.bytes.insert(0x800008, 0xc3);
        state.bytes.insert(0x800009, 0x42);
    });
    assert_eq!(scenario.exit(37, 0), 1);
    hardware::STATE.with(|state| {
        assert_eq!(state.borrow().sync, [0, 1, 2, 0, 1, 2]);
        assert!(state.borrow().invalidated_epts.contains(&0x905e));
        assert_eq!(state.borrow().entries[&0xa000] & 7, 1);
        assert_eq!(state.borrow().bytes[&(SHADOW + 0x008)], 0xcc);
        assert!(!state.borrow().bytes.contains_key(&(SHADOW + 0x009)));
    });
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    assert_eq!(
        hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27),
        0
    );
}

#[test]
fn guest_mov_dr_is_virtualized_and_debugger_ownership_suspends_the_overlay() {
    let mut scenario = Scenario::new();
    scenario.call(1);
    scenario.frame[0] = 0x123000;
    assert_eq!(scenario.exit(29, 0), 2);
    assert_eq!(hardware::debug_registers()[0], 0x123000);
    scenario.call(1);
    assert_eq!(scenario.exit(29, 16), 2);
    assert_eq!(scenario.frame[0], 0x123000);
    scenario.frame[0] = 0x401;
    assert_eq!(scenario.exit(29, 7), 2);
    scenario.call(1);
    assert_eq!(scenario.boot.interception.debug_armed, 0);
    assert_eq!(hardware::read(GUEST_DR7), Ok(0x401));
    assert_eq!(hardware::debug_registers()[0], 0x123000);
    hardware::write(GUEST_CR4, 8).unwrap();
    assert_eq!(scenario.exit(29, 4), 4);
}

#[test]
fn revocation_preserves_prior_controls_and_an_inflight_cr3_or_debug_exit() {
    let mut scenario = Scenario::new();
    hardware::write(CPU_BASED_VM_EXEC_CONTROL, (1 << 23) | (1 << 28)).unwrap();
    hardware::write(EXCEPTION_BITMAP, 2 | (1 << 14)).unwrap();
    scenario.call(1);
    scenario.session.active.store(
        u64::from(INTERCEPT_REVOKED),
        std::sync::atomic::Ordering::Release,
    );
    scenario.frame[0] = 0x5000;
    assert_eq!(scenario.exit(28, 3), 2);
    scenario.call(1);
    assert_eq!(
        hardware::read(CPU_BASED_VM_EXEC_CONTROL),
        Ok((1 << 23) | (1 << 28))
    );
    assert_eq!(hardware::read(EXCEPTION_BITMAP), Ok(2 | (1 << 14)));
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
}

#[test]
fn nested_activation_and_cache_changes_revoke_the_session_before_guest_reentry() {
    for phase in [0, 2] {
        let mut scenario = Scenario::new();
        scenario.call(1);
        scenario.boot.last_reason = 27;
        assert_eq!(scenario.call(phase), 0);
        assert!(!scenario.session.is_active());
        scenario.call(1);
        assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    }
}

#[test]
fn an_inflight_hook_write_retries_after_a_peer_removed_the_configuration() {
    let mut scenario = Scenario::new();
    scenario.call(1);
    scenario.boot.interception.exit_ept = scenario.boot.interception.applied_ept;
    scenario.boot.last_reason = 48;
    scenario.boot.last_qualification = 2;
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
    scenario
        .session
        .active
        .store(0, std::sync::atomic::Ordering::Release);
    scenario.session.configuration.get_mut().hook_count = 0;
    scenario.call(3);
    assert_eq!(scenario.boot.interception.applied_ept, 0);
    assert_eq!(scenario.call(0), 1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
}

#[test]
fn competing_revocation_barriers_retire_the_local_view_without_halting_the_guest() {
    let mut scenario = Scenario::new();
    scenario.call(1);
    hardware::STATE.with(|state| state.borrow_mut().sync_busy = true);
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
    assert_eq!(scenario.exit(48, 2), 1);
    assert!(!scenario.session.is_active());
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    hardware::STATE.with(|state| assert_eq!(state.borrow().sync, [0, 0]));
}

#[test]
fn reads_use_original_read_only_data_and_mtf_returns_to_execute_only_shadow_without_a_barrier() {
    let mut scenario = Scenario::new();
    scenario.boot.telemetry_active = 1;
    scenario.call(1);
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
    assert_eq!(scenario.exit(48, 1), 1);
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x905e));
    hardware::STATE.with(|state| {
        assert_eq!(state.borrow().entries[&0xa000] & 7, 1);
        assert!(state.borrow().sync.is_empty());
    });
    assert_eq!(scenario.exit(37, 0), 1);
    assert_eq!(scenario.boot.mtf_exits, 1);
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x805e));
    assert_eq!(
        scenario
            .session
            .data_exits
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert!(scenario.session.is_active());
}

#[test]
fn writes_from_a_non_target_process_update_shadow_and_return_to_the_original_ept() {
    let mut scenario = Scenario::new();
    hardware::write(GUEST_CR3, 0x5001).unwrap();
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800040).unwrap();
    assert_eq!(scenario.exit(48, 2), 1);
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x905e));
    hardware::STATE.with(|state| {
        state.borrow_mut().bytes.insert(0x800040, 0x42);
    });
    assert_eq!(scenario.exit(37, 0), 1);
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    hardware::STATE.with(|state| assert_eq!(state.borrow().bytes[&(SHADOW + 0x040)], 0x42));
}

#[test]
fn cancellation_closes_a_committed_write_and_releases_its_lock_even_when_a_peer_owns_recovery() {
    for concurrent in [false, true] {
        let mut scenario = Scenario::new();
        if concurrent {
            let configuration = scenario.session.configuration.get_mut();
            configuration.options = INTERCEPT_CONCURRENT_WRITES;
            configuration.cpu_data[0] = 0x905e;
            configuration.cpu_leaves[0][0] = 0xa000;
        }
        scenario.call(1);
        hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800082).unwrap();
        assert_eq!(scenario.exit(48, 2), 1);
        scenario.call(1);
        hardware::page_byte(0x800082, Some(0xa7));
        hardware::STATE.with(|state| state.borrow_mut().sync_busy = true);
        scenario.session.active.store(u64::from(INTERCEPT_REVOKED), Ordering::Release);
        assert_eq!(scenario.call(2), 0);
        assert_eq!(scenario.call(1), 0);
        assert_eq!(scenario.boot.interception.step_active, 0);
        assert_eq!(scenario.boot.interception.refresh_owned, 0);
        assert_eq!(hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27), 0);
        assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
        hardware::STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.entries[&0xa000] & 7, 1);
            assert_eq!(state.entries[&0x2000] & 7, 7);
            assert_eq!(state.bytes[&0x800082], 0xa7);
            assert_eq!(state.bytes[&(SHADOW + 0x082)], 0xa7);
        });
    }
}

#[test]
fn an_exception_or_cr3_exit_closes_the_write_window_before_normal_dispatch() {
    for reason in [0, 28, 52] {
        let mut scenario = Scenario::new();
        scenario.call(1);
        hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
        scenario.exit(48, 2);
        scenario.call(1);
        scenario.frame[0] = 0x5000;
        hardware::write(VM_EXIT_INTR_INFO, 0x8000030e).unwrap();
        assert_eq!(
            scenario.exit(reason, if reason == 28 { 3 } else { 0 }),
            if reason == 28 { 2 } else { 0 }
        );
        assert_eq!(scenario.boot.interception.step_active, 0);
        assert_eq!(
            hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27),
            0
        );
        hardware::STATE.with(|state| {
            assert_eq!(state.borrow().sync, [0, 1, 2]);
            assert_eq!(state.borrow().entries[&0xa000] & 7, 1);
        });
    }
}

#[test]
fn unsupported_mixed_instruction_retires_without_exposing_shadow_data_or_looping() {
    let mut scenario = Scenario::new();
    scenario.call(1);
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
    scenario.exit(48, 1);
    scenario.call(1);
    assert_eq!(scenario.exit(48, 4), 1);
    assert!(!scenario.session.is_active());
    assert_eq!(
        scenario
            .session
            .cause
            .load(std::sync::atomic::Ordering::Acquire),
        u64::from(protocol::memory::INTERCEPT_CAUSE_MIXED_ACCESS)
    );
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    hardware::STATE.with(|state| assert_eq!(state.borrow().entries[&0x2000] & 7, 7));
}

#[test]
fn unchanged_mixed_instructions_execute_original_data_once_and_restore_split_permissions() {
    for access in [0x2000, 0x4000, 0] {
        let mut scenario = Scenario::new();
        hardware::write(GUEST_CS_AR_BYTES, access).unwrap();
        hardware::STATE
            .with(|state| state.borrow_mut().instruction = Some(([0x90; 15], [0x90; 15])));
        scenario.call(1);
        hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
        assert_eq!(scenario.exit(48, 1), 1);
        scenario.call(1);
        assert_eq!(scenario.exit(48, 4), 1);
        assert_eq!(scenario.boot.interception.step_active, 3);
        hardware::STATE.with(|state| assert_eq!(state.borrow().entries[&0xa000] & 7, 7));
        scenario.call(1);
        assert_eq!(hardware::read(EPT_POINTER), Ok(0x905e));
        assert_eq!(scenario.exit(37, 0), 1);
        scenario.call(1);
        assert!(scenario.session.is_active());
        hardware::STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.entries[&0xa000] & 7, 1);
            assert_eq!(state.bytes[&(SHADOW + 0x008)], 0xcc);
            assert_eq!(&state.sync[state.sync.len() - 3..], &[0, 1, 2]);
        });
    }
}

#[test]
fn unchanged_read_only_mixed_instructions_use_private_mtf_without_parked_peers_or_refresh() {
    for bytes in [[0x3b, 0x05, 0, 0, 0, 0], [0x8b, 0x05, 0, 0, 0, 0]] {
        let mut scenario = Scenario::new();
        let configuration = scenario.session.configuration.get_mut();
        configuration.cpu_data[0] = 0xc05e;
        configuration.cpu_leaves[0][0] = 0xe000;
        let mut code = [0x90; 15];
        code[..6].copy_from_slice(&bytes);
        hardware::STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.instruction = Some((code, code));
            state.entries.insert(0xe000, 0x800001);
        });
        scenario.call(1);
        hardware::STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.sync.clear();
            state.sync_busy = true;
        });
        // The unaligned load is deliberately excluded from direct emulation.
        hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800fff).unwrap();
        hardware::write(GUEST_LINEAR_ADDRESS, 0x400006).unwrap();
        assert_eq!(scenario.exit(48, 0x181), 1);
        scenario.call(1);
        assert_eq!(scenario.exit(48, 4), 1);
        assert_eq!(scenario.boot.interception.step_active, 4);
        assert_eq!(scenario.boot.interception.refresh_owned, 0);
        hardware::STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.entries[&0xe000] & 7, 5);
            assert_eq!(state.entries[&0xa000] & 7, 1);
            assert!(state.sync.is_empty());
        });
        scenario.call(1);
        assert_eq!(hardware::read(EPT_POINTER), Ok(0xc05e));
        assert_eq!(hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27), 1 << 27);
        assert_eq!(scenario.exit(37, 0), 1);
        scenario.call(1);
        assert_eq!(scenario.boot.interception.step_active, 0);
        assert!(scenario.session.is_active());
        hardware::STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.entries[&0xe000] & 7, 1);
            assert_eq!(state.bytes[&(SHADOW + 8)], 0xcc);
            assert!(state.sync.is_empty());
        });
    }
}

#[test]
fn synchronization_recovery_preserves_the_original_revocation_cause() {
    let mut scenario = Scenario::new();
    scenario.call(1);
    scenario.session.cause.store(u64::from(protocol::memory::INTERCEPT_CAUSE_RENDEZVOUS), Ordering::Release);
    assert_eq!(scenario.call(2), 0);
    assert_eq!(scenario.session.cause.load(Ordering::Acquire), u64::from(protocol::memory::INTERCEPT_CAUSE_RENDEZVOUS));
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
}

#[test]
fn patched_mixed_movzx_reads_original_bytes_and_updates_the_decoded_register() {
    let mut scenario = Scenario::new();
    let mut code = [0x90; 15];
    code[..7].copy_from_slice(&[0x0f, 0xb6, 0x0d, 1, 0, 0, 0]);
    hardware::STATE.with(|state| state.borrow_mut().instruction = Some((code, [0x90; 15])));
    hardware::write(GUEST_RIP, 0x400000).unwrap();
    hardware::write(GUEST_RFLAGS, 0x202).unwrap();
    scenario.frame[1] = u64::MAX;
    scenario.call(1);
    hardware::write(GUEST_LINEAR_ADDRESS, 0x400008).unwrap();
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
    assert_eq!(scenario.exit(48, 0x181), 1);
    scenario.call(1);
    assert!(scenario.session.is_active());
    assert_eq!(scenario.frame[1], 0x90);
    assert_eq!(hardware::read(GUEST_RIP), Ok(0x400007));
    assert_eq!(hardware::read(GUEST_RFLAGS), Ok(0x202));
    hardware::STATE.with(|state| assert_eq!(state.borrow().entries[&0xa000] & 7, 1));
}

#[test]
fn conflicting_mixed_store_retires_the_profile_without_rolling_back_guest_data() {
    let mut scenario = Scenario::new();
    let mut code = [0x90; 15];
    code[..7].copy_from_slice(&[0xc6, 0x05, 1, 0, 0, 0, 0x42]);
    hardware::STATE.with(|state| state.borrow_mut().instruction = Some((code, [0x90; 15])));
    hardware::write(GUEST_RIP, 0x400000).unwrap();
    scenario.call(1);
    hardware::write(GUEST_LINEAR_ADDRESS, 0x400008).unwrap();
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
    scenario.exit(48, 0x182);
    scenario.call(1);
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800000).unwrap();
    assert_eq!(scenario.exit(48, 4), 1);
    assert!(!scenario.session.is_active());
    assert_eq!(hardware::read(GUEST_RIP), Ok(0x400007));
    hardware::STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.bytes[&0x800008], 0x42);
        assert_eq!(state.bytes[&(SHADOW + 0x008)], 0xcc);
        assert_eq!(state.entries[&0xa000] & 7, 1);
    });
}

#[test]
fn queued_old_generation_fault_retries_after_dynamic_publication() {
    let mut scenario = Scenario::new();
    scenario.call(1);
    scenario.session.configuration.get_mut().generation += 1;
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
    assert_eq!(scenario.exit(48, 1), 1);
    assert_eq!(scenario.boot.interception.step_active, 0);
    scenario.call(1);
    assert_eq!(scenario.boot.interception.hook_generation, 1);
    assert!(scenario.session.is_active());
}

#[test]
fn lease_preemption_expires_without_guest_activity_and_restores_timer_and_debug_state() {
    let mut scenario = Scenario::new();
    use std::sync::atomic::Ordering;
    scenario.session.tsc_hz.store(32000, Ordering::Release);
    scenario
        .session
        .lease_deadline
        .store(1100, Ordering::Release);
    scenario.session.configuration.get_mut().timer_rate = 5;
    hardware::STATE.with(|state| state.borrow_mut().clock = 100);
    hardware::write(VMX_PREEMPTION_TIMER_VALUE, 77).unwrap();
    scenario.call(1);
    assert_eq!(hardware::read(VMX_PREEMPTION_TIMER_VALUE), Ok(31));
    assert_eq!(hardware::read(PIN_BASED_VM_EXEC_CONTROL), Ok(1 << 6));
    hardware::STATE.with(|state| state.borrow_mut().clock = 1100);
    assert_eq!(scenario.exit(52, 0), 1);
    scenario.call(1);
    assert!(!scenario.session.is_active());
    assert_eq!(
        scenario.session.cause.load(Ordering::Acquire),
        u64::from(protocol::memory::INTERCEPT_CAUSE_LEASE)
    );
    assert_eq!(hardware::read(PIN_BASED_VM_EXEC_CONTROL), Ok(0));
    assert_eq!(hardware::read(VMX_PREEMPTION_TIMER_VALUE), Ok(77));
    assert_eq!(hardware::read(GUEST_DR7), Ok(0x400));
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
}

#[test]
fn watchdog_uses_the_earlier_diagnostic_deadline_and_preserves_its_timer() {
    let mut scenario = Scenario::new();
    use std::sync::atomic::Ordering;
    scenario.session.tsc_hz.store(32000, Ordering::Release);
    scenario
        .session
        .lease_deadline
        .store(32000, Ordering::Release);
    scenario.session.configuration.get_mut().timer_rate = 5;
    scenario.boot.diagnostic_interval_tsc = 100;
    hardware::write(PIN_BASED_VM_EXEC_CONTROL, 1 << 6).unwrap();
    hardware::write(VMX_PREEMPTION_TIMER_VALUE, 3).unwrap();
    scenario.call(1);
    assert_eq!(hardware::read(VMX_PREEMPTION_TIMER_VALUE), Ok(3));
    assert_eq!(scenario.exit(52, 0), 0);
    scenario.session.active.store(0, Ordering::Release);
    scenario.call(1);
    assert_eq!(hardware::read(PIN_BASED_VM_EXEC_CONTROL), Ok(1 << 6));
}

#[test]
fn timing_compensation_subtracts_each_root_interval_once_and_restores_the_existing_offset() {
    let mut scenario = Scenario::new();
    scenario.session.configuration.get_mut().timing = 1;
    hardware::write(TSC_OFFSET, 1000).unwrap();
    scenario.call(1);
    for (start, end, expected) in [(100, 160, 940), (200, 230, 910)] {
        scenario.boot.interception.timing_start = start;
        hardware::STATE.with(|state| state.borrow_mut().clock = end);
        assert_eq!(scenario.call(5), 0);
        assert_eq!(hardware::read(TSC_OFFSET), Ok(expected));
        assert_eq!(scenario.call(5), 0);
        assert_eq!(hardware::read(TSC_OFFSET), Ok(expected));
    }
    assert_eq!(
        scenario
            .session
            .timing_ticks
            .load(std::sync::atomic::Ordering::Acquire),
        90
    );
    scenario
        .session
        .active
        .store(0, std::sync::atomic::Ordering::Release);
    scenario.call(1);
    assert_eq!(hardware::read(TSC_OFFSET), Ok(1000));
    assert_eq!(scenario.boot.interception.timing_saved, 0);
}

#[test]
fn concurrent_write_windows_change_only_the_current_cpu_leaf_without_parking_peers() {
    let mut scenario = Scenario::new();
    let configuration = scenario.session.configuration.get_mut();
    configuration.options = protocol::memory::INTERCEPT_CONCURRENT_WRITES;
    configuration.cpu_data[0] = 0xc05e;
    configuration.cpu_data[1] = 0xd05e;
    configuration.cpu_leaves[0][0] = 0xe000;
    configuration.cpu_leaves[1][0] = 0xf000;
    hardware::STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.entries.insert(0xe000, 0x800031);
        state.entries.insert(0xf000, 0x800031);
    });
    scenario.call(1);
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800009).unwrap();
    assert_eq!(scenario.exit(48, 2), 1);
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0xc05e));
    hardware::STATE.with(|state| {
        let mut state = state.borrow_mut();
        assert!(state.sync.is_empty());
        assert_eq!(state.entries[&0xe000] & 7, 3);
        assert_eq!(state.entries[&0xf000] & 7, 1);
        assert_eq!(state.entries[&0xa000] & 7, 1);
        state.bytes.insert(0x800009, 0x42);
    });
    assert_eq!(scenario.exit(37, 0), 1);
    hardware::STATE.with(|state| {
        let state = state.borrow();
        assert!(state.sync.is_empty());
        assert_eq!(state.entries[&0xe000] & 7, 1);
        assert_eq!(state.bytes[&(SHADOW + 0x009)], 0x42);
        assert_eq!(state.bytes[&(SHADOW + 0x008)], 0xcc);
    });
}

#[test]
fn persistent_reads_need_no_mtf_and_survive_unrelated_exits_until_scope_change() {
    let mut scenario = Scenario::new();
    scenario.session.configuration.get_mut().options = protocol::memory::INTERCEPT_PERSISTENT_DATA;
    scenario.call(1);
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
    scenario.exit(48, 1);
    scenario.call(1);
    assert_eq!(scenario.boot.interception.step_active, 0);
    assert_eq!(
        hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27),
        0
    );
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x905e));
    scenario.exit(10, 0);
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x905e));
    hardware::write(GUEST_CR3, 0x5007).unwrap();
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    assert_eq!(scenario.boot.interception.cooperative_data, 0);
}

#[test]
fn scalar_original_reads_do_not_park_peers_or_open_a_shared_mtf_window() {
    let mut scenario = Scenario::new();
    scenario.session.configuration.get_mut().options = protocol::memory::INTERCEPT_PERSISTENT_DATA;
    scenario.call(1);
    hardware::write(GUEST_DR7, 0x400).unwrap();
    hardware::write(GUEST_RIP, 0x400000).unwrap();
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
    hardware::write(GUEST_LINEAR_ADDRESS, 0x400008).unwrap();
    let mut code = [0x90; 15];
    code[..7].copy_from_slice(&[0x0f, 0xb6, 0x05, 1, 0, 0, 0]);
    hardware::STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.instruction = Some((code, code));
        state.sync_busy = true;
        state.bytes.insert(0x800008, 0x77);
    });
    for _ in 0..128 {
        hardware::write(GUEST_RIP, 0x400000).unwrap();
        assert_eq!(scenario.exit(48, 0x181), 1);
        assert_eq!(scenario.frame[0], 0x77);
        assert_eq!(hardware::read(GUEST_RIP), Ok(0x400007));
        assert_eq!(scenario.boot.interception.step_active, 0);
        assert_eq!(scenario.boot.interception.data_pending, 0);
        assert_eq!(scenario.call(1), 0);
        assert_eq!(hardware::read(EPT_POINTER), Ok(0x805e));
    }
    hardware::STATE.with(|state| assert!(state.borrow().sync.is_empty()));
    assert!(scenario.session.is_active());
}

#[test]
fn exact_cr3_targets_cache_only_equivalent_views_and_restore_original_targets() {
    let mut scenario = Scenario::new();
    scenario.boot.nested.host_misc = 4 << 16;
    for index in 0..4 {
        hardware::write(0x6008 + index * 2, 0xaa000 + index * 4096).unwrap();
    }
    hardware::write(CR3_TARGET_COUNT, 2).unwrap();
    for root in [0x5007, 0x6008, 0x7009, 0x800a] {
        hardware::write(GUEST_CR3, root).unwrap();
        assert_eq!(scenario.call(1), 0);
        assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    }
    assert_eq!(hardware::read(CR3_TARGET_COUNT), Ok(4));
    hardware::write(GUEST_CR3, 0x3007).unwrap();
    scenario.call(1);
    assert_eq!(hardware::read(CR3_TARGET_COUNT), Ok(1));
    assert_eq!(hardware::read(0x6008), Ok(0x3007));
    // A newly scoped background root invalidates the learned cache.
    scenario.session.configuration.get_mut().generation += 1;
    scenario.session.configuration.get_mut().extra_roots[0] = 0x5000;
    hardware::write(GUEST_CR3, 0x6008).unwrap();
    scenario.call(1);
    assert_eq!(hardware::read(CR3_TARGET_COUNT), Ok(1));
    assert_eq!(hardware::read(0x6008), Ok(0x6008));
    scenario.session.configuration.get_mut().options = protocol::memory::INTERCEPT_PERSISTENT_DATA;
    hardware::write(GUEST_CR3, 0x3007).unwrap();
    scenario.call(1);
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800009).unwrap();
    scenario.exit(48, 1);
    scenario.call(1);
    assert_eq!(hardware::read(CR3_TARGET_COUNT), Ok(0), "data view must still observe reloads");
    scenario.session.active.store(0, Ordering::Release);
    scenario.call(1);
    assert_eq!(hardware::read(CR3_TARGET_COUNT), Ok(2));
    for index in 0..4 {
        assert_eq!(hardware::read(0x6008 + index * 2), Ok(0xaa000 + index * 4096));
    }
}

#[test]
fn additional_registered_roots_select_hooks_without_extending_to_unregistered_processes() {
    let mut scenario = Scenario::new();
    scenario.session.configuration.get_mut().extra_roots[0] = 0x5000;
    hardware::write(GUEST_CR3, 0x5007).unwrap();
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x805e));
    hardware::write(GUEST_CR3, 0x6007).unwrap();
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
}

#[test]
fn an_inflight_mtf_is_consumed_after_peer_removal_and_local_flush() {
    let mut scenario = Scenario::new();
    scenario.call(1);
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
    scenario.exit(48, 1);
    scenario.call(1);
    scenario.boot.interception.exit_step = 1;
    scenario.boot.last_reason = 37;
    scenario
        .session
        .active
        .store(0, std::sync::atomic::Ordering::Release);
    scenario.session.configuration.get_mut().hook_count = 0;
    scenario.call(3);
    assert_eq!(scenario.boot.interception.step_active, 0);
    assert_eq!(scenario.call(0), 1);
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    assert_eq!(hardware::read(CPU_BASED_VM_EXEC_CONTROL), Ok(0));
}

#[test]
fn an_unowned_mtf_exit_is_not_consumed() {
    let mut scenario = Scenario::new();
    scenario.call(1);
    assert_eq!(scenario.exit(37, 0), 0);
}

#[test]
fn cooperative_vmfunc_switches_the_hardware_root_without_an_exit_or_mtf_and_survives_cpuid() {
    let mut scenario = Scenario::new();
    scenario.enable_vmfunc();
    scenario.call(1);
    assert_ne!(
        hardware::read(SECONDARY_VM_EXEC_CONTROL).unwrap() & (1 << 13),
        0
    );
    assert_eq!(hardware::read(VM_FUNCTION_CONTROL), Ok(1));
    assert_eq!(hardware::read(EPTP_LIST_ADDRESS), Ok(0xb000));
    assert_eq!(hardware::vmfunc(0, 1), 0);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x905e));
    // Software still remembers execution until the next VM exit snapshots
    // hardware. This is the race the early observer must resolve.
    assert_eq!(scenario.boot.interception.applied_ept, 0x805e);
    assert_eq!(scenario.exit(10, 0), 0);
    assert_eq!(scenario.boot.interception.exit_ept, 0x905e);
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x905e));
    assert_eq!(
        hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27),
        0
    );
    assert_eq!(
        scenario
            .session
            .data_exits
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    hardware::STATE.with(|state| assert!(state.borrow().sync.is_empty()));
    assert_eq!(hardware::vmfunc(0, 0), 0);
    scenario.exit(10, 0);
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x805e));
}

#[test]
fn cooperative_data_fetch_restores_execute_view_and_preserves_debug_redirects() {
    let mut scenario = Scenario::new();
    scenario.enable_vmfunc();
    scenario.call(1);
    assert_eq!(hardware::vmfunc(0, 1), 0);
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800000).unwrap();
    assert_eq!(scenario.exit(48, 4), 1);
    assert!(scenario.session.is_active());
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x805e));
    assert_eq!(hardware::debug_registers()[0], 0x400000);
    hardware::write(VM_EXIT_INTR_INFO, 0x80000301).unwrap();
    hardware::write(GUEST_RIP, 0x400000).unwrap();
    hardware::load_debug(&[0x400000, 0, 0, 0, 0xffff0ff0]);
    assert_eq!(scenario.exit(0, 1), 1);
    assert_eq!(hardware::read(GUEST_RIP), Ok(0x400100));
}

#[test]
fn cooperative_vmfunc_is_disabled_on_cr3_change_and_restores_original_vmcs_controls() {
    let mut scenario = Scenario::new();
    scenario.enable_vmfunc();
    hardware::write(VM_FUNCTION_CONTROL, 0x40).unwrap();
    hardware::write(EPTP_LIST_ADDRESS, 0xc000).unwrap();
    hardware::write(CR3_TARGET_COUNT, 3).unwrap();
    scenario.call(1);
    assert_eq!(hardware::read(CR3_TARGET_COUNT), Ok(0));
    assert_eq!(hardware::vmfunc(0, 1), 0);
    scenario.frame[0] = 0x5007;
    assert_eq!(scenario.exit(28, 3), 2);
    scenario.call(1);
    assert_eq!(hardware::vmfunc(0, 1), 4);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    assert_eq!(hardware::read(VM_FUNCTION_CONTROL), Ok(0x40));
    assert_eq!(hardware::read(EPTP_LIST_ADDRESS), Ok(0xc000));
    assert_eq!(hardware::read(SECONDARY_VM_EXEC_CONTROL), Ok(1 << 5));
    scenario
        .session
        .active
        .store(0, std::sync::atomic::Ordering::Release);
    scenario.call(1);
    assert_eq!(hardware::read(CR3_TARGET_COUNT), Ok(3));
}

#[test]
fn a_cooperative_write_uses_mtf_and_returns_to_original_data_after_refreshing_the_shadow() {
    let mut scenario = Scenario::new();
    scenario.enable_vmfunc();
    scenario.call(1);
    assert_eq!(hardware::vmfunc(0, 1), 0);
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800040).unwrap();
    assert_eq!(scenario.exit(48, 2), 1);
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x905e));
    assert_eq!(hardware::vmfunc(0, 0), 4);
    hardware::STATE.with(|state| {
        state.borrow_mut().bytes.insert(0x800040, 0x42);
    });
    assert_eq!(scenario.exit(37, 0), 1);
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x905e));
    assert_eq!(hardware::vmfunc(0, 0), 0);
    hardware::STATE.with(|state| {
        assert_eq!(state.borrow().sync, [0, 1, 2]);
        assert_eq!(state.borrow().bytes[&(SHADOW + 0x040)], 0x42);
    });
}

#[test]
fn invalid_vmfunc_slots_and_functions_inject_ud_without_selecting_unadmitted_roots() {
    for (function, slot) in [(0, 2), (0, 511), (0, 512), (1, 0)] {
        let mut scenario = Scenario::new();
        scenario.enable_vmfunc();
        scenario.call(1);
        assert_eq!(hardware::vmfunc(function, slot), 59);
        scenario.frame[0] = u64::from(function);
        scenario.frame[1] = u64::from(slot);
        assert_eq!(scenario.exit(59, 0), 4);
        assert_eq!(hardware::read(EPT_POINTER), Ok(0x805e));
    }
    let mut scenario = Scenario::new();
    scenario.enable_vmfunc();
    scenario.call(1);
    assert_eq!(hardware::vmfunc(64, 0), 4);
}

#[test]
fn intercepted_valid_vmfunc_selectors_advance_and_ignore_the_high_gpr_halves() {
    let mut scenario = Scenario::new();
    scenario.enable_vmfunc();
    scenario.call(1);
    scenario.frame[0] = 1 << 32;
    scenario.frame[1] = (1 << 32) | 1;
    assert_eq!(scenario.exit(59, 0), 2);
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x905e));
    scenario.frame[1] = 0;
    assert_eq!(scenario.exit(59, 0), 2);
    scenario.call(1);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x805e));
}

#[test]
fn vmfunc_exit_queued_before_peer_removal_injects_ud_after_the_list_is_retired() {
    let mut scenario = Scenario::new();
    scenario.enable_vmfunc();
    scenario.call(1);
    scenario.boot.interception.exit_vmfunc = 1;
    scenario.boot.last_reason = 59;
    scenario
        .session
        .active
        .store(0, std::sync::atomic::Ordering::Release);
    scenario.session.configuration.get_mut().hook_count = 0;
    scenario.call(3);
    assert_eq!(scenario.call(0), 4);
    assert_eq!(hardware::vmfunc(0, 1), 4);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
}

#[test]
fn a_synchronization_nmi_closes_the_write_window_before_bypassing_l1_dispatch() {
    let mut scenario = Scenario::new();
    scenario.call(1);
    hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800008).unwrap();
    scenario.exit(48, 2);
    scenario.call(1);
    scenario.boot.interception.exit_step = 2;
    assert_eq!(scenario.call(4), 0);
    assert_eq!(scenario.boot.interception.step_active, 0);
    assert_eq!(
        hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27),
        0
    );
    hardware::STATE.with(|state| assert_eq!(state.borrow().sync, [0, 1, 2]));
}

#[test]
fn all_four_debug_targets_share_split_view_and_cooperative_vmfunc_without_claiming_guest_breakpoints()
 {
    let mut scenario = Scenario::new();
    scenario.enable_vmfunc();
    let configuration = scenario.session.configuration.get_mut();
    configuration.debug_count = 4;
    for (index, target) in configuration.debug.iter_mut().enumerate() {
        *target = DebugTarget {
            address: 0x400000 + index as u64 * 16,
            redirect: 0x500000 + index as u64 * 16,
        };
    }
    scenario.call(1);
    assert_eq!(hardware::read(GUEST_DR7), Ok(0x4aa));
    assert_eq!(
        &hardware::debug_registers()[..4],
        &[0x400000, 0x400010, 0x400020, 0x400030]
    );
    for index in 0..4 {
        hardware::write(VM_EXIT_INTR_INFO, 0x80000301).unwrap();
        hardware::write(GUEST_RIP, 0x400000 + index * 16).unwrap();
        hardware::load_debug(&[0x400000, 0x400010, 0x400020, 0x400030, 0xffff0ff0]);
        assert_eq!(scenario.exit(0, 1 << index), 1);
        assert_eq!(hardware::read(GUEST_RIP), Ok(0x500000 + index * 16));
        scenario.call(1);
        assert_eq!(hardware::vmfunc(0, 1), 0);
        scenario.exit(10, 0);
        scenario.call(1);
        assert_eq!(hardware::vmfunc(0, 0), 0);
    }
    scenario.exit(10, 0);
    hardware::write(GUEST_DR7, 0x401).unwrap();
    scenario.call(1);
    assert_eq!(scenario.boot.interception.debug_armed, 0);
    assert_eq!(hardware::vmfunc(0, 1), 0);
    assert!(scenario.session.is_active());
}

#[test]
fn transient_vmcs_failures_retire_the_profile_and_restore_controls_before_reentry() {
    for writing in [false, true] {
        let mut scenario = Scenario::new();
        scenario.enable_vmfunc();
        scenario.call(1);
        hardware::write(GUEST_CR3, 0x5000).unwrap();
        hardware::STATE.with(|state| {
            let mut state = state.borrow_mut();
            if writing {
                state.fail_writes.insert(EPT_POINTER, 1);
            } else {
                state.fail_reads.insert(GUEST_CR3, 1);
            }
        });
        assert_eq!(scenario.call(1), 0);
        assert!(!scenario.session.is_active());
        assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
        assert_eq!(hardware::read(CPU_BASED_VM_EXEC_CONTROL), Ok(0));
        assert_eq!(hardware::read(EXCEPTION_BITMAP), Ok(0));
        assert_eq!(hardware::debug_registers()[0], 11);
        assert_eq!(
            scenario
                .session
                .cause
                .load(std::sync::atomic::Ordering::Acquire),
            u64::from(protocol::memory::INTERCEPT_CAUSE_RUNTIME)
        );
        hardware::STATE.with(|state| assert_eq!(state.borrow().sync.last(), Some(&2)));
    }
}

#[test]
fn a_failure_during_revocation_releases_the_owned_barrier_before_retrying() {
    let mut scenario = Scenario::new();
    scenario.call(1);
    hardware::STATE.with(|state| {
        state
            .borrow_mut()
            .fail_reads
            .insert(PIN_BASED_VM_EXEC_CONTROL, 1);
    });
    assert_eq!(scenario.call(2), 0);
    assert!(!scenario.session.is_active());
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    hardware::STATE.with(|state| assert_eq!(state.borrow().sync, [0, 1, 2, 0, 1, 2]));
}

#[test]
fn concurrent_windows_own_refresh_serialization_until_mtf_and_release_it_for_the_next_write() {
    let mut scenario = Scenario::new();
    let profile = scenario.session.configuration.get_mut();
    profile.options = protocol::memory::INTERCEPT_CONCURRENT_WRITES;
    profile.cpu_data[0] = 0xc05e;
    profile.cpu_leaves[0][0] = 0xe000;
    scenario.call(1);
    for offset in [9, 10] {
        hardware::write(GUEST_PHYSICAL_ADDRESS, 0x800000 + offset).unwrap();
        assert_eq!(scenario.exit(48, 2), 1);
        assert_eq!(scenario.boot.interception.refresh_owned, 1);
        scenario.call(1);
        hardware::STATE.with(|state| {
            state.borrow_mut().bytes.insert(0x800000 + offset, 0x42);
        });
        assert_eq!(scenario.exit(37, 0), 1);
        assert_eq!(scenario.boot.interception.refresh_owned, 0);
        scenario.call(1);
    }
    assert!(scenario.session.is_active());
}

#[test]
fn stale_debug_faults_from_removed_aliases_or_generations_never_redirect() {
    for remove_alias in [false, true] {
        let mut scenario = Scenario::new();
        hardware::write(GUEST_CR3, 0x4007).unwrap();
        scenario.call(1);
        if remove_alias {
            scenario.session.configuration.get_mut().roots[1] = 0;
        } else {
            scenario.session.configuration.get_mut().generation += 1;
        }
        hardware::write(VM_EXIT_INTR_INFO, 0x80000301).unwrap();
        hardware::write(GUEST_RIP, 0x400000).unwrap();
        hardware::load_debug(&[0x400000, 0, 0, 0, 0xffff0ff0]);
        assert_eq!(scenario.exit(0, 1), 1);
        assert_eq!(hardware::read(GUEST_RIP), Ok(0x400000));
        assert_eq!(
            scenario
                .session
                .hits
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );
    }
}

#[test]
fn peer_revocation_restores_base_write_guards_on_the_next_local_entry() {
    let mut scenario = Scenario::new();
    scenario.call(1);
    scenario.session.active.store(
        u64::from(INTERCEPT_REVOKED),
        std::sync::atomic::Ordering::Release,
    );
    assert_eq!(scenario.call(1), 0);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    hardware::STATE.with(|state| assert_eq!(state.borrow().entries[&0x2000] & 7, 7));
    assert_eq!(hardware::read(CPU_BASED_VM_EXEC_CONTROL), Ok(0));
}

#[test]
fn retiring_splits_invalidates_both_banks_and_the_sparse_cpu_slot_before_acknowledging() {
    use protocol::memory::{
        HOOK_MAX_PAGES, INTERCEPT_CPU_VIEW_PAGES, INTERCEPT_TABLE_PAGES, intercept_bank_pages,
    };
    let mut scenario = Scenario::new();
    scenario.enable_vmfunc();
    let configuration = scenario.session.configuration.get_mut();
    configuration.cpu_mask = 1 | (1 << 3) | (1 << 63);
    scenario.boot.processor_number = 63;
    assert_eq!(scenario.call(1), 0);
    assert_eq!(hardware::vmfunc(0, 1), 0);
    scenario.session.split_epoch.store(1, Ordering::Release);
    assert_eq!(scenario.call(3), 0);
    assert_eq!(
        scenario
            .boot
            .interception
            .split_flush_epoch
            .load(Ordering::Acquire),
        1
    );
    assert_eq!(scenario.boot.interception.vmfunc_armed, 0);
    assert_eq!(scenario.boot.interception.applied_ept, 0);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    hardware::STATE.with(|state| {
        let state = state.borrow();
        for bank in 0..2 {
            let start =
                0x8000 + (bank * intercept_bank_pages(1 | (1 << 3) | (1 << 63))) as u64 * 4096;
            for ept in [
                start | 0x5e,
                (start + 4096) | 0x5e,
                (start
                    + (INTERCEPT_TABLE_PAGES
                        + 2 * HOOK_MAX_PAGES
                        + 1
                        + 2 * INTERCEPT_CPU_VIEW_PAGES) as u64
                        * 4096)
                    | 0x5e,
            ] {
                assert!(state.invalidated_epts.contains(&ept));
            }
        }
        assert!(state.invalidated_epts.contains(&0x105e));
    });
    hardware::STATE.with(|state| state.borrow_mut().invalidated_epts.clear());
    assert_eq!(scenario.call(3), 0);
    hardware::STATE.with(|state| assert_eq!(state.borrow().invalidated_epts, [0x805e, 0x905e]));
}

#[test]
fn a_recovered_invalidation_failure_does_not_acknowledge_split_reuse_until_a_complete_retry() {
    use protocol::memory::intercept_bank_pages;
    let mut scenario = Scenario::new();
    assert_eq!(scenario.call(1), 0);
    let stale = (0x8000 + intercept_bank_pages(u64::MAX) as u64 * 4096) | 0x5e;
    hardware::STATE.with(|state| state.borrow_mut().fail_invalidations.insert(stale, 1));
    scenario.session.split_epoch.store(7, Ordering::Release);
    assert_eq!(scenario.call(3), 0);
    assert_eq!(
        scenario
            .boot
            .interception
            .split_flush_epoch
            .load(Ordering::Acquire),
        0
    );
    assert_eq!(
        scenario.session.active.load(Ordering::Acquire),
        u64::from(INTERCEPT_REVOKED)
    );
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x105e));
    assert_eq!(scenario.call(3), 0);
    assert_eq!(
        scenario
            .boot
            .interception
            .split_flush_epoch
            .load(Ordering::Acquire),
        7
    );
}
