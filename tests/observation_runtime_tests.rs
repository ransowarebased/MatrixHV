use super::*;
use memory::observation::{ContextRecord, Observation, WatchTarget};
use protocol::memory::*;

fn observer(scenario: &mut Scenario) -> Box<Observation> {
    let layout = std::alloc::Layout::new::<Observation>();
    let observation =
        unsafe { Box::from_raw(std::alloc::alloc_zeroed(layout).cast::<Observation>()) };
    scenario.session.observation = &*observation as *const _ as u64;
    observation
}

fn query(operation: u32, count: usize, cursor: u64) -> Vec<u8> {
    let size = match operation {
        WATCH_FETCH => WATCH_RECORD_BYTES,
        STACK_WALK => 16,
        _ => CONTEXT_RECORD_BYTES,
    };
    let mut packet = vec![0; HEADER_BYTES + count * size];
    packet[12..16].copy_from_slice(&operation.to_le_bytes());
    packet[32..36].copy_from_slice(&(count as u32).to_le_bytes());
    packet[64..72].copy_from_slice(&cursor.to_le_bytes());
    packet
}

#[test]
fn watch_data_traps_log_post_instruction_context_and_preserve_guest_single_step() {
    for single_step in [false, true] {
        let mut scenario = Scenario::new();
        let mut observation = observer(&mut scenario);
        observation.watch_count = 1;
        observation.watch[0] = WatchTarget {
            address: 0x600008,
            control: 9,
        };
        scenario.frame = core::array::from_fn(|index| 0x12340000 + index as u64);
        hardware::write(GUEST_GS_BASE, 0x7fff0000).unwrap();
        hardware::write(GUEST_RSP, 0x700010).unwrap();
        hardware::write(GUEST_RIP, 0x401006).unwrap();
        hardware::write(VM_EXIT_INTR_INFO, 0x80000301).unwrap();
        let frame = scenario.frame;
        scenario.call(1);
        assert_eq!(hardware::read(GUEST_DR7).unwrap() >> 20 & 15, 9);
        assert_eq!(
            scenario.exit(0, 2 | if single_step { 1 << 14 } else { 0 }),
            u64::from(!single_step)
        );
        assert_eq!(scenario.frame, frame);
        assert_eq!(hardware::read(GUEST_RIP), Ok(0x401006));
        assert_ne!(hardware::read(GUEST_RFLAGS).unwrap() & (1 << 16), 0);
        assert_eq!(
            hardware::debug_registers()[4] & 0x400f,
            if single_step { 1 << 14 } else { 0 }
        );
        let mut packet = query(WATCH_FETCH, 1, 0);
        observation.fetch(&mut packet).unwrap();
        assert_eq!(word(&packet, 32), 1);
        let record = &packet[HEADER_BYTES..];
        assert_eq!(quad(record, 24), 0x401006);
        assert_eq!(quad(record, 32), 0x700010);
        assert_eq!(quad(record, 64), 0x7fff0000);
        assert_eq!(quad(record, 72 + 7 * 8), frame[7]);
        assert_eq!(quad(record, 208), 0x600008);
        assert_eq!(quad(record, 232), WATCH_POST_INSTRUCTION);
    }
}

#[test]
fn watch_ring_reports_overwritten_sequences_and_validates_descriptor_encodings() {
    let mut scenario = Scenario::new();
    let mut observation = observer(&mut scenario);
    for (length, bits) in [(1u32, 0u64), (2, 4), (4, 12), (8, 8)] {
        let mut packet = vec![0; HEADER_BYTES + 16];
        packet[32..36].copy_from_slice(&1u32.to_le_bytes());
        packet[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&0x600008u64.to_le_bytes());
        packet[HEADER_BYTES + 8..HEADER_BYTES + 12].copy_from_slice(&3u32.to_le_bytes());
        packet[HEADER_BYTES + 12..].copy_from_slice(&length.to_le_bytes());
        let (targets, count) = Observation::watch_targets(&packet, false).unwrap();
        assert_eq!(count, 1);
        assert_eq!(targets[0].control, bits | 3);
        packet[HEADER_BYTES + 8..HEADER_BYTES + 12].copy_from_slice(&2u32.to_le_bytes());
        assert!(matches!(
            Observation::watch_targets(&packet, false),
            Err(Error::Bounds)
        ));
    }
    observation.watch_count = 1;
    observation.watch[0] = WatchTarget {
        address: 0x600008,
        control: 9,
    };
    for index in 0..100 {
        observation.capture(
            ContextRecord {
                rip: index,
                ..Default::default()
            },
            Some(0),
        );
    }
    let mut packet = query(WATCH_FETCH, WATCH_RING_RECORDS, 0);
    observation.fetch(&mut packet).unwrap();
    assert_eq!(word(&packet, 32), 64);
    assert_eq!(quad(&packet, 96), 37);
    assert_eq!(quad(&packet, 88), 100);
    assert_eq!(quad(&packet, HEADER_BYTES), 37);
    assert_eq!(quad(&packet, HEADER_BYTES + 63 * WATCH_RECORD_BYTES), 100);
    observation.reset_watch();
    observation.fetch(&mut packet).unwrap();
    assert_eq!(word(&packet, 32), 0);
    assert_eq!(quad(&packet, 88), 0);
    assert_eq!(quad(&packet, 96), 0);
}

#[test]
fn empty_watch_ring_has_no_oldest_sequence() {
    let mut scenario = Scenario::new();
    let observation = observer(&mut scenario);
    let mut packet = query(WATCH_FETCH, 1, 0);
    observation.fetch(&mut packet).unwrap();
    assert_eq!(word(&packet, 32), 0);
    assert_eq!(quad(&packet, 88), 0);
    assert_eq!(quad(&packet, 96), 0);
}

#[test]
fn every_exit_samples_scoped_threads_and_keeps_user_teb_after_swapgs() {
    let mut scenario = Scenario::new();
    let mut observation = observer(&mut scenario);
    observation.context_enabled = true;
    hardware::write(GUEST_RIP, 0xffff800000123000).unwrap();
    hardware::write(GUEST_GS_BASE, 0xffff800000100000).unwrap();
    hardware::STATE.with(|state| state.borrow_mut().kernel_gs = 0x7fff0000);
    scenario.call(1);
    scenario.exit(10, 0);
    scenario.exit(10, 0);
    hardware::write(GUEST_CR3, 0x5000).unwrap();
    scenario.exit(10, 0);
    let mut packet = query(CONTEXT_SNAPSHOT, CONTEXT_CPU_RECORDS, 0);
    observation.fetch(&mut packet).unwrap();
    assert_eq!(word(&packet, 32), 1);
    assert_eq!(quad(&packet, HEADER_BYTES), 2);
    assert_eq!(quad(&packet, HEADER_BYTES + 64), 0x7fff0000);
    assert_eq!(quad(&packet, HEADER_BYTES + 56), 0xffff800000100000);
    observation.reset_contexts();
    packet = query(CONTEXT_SNAPSHOT, CONTEXT_CPU_RECORDS, 0);
    observation.fetch(&mut packet).unwrap();
    assert_eq!(word(&packet, 32), 0);
}

#[test]
fn context_sampling_uses_the_timer_without_a_lease_and_restores_prior_timer_state() {
    let mut scenario = Scenario::new();
    let mut observation = observer(&mut scenario);
    observation.context_enabled = true;
    observation.sample_ticks = 1000;
    hardware::write(VMX_PREEMPTION_TIMER_VALUE, 12345).unwrap();
    scenario.call(1);
    assert_eq!(hardware::read(VMX_PREEMPTION_TIMER_VALUE), Ok(1000));
    assert_ne!(
        hardware::read(PIN_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 6),
        0
    );
    assert_eq!(scenario.exit(52, 0), 1);
    assert!(scenario.session.is_active());
    observation.context_enabled = false;
    scenario.call(1);
    assert_eq!(hardware::read(VMX_PREEMPTION_TIMER_VALUE), Ok(12345));
    assert_eq!(
        hardware::read(PIN_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 6),
        0
    );
}

#[test]
fn context_sampling_follows_cr3_scope_without_shortening_unscoped_lease_timers() {
    for leased in [false, true] {
        let mut scenario = Scenario::new();
        let mut observation = observer(&mut scenario);
        observation.context_enabled = true;
        observation.sample_ticks = 1000;
        hardware::write(VMX_PREEMPTION_TIMER_VALUE, 12345).unwrap();
        if leased {
            scenario.session.tsc_hz.store(1_000_000, Ordering::Release);
            scenario
                .session
                .lease_deadline
                .store(10000, Ordering::Release);
        }
        for cr3 in [0x5000, 0x3007, 0x5000, 0x4000, 0x5000] {
            hardware::write(GUEST_CR3, cr3).unwrap();
            scenario.call(1);
            let scoped = cr3 != 0x5000;
            assert_eq!(
                hardware::read(VMX_PREEMPTION_TIMER_VALUE),
                Ok(if scoped {
                    1000
                } else if leased {
                    10000
                } else {
                    12345
                })
            );
            assert_eq!(
                hardware::read(PIN_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 6) != 0,
                scoped || leased
            );
            assert!(scenario.session.is_active());
        }
        observation.context_enabled = false;
        scenario.session.tsc_hz.store(0, Ordering::Release);
        scenario.call(1);
        assert_eq!(hardware::read(VMX_PREEMPTION_TIMER_VALUE), Ok(12345));
        assert_eq!(
            hardware::read(PIN_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 6),
            0
        );
    }
}

struct StackMemory {
    bytes: std::collections::BTreeMap<u64, u8>,
}
impl StackMemory {
    fn store(&mut self, address: u64, value: u64) {
        for (index, byte) in value.to_le_bytes().iter().enumerate() {
            self.bytes.insert(address + index as u64, *byte);
        }
    }
}
impl memory::access::PhysicalMemory for StackMemory {
    fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), Error> {
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = *self
                .bytes
                .get(&(address + index as u64))
                .ok_or(Error::Unmapped)?;
        }
        Ok(())
    }
    fn write(&mut self, _: u64, _: &[u8]) -> Result<(), Error> {
        Err(Error::Permission)
    }
}

#[test]
fn stack_walk_reads_a_bounded_frame_chain_from_the_cached_cr3_and_stops_on_cycles() {
    let mut scenario = Scenario::new();
    let mut observation = observer(&mut scenario);
    observation.context_enabled = true;
    observation.capture(
        ContextRecord {
            cr3: 0x1000,
            rip: 0x401000,
            rsp: 0x700000,
            rbp: 0x700080,
            cpl: 3,
            ..Default::default()
        },
        None,
    );
    let mut memory = StackMemory {
        bytes: Default::default(),
    };
    memory.store(0x1000, 0x2007);
    memory.store(0x2000, 0x3007);
    memory.store(0x3000 + 3 * 8, 0x4007);
    memory.store(0x4000 + 0x100 * 8, 0x8007);
    memory.store(0x8080, 0x7000a0);
    memory.store(0x8088, 0x402000);
    memory.store(0x80a0, 0x700080);
    memory.store(0x80a8, 0x403000);
    let mapping = memory::access::page_mapping(&mut memory, 0x1000, 0x700080, false, 48).unwrap();
    assert_eq!(mapping.physical_address, 0x8080);
    assert_ne!(mapping.pte_fingerprint, 0);
    let mut packet = query(STACK_WALK, 64, 1);
    observation
        .stack_walk(&mut memory, &mut packet, false, 48)
        .unwrap();
    assert_eq!(word(&packet, 32), 2);
    assert_eq!(word(&packet, 72), Error::Bounds as u32);
    assert_eq!(quad(&packet, HEADER_BYTES + 16), 0x402000);
}

#[test]
fn fetched_context_sequences_survive_resampling_until_the_next_snapshot() {
    let mut scenario = Scenario::new();
    let mut observation = observer(&mut scenario);
    observation.context_enabled = true;
    observation.capture(
        ContextRecord {
            rip: 0x401000,
            rsp: 0x700000,
            thread_teb: 0x710000,
            ..Default::default()
        },
        None,
    );
    let mut snapshot = query(CONTEXT_SNAPSHOT, CONTEXT_CPU_RECORDS, 0);
    observation.fetch(&mut snapshot).unwrap();
    let sequence = quad(&snapshot, HEADER_BYTES);
    for index in 0..100 {
        observation.capture(
            ContextRecord {
                rip: 0x402000 + index,
                rsp: 0x720000,
                thread_teb: 0x710000,
                ..Default::default()
            },
            None,
        );
    }
    let mut memory = StackMemory {
        bytes: Default::default(),
    };
    let mut walk = query(STACK_WALK, 1, sequence);
    observation
        .stack_walk(&mut memory, &mut walk, false, 48)
        .unwrap();
    assert_eq!(word(&walk, 32), 1);
    assert_eq!(quad(&walk, HEADER_BYTES), 0x401000);
    assert_eq!(quad(&walk, HEADER_BYTES + 8), 0x700000);
    snapshot = query(CONTEXT_SNAPSHOT, CONTEXT_CPU_RECORDS, 0);
    observation.fetch(&mut snapshot).unwrap();
    assert!(matches!(
        observation.stack_walk(&mut memory, &mut walk, false, 48),
        Err(Error::Session)
    ));
    let mut walk = query(STACK_WALK, 1, quad(&snapshot, HEADER_BYTES));
    observation.reset_contexts();
    assert!(matches!(
        observation.stack_walk(&mut memory, &mut walk, false, 48),
        Err(Error::Session)
    ));
}

#[test]
fn cet_syscall_return_restores_user_ssp_and_rolls_back_failed_transitions() {
    for fail in [false, true] {
        let mut scenario = syscall_scenario();
        hardware::write(GUEST_CR4, 1 << 23).unwrap();
        hardware::write(VM_ENTRY_CONTROLS, 1 << 20).unwrap();
        hardware::write(GUEST_SSP, 0xffff800000900000).unwrap();
        hardware::STATE.with(|state| state.borrow_mut().user_cet = [1, 0x710000]);
        scenario.call(1);
        if fail {
            hardware::STATE.with(|state| {
                state.borrow_mut().fail_writes.insert(GUEST_SSP, 1);
            });
        }
        assert_eq!(scenario.exit(0, 1), 1);
        assert_eq!(
            hardware::read(GUEST_SSP),
            Ok(if fail { 0xffff800000900000 } else { 0x710000 })
        );
        assert_eq!(
            hardware::read(GUEST_CS_SELECTOR),
            Ok(if fail { 0x10 } else { 0x33 })
        );
        assert_eq!(
            hardware::read(GUEST_RIP),
            Ok(if fail { 0xffff800000400000 } else { 0x402000 })
        );
    }
}

#[test]
fn ept_debug_watch_and_syscall_profiles_arm_distinct_slots_without_overwriting_the_guest_gate() {
    let mut scenario = syscall_scenario();
    let mut observation = observer(&mut scenario);
    let configuration = scenario.session.configuration.get_mut();
    configuration.debug_count = 1;
    configuration.debug[0] = DebugTarget {
        address: 0x400000,
        redirect: 0x400100,
    };
    observation.watch_count = 1;
    observation.watch[0] = WatchTarget {
        address: 0x600008,
        control: 9,
    };
    scenario.enable_vmfunc();
    scenario.call(1);
    assert_eq!(
        hardware::debug_registers()[..4],
        [0x400000, 0xffff800000400000, 0x600008, 0x7ffe0ff0]
    );
    assert_eq!(hardware::read(GUEST_DR7).unwrap() & 0xff, 0x6a);
    assert_eq!(hardware::read(EPT_POINTER), Ok(0x805e));
    assert_eq!(hardware::vmfunc(0, 1), 0);
}

#[test]
fn legacy_sessions_route_debug_and_syscall_slots_independently() {
    let mut scenario = syscall_scenario();
    let configuration = scenario.session.configuration.get_mut();
    configuration.debug_count = 1;
    configuration.debug[0] = DebugTarget {
        address: 0x400000,
        redirect: 0x400100,
    };
    scenario.call(1);
    hardware::write(GUEST_RIP, 0x400000).unwrap();
    assert_eq!(scenario.exit(0, 1), 1);
    assert_eq!(hardware::read(GUEST_RIP), Ok(0x400100));
    scenario.call(1);
    hardware::write(GUEST_RIP, 0xffff800000400000).unwrap();
    assert_eq!(scenario.exit(0, 2), 1);
    assert_eq!(hardware::read(GUEST_RIP), Ok(0x402000));
}
