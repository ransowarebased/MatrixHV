use super::*;
use memory::observation::{ContextRecord, EventConfig, Observation, WatchTarget};

#[test]
fn expanded_region_capture_keeps_every_region_and_rejects_excess_probes() {
    let mut scenario = Scenario::new();
    scenario.session.configuration.get_mut().debug_count = 0;
    let mut observation = observer(&mut scenario);
    let mut setup = vec![0; HEADER_BYTES + (EVENT_REGIONS + 1) * 16];
    setup[32..36].copy_from_slice(&(EVENT_REGIONS as u32).to_le_bytes());
    setup[44..48].copy_from_slice(&1u32.to_le_bytes());
    for (index, descriptor) in setup[HEADER_BYTES..].chunks_exact_mut(16).enumerate() {
        let (address, length) = if index < EVENT_REGIONS {
            (0x600000 + index as u64 * 4096, 8)
        } else {
            (0x401000, EVENT_INSTRUCTION)
        };
        descriptor[..8].copy_from_slice(&address.to_le_bytes());
        descriptor[8..].copy_from_slice(&length.to_le_bytes());
    }
    observation.events.config = EventConfig::parse(&setup, false).unwrap();
    for (address, value) in [(0x3000, 0x10007), (0x10000, 0x87)] {
        hardware::original_value(address, 8, Some(value));
    }
    for index in 0..EVENT_REGIONS {
        hardware::original_value(0x600000 + index as u64 * 4096, 8, Some(index as u64 + 100));
    }
    hardware::STATE.with(|state| state.borrow_mut().instruction = Some(([0x90; 15], [0x90; 15])));
    for (field, value) in [
        (GUEST_RIP, 0x401000),
        (GUEST_RSP, 0x700000),
        (GUEST_CS_SELECTOR, 3),
        (VM_EXIT_INTR_INFO, 0x80000301),
    ] {
        hardware::write(field, value).unwrap();
    }
    scenario.call(1);
    assert_eq!(scenario.exit(0, 1), 1);
    let mut packet = query(EVENT_FETCH, 1, 0);
    observation.events.fetch(&mut packet).unwrap();
    assert_eq!(word(&packet, 32), 1);
    assert!(packet.len() <= BUFFER_BYTES);
    let first_region = HEADER_BYTES
        + EVENT_RECORD_HEADER
        + 2 * EVENT_SEGMENT_HEADER
        + EVENT_CODE_BYTES
        + EVENT_STACK_BYTES;
    for index in 0..EVENT_REGIONS {
        let segment = first_region + index * (EVENT_SEGMENT_HEADER + EVENT_REGION_BYTES);
        assert_eq!(quad(&packet, segment), 0x600000 + index as u64 * 4096);
        assert_eq!(word(&packet, segment + 12), 0);
        assert_eq!(
            quad(&packet, segment + EVENT_SEGMENT_HEADER),
            index as u64 + 100
        );
    }
    setup[32..36].copy_from_slice(&((EVENT_REGIONS + 1) as u32).to_le_bytes());
    assert!(EventConfig::parse(&setup, false).is_err());
    let mut five_probes = vec![0; HEADER_BYTES + 5 * 16];
    five_probes[44..48].copy_from_slice(&5u32.to_le_bytes());
    assert!(EventConfig::parse(&five_probes, false).is_err());
}

#[test]
fn argument_offsets_apply_before_copy_or_pointer_follow_and_report_invalid_addresses() {
    for (depth, displacement, scalar, expected_address, expected_status) in [
        (1, 8i16, 0x600000, 0x600008, 0),
        (2, 8, 0x600000, 0x600100, 0),
        (1, -8, 0x600010, 0x600008, 0),
        (2, -8, 0x600010, 0x600100, 0),
        (1, 8, u64::MAX, 0, Error::Bounds as u32),
        (1, 8, u64::MAX - 11, 0, Error::Bounds as u32),
        (2, -8, 4, 4, Error::Bounds as u32),
        (2, 8, 0x3ffffff8, 0x40000000, Error::Unmapped as u32),
    ] {
        let mut scenario = Scenario::new();
        scenario.session.configuration.get_mut().debug_count = 0;
        let mut observation = observer(&mut scenario);
        let mut setup = vec![0; HEADER_BYTES + 32];
        setup[32..36].copy_from_slice(&1u32.to_le_bytes());
        setup[44..48].copy_from_slice(&1u32.to_le_bytes());
        setup[HEADER_BYTES..HEADER_BYTES + 8]
            .copy_from_slice(&(ARGUMENT_REGISTER | 2).to_le_bytes());
        let encoded = 8 | (depth << 32) | (u64::from(displacement as u16) << 48);
        setup[HEADER_BYTES + 8..HEADER_BYTES + 16].copy_from_slice(&encoded.to_le_bytes());
        setup[HEADER_BYTES + 16..HEADER_BYTES + 24].copy_from_slice(&0x401000u64.to_le_bytes());
        setup[HEADER_BYTES + 24..].copy_from_slice(&EVENT_INSTRUCTION.to_le_bytes());
        observation.events.config = EventConfig::parse(&setup, false).unwrap();
        for (address, value) in [
            (0x3000, 0x10007),
            (0x10000, 0x87),
            (0x600008, 0x600100),
            (0x600100, 0x1122334455667788),
        ] {
            hardware::original_value(address, 8, Some(value));
        }
        hardware::STATE
            .with(|state| state.borrow_mut().instruction = Some(([0x90; 15], [0x90; 15])));
        for (field, value) in [
            (GUEST_RIP, 0x401000),
            (GUEST_RSP, 0x700000),
            (GUEST_CS_SELECTOR, 3),
            (VM_EXIT_INTR_INFO, 0x80000301),
        ] {
            hardware::write(field, value).unwrap();
        }
        scenario.frame[2] = scalar;
        let original_frame = scenario.frame;
        scenario.call(1);
        assert_eq!(scenario.exit(0, 1), 1);
        assert_eq!(scenario.frame, original_frame);
        let mut packet = query(EVENT_FETCH, 1, 0);
        observation.events.fetch(&mut packet).unwrap();
        let offset = HEADER_BYTES
            + EVENT_RECORD_HEADER
            + 2 * EVENT_SEGMENT_HEADER
            + EVENT_CODE_BYTES
            + EVENT_STACK_BYTES;
        let segment = &packet[offset..];
        assert_eq!(quad(segment, 0), expected_address);
        assert_eq!(quad(segment, 24), scalar);
        assert_eq!(quad(segment, 48) & 0xffff, depth);
        assert_eq!((quad(segment, 48) >> 48) as u16 as i16, displacement);
        assert_eq!(word(segment, 12), expected_status);
        if expected_status == 0 {
            assert_eq!(
                quad(segment, EVENT_SEGMENT_HEADER),
                if depth == 1 {
                    0x600100
                } else {
                    0x1122334455667788
                }
            );
        } else {
            assert_eq!(u16::from_le_bytes(segment[10..12].try_into().unwrap()), 0);
            assert_eq!(word(segment, 64 + 24), 8);
            assert_eq!(word(segment, 64 + 28), 0);
        }
    }
}

#[test]
fn kernel_instruction_probes_capture_supervisor_pages_without_claiming_user_permissions() {
    let mut scenario = Scenario::new();
    scenario.session.configuration.get_mut().debug_count = 0;
    let mut observation = observer(&mut scenario);
    let rip = 0xffff800000401000u64;
    let mut setup = vec![0; HEADER_BYTES + 32];
    setup[32..36].copy_from_slice(&1u32.to_le_bytes());
    setup[44..48].copy_from_slice(&1u32.to_le_bytes());
    setup[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&rip.to_le_bytes());
    setup[HEADER_BYTES + 8..HEADER_BYTES + 16].copy_from_slice(&16u64.to_le_bytes());
    setup[HEADER_BYTES + 16..HEADER_BYTES + 24].copy_from_slice(&rip.to_le_bytes());
    setup[HEADER_BYTES + 24..].copy_from_slice(&EVENT_INSTRUCTION.to_le_bytes());
    observation.events.config = EventConfig::parse(&setup, false).unwrap();
    assert_eq!(observation.events.config.regions[0].kind, 0);
    for (address, value) in [(0x3800, 0x10003), (0x10000, 0x83), (0x401000, 0xdeadbeef)] {
        hardware::original_value(address, 8, Some(value));
    }
    hardware::STATE.with(|state| state.borrow_mut().instruction = Some(([0x90; 15], [0x90; 15])));
    for (field, value) in [
        (GUEST_RIP, rip),
        (GUEST_RSP, 0xffff800000700000),
        (GUEST_CS_SELECTOR, 0x10),
        (GUEST_GS_BASE, 0xffff800000800000),
        (VM_EXIT_INTR_INFO, 0x80000301),
    ] {
        hardware::write(field, value).unwrap();
    }
    scenario.call(1);
    assert_eq!(hardware::debug_registers()[0], rip);
    assert_eq!(scenario.exit(0, 1), 1);
    let mut packet = query(EVENT_FETCH, 1, 0);
    observation.events.fetch(&mut packet).unwrap();
    assert_eq!(word(&packet, 32), 1);
    let event = &packet[HEADER_BYTES..];
    assert_eq!(quad(event, 200), 0);
    let segment = &event[EVENT_RECORD_HEADER..];
    assert_eq!(word(segment, 12), 0);
    assert_eq!(word(segment, 64 + 36), 11);
    assert_eq!(quad(segment, EVENT_SEGMENT_HEADER), 0xdeadbeef);
}

#[test]
fn configured_snapshots_freeze_arm_hit_and_after_bytes_and_restore_mtf() {
    for original_mtf in [0, 1 << 27] {
        let mut scenario = Scenario::new();
        scenario.session.configuration.get_mut().debug_count = 0;
        let mut observation = observer(&mut scenario);
        let mut setup = vec![0; HEADER_BYTES + 32];
        setup[24..32].copy_from_slice(&1u64.to_le_bytes());
        setup[32..36].copy_from_slice(&1u32.to_le_bytes());
        setup[44..48].copy_from_slice(&1u32.to_le_bytes());
        setup[56..64]
            .copy_from_slice(&u64::from(EVENT_SNAPSHOT_ARM | EVENT_SNAPSHOT_AFTER).to_le_bytes());
        setup[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&0x600000u64.to_le_bytes());
        setup[HEADER_BYTES + 8..HEADER_BYTES + 16].copy_from_slice(&8u64.to_le_bytes());
        setup[HEADER_BYTES + 16..HEADER_BYTES + 24].copy_from_slice(&0x401000u64.to_le_bytes());
        setup[HEADER_BYTES + 24..].copy_from_slice(&EVENT_INSTRUCTION.to_le_bytes());
        observation.events.config = EventConfig::parse(&setup, false).unwrap();
        observation.events.reset();
        hardware::STATE
            .with(|state| state.borrow_mut().instruction = Some(([0x90; 15], [0x90; 15])));
        for (address, value) in [(0x3000, 0x10007), (0x10000, 0x87), (0x600000, 1)] {
            hardware::original_value(address, 8, Some(value));
        }
        for (field, value) in [
            (GUEST_RIP, 0x401000),
            (GUEST_RSP, 0x700000),
            (GUEST_CS_SELECTOR, 3),
            (VM_EXIT_INTR_INFO, 0x80000301),
            (CPU_BASED_VM_EXEC_CONTROL, original_mtf),
        ] {
            hardware::write(field, value).unwrap();
        }
        assert_eq!(scenario.call(1), 0);
        hardware::original_value(0x600000, 8, Some(2));
        assert_eq!(scenario.exit(0, 1), 1);
        assert_eq!(scenario.boot.interception.snapshot_pending[4], 2);
        assert_eq!(scenario.call(1), 0);
        assert_ne!(
            hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27),
            0
        );
        hardware::write(GUEST_RIP, 0x401001).unwrap();
        hardware::original_value(0x600000, 8, Some(3));
        assert_eq!(scenario.exit(37, 0), u64::from(original_mtf == 0));
        assert_eq!(scenario.boot.interception.snapshot_pending, [0; 6]);
        assert_eq!(
            hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27),
            original_mtf
        );
        hardware::original_value(0x600000, 8, Some(99));
        for (index, (kind, value)) in [EVENT_ARM, EVENT_INSTRUCTION, EVENT_AFTER]
            .into_iter()
            .zip([1, 2, 3])
            .enumerate()
        {
            let mut packet = query(EVENT_FETCH, 1, index as u64);
            observation.events.fetch(&mut packet).unwrap();
            assert_eq!(word(&packet, 32), 1);
            assert_eq!(quad(&packet, 48), 1);
            let record = &packet[HEADER_BYTES..];
            assert_eq!(quad(record, CONTEXT_RECORD_BYTES), kind);
            let region = EVENT_RECORD_HEADER
                + 3 * EVENT_SEGMENT_HEADER
                + EVENT_CODE_BYTES
                + EVENT_STACK_BYTES;
            assert_eq!(quad(record, region), value);
            if kind == EVENT_AFTER {
                assert_eq!(quad(record, CONTEXT_RECORD_BYTES + 32), 2);
            }
        }
    }
}

#[test]
fn a_reused_process_identity_revokes_capture_before_reading_event_data() {
    let mut scenario = Scenario::new();
    scenario.session.configuration.get_mut().debug_count = 0;
    let mut observation = observer(&mut scenario);
    let mut setup = vec![0; HEADER_BYTES + 16 + EVENT_GUARD_BYTES];
    setup[44..48].copy_from_slice(&1u32.to_le_bytes());
    setup[148..152].copy_from_slice(&1u32.to_le_bytes());
    setup[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&0x401000u64.to_le_bytes());
    setup[HEADER_BYTES + 8..HEADER_BYTES + 16].copy_from_slice(&EVENT_INSTRUCTION.to_le_bytes());
    for (slot, value) in
        setup[HEADER_BYTES + 16..]
            .chunks_exact_mut(8)
            .zip([0x3000u64, 0x500000, 12345, u64::MAX])
    {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    observation.events.config = EventConfig::parse(&setup, false).unwrap();
    for (address, value) in [(0x3000, 0x10007), (0x10000, 0x87), (0x500000, 12345)] {
        hardware::original_value(address, 8, Some(value));
    }
    hardware::write(GUEST_RIP, 0x401000).unwrap();
    hardware::write(GUEST_CS_SELECTOR, 3).unwrap();
    hardware::write(VM_EXIT_INTR_INFO, 0x80000301).unwrap();
    scenario.call(1);
    hardware::original_value(0x500000, 8, Some(67890));
    assert_eq!(scenario.exit(0, 1), 1);
    assert!(!scenario.session.is_active());
    assert_eq!(hardware::read(GUEST_RIP), Ok(0x401000));
    assert_eq!(hardware::read(GUEST_DR7), Ok(0x400));
    let mut packet = query(EVENT_FETCH, 1, 0);
    observation.events.fetch(&mut packet).unwrap();
    assert_eq!(word(&packet, 32), 0);
}

#[test]
fn exact_probe_refuses_to_run_without_owning_a_debug_slot() {
    let mut scenario = Scenario::new();
    scenario.session.configuration.get_mut().debug_count = 0;
    let mut observation = observer(&mut scenario);
    let mut setup = vec![0; HEADER_BYTES + 16];
    setup[44..48].copy_from_slice(&1u32.to_le_bytes());
    setup[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&0x401000u64.to_le_bytes());
    setup[HEADER_BYTES + 8..].copy_from_slice(&EVENT_INSTRUCTION.to_le_bytes());
    observation.events.config = EventConfig::parse(&setup, false).unwrap();
    hardware::write(GUEST_DR7, 0x4ff).unwrap();
    let registers = hardware::debug_registers();
    assert_eq!(scenario.call(1), 0);
    assert!(!scenario.session.is_active());
    assert_eq!(
        scenario.session.cause.load(Ordering::Acquire),
        u64::from(INTERCEPT_CAUSE_DEBUG_CAPACITY)
    );
    assert_eq!(hardware::debug_registers(), registers);
    assert_eq!(hardware::read(GUEST_DR7), Ok(0x4ff));
}

#[test]
fn retired_snapshot_mtf_ownership_survives_a_queued_exit() {
    let mut scenario = Scenario::new();
    scenario.session.configuration.get_mut().debug_count = 0;
    let mut observation = observer(&mut scenario);
    let mut setup = vec![0; HEADER_BYTES + 16];
    setup[44..48].copy_from_slice(&1u32.to_le_bytes());
    setup[56..64].copy_from_slice(&u64::from(EVENT_SNAPSHOT_AFTER).to_le_bytes());
    setup[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&0x401000u64.to_le_bytes());
    setup[HEADER_BYTES + 8..].copy_from_slice(&EVENT_INSTRUCTION.to_le_bytes());
    observation.events.config = EventConfig::parse(&setup, false).unwrap();
    for (field, value) in [
        (GUEST_RIP, 0x401000),
        (GUEST_CS_SELECTOR, 3),
        (VM_EXIT_INTR_INFO, 0x80000301),
    ] {
        hardware::write(field, value).unwrap();
    }
    scenario.call(1);
    assert_eq!(scenario.exit(0, 1), 1);
    scenario.call(1);
    scenario.boot.last_reason = 37;
    scenario.boot.last_qualification = 0;
    assert_eq!(scenario.call(4), 0);
    assert_eq!(scenario.boot.interception.snapshot_exit_owned, 1);
    scenario
        .session
        .active
        .store(u64::from(INTERCEPT_REVOKED), Ordering::Release);
    assert_eq!(scenario.call(1), 0);
    assert_eq!(scenario.boot.interception.snapshot_pending, [0; 6]);
    assert_eq!(scenario.call(0), 1);
    assert_eq!(scenario.boot.interception.snapshot_exit_owned, 0);
    assert_eq!(
        hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27),
        0
    );
}

#[test]
fn after_snapshots_do_not_confirm_an_unobserved_privilege_transition() {
    for (initial_cpl, next_cpl) in [(3, 0), (3, 3), (0, 0), (0, 3)] {
        let mut scenario = Scenario::new();
        scenario.session.configuration.get_mut().debug_count = 0;
        let mut observation = observer(&mut scenario);
        let mut setup = vec![0; HEADER_BYTES + 16];
        setup[44..48].copy_from_slice(&1u32.to_le_bytes());
        setup[56..64].copy_from_slice(&u64::from(EVENT_SNAPSHOT_AFTER).to_le_bytes());
        setup[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&0x401000u64.to_le_bytes());
        setup[HEADER_BYTES + 8..].copy_from_slice(&EVENT_INSTRUCTION.to_le_bytes());
        observation.events.config = EventConfig::parse(&setup, false).unwrap();
        for (field, value) in [
            (GUEST_RIP, 0x401000),
            (GUEST_CS_SELECTOR, initial_cpl),
            (VM_EXIT_INTR_INFO, 0x80000301),
        ] {
            hardware::write(field, value).unwrap();
        }
        scenario.call(1);
        assert_eq!(scenario.exit(0, 1), 1);
        scenario.call(1);
        hardware::write(GUEST_CS_SELECTOR, next_cpl).unwrap();
        hardware::write(
            GUEST_RIP,
            if next_cpl == 0 {
                0xfffff80000001000
            } else {
                0x401001
            },
        )
        .unwrap();
        assert_eq!(scenario.exit(37, 0), 1);
        let mut packet = query(EVENT_FETCH, 1, 1);
        observation.events.fetch(&mut packet).unwrap();
        assert_eq!(word(&packet, 32), 1);
        let after = &packet[HEADER_BYTES..];
        assert_eq!(quad(after, CONTEXT_RECORD_BYTES), EVENT_AFTER);
        assert_eq!(
            quad(after, CONTEXT_RECORD_BYTES + 96),
            if next_cpl != initial_cpl {
                Error::Unsupported as u64
            } else {
                0
            }
        );
        assert_eq!(scenario.boot.interception.snapshot_pending, [0; 6]);
        assert_eq!(
            hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27),
            0
        );
    }
}

#[test]
fn after_snapshots_handle_emulated_retirement_guest_debug_traps_and_faults() {
    for outcome in [10, 1, 14] {
        let mut scenario = Scenario::new();
        scenario.session.configuration.get_mut().debug_count = 0;
        let mut observation = observer(&mut scenario);
        let mut setup = vec![0; HEADER_BYTES + 16];
        setup[44..48].copy_from_slice(&1u32.to_le_bytes());
        setup[56..64].copy_from_slice(&u64::from(EVENT_SNAPSHOT_AFTER).to_le_bytes());
        setup[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&0x401000u64.to_le_bytes());
        setup[HEADER_BYTES + 8..].copy_from_slice(&EVENT_INSTRUCTION.to_le_bytes());
        observation.events.config = EventConfig::parse(&setup, false).unwrap();
        for (field, value) in [
            (GUEST_RIP, 0x401000),
            (GUEST_CS_SELECTOR, 3),
            (VM_EXIT_INTR_INFO, 0x80000301),
        ] {
            hardware::write(field, value).unwrap();
        }
        scenario.call(1);
        assert_eq!(scenario.exit(0, 1), 1);
        scenario.call(1);
        if outcome == 10 {
            assert_eq!(scenario.exit(10, 0), 0);
            hardware::write(GUEST_RIP, 0x401002).unwrap();
            assert_eq!(scenario.call(1), 0);
        } else {
            hardware::write(VM_EXIT_INTR_INFO, 0x80000300 | outcome).unwrap();
            if outcome == 1 {
                hardware::write(GUEST_RIP, 0x401002).unwrap();
            }
            assert_eq!(scenario.exit(0, if outcome == 1 { 1 << 14 } else { 0 }), 0);
            if outcome == 1 {
                assert_ne!(hardware::debug_registers()[4] & (1 << 14), 0);
            }
        }
        assert_eq!(scenario.boot.interception.snapshot_pending, [0; 6]);
        assert_eq!(
            hardware::read(CPU_BASED_VM_EXEC_CONTROL).unwrap() & (1 << 27),
            0
        );
        let mut packet = query(EVENT_FETCH, 1, 1);
        observation.events.fetch(&mut packet).unwrap();
        assert_eq!(word(&packet, 32), 1);
        let after = &packet[HEADER_BYTES..];
        assert_eq!(quad(after, CONTEXT_RECORD_BYTES), EVENT_AFTER);
        assert_eq!(
            quad(after, CONTEXT_RECORD_BYTES + 96),
            if outcome == 14 {
                Error::Unsupported as u64
            } else {
                0
            }
        );
    }
}

#[test]
fn argument_capture_freezes_registers_stack_values_and_bounded_pointer_chains() {
    let mut scenario = Scenario::new();
    scenario.session.configuration.get_mut().debug_count = 0;
    let mut observation = observer(&mut scenario);
    let mut setup = vec![0; HEADER_BYTES + 5 * 16];
    setup[32..36].copy_from_slice(&4u32.to_le_bytes());
    setup[44..48].copy_from_slice(&1u32.to_le_bytes());
    setup[144..148].copy_from_slice(&64u32.to_le_bytes());
    setup[152..156].copy_from_slice(&0x48u32.to_le_bytes());
    for (descriptor, (address, size)) in setup[HEADER_BYTES..].chunks_exact_mut(16).zip([
        (ARGUMENT_REGISTER | 2, 8 | (2u64 << 32)),
        (ARGUMENT_STACK | 0x28, 0),
        (ARGUMENT_REGISTER | 1, 16 | (1u64 << 32)),
        (ARGUMENT_REGISTER | 9, 8 | (2u64 << 32)),
        (0x401000, EVENT_INSTRUCTION),
    ]) {
        descriptor[..8].copy_from_slice(&address.to_le_bytes());
        descriptor[8..].copy_from_slice(&size.to_le_bytes());
    }
    observation.events.config = EventConfig::parse(&setup, false).unwrap();
    for (address, value) in [
        (0x3000, 0x10007),
        (0x10000, 0x87),
        (0x600000, 0x600100),
        (0x600100, 0x1122334455667788),
        (0x700028, 42),
        (0x3ffffff8, 0x12345678),
        (0x500048, 31337),
    ] {
        hardware::original_value(address, 8, Some(value));
    }
    hardware::STATE.with(|state| state.borrow_mut().instruction = Some(([0x90; 15], [0x90; 15])));
    for (field, value) in [
        (GUEST_RIP, 0x401000),
        (GUEST_RSP, 0x700000),
        (GUEST_CS_SELECTOR, 3),
        (GUEST_GS_BASE, 0x500000),
        (VM_EXIT_INTR_INFO, 0x80000301),
    ] {
        hardware::write(field, value).unwrap();
    }
    scenario.frame[1] = 0x3ffffff8;
    scenario.frame[2] = 0x600000;
    scenario.frame[8] = 0x40000000;
    scenario.call(1);
    assert_eq!(scenario.exit(0, 1), 1);
    hardware::original_value(0x600100, 8, Some(0));
    hardware::original_value(0x700028, 8, Some(99));
    let mut packet = query(EVENT_FETCH, 1, 0);
    observation.events.fetch(&mut packet).unwrap();
    assert_eq!(word(&packet, 32), 1);
    let event = &packet[HEADER_BYTES..];
    assert_eq!(quad(event, CONTEXT_RECORD_BYTES + 128), 31337);
    assert_eq!(quad(event, CONTEXT_RECORD_BYTES + 136), 0);
    let stack = &event[EVENT_RECORD_HEADER + EVENT_SEGMENT_HEADER + EVENT_CODE_BYTES..];
    assert_eq!(u16::from_le_bytes(stack[8..10].try_into().unwrap()), 64);
    let arguments = &stack[EVENT_SEGMENT_HEADER + EVENT_STACK_BYTES..];
    let stride = EVENT_SEGMENT_HEADER + EVENT_REGION_BYTES;
    let first = &arguments[..stride];
    assert_eq!(quad(first, 0), 0x600100);
    assert_eq!(quad(first, 24), 0x600000);
    assert_eq!(quad(first, 48), 2);
    assert_eq!(quad(first, EVENT_SEGMENT_HEADER), 0x1122334455667788);
    let scalar = &arguments[stride..2 * stride];
    assert_eq!(quad(scalar, 16), 0x700028);
    assert_eq!(quad(scalar, 24), 42);
    assert_eq!(word(scalar, 12), 0);
    let partial = &arguments[2 * stride..3 * stride];
    assert_eq!(u16::from_le_bytes(partial[10..12].try_into().unwrap()), 8);
    assert_eq!(word(partial, 12), Error::Unmapped as u32);
    let invalid = &arguments[3 * stride..4 * stride];
    assert_eq!(u16::from_le_bytes(invalid[10..12].try_into().unwrap()), 0);
    assert_eq!(word(invalid, 12), Error::Unmapped as u32);
}

#[test]
fn single_capture_limits_span_cpus_and_busy_records_are_never_observable() {
    let mut scenario = Scenario::new();
    let mut observation = observer(&mut scenario);
    observation.events.config.max_events = 1;
    observation.events.reset();
    let mut empty = query(EVENT_FETCH, 1, 0);
    observation.events.fetch(&mut empty).unwrap();
    assert_eq!(word(&empty, 32), 0);
    observation.events.emit(
        ContextRecord::default(),
        memory::observation::Event::default(),
        |_| {
            let mut busy = query(EVENT_FETCH, 1, 0);
            assert_eq!(observation.events.fetch(&mut busy), Err(Error::Busy));
            observation.events.emit(
                ContextRecord {
                    cpu: 1,
                    ..Default::default()
                },
                memory::observation::Event::default(),
                |_| panic!("capture exceeded its global event limit"),
            );
        },
    );
    assert!(!observation.events.accepting());
    let mut published = query(EVENT_FETCH, 1, 0);
    observation.events.fetch(&mut published).unwrap();
    assert_eq!(word(&published, 32), 1);
    assert_eq!(quad(&published, 48), 1);
    assert_eq!(quad(&published, 56), EVENT_FORMAT_VERSION);
}

#[test]
fn simultaneous_cpus_publish_only_one_complete_single_capture_record() {
    let mut scenario = Scenario::new();
    let mut observation = observer(&mut scenario);
    observation.events.config.max_events = 1;
    observation.events.reset();
    let pointer = &*observation as *const Observation as usize;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|cpu| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                // Configuration stays immutable until every worker has joined.
                let observation = unsafe { &*(pointer as *const Observation) };
                observation.events.emit(
                    ContextRecord {
                        cpu,
                        tsc: cpu + 1,
                        ..Default::default()
                    },
                    memory::observation::Event {
                        kind: EVENT_INSTRUCTION,
                        ..Default::default()
                    },
                    |bytes| {
                        bytes.fill((cpu + 1) as u8);
                        std::thread::yield_now();
                    },
                );
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let mut total = 0;
    for cpu in 0..8 {
        let mut packet = query(EVENT_FETCH, 1, 0);
        packet[24..32].copy_from_slice(&(cpu as u64).to_le_bytes());
        observation.events.fetch(&mut packet).unwrap();
        total += word(&packet, 32);
        if word(&packet, 32) != 0 {
            let record = &packet[HEADER_BYTES..];
            assert!(
                record[EVENT_RECORD_HEADER..]
                    .iter()
                    .all(|byte| *byte == (cpu + 1) as u8)
            );
            assert_eq!(quad(record, 192), cpu as u64);
            assert_eq!(quad(record, 0), 1);
        }
    }
    assert_eq!(total, 1);
}

#[test]
fn instruction_probes_capture_call_destinations_before_execution_and_keep_the_guest_frame() {
    let rip = 0x401000u64;
    for (code, rax, rcx, rdx, kind, target, source, status) in [
        (
            vec![0xe8, 0xfb, 0x0f, 0, 0],
            0,
            0,
            0,
            CALL_DIRECT,
            0x402000,
            0,
            0,
        ),
        (
            vec![0xe8, 0xfb, 0xef, 0xff, 0xff],
            0,
            0,
            0,
            CALL_DIRECT,
            0x400000,
            0,
            0,
        ),
        (
            vec![0xff, 0xd0],
            0x403000,
            0,
            0,
            CALL_REGISTER,
            0x403000,
            0,
            0,
        ),
        (
            vec![0xff, 0x51, 8],
            0,
            0x600000,
            0,
            CALL_MEMORY,
            0x404000,
            0x600008,
            0,
        ),
        (
            vec![0xff, 0x54, 0xd1, 0x18],
            0,
            0x600000,
            2,
            CALL_MEMORY,
            0x405000,
            0x600028,
            0,
        ),
        (
            vec![0xff, 0x15, 10, 0, 0, 0],
            0,
            0,
            0,
            CALL_MEMORY,
            0x406000,
            rip + 16,
            0,
        ),
        (
            vec![0xff, 0x11],
            0,
            0x40000000,
            0,
            CALL_MEMORY,
            0,
            0x40000000,
            Error::Unmapped as u64,
        ),
        (
            vec![0xff, 0x11],
            0,
            0x600010,
            0,
            CALL_MEMORY,
            0,
            0x600010,
            0,
        ),
    ] {
        let mut scenario = Scenario::new();
        scenario.session.configuration.get_mut().debug_count = 0;
        let mut observation = observer(&mut scenario);
        let mut setup = vec![0; HEADER_BYTES + 16];
        setup[44..48].copy_from_slice(&1u32.to_le_bytes());
        setup[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&rip.to_le_bytes());
        setup[HEADER_BYTES + 8..].copy_from_slice(&EVENT_INSTRUCTION.to_le_bytes());
        observation.events.config = EventConfig::parse(&setup, false).unwrap();
        let mut instruction = [0x90; 15];
        instruction[..code.len()].copy_from_slice(&code);
        hardware::STATE
            .with(|state| state.borrow_mut().instruction = Some((instruction, instruction)));
        for (address, value) in [
            (0x3000, 0x10007),
            (0x10000, 0x87),
            (0x600008, 0x404000),
            (0x600010, 0),
            (0x600028, 0x405000),
            (rip + 16, 0x406000),
        ] {
            hardware::original_value(address, 8, Some(value));
        }
        for (offset, byte) in instruction.iter().enumerate() {
            hardware::page_byte(rip + offset as u64, Some(*byte));
        }
        for (field, value) in [
            (GUEST_RIP, rip),
            (GUEST_RSP, 0x700080),
            (GUEST_CS_SELECTOR, 3),
            (GUEST_RFLAGS, 0x302),
            (VM_EXIT_INTR_INFO, 0x80000301),
        ] {
            hardware::write(field, value).unwrap();
        }
        scenario.frame[0] = rax;
        scenario.frame[1] = rcx;
        scenario.frame[2] = rdx;
        let frame = scenario.frame;
        assert_eq!(scenario.call(1), 0);
        assert_eq!(scenario.exit(0, 1), 1);
        assert_eq!(scenario.frame, frame);
        assert_eq!(hardware::read(GUEST_RIP), Ok(rip));
        assert_eq!(hardware::read(GUEST_RSP), Ok(0x700080));
        assert_eq!(hardware::read(GUEST_RFLAGS), Ok(0x10302));
        hardware::page_byte(rip, Some(0xcc));
        hardware::original_value(source, 8, Some(0xdeadbeef));
        let mut packet = query(EVENT_FETCH, 1, 0);
        observation.events.fetch(&mut packet).unwrap();
        assert_eq!(word(&packet, 32), 1, "code={code:x?}");
        let record = &packet[HEADER_BYTES..];
        assert_eq!(quad(record, 24), rip);
        assert_eq!(quad(record, 48), 0x302);
        let metadata = &record[CONTEXT_RECORD_BYTES..];
        assert_eq!(quad(metadata, 0), EVENT_INSTRUCTION);
        assert_eq!(quad(metadata, 56), EVENT_FORMAT_VERSION);
        assert_eq!(quad(metadata, 64), code.len() as u64);
        assert_eq!(quad(metadata, 72), kind);
        assert_eq!(quad(metadata, 80), target, "code={code:x?}");
        assert_eq!(quad(metadata, 88), source);
        assert_eq!(quad(metadata, 96), status);
        assert_eq!(
            &record[EVENT_RECORD_HEADER + EVENT_SEGMENT_HEADER..][..code.len()],
            code.as_slice()
        );
    }
}

#[test]
fn exact_instruction_probes_are_scoped_to_the_configured_address_space() {
    let mut scenario = Scenario::new();
    let mut observation = observer(&mut scenario);
    let mut setup = vec![0; HEADER_BYTES + 16];
    setup[44..48].copy_from_slice(&1u32.to_le_bytes());
    setup[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&0x401000u64.to_le_bytes());
    setup[HEADER_BYTES + 8..].copy_from_slice(&EVENT_INSTRUCTION.to_le_bytes());
    observation.events.config = EventConfig::parse(&setup, false).unwrap();
    hardware::write(GUEST_CR3, 0x5000).unwrap();
    hardware::write(GUEST_CS_SELECTOR, 3).unwrap();
    let debug = hardware::debug_registers();
    assert_eq!(scenario.call(1), 0);
    assert_eq!(hardware::debug_registers(), debug);
    let mut packet = query(EVENT_FETCH, 1, 0);
    observation.events.fetch(&mut packet).unwrap();
    assert_eq!(word(&packet, 32), 0);
    assert_eq!(quad(&packet, 104), 0);
}

#[test]
fn observation_filters_reject_hot_loop_hits_before_ring_sequences_advance() {
    let mut scenario = Scenario::new();
    let mut observation = observer(&mut scenario);
    observation.watch_count = 1;
    observation.watch[0] = WatchTarget {
        address: 0x2000,
        control: 1,
    };
    observation.context_enabled = true;
    let mut filter = vec![0; HEADER_BYTES + 2 * OBSERVATION_FILTER_BYTES];
    filter[12..16].copy_from_slice(&WATCH_FILTER_SET.to_le_bytes());
    filter[24..32].copy_from_slice(&0x3000_u64.to_le_bytes());
    filter[32..36].copy_from_slice(&2_u32.to_le_bytes());
    for (index, values) in [[0x1000_u64, 0x2000, 0], [0x1100, 0x1200, 1]]
        .iter()
        .enumerate()
    {
        for (slot, value) in values.iter().enumerate() {
            let offset = HEADER_BYTES + index * OBSERVATION_FILTER_BYTES + slot * 8;
            filter[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    observation.set_filter(&filter, false).unwrap();
    let accepted = ContextRecord {
        rip: 0x1000,
        thread_teb: 0x3000,
        ..Default::default()
    };
    observation.capture(accepted, Some(0));
    for _ in 0..256 {
        observation.capture(
            ContextRecord {
                rip: 0x1150,
                ..accepted
            },
            Some(0),
        );
        observation.capture(
            ContextRecord {
                thread_teb: 0x4000,
                ..accepted
            },
            Some(0),
        );
        observation.capture(
            ContextRecord {
                rip: 0x2000,
                ..accepted
            },
            Some(0),
        );
    }
    let mut fetch = vec![0; HEADER_BYTES + WATCH_RECORD_BYTES * WATCH_RING_RECORDS];
    fetch[12..16].copy_from_slice(&WATCH_FETCH.to_le_bytes());
    fetch[32..36].copy_from_slice(&(WATCH_RING_RECORDS as u32).to_le_bytes());
    observation.fetch(&mut fetch).unwrap();
    assert_eq!(word(&fetch, 32), 1);
    assert_eq!(quad(&fetch, HEADER_BYTES), 1);
    assert_eq!(quad(&fetch, HEADER_BYTES + 24), 0x1000);
    observation.capture(
        ContextRecord {
            rip: 0x1150,
            ..accepted
        },
        None,
    );
    let mut snapshot = vec![0; HEADER_BYTES + CONTEXT_RECORD_BYTES];
    snapshot[12..16].copy_from_slice(&CONTEXT_SNAPSHOT.to_le_bytes());
    snapshot[32..36].copy_from_slice(&1_u32.to_le_bytes());
    observation.fetch(&mut snapshot).unwrap();
    assert_eq!(word(&snapshot, 32), 1);
    assert_eq!(quad(&snapshot, HEADER_BYTES + 24), 0x1150);
    filter[12..16].copy_from_slice(&CONTEXT_FILTER_SET.to_le_bytes());
    observation.set_filter(&filter, false).unwrap();
    observation.capture(
        ContextRecord {
            rip: 0x1150,
            ..accepted
        },
        None,
    );
    let mut cached = vec![0; HEADER_BYTES + CONTEXT_RECORD_BYTES];
    cached[32..36].copy_from_slice(&1_u32.to_le_bytes());
    cached[64..72].copy_from_slice(&1_u64.to_le_bytes());
    observation.get_context(&mut cached).unwrap();
    assert_eq!(quad(&cached, HEADER_BYTES + 24), 0x1150);
    observation.reset_filters();
    observation.capture(
        ContextRecord {
            rip: 0x1150,
            ..accepted
        },
        Some(0),
    );
    fetch[32..36].copy_from_slice(&(WATCH_RING_RECORDS as u32).to_le_bytes());
    observation.fetch(&mut fetch).unwrap();
    assert_eq!(word(&fetch, 32), 2);
}

#[test]
fn invalid_filter_updates_preserve_the_previous_filter_and_cached_context() {
    let mut scenario = Scenario::new();
    let mut observation = observer(&mut scenario);
    observation.context_enabled = true;
    let mut filter = vec![0; HEADER_BYTES];
    filter[12..16].copy_from_slice(&CONTEXT_FILTER_SET.to_le_bytes());
    filter[24..32].copy_from_slice(&0x3000_u64.to_le_bytes());
    observation.set_filter(&filter, false).unwrap();
    filter[24..32].copy_from_slice(&0x8000_0000_0000_u64.to_le_bytes());
    assert_eq!(observation.set_filter(&filter, false), Err(Error::Bounds));
    observation.capture(
        ContextRecord {
            rip: 0x1000,
            thread_teb: 0x3000,
            ..Default::default()
        },
        None,
    );
    observation.capture(
        ContextRecord {
            rip: 0x2000,
            thread_teb: 0x4000,
            ..Default::default()
        },
        None,
    );
    let mut cached = vec![0; HEADER_BYTES + CONTEXT_RECORD_BYTES];
    cached[32..36].copy_from_slice(&1_u32.to_le_bytes());
    cached[64..72].copy_from_slice(&1_u64.to_le_bytes());
    observation.get_context(&mut cached).unwrap();
    assert_eq!(quad(&cached, HEADER_BYTES + 64), 0x3000);
    cached[64..72].copy_from_slice(&2_u64.to_le_bytes());
    assert_eq!(observation.get_context(&mut cached), Err(Error::Session));
}
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
        EVENT_FETCH => EVENT_RECORD_BYTES,
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
fn ept_debug_watch_and_syscall_profiles_preserve_the_remaining_guest_debug_slot() {
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
        [0x400000, 0xffff800000400000, 0x600008, 44]
    );
    assert_eq!(hardware::read(GUEST_DR7).unwrap() & 0xff, 0x2a);
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

#[test]
fn event_snapshots_freeze_stack_code_and_selected_bytes_and_report_overwrites() {
    let mut scenario = Scenario::new();
    let mut observer = observer(&mut scenario);
    observer.events.reset();
    let mut setup = vec![0; HEADER_BYTES + 16];
    setup[32..36].copy_from_slice(&1u32.to_le_bytes());
    setup[48..56].copy_from_slice(&(1u64 << 14).to_le_bytes());
    setup[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&0x500000u64.to_le_bytes());
    setup[HEADER_BYTES + 8..].copy_from_slice(&8u64.to_le_bytes());
    observer.events.config = EventConfig::parse(&setup, false).unwrap();
    for (address, value) in [
        (0x3000, 0x10007),
        (0x10000, 0x87),
        (0x700010, 0x12345678),
        (0x500000, 0xfedcba98),
        (0x401000, 0xc3),
    ] {
        hardware::original_value(address, 8, Some(value));
    }
    for (field, value) in [
        (GUEST_RIP, 0x401000),
        (GUEST_RSP, 0x700010),
        (GUEST_CS_SELECTOR, 3),
        (VM_EXIT_INTR_INFO, 0x80000b0e),
        (VM_EXIT_INTR_ERROR_CODE, 5),
        (EXCEPTION_BITMAP, 1 << 6),
    ] {
        hardware::write(field, value).unwrap();
    }
    assert_eq!(scenario.call(1), 0);
    assert_eq!(
        hardware::read(EXCEPTION_BITMAP).unwrap() & (1 << 14 | 1 << 6),
        1 << 14 | 1 << 6
    );
    assert_eq!(scenario.exit(0, 0x800123), 0);
    hardware::original_value(0x700010, 8, Some(0));
    hardware::original_value(0x500000, 8, Some(0));
    hardware::original_value(0x401000, 8, Some(0));
    let mut packet = query(EVENT_FETCH, 1, 0);
    observer.events.fetch(&mut packet).unwrap();
    let event = &packet[HEADER_BYTES..];
    assert_eq!(quad(event, CONTEXT_RECORD_BYTES), EVENT_EXCEPTION);
    assert_eq!(quad(event, CONTEXT_RECORD_BYTES + 32), 5);
    assert_eq!(quad(event, CONTEXT_RECORD_BYTES + 48), 0x800123);
    let code = EVENT_RECORD_HEADER + EVENT_SEGMENT_HEADER;
    let stack = code + EVENT_CODE_BYTES + EVENT_SEGMENT_HEADER;
    let region = stack + EVENT_STACK_BYTES + EVENT_SEGMENT_HEADER;
    assert_eq!(quad(event, code), 0xc3);
    assert_eq!(quad(event, stack), 0x12345678);
    assert_eq!(quad(event, region), 0xfedcba98);
    for _ in 0..EVENT_RING_RECORDS {
        assert_eq!(scenario.exit(0, 0x800123), 0);
    }
    let mut peek = query(EVENT_FETCH, 0, 0);
    observer.events.fetch(&mut peek).unwrap();
    assert_eq!(quad(&peek, 96), 2);
    assert_eq!(quad(&peek, 104), EVENT_RING_RECORDS as u64 + 1);
    scenario.session.active.store(0, Ordering::Release);
    assert_eq!(scenario.call(1), 0);
    assert_eq!(hardware::read(EXCEPTION_BITMAP), Ok(1 << 6));
}

#[test]
fn probes_pair_recursion_migration_and_shared_returns_and_keep_handled_exceptions_open() {
    use memory::observation::Event;
    let mut scenario = Scenario::new();
    let mut observer = observer(&mut scenario);
    let mut setup = vec![0; HEADER_BYTES + 32];
    setup[44..48].copy_from_slice(&2u32.to_le_bytes());
    for (descriptor, (address, kind)) in setup[HEADER_BYTES..]
        .chunks_exact_mut(16)
        .zip([(0x401000u64, EVENT_ENTRY), (0x402000u64, EVENT_RETURN)])
    {
        descriptor[..8].copy_from_slice(&address.to_le_bytes());
        descriptor[8..].copy_from_slice(&kind.to_le_bytes());
    }
    observer.events.config = EventConfig::parse(&setup, false).unwrap();
    let context = ContextRecord {
        cpu: 0,
        cpl: 3,
        thread_teb: 0x500000,
        ..Default::default()
    };
    let mut events = Vec::new();
    let mut hit = |kind, rip, rsp, cpu, return_rip| {
        observer.events.correlate(
            ContextRecord {
                rip,
                rsp,
                cpu,
                ..context
            },
            Event {
                kind,
                address: rip,
                ..Event::default()
            },
            return_rip,
            0x800000,
            |event| events.push(event),
        );
    };
    hit(EVENT_ENTRY, 0x401000, 0x701000, 0, 0x402000);
    hit(EVENT_ENTRY, 0x401000, 0x700f00, 0, 0x402000);
    hit(EVENT_EXCEPTION, 0x401005, 0x700e00, 1, 0);
    hit(EVENT_CONTEXT, 0x402000, 0x700f08, 1, 0);
    hit(EVENT_RETURN, 0x402000, 0x700f08, 1, 0);
    hit(EVENT_ENTRY, 0x401000, 0x700f00, 1, 0x402000);
    hit(EVENT_RETURN, 0x402000, 0x701008, 0, 0);
    assert_eq!(
        events
            .iter()
            .map(|event| (event.kind, event.invocation, event.parent))
            .collect::<Vec<_>>(),
        [
            (EVENT_ENTRY, 1, 0),
            (EVENT_ENTRY, 2, 1),
            (EVENT_EXCEPTION, 2, 1),
            (EVENT_CONTEXT, 2, 1),
            (EVENT_RETURN, 2, 1),
            (EVENT_ENTRY, 3, 1),
            (EVENT_ABANDON, 3, 1),
            (EVENT_RETURN, 1, 0)
        ]
    );
}

#[test]
fn coincident_watch_and_redirect_capture_the_original_guest_frame() {
    let mut scenario = Scenario::new();
    let mut observation = observer(&mut scenario);
    observation.watch_count = 1;
    observation.watch[0] = WatchTarget {
        address: 0x600008,
        control: 9,
    };
    for (field, value) in [
        (GUEST_RIP, 0x400000),
        (GUEST_RFLAGS, 0x202),
        (VM_EXIT_INTR_INFO, 0x80000301),
    ] {
        hardware::write(field, value).unwrap();
    }
    assert_eq!(scenario.call(1), 0);
    assert_eq!(scenario.exit(0, 3), 1);
    assert_eq!(hardware::read(GUEST_RIP), Ok(0x400100));
    let mut packet = query(EVENT_FETCH, 1, 0);
    observation.events.fetch(&mut packet).unwrap();
    let event = &packet[HEADER_BYTES..];
    assert_eq!(quad(event, CONTEXT_RECORD_BYTES), EVENT_WATCH);
    assert_eq!(quad(event, 24), 0x400000);
    assert_eq!(quad(event, 48), 0x202);
}

#[test]
fn execution_probe_debug_exits_publish_a_paired_invocation() {
    let mut scenario = Scenario::new();
    scenario.session.configuration.get_mut().debug_count = 0;
    let mut observation = observer(&mut scenario);
    let entry = 0x401000u64;
    let continuation = 0x402000u64;
    let stack = 0x701000u64;
    let teb = 0x500000u64;
    let mut setup = vec![0; HEADER_BYTES + 32];
    setup[44..48].copy_from_slice(&2u32.to_le_bytes());
    for (descriptor, (address, kind)) in setup[HEADER_BYTES..]
        .chunks_exact_mut(16)
        .zip([(entry, EVENT_ENTRY), (continuation, EVENT_RETURN)])
    {
        descriptor[..8].copy_from_slice(&address.to_le_bytes());
        descriptor[8..].copy_from_slice(&kind.to_le_bytes());
    }
    observation.events.config = EventConfig::parse(&setup, false).unwrap();
    for (address, value) in [
        (0x3000, 0x10007),
        (0x10000, 0x87),
        (stack, continuation),
        (teb + 8, 0x702000),
    ] {
        hardware::original_value(address, 8, Some(value));
    }
    for (field, value) in [
        (GUEST_RIP, entry),
        (GUEST_RSP, stack),
        (GUEST_GS_BASE, teb),
        (GUEST_CS_SELECTOR, 3),
        (VM_EXIT_INTR_INFO, 0x80000301),
    ] {
        hardware::write(field, value).unwrap();
    }
    assert_eq!(scenario.call(1), 0);
    assert_eq!(hardware::debug_registers()[..2], [entry, continuation]);
    assert_eq!(scenario.exit(0, 1), 1);
    assert_eq!(hardware::read(GUEST_RIP), Ok(entry));

    hardware::write(GUEST_RIP, continuation).unwrap();
    hardware::write(GUEST_RSP, stack + 8).unwrap();
    assert_eq!(scenario.call(1), 0);
    assert_eq!(scenario.exit(0, 2), 1);
    assert_eq!(hardware::read(GUEST_RIP), Ok(continuation));
    for (index, kind) in [EVENT_ENTRY, EVENT_RETURN].into_iter().enumerate() {
        let mut packet = query(EVENT_FETCH, 1, index as u64);
        observation.events.fetch(&mut packet).unwrap();
        assert_eq!(word(&packet, 32), 1);
        assert_eq!(quad(&packet, HEADER_BYTES + CONTEXT_RECORD_BYTES), kind);
        assert_eq!(quad(&packet, HEADER_BYTES + CONTEXT_RECORD_BYTES + 8), 1);
    }
}
