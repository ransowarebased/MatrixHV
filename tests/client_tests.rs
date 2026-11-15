use matrixhv_sdk::memory::{Item, decode_transfers, info_packet, invoke, packet};
use matrixhv_sdk::protocol::memory::{
    HEADER_BYTES, ITEM_BYTES, READ, ROAD_STATUS_DEMAND_ZERO, WRITE,
};

#[test]
fn event_decoder_rejects_unpublished_records_wrong_versions_and_inconsistent_counts() {
    use matrixhv_sdk::memory::{InterceptionRequest, decode_event_batch, interception_packet};
    use matrixhv_sdk::protocol::memory::*;
    let mut packet = interception_packet(&InterceptionRequest {
        operation: EVENT_FETCH,
        token: 1,
        cpu: 3,
        count: 1,
        ..Default::default()
    })
    .unwrap();
    let put = |bytes: &mut [u8], offset: usize, value: u64| {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    };
    put(&mut packet, 56, EVENT_FORMAT_VERSION);
    packet[32..36].copy_from_slice(&0u32.to_le_bytes());
    assert!(decode_event_batch(&packet).unwrap().records.is_empty());
    packet[32..36].copy_from_slice(&1u32.to_le_bytes());
    assert!(decode_event_batch(&packet).is_err());
    put(&mut packet, HEADER_BYTES, 1);
    put(&mut packet, 104, 1);
    put(
        &mut packet,
        HEADER_BYTES + CONTEXT_RECORD_BYTES + 56,
        EVENT_FORMAT_VERSION,
    );
    assert_eq!(decode_event_batch(&packet).unwrap().records.len(), 1);
    put(&mut packet, HEADER_BYTES + CONTEXT_RECORD_BYTES + 56, 1);
    assert!(decode_event_batch(&packet).is_err());
    put(
        &mut packet,
        HEADER_BYTES + CONTEXT_RECORD_BYTES + 56,
        EVENT_FORMAT_VERSION,
    );
    packet[32..36].copy_from_slice(&2u32.to_le_bytes());
    assert!(decode_event_batch(&packet).is_err());
}

#[test]
fn capture_requests_bound_argument_work_and_preserve_process_guards_and_snapshot_phases() {
    use matrixhv_sdk::memory::{
        ArgumentCapture, IdentityGuard, InterceptionRequest, interception_packet,
    };
    use matrixhv_sdk::protocol::memory::*;
    let mut request = InterceptionRequest {
        operation: EVENT_SET,
        cr3: 0x3000,
        event_probes: vec![(0x401000, EVENT_INSTRUCTION)],
        event_arguments: vec![ArgumentCapture {
            location: 1,
            copy_bytes: 8,
            pointer_depth: 2,
            ..Default::default()
        }],
        event_identity: [42, 123456, 0xffff800000500000],
        event_guards: vec![IdentityGuard {
            cr3: 0x9000,
            address: 0xffff800000500010,
            expected: 123456,
            mask: u64::MAX,
        }],
        event_limit: 1,
        snapshot_arm: true,
        snapshot_after: true,
        ..Default::default()
    };
    let packet = interception_packet(&request).unwrap();
    assert_eq!(word(&packet, 148), 1);
    assert_eq!(quad(&packet, 96), 42);
    assert_eq!(quad(&packet, 104), 123456);
    assert_eq!(
        quad(&packet, 56),
        u64::from(EVENT_SNAPSHOT_ARM | EVENT_SNAPSHOT_AFTER)
    );
    assert_eq!(quad(&packet, HEADER_BYTES), ARGUMENT_REGISTER | 1);
    assert_eq!(quad(&packet, HEADER_BYTES + 8), 8 | (2 << 32));
    assert_eq!(quad(&packet, HEADER_BYTES + 32), 0x9000);
    request.event_arguments[0].pointer_depth = ARGUMENT_MAX_DEPTH + 1;
    assert!(interception_packet(&request).is_err());
    request.event_arguments[0].pointer_depth = 2;
    request.event_arguments[0].copy_bytes = EVENT_REGION_BYTES + 1;
    assert!(interception_packet(&request).is_err());
}

#[test]
fn malformed_packets_are_rejected_before_native_transport() {
    for length in [0, 40, HEADER_BYTES - 1, HEADER_BYTES, 65537] {
        assert!(
            invoke(&mut vec![0; length])
                .unwrap_err()
                .contains("invalid")
        );
    }
    let mut bytes = info_packet().unwrap();
    bytes[36..40].copy_from_slice(&0u32.to_le_bytes());
    assert!(invoke(&mut bytes).unwrap_err().contains("invalid"));
}

#[test]
fn expanded_regions_and_signed_argument_offsets_preserve_the_four_probe_limit() {
    use matrixhv_sdk::memory::{ArgumentCapture, InterceptionRequest, interception_packet};
    use matrixhv_sdk::protocol::memory::*;
    assert_eq!(EVENT_REGIONS, 12);
    let mut request = InterceptionRequest {
        operation: EVENT_SET,
        event_regions: (0..EVENT_REGIONS - 1)
            .map(|index| (0x600000 + index as u64 * 4096, 4096))
            .collect(),
        cr3: 0x3000,
        event_arguments: vec![ArgumentCapture {
            location: 2,
            copy_bytes: 512,
            pointer_depth: 2,
            pointer_offset: 8,
            ..Default::default()
        }],
        event_probes: (0..4)
            .map(|index| (0x401000 + index * 16, EVENT_INSTRUCTION))
            .collect(),
        ..Default::default()
    };
    let argument = HEADER_BYTES + (EVENT_REGIONS - 1) * 16;
    let packet = interception_packet(&request).unwrap();
    assert_eq!(word(&packet, 32) as usize, EVENT_REGIONS);
    assert_eq!(word(&packet, 44), 4);
    assert_eq!(quad(&packet, argument + 8), 512 | (2 << 32) | (8 << 48));
    request.event_arguments[0].pointer_offset = -8;
    let packet = interception_packet(&request).unwrap();
    assert_eq!((quad(&packet, argument + 8) >> 48) as u16 as i16, -8);
    request.event_probes.push((0x402000, EVENT_INSTRUCTION));
    assert!(interception_packet(&request).is_err());
    request.event_probes.pop();
    request.event_regions.push((0x700000, 8));
    assert!(interception_packet(&request).is_err());
    request.event_regions.pop();
    request.event_arguments[0].pointer_depth = 0;
    request.event_arguments[0].copy_bytes = 0;
    assert!(interception_packet(&request).is_err());
}

#[test]
fn transfer_responses_preserve_partial_results_and_demand_zero() {
    let items = [Item {
        address: 0x1000,
        bytes: vec![0; 4],
    }];
    let mut bytes = packet(READ, 10, 0x2000, &items).unwrap();
    bytes[HEADER_BYTES + 16..HEADER_BYTES + 20]
        .copy_from_slice(&ROAD_STATUS_DEMAND_ZERO.to_le_bytes());
    bytes[HEADER_BYTES + 20..HEADER_BYTES + 24].copy_from_slice(&4u32.to_le_bytes());
    let results = decode_transfers(&bytes).unwrap();
    assert!(results[0].is_complete());
    assert_eq!(results[0].bytes, vec![0; 4]);
    bytes[HEADER_BYTES + 20..HEADER_BYTES + 24].copy_from_slice(&2u32.to_le_bytes());
    let results = decode_transfers(&bytes).unwrap();
    assert!(!results[0].is_complete());
    assert_eq!(results[0].transferred, 2);
    assert_eq!(results[0].bytes, vec![0; 2]);
}

#[test]
fn response_decoder_rejects_truncated_tables_and_invalid_payloads() {
    let mut bytes = packet(
        READ,
        10,
        0x2000,
        &[Item {
            address: 0x1000,
            bytes: vec![0; 4],
        }],
    )
    .unwrap();
    assert!(decode_transfers(&bytes[..HEADER_BYTES - 1]).is_err());
    bytes[HEADER_BYTES + 8..HEADER_BYTES + 12].copy_from_slice(&0u32.to_le_bytes());
    assert!(decode_transfers(&bytes).is_err());
    bytes[HEADER_BYTES + 8..HEADER_BYTES + 12]
        .copy_from_slice(&((HEADER_BYTES + ITEM_BYTES) as u32).to_le_bytes());
    bytes[HEADER_BYTES + 20..HEADER_BYTES + 24].copy_from_slice(&5u32.to_le_bytes());
    assert!(decode_transfers(&bytes).is_err());
    bytes[32..36].copy_from_slice(&128u32.to_le_bytes());
    assert!(decode_transfers(&bytes).is_err());
}

#[test]
fn write_responses_return_transfer_metadata_without_echoing_the_payload() {
    let mut bytes = packet(
        WRITE,
        10,
        0x2000,
        &[Item {
            address: 0x1000,
            bytes: vec![1, 2],
        }],
    )
    .unwrap();
    bytes[HEADER_BYTES + 20..HEADER_BYTES + 24].copy_from_slice(&2u32.to_le_bytes());
    let results = decode_transfers(&bytes).unwrap();
    assert!(results[0].is_complete());
    assert!(results[0].bytes.is_empty());
}
