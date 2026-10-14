use neo::memory::{
    InterceptionRequest, Item, decode_transfers, info_packet, interception_packet, invoke, packet,
    start_tracking_packet,
};
use neo::protocol::memory::{
    AD_START, HEADER_BYTES, HOOK_INSTALL, INFO_BYTES, INTERCEPT_NO_LEASE, ITEM_BYTES, READ,
    ROAD_STATUS_DEMAND_ZERO, WRITE, quad, word,
};

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

#[test]
fn typed_requests_encode_protocol_fields_without_cli_arguments() {
    let info = info_packet().unwrap();
    assert_eq!(info.len(), INFO_BYTES);
    assert_eq!(word(&info, 36) as usize, INFO_BYTES);
    let tracking = start_tracking_packet(10, &[(0x2000, 0x1000)]).unwrap();
    assert_eq!(word(&tracking, 12), AD_START);
    assert_eq!(quad(&tracking, 24), 10);
    assert_eq!(quad(&tracking, HEADER_BYTES), 0x2000);
    assert_eq!(quad(&tracking, HEADER_BYTES + 8), 0x1000);
    let mut request = InterceptionRequest {
        operation: HOOK_INSTALL,
        cr3: 0x2000,
        flags: INTERCEPT_NO_LEASE,
        items: vec![Item {
            address: 0x1000,
            bytes: vec![0x90],
        }],
        ..Default::default()
    };
    let hook = interception_packet(&request).unwrap();
    assert_eq!(word(&hook, 12), HOOK_INSTALL);
    assert_eq!(word(&hook, 128), INTERCEPT_NO_LEASE);
    request.items[0].address = 0x1fff;
    request.items[0].bytes = vec![0x90; 2];
    assert!(interception_packet(&request).is_err());
    request.items[0].bytes.truncate(1);
    request.lease_ms = 10;
    assert!(interception_packet(&request).is_err());
}
