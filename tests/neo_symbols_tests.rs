use super::*;
use std::collections::BTreeMap;

fn layout() -> VadLayout {
    VadLayout {
        root_offset: 0,
        node_offset: 0,
        left_offset: 0,
        right_offset: 8,
        start_offset: 16,
        end_offset: 20,
        start_high_offset: 24,
        end_high_offset: 25,
        flags_offset: 28,
        commit: VadCommit::Charge {
            offset: 32,
            high_offset: 26,
        },
        protection_mask: 0x1f,
        private_mask: 1 << 8,
        bytes: 40,
    }
}

fn row(start: u32, end: u32, flags: u32, charge: u32) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    for (offset, value) in [(16, start), (20, end), (28, flags), (32, charge)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[test]
fn vad_commit_and_protection_do_not_confuse_residency_with_commitment() {
    let layout = layout();
    let full = layout.region(&row(1, 2, 0x100 | 4, 2)).unwrap();
    assert_eq!((full.start, full.end, full.protection), (0x1000, 0x3000, 4));
    assert!(full.private);
    assert_eq!(full.committed, Some(true));
    assert_eq!(layout.region(&row(1, 2, 0x104, 1)).unwrap().committed, None);
    assert_eq!(
        layout.region(&row(1, 2, 0x104, 0)).unwrap().committed,
        Some(false)
    );
    assert_eq!(layout.region(&row(1, 2, 4, 2)).unwrap().committed, None);
    assert!(layout.region(&row(3, 2, 4, 0)).is_err());
    assert!(layout.region(&[0; 20]).is_err());
}

#[test]
fn full_vad_walk_sorts_regions_and_detects_cycles_and_overlaps() {
    let layout = layout();
    let root_address = 0xffff800000001000u64;
    let node = root_address + 0x1000;
    let left = node + 0x1000;
    let mut rows = BTreeMap::new();
    rows.insert(root_address, node.to_le_bytes().to_vec());
    let mut root = row(5, 6, 0x104, 2);
    root[..8].copy_from_slice(&left.to_le_bytes());
    rows.insert(node, root);
    rows.insert(left, row(1, 2, 0x104, 2));
    let reader = |address, length| {
        rows.get(&address)
            .filter(|bytes| bytes.len() == length)
            .cloned()
            .ok_or_else(|| "invalid fixture read".to_string())
    };
    let regions = layout.regions(root_address, &mut { reader }).unwrap();
    assert_eq!(
        regions
            .iter()
            .map(|region| region.start)
            .collect::<Vec<_>>(),
        [0x1000, 0x5000]
    );
    rows.get_mut(&left).unwrap()[..8].copy_from_slice(&node.to_le_bytes());
    let error = layout
        .regions(root_address, &mut |address, _| {
            rows.get(&address).cloned().ok_or("missing node".into())
        })
        .unwrap_err();
    assert!(error.contains("VAD tree"));
    rows.insert(left, row(4, 5, 0x104, 2));
    assert!(
        layout
            .regions(root_address, &mut |address, _| rows
                .get(&address)
                .cloned()
                .ok_or("missing node".into()))
            .is_err()
    );
}
