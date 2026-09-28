use super::{
    NATIVE_SNAPSHOT_FIELDS, NativeSnapshotLayout, control_stage_name, native_snapshot_fields,
    save_native_frame,
};
use std::arch::x86_64::CpuidResult;
use std::io::Write;

fn layout() -> NativeSnapshotLayout {
    NativeSnapshotLayout::from_cpuid(CpuidResult {
        eax: 16592,
        ebx: 208,
        ecx: 16384,
        edx: 24,
    })
    .unwrap()
}

fn published(count: u64, sequence: u64) -> CpuidResult {
    CpuidResult {
        eax: count as u32,
        ebx: (count >> 32) as u32,
        ecx: sequence as u32,
        edx: (sequence >> 32) as u32,
    }
}

fn snapshot(layout: NativeSnapshotLayout) -> Vec<u8> {
    let mut bytes = vec![0; layout.snapshot_bytes];
    let mut fields = std::array::from_fn::<_, 26, _>(|index| 0x1122_3344_5566_0000 + index as u64);
    fields[0] = 11;
    fields[1] = 0xffff_f800_1234_5678;
    fields[8] = 0xffff_8000_1000_0000;
    fields[9] = fields[8] + layout.stack_bytes as u64;
    fields[2] = fields[9] - 32;
    for (chunk, value) in bytes[..layout.stack_offset].chunks_exact_mut(8).zip(fields) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    for (index, byte) in bytes[layout.stack_offset..].iter_mut().enumerate() {
        *byte = index.wrapping_mul(17) as u8;
    }
    bytes
}

fn payload(bytes: &[u8], subleaf: u32, frame_index: u32) -> CpuidResult {
    let offset = (subleaf - 0x4000 - frame_index * (bytes.len() / 16) as u32) as usize * 16;
    let words: [u32; 4] = std::array::from_fn(|index| {
        u32::from_le_bytes(
            bytes[offset + index * 4..offset + index * 4 + 4]
                .try_into()
                .unwrap(),
        )
    });
    CpuidResult {
        eax: words[0],
        ebx: words[1],
        ecx: words[2],
        edx: words[3],
    }
}

#[test]
fn snapshot_preserves_every_stack_byte_and_full_width_register() {
    let layout = layout();
    let bytes = snapshot(layout);
    let sequence = 0xfedc_ba98_7654_3210;
    let mut query = |subleaf| match subleaf {
        51 => published(24, sequence),
        _ => payload(&bytes, subleaf, 23),
    };
    let captured = layout
        .read_frame(23, sequence, &mut query)
        .unwrap()
        .unwrap();
    assert_eq!(captured, bytes);
    let fields = native_snapshot_fields(&captured);
    assert_eq!(fields[1], 0xffff_f800_1234_5678);
    for (index, name) in NATIVE_SNAPSHOT_FIELDS.iter().enumerate().skip(10) {
        assert_eq!(
            fields[index],
            0x1122_3344_5566_0000 + index as u64,
            "{name}"
        );
    }
    assert_eq!(captured[layout.stack_offset..].len(), 16384);
    assert_eq!(control_stage_name(fields[0]), "before_invept");
    assert_eq!(control_stage_name(10), "vmcs_cleared");
    assert_eq!(control_stage_name(12), "before_invvpid");
}

#[test]
fn snapshot_rejects_sequence_changes_and_count_resets_during_read() {
    let layout = layout();
    let bytes = snapshot(layout);
    for after in [(2, 8), (1, 7)] {
        let mut publications = 0;
        let mut query = |subleaf| {
            if subleaf == 51 {
                publications += 1;
                let state = if publications == 1 { (2, 7) } else { after };
                published(state.0, state.1)
            } else {
                payload(&bytes, subleaf, 0)
            }
        };
        assert!(layout.read_frame(0, 7, &mut query).unwrap().is_none());
    }
}

#[test]
fn snapshot_accepts_new_published_frames_without_discarding_immutable_bytes() {
    let layout = layout();
    let bytes = snapshot(layout);
    let mut publications = 0;
    let mut query = |subleaf| {
        if subleaf == 51 {
            publications += 1;
            published(publications, 7)
        } else {
            payload(&bytes, subleaf, 0)
        }
    };
    assert_eq!(layout.read_frame(0, 7, &mut query).unwrap().unwrap(), bytes);
}

#[test]
fn snapshot_rejects_header_changes_even_if_publication_state_matches() {
    let layout = layout();
    let bytes = snapshot(layout);
    let mut reads = 0;
    let mut query = |subleaf| {
        if subleaf == 51 {
            published(1, 7)
        } else {
            reads += 1;
            let mut result = payload(&bytes, subleaf, 0);
            if reads > layout.snapshot_bytes / 16 {
                result.eax ^= 1;
            }
            result
        }
    };
    assert!(layout.read_frame(0, 7, &mut query).unwrap().is_none());
}

#[test]
fn unpublished_frames_and_invalid_counts_never_read_payload() {
    let layout = layout();
    for (count, sequence) in [(0, 7), (1, 8), (25, 7)] {
        let mut query = |subleaf| {
            assert_eq!(subleaf, 51);
            published(count, sequence)
        };
        let result = layout.read_frame(0, 7, &mut query);
        if count > layout.capacity {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_none());
        }
    }
}

#[test]
fn layout_rejects_invalid_abi_and_subleaf_address_overflow() {
    for result in [
        CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        },
        CpuidResult {
            eax: 16592,
            ebx: 200,
            ecx: 16392,
            edx: 24,
        },
        CpuidResult {
            eax: 16584,
            ebx: 208,
            ecx: 16376,
            edx: 24,
        },
        CpuidResult {
            eax: 16592,
            ebx: 208,
            ecx: 16384,
            edx: 0,
        },
        CpuidResult {
            eax: 16592,
            ebx: 208,
            ecx: 16384,
            edx: 48,
        },
        CpuidResult {
            eax: 131280,
            ebx: 208,
            ecx: 131072,
            edx: 1,
        },
    ] {
        assert!(NativeSnapshotLayout::from_cpuid(result).is_err());
    }
}

#[test]
fn snapshot_rejects_stack_bounds_that_do_not_cover_the_saved_allocation() {
    let layout = layout();
    for field in [2, 9] {
        let mut bytes = snapshot(layout);
        bytes[field * 8..field * 8 + 8].copy_from_slice(&0u64.to_le_bytes());
        let mut query = |subleaf| match subleaf {
            51 => published(1, 7),
            _ => payload(&bytes, subleaf, 0),
        };
        assert!(layout.read_frame(0, 7, &mut query).is_err());
    }
}

#[test]
fn persisted_frame_matches_binary_and_duplicate_capture_cannot_overwrite_it() {
    let layout = layout();
    let bytes = snapshot(layout);
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../builds/neo-control-trace-tests")
        .join(format!("{}-{run}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let trace_path = directory.join("trace.txt");
    let mut trace = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&trace_path)
        .unwrap();
    save_native_frame(&trace_path, &mut trace, 0, 7, 0, layout, &bytes).unwrap();
    trace.flush().unwrap();
    let frame_path = directory.join("trace.txt.cpu0.seq0000000000000007.frame00.bin");
    assert_eq!(std::fs::read(&frame_path).unwrap(), bytes);
    let record = std::fs::read_to_string(&trace_path).unwrap();
    assert!(record.contains("native_rip=0xfffff80012345678\n"));
    assert!(record.contains("native_stack_bytes=16384\n"));
    assert!(record.contains("native_stack_offset=208\n"));
    assert!(record.contains("native_frame_complete=true\n"));
    assert!(save_native_frame(&trace_path, &mut trace, 0, 7, 0, layout, &[]).is_err());
    assert_eq!(std::fs::read(&frame_path).unwrap(), bytes);
    assert_eq!(std::fs::read_to_string(&trace_path).unwrap(), record);
}
