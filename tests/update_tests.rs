use crate::update::*;
use ed25519_dalek::{Signer, SigningKey};

fn package(version: u64) -> (Vec<u8>, Abi, [u8; 32]) {
    let key = SigningKey::from_bytes(&[0x21; 32]);
    let public_key = key.verifying_key().to_bytes();
    let abi = Abi {
        bridge: 4,
        boot_bytes: 128,
        event_bytes: 256,
        nested_bytes: 64,
        cpu_bytes: 32,
    };
    let image_offset = HEADER_BYTES + 2 * 16 + 7 * 16;
    let mut bytes = vec![0; image_offset + 4096 + 96];
    bytes[..8].copy_from_slice(PACKAGE_MAGIC);
    for (offset, value) in [
        (8, 1),
        (12, 256),
        (16, bytes.len() as u32),
        (20, image_offset as u32),
        (24, 4192),
        (28, STATE_ABI),
        (40, abi.bridge),
        (44, 2),
        (48, 7),
        (52, 5),
        (80, abi.boot_bytes),
        (84, abi.event_bytes),
        (88, abi.nested_bytes),
        (92, abi.cpu_bytes),
        (96, 256),
        (100, 288),
        (256, 0),
        (260, 4096),
        (264, 5),
        (272, 4096),
        (276, 96),
        (280, 3),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[32..40].copy_from_slice(&version.to_le_bytes());
    bytes[104..136].copy_from_slice(&hash(&public_key));
    bytes[image_offset] = 0xc3;
    for index in 0..7 {
        let offset = 288 + index * 16;
        bytes[offset..offset + 4].copy_from_slice(&(4096_u32 + index as u32 * 8).to_le_bytes());
        bytes[offset + 4..offset + 8].copy_from_slice(&(index as u32 + 1).to_le_bytes());
    }
    resign(&mut bytes);
    (bytes, abi, public_key)
}

fn resign(bytes: &mut [u8]) {
    let image_offset = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
    let image_hash = hash(&bytes[image_offset..]);
    bytes[136..168].copy_from_slice(&image_hash);
    let identity = package_identity(bytes).unwrap();
    let key = SigningKey::from_bytes(&[0x21; 32]);
    bytes[192..256].copy_from_slice(&key.sign(&identity).to_bytes());
}

fn transaction() -> Transaction {
    Transaction {
        status: Status::default(),
        upload: Upload::default(),
        expected_mask: 0,
        current_bank: 0,
        previous_bank: 0,
        current_version: 1,
        current_identity: [0x42; 32],
        pending_dispatch: 0,
        previous_host_rips: [0; 64],
        previous_idts: [0; 64],
    }
}

fn active() -> CpuMasks {
    CpuMasks {
        expected: 3,
        active: 3,
        ..CpuMasks::default()
    }
}
fn stopped() -> CpuMasks {
    CpuMasks {
        expected: 3,
        stopped: 3,
        ..CpuMasks::default()
    }
}

#[test]
fn authenticated_package_relocates_only_declared_data() {
    let (bytes, abi, key) = package(2);
    let parsed = Package::parse(&bytes, abi, &key).unwrap();
    let mut output = vec![0xaa; BANK_BYTES];
    parsed.relocate(&mut output, &[1, 2, 3, 4, 5, 6]).unwrap();
    assert_eq!(output[0], 0xc3);
    assert_eq!(&output[4096..4104], &1_u64.to_le_bytes());
    assert_eq!(&output[4144..4176], &parsed.identity);
    assert_eq!(parsed.page_flags(0), 1);
    assert_eq!(parsed.page_flags(1), 3 | (1 << 63));
    assert!(output[4192..].iter().all(|byte| *byte == 0));
}

#[test]
fn tampering_and_another_signer_are_rejected() {
    let (mut bytes, abi, key) = package(2);
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(
        Package::parse(&bytes, abi, &key).unwrap_err(),
        Error::Signature
    );
    resign(&mut bytes);
    assert_eq!(
        Package::parse(&bytes, abi, &[0; 32]).unwrap_err(),
        Error::Signature
    );
}

#[test]
fn incompatible_abi_and_malformed_regions_or_relocations_are_rejected() {
    let (mut bytes, mut abi, key) = package(2);
    abi.boot_bytes += 1;
    assert_eq!(Package::parse(&bytes, abi, &key).unwrap_err(), Error::Abi);
    abi.boot_bytes -= 1;
    bytes[264..268].copy_from_slice(&7_u32.to_le_bytes());
    resign(&mut bytes);
    assert_eq!(
        Package::parse(&bytes, abi, &key).unwrap_err(),
        Error::Region
    );
    bytes[264..268].copy_from_slice(&5_u32.to_le_bytes());
    bytes[288..292].copy_from_slice(&0_u32.to_le_bytes());
    resign(&mut bytes);
    assert_eq!(
        Package::parse(&bytes, abi, &key).unwrap_err(),
        Error::Relocation
    );
}

#[test]
fn upload_accepts_out_of_order_idempotent_blocks_and_rejects_conflicts() {
    let mut upload = Upload::default();
    let mut staging = vec![0; MAX_PACKAGE_BYTES];
    upload.prepare(7, 2200).unwrap();
    upload.write(7, 2048, &[3; 152], &mut staging).unwrap();
    upload.write(7, 0, &[1; 1024], &mut staging).unwrap();
    upload.write(7, 0, &[1; 1024], &mut staging).unwrap();
    assert_eq!(upload.received_bytes, 1176);
    assert_eq!(
        upload.write(7, 0, &[2; 1024], &mut staging),
        Err(Error::Chunk)
    );
    assert_eq!(
        upload.write(7, 1, &[1; 1024], &mut staging),
        Err(Error::Chunk)
    );
    assert_eq!(
        upload.write(8, 1024, &[2; 1024], &mut staging),
        Err(Error::Transaction)
    );
    upload.write(7, 1024, &[2; 1024], &mut staging).unwrap();
    assert!(upload.complete());
}

fn prepared() -> (Transaction, Vec<u8>, Abi, [u8; 32]) {
    let (bytes, abi, key) = package(2);
    let mut state = transaction();
    state.prepare(9, bytes.len(), active()).unwrap();
    let mut staging = vec![0; MAX_PACKAGE_BYTES];
    for (index, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
        state
            .upload
            .write(9, index * CHUNK_BYTES, chunk, &mut staging)
            .unwrap();
    }
    let parsed = Package::parse(&bytes, abi, &key).unwrap();
    state.validated(9, &parsed, 0x1000).unwrap();
    (state, bytes, abi, key)
}

#[test]
fn cancellation_and_nested_rejection_happen_before_off() {
    let (mut state, _, _, _) = prepared();
    assert_eq!(state.check_cpu(9, 0, Error::HyperV), Err(Error::HyperV));
    assert_eq!(state.begin_off(9, active()), Err(Error::Incomplete));
    assert_eq!(state.status.phase, Phase::Prepared as u32);
    state.cancel(9).unwrap();
    assert_eq!(state.status.retained_banks, 1);
    state.prepare(10, 256, active()).unwrap();
    assert_eq!(state.prepare(11, 256, active()), Err(Error::Busy));
}

#[test]
fn partial_stop_and_activation_retain_both_banks_until_recovery_is_probed() {
    let (mut state, _, _, _) = prepared();
    for cpu in 0..2 {
        state.check_cpu(9, cpu, Error::None).unwrap();
    }
    state.begin_off(9, active()).unwrap();
    let partial = CpuMasks {
        expected: 3,
        active: 2,
        stopped: 1,
        ..CpuMasks::default()
    };
    assert_eq!(state.commit(9, partial), Err(Error::Incomplete));
    assert_eq!(state.status.retained_banks, 3);
    state.recover(9, partial).unwrap();
    assert_eq!(state.recovered(9, active()), Err(Error::Retained));
    for cpu in 0..2 {
        state.probe_cpu(9, cpu, &[0x42; 32], active()).unwrap();
    }
    state.recovered(9, active()).unwrap();
    assert_eq!(state.status.retained_banks, 1);
}

#[test]
fn successful_swap_requires_all_cpu_identities_and_flush_completion() {
    let (mut state, _, _, _) = prepared();
    for cpu in 0..2 {
        state.check_cpu(9, cpu, Error::None).unwrap();
    }
    state.begin_off(9, active()).unwrap();
    state.commit(9, stopped()).unwrap();
    assert_eq!(state.finish(9, active()), Err(Error::Retained));
    let identity = state.status.next_identity;
    for cpu in 0..2 {
        state.probe_cpu(9, cpu, &identity, active()).unwrap();
    }
    let pending = CpuMasks {
        rearm: 1,
        ..active()
    };
    assert_eq!(state.finish(9, pending), Err(Error::Retained));
    state.finish(9, active()).unwrap();
    assert_eq!(state.current_bank, 1);
    assert_eq!(state.current_version, 2);
    assert_eq!(state.status.retained_banks, 2);
}

#[test]
fn activation_failure_requires_new_cpus_to_stop_before_switching_back() {
    let (mut state, _, _, _) = prepared();
    for cpu in 0..2 {
        state.check_cpu(9, cpu, Error::None).unwrap();
    }
    state.begin_off(9, active()).unwrap();
    state.commit(9, stopped()).unwrap();
    let partial = CpuMasks {
        expected: 3,
        active: 1,
        stopped: 2,
        ..CpuMasks::default()
    };
    assert_eq!(state.recover(9, partial), Err(Error::Retained));
    assert_eq!(state.status.retained_banks, 3);
    state.recover(9, stopped()).unwrap();
    assert_eq!(state.current_bank, 0);
}

#[test]
fn failed_host_state_never_releases_a_bank_or_reports_success() {
    let (mut state, _, _, _) = prepared();
    for cpu in 0..2 {
        state.check_cpu(9, cpu, Error::None).unwrap();
    }
    state.begin_off(9, active()).unwrap();
    let failed = CpuMasks {
        expected: 3,
        active: 2,
        failed: 1,
        ..CpuMasks::default()
    };
    assert_eq!(state.recover(9, failed), Err(Error::Retained));
    assert_eq!(state.status.retained_banks, 3);
    assert_ne!(state.status.phase, Phase::Complete as u32);
}

#[test]
fn oversized_upload_and_truncated_pe_are_rejected() {
    let mut upload = Upload::default();
    assert_eq!(upload.prepare(1, MAX_PACKAGE_BYTES + 1), Err(Error::Bounds));
    for length in 0..256 {
        assert!(EmbeddedImage::parse(&vec![0; length]).is_err());
    }
}

fn loaded_image() -> Vec<u8> {
    let mut bytes = vec![0; 5 * 4096];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[60..64].copy_from_slice(&128_u32.to_le_bytes());
    bytes[128..132].copy_from_slice(b"PE\0\0");
    bytes[132..134].copy_from_slice(&0x8664_u16.to_le_bytes());
    bytes[134..136].copy_from_slice(&4_u16.to_le_bytes());
    bytes[148..150].copy_from_slice(&240_u16.to_le_bytes());
    bytes[152..154].copy_from_slice(&0x20b_u16.to_le_bytes());
    bytes[208..212].copy_from_slice(&(5_u32 * 4096).to_le_bytes());
    bytes[304..308].copy_from_slice(&(4_u32 * 4096).to_le_bytes());
    bytes[308..312].copy_from_slice(&12_u32.to_le_bytes());
    for (index, flags) in [0x6000_0000_u32, 0x4000_0000, 0xc000_0000, 0x4000_0000]
        .into_iter()
        .enumerate()
    {
        let offset = 392 + index * 40;
        bytes[offset + 8..offset + 12].copy_from_slice(&4096_u32.to_le_bytes());
        bytes[offset + 12..offset + 16].copy_from_slice(&((index as u32 + 1) * 4096).to_le_bytes());
        bytes[offset + 36..offset + 40].copy_from_slice(&flags.to_le_bytes());
    }
    bytes[8192..8200].copy_from_slice(&0x0100_1234_u64.to_le_bytes());
    bytes[16384..16388].copy_from_slice(&8192_u32.to_le_bytes());
    bytes[16388..16392].copy_from_slice(&12_u32.to_le_bytes());
    bytes[16392..16394].copy_from_slice(&0xa000_u16.to_le_bytes());
    bytes
}

#[test]
fn embedded_loader_relocates_internal_pointers_and_assigns_host_permissions() {
    let bytes = loaded_image();
    let image = EmbeddedImage::parse(&bytes).unwrap();
    let mut destination = vec![0xaa; bytes.len() + 4096];
    image
        .copy_relocated(&mut destination, 0x0100_0000, 0x0200_0000)
        .unwrap();
    assert_eq!(
        u64::from_le_bytes(destination[8192..8200].try_into().unwrap()),
        0x0200_1234
    );
    assert_eq!(image.page_flags(1), 1);
    assert_eq!(image.page_flags(2), 1 | (1 << 63));
    assert_eq!(image.page_flags(3), 3 | (1 << 63));
    assert!(destination[bytes.len()..].iter().all(|byte| *byte == 0));
    assert_eq!(
        image.copy_relocated(&mut destination, 0x0300_0000, 0x0400_0000),
        Err(Error::Relocation)
    );
}

#[test]
fn embedded_loader_rejects_overlapping_sections_and_malformed_fixups_before_copying() {
    let mut bytes = loaded_image();
    bytes[444..448].copy_from_slice(&4096_u32.to_le_bytes());
    assert!(matches!(EmbeddedImage::parse(&bytes), Err(Error::Region)));
    for fixup in [0x3000_u16, 0xafff] {
        let mut bytes = loaded_image();
        bytes[16392..16394].copy_from_slice(&fixup.to_le_bytes());
        if fixup == 0xafff {
            bytes[16384..16388].copy_from_slice(&16384_u32.to_le_bytes());
        }
        assert!(matches!(
            EmbeddedImage::parse(&bytes),
            Err(Error::Relocation)
        ));
    }
}

#[test]
fn request_bounds_and_operation_metadata_are_enforced() {
    let mut bytes = vec![0; REQUEST_BYTES];
    bytes[..8].copy_from_slice(&REQUEST_MAGIC.to_le_bytes());
    bytes[8..12].copy_from_slice(&PACKAGE_VERSION.to_le_bytes());
    bytes[12..16].copy_from_slice(&PREPARE.to_le_bytes());
    bytes[16..24].copy_from_slice(&9_u64.to_le_bytes());
    bytes[40..44].copy_from_slice(&256_u32.to_le_bytes());
    assert!(Request::parse(&bytes).is_ok());
    bytes[32..36].copy_from_slice(&1_u32.to_le_bytes());
    assert!(matches!(Request::parse(&bytes), Err(Error::Format)));
    bytes[32..36].fill(0);
    bytes[12..16].copy_from_slice(&QUERY.to_le_bytes());
    assert!(matches!(Request::parse(&bytes), Err(Error::Format)));
    bytes[40..44].fill(0);
    bytes.extend_from_slice(&[0; CHUNK_BYTES + 1]);
    assert!(matches!(Request::parse(&bytes), Err(Error::Bounds)));
}

#[test]
fn older_versions_and_wrong_cpu_identities_never_complete_a_transaction() {
    let (mut state, bytes, abi, key) = prepared();
    let (old_bytes, _, _) = package(1);
    state.cancel(9).unwrap();
    state.prepare(10, old_bytes.len(), active()).unwrap();
    let mut staging = vec![0; MAX_PACKAGE_BYTES];
    for (index, chunk) in old_bytes.chunks(CHUNK_BYTES).enumerate() {
        state
            .upload
            .write(10, index * CHUNK_BYTES, chunk, &mut staging)
            .unwrap();
    }
    assert_eq!(
        state.validated(10, &Package::parse(&old_bytes, abi, &key).unwrap(), 0x1000),
        Err(Error::Version)
    );
    state
        .validated(10, &Package::parse(&bytes, abi, &key).unwrap(), 0x1000)
        .unwrap();
    for cpu in 0..2 {
        state.check_cpu(10, cpu, Error::None).unwrap();
    }
    state.begin_off(10, active()).unwrap();
    state.commit(10, stopped()).unwrap();
    assert_eq!(
        state.probe_cpu(10, 0, &[0; 32], active()),
        Err(Error::Probe)
    );
    assert_eq!(state.status.verified_mask, 0);
    assert_eq!(state.finish(10, active()), Err(Error::Retained));
}
