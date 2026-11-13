use super::*;
use std::collections::BTreeMap;

const ROOT: u64 = 0x3450_0000;
const PROTECTED_ROOT: u64 = 0x4000_0005_655f_9000;
const PEB: u64 = 0x20000;
const IMAGE: u64 = 0x100000;
const PARAMETERS: u64 = 0x30000;
const PATH: u64 = 0x40000;

fn fixture() -> BTreeMap<(u64, u64), Vec<u8>> {
    let mut rows = BTreeMap::new();
    rows.insert((ROOT, PEB + 0x10), IMAGE.to_le_bytes().to_vec());
    rows.insert((ROOT, PEB + 0x20), PARAMETERS.to_le_bytes().to_vec());
    let mut dos = vec![0; 64];
    dos[..2].copy_from_slice(b"MZ");
    dos[60..64].copy_from_slice(&0x80u32.to_le_bytes());
    rows.insert((ROOT, IMAGE), dos);
    let mut pe = vec![0; 84];
    pe[..4].copy_from_slice(b"PE\0\0");
    pe[4..6].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[24..26].copy_from_slice(&0x20bu16.to_le_bytes());
    pe[80..84].copy_from_slice(&0x20000u32.to_le_bytes());
    rows.insert((ROOT, IMAGE + 0x80), pe);
    let path: Vec<u8> = "C:\\Games\\Example.exe"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut descriptor = vec![0; 16];
    descriptor[..2].copy_from_slice(&(path.len() as u16).to_le_bytes());
    descriptor[2..4].copy_from_slice(&(path.len() as u16).to_le_bytes());
    descriptor[8..16].copy_from_slice(&PATH.to_le_bytes());
    rows.insert((ROOT, PARAMETERS + 0x60), descriptor);
    rows.insert((ROOT, PATH), path);
    rows
}

fn read_fixture(
    rows: &BTreeMap<(u64, u64), Vec<u8>>,
    root: u64,
    address: u64,
    length: usize,
) -> Option<Vec<u8>> {
    rows.get(&(root, address))
        .filter(|bytes| bytes.len() == length)
        .cloned()
}

#[test]
fn chooses_validated_image_over_an_untranslatable_process_field() {
    let rows = fixture();
    let candidates = [PROTECTED_ROOT, ROOT | 7, ROOT | 9];
    let result = match_image_roots(
        &candidates,
        PEB,
        "example.EXE",
        &mut |root, address, len| read_fixture(&rows, root, address, len),
    );
    assert_eq!(
        result,
        Some(ImageRoot {
            cr3: ROOT,
            image: IMAGE,
        })
    );
}

#[test]
fn rejects_wrong_image_name_and_invalid_headers_or_path() {
    let mut rows = fixture();
    let probe = |rows: &BTreeMap<(u64, u64), Vec<u8>>, name: &str| {
        image_root_candidate(ROOT, PEB, name, &mut |root, address, len| {
            read_fixture(rows, root, address, len)
        })
    };
    assert!(probe(&rows, "other.exe").is_none());
    rows.get_mut(&(ROOT, IMAGE + 0x80)).unwrap()[4] = 0;
    assert!(probe(&rows, "example.exe").is_none());
    rows = fixture();
    rows.get_mut(&(ROOT, PARAMETERS + 0x60)).unwrap()[0] |= 1;
    assert!(probe(&rows, "example.exe").is_none());
    rows = fixture();
    rows.get_mut(&(ROOT, PEB + 0x10))
        .unwrap()
        .copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(probe(&rows, "example.exe").is_none());
}

#[test]
fn failed_root_can_be_tested_again_after_a_transient_read_failure() {
    let rows = fixture();
    let mut first = true;
    let mut reader = |root, address, len| {
        if first {
            first = false;
            return None;
        }
        read_fixture(&rows, root, address, len)
    };
    assert!(match_image_roots(&[ROOT], PEB, "example.exe", &mut reader).is_none());
    assert!(match_image_roots(&[ROOT], PEB, "example.exe", &mut reader).is_some());
}

#[test]
fn rejects_invalid_target_before_calling_the_transport() {
    assert!(find_pe_image_root(0, "example.exe", &[], std::time::Duration::ZERO).is_err());
    assert!(find_pe_image_root(PEB, "C:\\example.exe", &[], std::time::Duration::ZERO).is_err());
}
