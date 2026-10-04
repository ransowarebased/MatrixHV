use crate::memory::access;

use crate::memory::{Item, packet, parse_items};
use crate::protocol::memory::*;
use access::{PhysicalMemory, execute, transfer, translate};
use std::collections::BTreeMap;

#[derive(Default)]
struct Ram {
    pages: BTreeMap<u64, Vec<u8>>,
    writes: usize,
}

impl Ram {
    fn page(&mut self, address: u64) {
        self.pages.insert(address, vec![0; 4096]);
    }
    fn entry(&mut self, table: u64, index: usize, value: u64) {
        self.pages.get_mut(&table).unwrap()[index * 8..index * 8 + 8]
            .copy_from_slice(&value.to_le_bytes());
    }
    fn mapped() -> Self {
        let mut ram = Self::default();
        for address in [0x1000, 0x2000, 0x3000, 0x4000, 0x10000, 0x12000] {
            ram.page(address);
        }
        ram.entry(0x1000, 0, 0x2007);
        ram.entry(0x2000, 0, 0x3007);
        ram.entry(0x3000, 0, 0x4007);
        ram.entry(0x4000, 0, 0x10007);
        ram.entry(0x4000, 1, 0x12007);
        ram
    }
}

impl PhysicalMemory for Ram {
    fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), Error> {
        let page = self.pages.get(&(address & !4095)).ok_or(Error::Unmapped)?;
        let offset = address as usize & 4095;
        bytes.copy_from_slice(
            page.get(offset..offset + bytes.len())
                .ok_or(Error::Bounds)?,
        );
        Ok(())
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Error> {
        let page = self
            .pages
            .get_mut(&(address & !4095))
            .ok_or(Error::Unmapped)?;
        let offset = address as usize & 4095;
        page.get_mut(offset..offset + bytes.len())
            .ok_or(Error::Bounds)?
            .copy_from_slice(bytes);
        self.writes += 1;
        Ok(())
    }
}

#[test]
fn batch_reads_noncontiguous_pages_and_reports_independent_failures() {
    let mut ram = Ram::mapped();
    ram.pages.get_mut(&0x10000).unwrap()[4094..].copy_from_slice(&[1, 2]);
    ram.pages.get_mut(&0x12000).unwrap()[..2].copy_from_slice(&[3, 4]);
    let mut request = packet(
        READ,
        42,
        0x1000,
        &[
            Item {
                address: 4094,
                bytes: vec![0; 4],
            },
            Item {
                address: 8192,
                bytes: vec![0; 1],
            },
            Item {
                address: 4094,
                bytes: vec![0; 2],
            },
        ],
    )
    .unwrap();
    execute(&mut ram, &mut request, false, 48).unwrap();
    let offset = word(&request, HEADER_BYTES + 8) as usize;
    assert_eq!(&request[offset..offset + 4], &[1, 2, 3, 4]);
    assert_eq!(word(&request, HEADER_BYTES + 20), 4);
    assert_eq!(
        word(&request, HEADER_BYTES + ITEM_BYTES + 16),
        Error::Unmapped as u32
    );
    assert_eq!(word(&request, HEADER_BYTES + ITEM_BYTES * 2 + 20), 2);
}

#[test]
fn write_reports_partial_completion_when_the_next_page_is_absent() {
    let mut ram = Ram::mapped();
    ram.entry(0x4000, 1, 0);
    let mut request = packet(
        WRITE,
        42,
        0x1000,
        &[Item {
            address: 4094,
            bytes: vec![1, 2, 3, 4],
        }],
    )
    .unwrap();
    execute(&mut ram, &mut request, false, 48).unwrap();
    assert_eq!(word(&request, HEADER_BYTES + 16), Error::Unmapped as u32);
    assert_eq!(word(&request, HEADER_BYTES + 20), 2);
    assert_eq!(&ram.pages[&0x10000][4094..], &[1, 2]);
}

#[test]
fn malformed_later_descriptor_prevents_all_writes() {
    for bad_offset in [0, HEADER_BYTES as u32, u32::MAX] {
        let mut ram = Ram::mapped();
        let mut request = packet(
            WRITE,
            42,
            0x1000,
            &[
                Item {
                    address: 0,
                    bytes: vec![9],
                },
                Item {
                    address: 1,
                    bytes: vec![9],
                },
            ],
        )
        .unwrap();
        request[HEADER_BYTES + ITEM_BYTES + 8..HEADER_BYTES + ITEM_BYTES + 12]
            .copy_from_slice(&bad_offset.to_le_bytes());
        assert_eq!(
            execute(&mut ram, &mut request, false, 48),
            Err(Error::Bounds)
        );
        assert_eq!(ram.writes, 0);
    }
}

#[test]
fn page_walk_enforces_write_and_caller_user_permissions_at_every_level() {
    for table in [0x1000, 0x2000, 0x3000, 0x4000] {
        let mut ram = Ram::mapped();
        let entry = quad(&ram.pages[&table], 0);
        ram.entry(table, 0, entry & !2);
        assert_eq!(
            translate(&mut ram, 0x1000, 0, false, 48, true, false),
            Err(Error::Permission)
        );
        assert!(translate(&mut ram, 0x1000, 0, false, 48, false, false).is_ok());
        ram.entry(table, 0, entry & !4);
        assert_eq!(
            translate(&mut ram, 0x1000, 0, false, 48, false, true),
            Err(Error::Permission)
        );
    }
}

#[test]
fn paging_supports_large_pages_pat_pcid_and_five_levels() {
    let mut ram = Ram::mapped();
    assert_eq!(
        translate(&mut ram, 0x1005, 17, false, 48, false, true),
        Ok(0x10011)
    );
    ram.entry(0x2000, 0, 0x4000_1087);
    assert_eq!(
        translate(&mut ram, 0x1000, 123, false, 48, false, true),
        Ok(0x4000_007b)
    );
    ram.entry(0x2000, 0, 0x3007);
    ram.entry(0x3000, 0, 0x20_1087);
    assert_eq!(
        translate(&mut ram, 0x1000, 123, false, 48, false, true),
        Ok(0x20_007b)
    );
    ram.entry(0x3000, 0, 0x4007);
    ram.page(0x5000);
    ram.entry(0x5000, 0, 0x1007);
    assert_eq!(
        translate(&mut ram, 0x5000, 17, true, 48, false, true),
        Ok(0x10011)
    );
}

#[test]
fn page_walk_rejects_noncanonical_and_reserved_addresses() {
    let mut ram = Ram::mapped();
    assert_eq!(
        translate(
            &mut ram,
            0x1000,
            0x0000_8000_0000_0000,
            false,
            48,
            false,
            false
        ),
        Err(Error::Bounds)
    );
    assert_eq!(
        translate(
            &mut ram,
            0x1000,
            0x0100_0000_0000_0000,
            true,
            48,
            false,
            false
        ),
        Err(Error::Bounds)
    );
    assert_eq!(
        translate(&mut ram, 0, 0, false, 48, false, false),
        Err(Error::Bounds)
    );
    assert_eq!(
        translate(&mut ram, 0x1000, 0, false, 53, false, false),
        Err(Error::Unsupported)
    );
    ram.entry(0x1000, 0, 0x2087);
    assert_eq!(
        translate(&mut ram, 0x1000, 0, false, 48, false, false),
        Err(Error::Format)
    );
    ram.entry(0x1000, 0, (1 << 48) | 0x2007);
    assert_eq!(
        translate(&mut ram, 0x1000, 0, false, 48, false, false),
        Err(Error::Bounds)
    );
    ram.entry(0x1000, 0, 0x2007);
    ram.entry(0x2000, 0, 0x4000_2087);
    assert_eq!(
        translate(&mut ram, 0x1000, 0, false, 48, false, false),
        Err(Error::Format)
    );
}

#[test]
fn invalid_packet_headers_and_ranges_never_touch_target_memory() {
    let mut ram = Ram::mapped();
    for size in [0, 63, BUFFER_BYTES + 1] {
        assert_eq!(
            execute(&mut ram, &mut vec![0; size], false, 48),
            Err(Error::Bounds)
        );
    }
    let (done, result) = transfer(
        &mut ram,
        0x1000,
        u64::MAX,
        &mut [0; 2],
        false,
        48,
        (true, false),
    );
    assert_eq!((done, result), (0, Err(Error::Bounds)));
    for offset in [0, 8, 12, 32, 36, 44] {
        let mut request = packet(
            WRITE,
            42,
            0x1000,
            &[Item {
                address: 0,
                bytes: vec![1],
            }],
        )
        .unwrap();
        request[offset] ^= 0x80;
        assert!(execute(&mut ram, &mut request, false, 48).is_err());
    }
    assert_eq!(ram.writes, 0);
}

#[test]
fn cli_rejects_bad_hex_and_oversized_batches_before_allocating_transport() {
    for arguments in [vec!["0", "123"], vec!["0", ""], vec!["0", "zz"], vec!["0"]] {
        assert!(
            parse_items(
                WRITE,
                &arguments.into_iter().map(String::from).collect::<Vec<_>>()
            )
            .is_err()
        );
    }
    assert!(parse_items(READ, &["0".into(), "0xffffffffffffffff".into()]).is_err());
    assert!(parse_items(READ, &["0".into(), "65536".into()]).is_err());
    assert_eq!(
        parse_items(WRITE, &["0x1234".into(), "0x00Fe".into()]).unwrap()[0].bytes,
        vec![0, 254]
    );
    let items: Vec<_> = (0..MAX_ITEMS)
        .map(|index| Item {
            address: index as u64,
            bytes: vec![1],
        })
        .collect();
    assert!(packet(WRITE, 42, 0x1000, &items).is_ok());
}

#[test]
fn rsds_identity_uses_symbol_server_guid_and_hexadecimal_age() {
    let mut bytes = b"RSDS".to_vec();
    bytes.extend_from_slice(&0x12345678u32.to_le_bytes());
    bytes.extend_from_slice(&0xabcdu16.to_le_bytes());
    bytes.extend_from_slice(&0xef01u16.to_le_bytes());
    bytes.extend_from_slice(&[2, 3, 4, 5, 6, 7, 8, 9]);
    bytes.extend_from_slice(&16u32.to_le_bytes());
    bytes.extend_from_slice(b"C:\\symbols\\ntkrnlmp.pdb\0");
    let identity = crate::symbols::Identity::parse(&bytes).unwrap();
    assert_eq!(identity.key(), "12345678ABCDEF01020304050607080910");
    assert_eq!(identity.name, "ntkrnlmp.pdb");
    bytes.truncate(24);
    bytes.extend_from_slice(b"..pdb\0");
    assert!(crate::symbols::Identity::parse(&bytes).is_err());
}

#[test]
fn resident_memory_dispatch_contains_one_call_and_no_guest_lifecycle_transition() {
    let assembly = include_str!("../src/vmx/asm/control.S");
    let handler = assembly
        .split(".Lresident_dispatch_memory:")
        .nth(1)
        .unwrap()
        .split(".Lresident_memory_vmread_failed:")
        .next()
        .unwrap();
    assert_eq!(handler.matches("call r13").count(), 1);
    assert!(!handler.contains("vmcall"));
    assert!(!handler.contains("vmxoff"));
}

fn windows_layout() -> SoftPteLayout {
    SoftPteLayout {
        transition: 1 << 11,
        prototype: 1 << 10,
        software_protection: 31 << 5,
        transition_protection: 31 << 5,
        transition_frame: 0x000f_ffff_ffff_f000,
        prototype_address: 0xffff_ffff_ffff_0000,
        prototype_read_only: 2,
        pagefile: 0xffff_ffff_0000_f000,
        hardware_copy_on_write: 1 << 9,
        prototype_protection: 31 << 5,
    }
}

fn soft_packet(operation: u32, address: u64, length: usize) -> Vec<u8> {
    let mut request = packet(
        operation,
        42,
        0x1000,
        &[Item {
            address,
            bytes: vec![9; length],
        }],
    )
    .unwrap();
    for (index, field) in windows_layout().fields().iter().enumerate() {
        request[80 + index * 8..88 + index * 8].copy_from_slice(&field.to_le_bytes());
    }
    request
}

#[test]
fn vad_confirmed_zero_entries_respect_protection_and_never_create_physical_pages() {
    for (operation, protection, expected) in [
        (READ, 4u32, ROAD_STATUS_DEMAND_ZERO),
        (WRITE, 4, Error::DemandZeroWrite as u32),
        (READ, 0, Error::Permission as u32),
        (READ, 20, Error::Permission as u32),
    ] {
        let mut ram = Ram::mapped();
        ram.entry(0x2000, 0, 0);
        let mut request = soft_packet(operation, 0, 32);
        request[HEADER_BYTES + 16..HEADER_BYTES + 20].copy_from_slice(&1u32.to_le_bytes());
        request[HEADER_BYTES + 20..HEADER_BYTES + 24].copy_from_slice(&protection.to_le_bytes());
        execute(&mut ram, &mut request, false, 48).unwrap();
        assert_eq!(word(&request, HEADER_BYTES + 16), expected);
        assert_eq!(ram.writes, 0);
        if operation == READ && protection == 4 {
            assert_eq!(word(&request, HEADER_BYTES + 20), 32);
            assert!(
                request[HEADER_BYTES + ITEM_BYTES..]
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
    }
}

#[test]
fn demand_zero_reads_only_explicit_committed_protection_and_denies_writes() {
    let mut ram = Ram::mapped();
    ram.entry(0x4000, 0, 4 << 5);
    let mut request = soft_packet(READ, 0, 4098);
    execute(&mut ram, &mut request, false, 48).unwrap();
    assert_eq!(word(&request, HEADER_BYTES + 16), ROAD_STATUS_DEMAND_ZERO);
    assert_eq!(word(&request, HEADER_BYTES + 20), 4098);
    assert!(
        request[HEADER_BYTES + ITEM_BYTES..]
            .iter()
            .all(|byte| *byte == 0)
    );
    let mut request = soft_packet(WRITE, 0, 1);
    execute(&mut ram, &mut request, false, 48).unwrap();
    assert_eq!(
        word(&request, HEADER_BYTES + 16),
        Error::DemandZeroWrite as u32
    );
    assert_eq!(ram.writes, 0);
    for entry in [0, (4 << 5) | (1 << 32), (4 << 5) | 8, 16 << 5] {
        ram.entry(0x4000, 0, entry);
        let mut request = soft_packet(READ, 0, 1);
        execute(&mut ram, &mut request, false, 48).unwrap();
        assert_ne!(word(&request, HEADER_BYTES + 16), ROAD_STATUS_DEMAND_ZERO);
        assert_eq!(word(&request, HEADER_BYTES + 20), 0);
    }
}

#[test]
fn transition_reads_use_the_pdb_frame_mask_and_preserve_read_protection() {
    let mut ram = Ram::mapped();
    ram.pages.get_mut(&0x10000).unwrap()[0] = 73;
    ram.entry(0x4000, 0, 0x10000 | (1 << 11) | (4 << 5));
    let mut request = soft_packet(READ, 0, 1);
    execute(&mut ram, &mut request, false, 48).unwrap();
    assert_eq!(word(&request, HEADER_BYTES + 16), 0);
    assert_eq!(request[HEADER_BYTES + ITEM_BYTES], 73);
    let mut request = soft_packet(WRITE, 0, 1);
    execute(&mut ram, &mut request, false, 48).unwrap();
    assert_eq!(word(&request, HEADER_BYTES + 16), Error::Permission as u32);
    assert_eq!(ram.writes, 0);
}

#[test]
fn prototype_reads_use_kernel_cr3_when_the_user_root_has_no_kernel_mapping() {
    let mut ram = Ram::mapped();
    for page in [0x5000, 0x6000, 0x7000, 0x8000, 0x9000] {
        ram.page(page);
    }
    ram.entry(0x5000, 511, 0x6007);
    ram.entry(0x6000, 0, 0x7007);
    ram.entry(0x7000, 0, 0x8007);
    ram.entry(0x8000, 0, 0x9007);
    ram.entry(0x9000, 0, 0x10001);
    ram.entry(0x4000, 0, (0xffff_ff80_0000_0000u64 << 16) | (1 << 10));
    ram.pages.get_mut(&0x10000).unwrap()[0] = 91;
    let mut request = soft_packet(READ, 0, 1);
    request[64..72].copy_from_slice(&0x5000u64.to_le_bytes());
    execute(&mut ram, &mut request, false, 48).unwrap();
    assert_eq!(word(&request, HEADER_BYTES + 16), 0);
    assert_eq!(request[HEADER_BYTES + ITEM_BYTES], 91);
    let mut request = soft_packet(WRITE, 0, 1);
    request[64..72].copy_from_slice(&0x5000u64.to_le_bytes());
    execute(&mut ram, &mut request, false, 48).unwrap();
    assert_eq!(word(&request, HEADER_BYTES + 16), Error::CopyOnWrite as u32);
}

#[test]
fn kva_shadow_selects_user_and_kernel_roots_per_item_in_the_same_batch() {
    let mut ram = Ram::mapped();
    ram.page(0x5000);
    ram.entry(0x5000, 511, 0x2007);
    ram.pages.get_mut(&0x10000).unwrap()[0] = 51;
    let mut request = packet(
        READ,
        42,
        0x5000,
        &[
            Item {
                address: 0,
                bytes: vec![0; 1],
            },
            Item {
                address: 0xffff_ff80_0000_0000,
                bytes: vec![0; 1],
            },
        ],
    )
    .unwrap();
    request[64..72].copy_from_slice(&0x5000u64.to_le_bytes());
    request[72..80].copy_from_slice(&0x1000u64.to_le_bytes());
    execute(&mut ram, &mut request, false, 48).unwrap();
    for index in 0..2 {
        assert_eq!(word(&request, HEADER_BYTES + index * ITEM_BYTES + 16), 0);
    }
    assert_eq!(&request[HEADER_BYTES + 2 * ITEM_BYTES..], &[51, 51]);
}

#[test]
fn optional_installed_kernel_pdb_validation() {
    let Some(path) = std::env::var_os("NEO_TEST_KERNEL_IMAGE") else {
        return;
    };
    let cache =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../builds/symbol-tests");
    let symbols = crate::symbols::KernelSymbols::load(std::path::Path::new(&path), &cache).unwrap();
    assert!(symbols.soft_layout.validate());
}

#[repr(align(4096))]
struct Page([u8; 4096]);

struct Machine {
    pages: Vec<Box<Page>>,
    host: u64,
    ept: u64,
}

fn resident_bitmap(
    machine: &mut Machine,
    mut environment: access::resident::Environment,
    buffer: u64,
    start: u64,
    count: usize,
    enabled: bool,
) -> Vec<u8> {
    let request = crate::memory::bitmap_packet(start, count).unwrap();
    assert!(request.len() <= 4096);
    unsafe {
        std::ptr::copy_nonoverlapping(request.as_ptr(), buffer as *mut u8, request.len());
    }
    machine.host_map_all();
    if enabled {
        environment.ept |= 1 << 6;
    }
    let mut scratch = vec![0; BUFFER_BYTES];
    assert_eq!(
        unsafe {
            access::resident::memory_entry(
                scratch.as_mut_ptr(),
                0x1000,
                request.len(),
                &environment,
            )
        },
        0
    );
    unsafe { std::slice::from_raw_parts(buffer as *const u8, request.len()) }.to_vec()
}

#[test]
fn resident_ad_bitmap_reads_leaf_bits_and_preserves_hardware_state() {
    let request = packet(INFO, 0, 0, &[]).unwrap();
    let (mut machine, environment, buffer, _) = Machine::setup(&request);
    for (address, flags) in [(0, 0x100), (4096, 0x300), (32768, 0x300)] {
        machine.map(machine.ept, address, address, 0x37 | flags);
    }
    // Parent A bits do not imply that every child page was accessed.
    unsafe {
        (*(machine.ept as *mut u64)) |= 0x100;
    }
    let response = resident_bitmap(&mut machine, environment, buffer, 0, 9, true);
    assert_eq!(word(&response, 40), 0);
    assert_eq!(word(&response, 72), AD_ENABLED);
    assert_eq!(&response[HEADER_BYTES..], &[3, 1, 2, 1]);
    let response_again = resident_bitmap(&mut machine, environment, buffer, 0, 9, true);
    assert_eq!(&response_again[HEADER_BYTES..], &[3, 1, 2, 1]);
}

#[test]
fn resident_ad_bitmap_excludes_decoys_mmio_and_absent_pages() {
    let request = packet(INFO, 0, 0, &[]).unwrap();
    let (mut machine, environment, buffer, _) = Machine::setup(&request);
    for (address, physical, flags) in [
        (0, 4096, 0x337),
        (4096, 4096, 0x307),
        (8192, 8192, 0x330),
        (12288, 12288, 0x337),
    ] {
        machine.map(machine.ept, address, physical, flags);
    }
    let response = resident_bitmap(&mut machine, environment, buffer, 0, 4, true);
    assert_eq!(word(&response, 40), 0);
    assert_eq!(&response[HEADER_BYTES..], &[8, 8]);
}

#[test]
fn resident_ad_bitmap_reports_conservative_large_leaf_coverage_across_boundaries() {
    for shift in [21, 30] {
        let page_size = 1u64 << shift;
        let request = packet(INFO, 0, 0, &[]).unwrap();
        let (mut machine, environment, buffer, _) = Machine::setup(&request);
        for (address, flags) in [(0, 0x100), (page_size, 0x200)] {
            machine.map(machine.ept, address, address, 0x37);
            let mut table = machine.ept;
            for level in [39, 30, 21] {
                let pointer = (table + ((address >> level) & 511) * 8) as *mut u64;
                if level == shift {
                    unsafe {
                        pointer.write(address | 0xb7 | flags);
                    }
                    break;
                }
                table = unsafe { pointer.read() } & 0x000f_ffff_ffff_f000;
            }
        }
        let response =
            resident_bitmap(&mut machine, environment, buffer, page_size - 4096, 4, true);
        assert_eq!(word(&response, 40), 0);
        assert_eq!(word(&response, 72), AD_ENABLED | AD_LARGE_PAGE);
        assert_eq!(&response[HEADER_BYTES..], &[1, 14]);
    }
}

#[test]
fn resident_ad_bitmap_rejects_unsupported_hardware() {
    let request = packet(INFO, 0, 0, &[]).unwrap();
    let (mut machine, environment, buffer, _) = Machine::setup(&request);
    let response = resident_bitmap(&mut machine, environment, buffer, 0, 1, false);
    assert_eq!(word(&response, 40), Error::Unsupported as u32);
    assert_eq!(word(&response, 72), 0);
}

#[test]
fn resident_info_ad_capability_matches_the_active_ept_pointer() {
    for enabled in [false, true] {
        let request = packet(INFO, 0, 0, &[]).unwrap();
        let (_machine, mut environment, buffer, _) = Machine::setup(&request);
        if enabled {
            environment.ept |= 1 << 6;
        }
        let mut scratch = vec![0; BUFFER_BYTES];
        assert_eq!(
            unsafe {
                access::resident::memory_entry(
                    scratch.as_mut_ptr(),
                    0x1000,
                    request.len(),
                    &environment,
                )
            },
            0
        );
        let response = unsafe { std::slice::from_raw_parts(buffer as *const u8, request.len()) };
        assert_eq!(word(response, 40), 0);
        assert_eq!(word(response, 72), if enabled { AD_ENABLED } else { 0 });
    }
}

#[test]
fn ad_bitmap_validates_ranges_sizes_and_padding_before_access() {
    assert_eq!(ad_bitmap_length(0, AD_MAX_PAGES), Ok(BUFFER_BYTES));
    for (start, count) in [
        (1, 1),
        (0, 0),
        (0, AD_MAX_PAGES + 1),
        (u64::MAX & !4095, 1),
        ((1 << 48) - 4096, 2),
    ] {
        assert!(crate::memory::bitmap_packet(start, count).is_err());
    }
    let mut ram = Ram::default();
    let mut request = crate::memory::bitmap_packet(0, 9).unwrap();
    let malformed_length = (request.len() - 1) as u32;
    request[36..40].copy_from_slice(&malformed_length.to_le_bytes());
    assert_eq!(
        execute(&mut ram, &mut request, false, 48),
        Err(Error::Format)
    );
    let mut request = crate::memory::bitmap_packet(0, 9).unwrap();
    request[32..36].copy_from_slice(&17u32.to_le_bytes());
    assert_eq!(
        execute(&mut ram, &mut request, false, 48),
        Err(Error::Bounds)
    );
    let mut request = crate::memory::bitmap_packet(1 << 36, 1).unwrap();
    assert_eq!(
        execute(&mut ram, &mut request, false, 36),
        Err(Error::Bounds)
    );
    assert_eq!(ram.writes, 0);
}

impl Machine {
    fn allocate(&mut self) -> u64 {
        let page = Box::new(Page([0; 4096]));
        let address = page.0.as_ptr() as u64;
        self.pages.push(page);
        address
    }

    fn map(&mut self, root: u64, address: u64, physical: u64, flags: u64) {
        let mut table = root;
        for shift in [39, 30, 21, 12] {
            let pointer = (table + ((address >> shift) & 511) * 8) as *mut u64;
            if shift == 12 {
                unsafe {
                    pointer.write(physical | flags);
                }
                return;
            }
            let mut entry = unsafe { pointer.read() };
            if entry == 0 {
                entry = self.allocate() | 7;
                unsafe {
                    pointer.write(entry);
                }
            }
            table = entry & 0x000f_ffff_ffff_f000;
        }
    }

    fn host_map_all(&mut self) {
        let mut index = 0;
        while index < self.pages.len() {
            let address = self.pages[index].0.as_ptr() as u64;
            self.map(self.host, address, address, 3);
            index += 1;
        }
    }

    fn setup(request: &[u8]) -> (Self, access::resident::Environment, u64, u64) {
        let mut machine = Self {
            pages: Vec::new(),
            host: 0,
            ept: 0,
        };
        machine.host = machine.allocate();
        machine.ept = machine.allocate();
        let caller_root = machine.allocate();
        let target_root = machine.allocate();
        let buffer = machine.allocate();
        let target = machine.allocate();
        unsafe {
            std::ptr::copy_nonoverlapping(request.as_ptr(), buffer as *mut u8, request.len());
            (target as *mut u8).write(101);
        }
        machine.map(caller_root, 0x1000, buffer, 7);
        machine.map(target_root, 0, target, 7);
        let mut index = 0;
        while index < machine.pages.len() {
            let address = machine.pages[index].0.as_ptr() as u64;
            machine.map(machine.ept, address, address, 3 | (6 << 3));
            index += 1;
        }
        machine.host_map_all();
        let environment = access::resident::Environment {
            caller_cr3: caller_root,
            guest_cr4: 0,
            ept: machine.ept,
            host_cr3: machine.host,
            syscall: 0xffff_f800_1234_0000,
            kernel_cr3: target_root,
            root_history: 0,
            tracking_session: 0,
            interception_session: 0,
            boot_context: 0,
            synchronize: 0,
            physical_bits: 52,
        };
        unsafe {
            (buffer as *mut u8)
                .add(16)
                .cast::<u64>()
                .write_unaligned(target_root);
        }
        (machine, environment, buffer, target)
    }
}

struct TrackingBarrier {
    operations: Vec<u64>,
    root: u64,
    target: u64,
}

unsafe extern "efiapi" fn tracking_barrier(context: u64, operation: u64) -> u64 {
    let barrier = unsafe { &mut *(context as *mut TrackingBarrier) };
    barrier.operations.push(operation);
    if operation == 1 {
        let leaf = ept_pointer(barrier.root, barrier.target, 12);
        assert_eq!(unsafe { leaf.read() } & 0x380, 0);
    }
    1
}

fn ept_pointer(root: u64, address: u64, level: u32) -> *mut u64 {
    let mut table = root;
    for shift in [39, 30, 21, 12] {
        let pointer = (table + ((address >> shift) & 511) * 8) as *mut u64;
        if shift == level { return pointer; }
        let entry = unsafe { pointer.read() };
        assert_eq!(entry & 128, 0);
        table = entry & 0x000f_ffff_ffff_f000;
    }
    panic!("invalid EPT level");
}

fn native_tracking_request(environment: &access::resident::Environment, buffers: &[u64], request: &[u8]) -> Vec<u8> {
    for (index, bytes) in request.chunks(4096).enumerate() {
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffers[index] as *mut u8, bytes.len()); }
    }
    let mut scratch = vec![0; BUFFER_BYTES];
    assert_eq!(unsafe {
        access::resident::memory_entry(scratch.as_mut_ptr(), 0x1000, request.len(), environment)
    }, 0);
    let mut response = Vec::with_capacity(request.len());
    for (index, bytes) in request.chunks(4096).enumerate() {
        response.extend_from_slice(unsafe { std::slice::from_raw_parts(buffers[index] as *const u8, bytes.len()) });
    }
    response
}

#[test]
fn resident_tracking_splits_large_ept_leaves_and_captures_exact_dirty_pages() {
    #[repr(align(4096))]
    struct Pool([u8; 8192]);
    for shift in [21, 30] {
        let request = packet(INFO, 0, 0, &[]).unwrap();
        let (mut machine, mut environment, buffer, target) = Machine::setup(&request);
        let second_buffer = machine.allocate();
        machine.map(environment.caller_cr3, 0x2000, second_buffer, 7);
        machine.map(machine.ept, second_buffer, second_buffer, 0x37);
        let pool = Box::new(Pool([0; 8192]));
        let pool_address = pool.0.as_ptr() as u64;
        for address in [pool_address, pool_address + 4096] {
            machine.map(machine.host, address, address, 3);
        }
        machine.host_map_all();
        let attributes = 0x337 | (6 << 52) | (1 << 63);
        let large = ept_pointer(machine.ept, target, shift);
        let page_size = 1u64 << shift;
        unsafe { large.write((target & !(page_size - 1)) | attributes | 128); }
        let layout = std::alloc::Layout::new::<crate::memory::tracking::Session>();
        let pointer = unsafe { std::alloc::alloc_zeroed(layout) as *mut crate::memory::tracking::Session };
        assert!(!pointer.is_null());
        let mut session = unsafe { Box::from_raw(pointer) };
        session.initialize(pool_address, 2);
        let mut barrier = TrackingBarrier { operations: Vec::new(), root: machine.ept, target };
        environment.ept |= 1 << 6;
        environment.tracking_session = pointer as u64;
        environment.boot_context = &mut barrier as *mut TrackingBarrier as u64;
        environment.synchronize = tracking_barrier as *const () as u64;
        let mut start = crate::memory::tracking_packet(AD_START, 0, 1).unwrap();
        start[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&environment.kernel_cr3.to_le_bytes());
        let started = native_tracking_request(&environment, &[buffer], &start);
        assert_eq!(word(&started, 40), 0);
        assert_eq!(barrier.operations, [0, 1, 2]);
        assert_eq!(session.pool.used, if shift == 21 { 1 } else { 2 });
        let leaf = ept_pointer(machine.ept, target, 12);
        assert_eq!(unsafe { leaf.read() }, target | (attributes & !0x300));
        let neighbor = ept_pointer(machine.ept, target ^ 4096, 12);
        assert_eq!(unsafe { neighbor.read() }, (target ^ 4096) | attributes);
        unsafe {
            (target as *mut u8).add(4095).write(87);
            *leaf |= 0x300;
        }
        let id = quad(&started, 80);
        let stop = crate::memory::tracking_packet(AD_STOP, id, 0).unwrap();
        let stopped = native_tracking_request(&environment, &[buffer], &stop);
        assert_eq!(word(&stopped, 40), 0);
        assert_eq!(barrier.operations, [0, 1, 2, 0, 2]);
        let fetch = crate::memory::tracking_packet(AD_FETCH, id, 1).unwrap();
        let fetched = native_tracking_request(&environment, &[buffer, second_buffer], &fetch);
        assert_eq!(word(&fetched, 40), 0);
        let record = &fetched[HEADER_BYTES..];
        assert_eq!(quad(record, 16), target);
        assert_eq!(word(record, 48), TRACK_ACCESSED | TRACK_DIRTY | TRACK_DUMP_VALID | TRACK_HASH_CHANGED);
        assert_eq!(record[120], 101);
        assert_eq!(record[TRACK_RECORD_BYTES - 1], 87);
        crate::memory::verify_dump(record).unwrap();
    }
}

#[test]
fn resident_interception_transport_builds_a_private_root_in_validated_host_storage() {
    let request = packet(INFO, 0, 0, &[]).unwrap();
    let (mut machine, mut environment, buffer, target) = Machine::setup(&request);
    machine.map(machine.ept, target, target, 0x37);
    let pool_bytes = intercept_storage_pages(1) * 4096;
    let pool_layout = std::alloc::Layout::from_size_align(pool_bytes, 4096).unwrap();
    let pool = unsafe { std::alloc::alloc_zeroed(pool_layout) };
    assert!(!pool.is_null());
    for index in 0..pool_bytes / 4096 {
        let address = pool as u64 + index as u64 * 4096;
        machine.map(machine.host, address, address, 3);
    }
    machine.host_map_all();
    let session_layout = std::alloc::Layout::new::<crate::memory::interception::Session>();
    let mut session = unsafe {
        Box::from_raw(std::alloc::alloc_zeroed(session_layout).cast::<crate::memory::interception::Session>())
    };
    session.initialize(pool as u64, 1);
    let mut barrier = TrackingBarrier { operations: Vec::new(), root: machine.ept, target };
    environment.interception_session = &*session as *const _ as u64;
    environment.boot_context = &mut barrier as *mut _ as u64;
    environment.synchronize = tracking_barrier as *const () as u64;
    let install = crate::memory::interception_packet(&[
        "hook".into(), "install".into(), format!("{:#x}", environment.kernel_cr3), "8".into(), "cc".into(),
    ]).unwrap();
    let installed = native_tracking_request(&environment, &[buffer], &install);
    assert_eq!(word(&installed, 40), 0);
    assert_eq!(barrier.operations, [0, 1, 2]);
    let configuration = unsafe { &*session.configuration.get() };
    let shadow = unsafe { ept_pointer(configuration.ept, target, 12).read() } & 0x000f_ffff_ffff_f000;
    assert_eq!(unsafe { (shadow as *const u8).add(8).read() }, 0xcc);
    assert_eq!(unsafe { (target as *const u8).add(8).read() }, 0);
    let edit = packet(WRITE, 0, environment.kernel_cr3, &[Item { address: 9, bytes: vec![0x42] }]).unwrap();
    let edited = native_tracking_request(&environment, &[buffer], &edit);
    assert_eq!(word(&edited, HEADER_BYTES + 16), 0);
    assert_eq!(unsafe { (target as *const u8).add(8).read() }, 0);
    assert_eq!(unsafe { (shadow as *const u8).add(8).read() }, 0xcc);
    assert_eq!(unsafe { (shadow as *const u8).add(9).read() }, 0x42);
    let status = crate::memory::interception_packet(&["hook".into(), "status".into()]).unwrap();
    let response = native_tracking_request(&environment, &[buffer], &status);
    assert_eq!(word(&response, 104), 1);
    assert_eq!(word(&response, 44), 1);
    assert_eq!(quad(&response, 48), environment.caller_cr3);
    assert_eq!(word(&response, 112), INTERCEPT_ACTIVE);
    let token = quad(&response, 80).to_string();
    let remove = crate::memory::interception_packet(&["hook".into(), "remove".into(), token]).unwrap();
    let removed = native_tracking_request(&environment, &[buffer], &remove);
    assert_eq!(word(&removed, 112), INTERCEPT_DISABLED);
    drop(session);
    unsafe { std::alloc::dealloc(pool, pool_layout); }
}

#[test]
fn resident_info_returns_observed_roots_without_treating_them_as_validated() {
    let mut request = packet(INFO, 0, 0, &[]).unwrap();
    request.resize(INFO_BYTES, 0);
    request[36..40].copy_from_slice(&(INFO_BYTES as u32).to_le_bytes());
    let (_machine, mut environment, buffer, _) = Machine::setup(&request);
    let mut history = [0u64; ROOT_HISTORY_COUNT];
    history[2] = 0x123000;
    history[7] = 0x456000;
    environment.root_history = history.as_ptr() as u64;
    let mut scratch = vec![0; BUFFER_BYTES];
    assert_eq!(
        unsafe {
            access::resident::memory_entry(
                scratch.as_mut_ptr(),
                0x1000,
                request.len(),
                &environment,
            )
        },
        0
    );
    let response = unsafe { std::slice::from_raw_parts(buffer as *const u8, request.len()) };
    assert_eq!(word(response, 40), 0);
    assert_eq!(quad(response, HEADER_BYTES + 2 * 8), history[2]);
    assert_eq!(quad(response, HEADER_BYTES + 7 * 8), history[7]);
    assert_eq!(quad(response, HEADER_BYTES), 0);
}

#[test]
fn resident_transport_copies_the_packet_once_and_returns_item_results_and_identity() {
    let request = packet(
        READ,
        42,
        0x1000,
        &[Item {
            address: 0,
            bytes: vec![0],
        }],
    )
    .unwrap();
    let (_machine, environment, buffer, _) = Machine::setup(&request);
    let mut scratch = vec![0; BUFFER_BYTES];
    let status = unsafe {
        access::resident::memory_entry(scratch.as_mut_ptr(), 0x1000, request.len(), &environment)
    };
    assert_eq!(status, 0);
    let response = unsafe { std::slice::from_raw_parts(buffer as *const u8, request.len()) };
    assert_eq!(word(response, 40), 0);
    assert_eq!(word(response, HEADER_BYTES + 20), 1);
    assert_eq!(response[HEADER_BYTES + ITEM_BYTES], 101);
    assert_eq!(quad(response, 56), environment.syscall);
}

#[test]
fn resident_transport_denies_ept_decoys_mmio_and_read_only_target_pages() {
    for (operation, flags, decoy, expected) in [
        (READ, 3 | (6 << 3), true, Error::Permission),
        (READ, 3, false, Error::Permission),
        (WRITE, 1 | (6 << 3), false, Error::Permission),
    ] {
        let request = packet(
            operation,
            42,
            0x1000,
            &[Item {
                address: 0,
                bytes: vec![9],
            }],
        )
        .unwrap();
        let (mut machine, environment, buffer, target) = Machine::setup(&request);
        let physical = if decoy { buffer } else { target };
        machine.map(machine.ept, target, physical, flags);
        let mut scratch = vec![0; BUFFER_BYTES];
        let status = unsafe {
            access::resident::memory_entry(
                scratch.as_mut_ptr(),
                0x1000,
                request.len(),
                &environment,
            )
        };
        assert_eq!(status, 0);
        let response = unsafe { std::slice::from_raw_parts(buffer as *const u8, request.len()) };
        assert_eq!(word(response, HEADER_BYTES + 16), expected as u32);
        assert_eq!(word(response, HEADER_BYTES + 20), 0);
        assert_eq!(unsafe { (target as *const u8).read() }, 101);
    }
}

#[test]
fn resident_transport_preflights_response_write_access_before_touching_target_memory() {
    let request = packet(
        WRITE,
        42,
        0x1000,
        &[Item {
            address: 0,
            bytes: vec![9],
        }],
    )
    .unwrap();
    let (mut machine, environment, buffer, target) = Machine::setup(&request);
    machine.map(environment.caller_cr3, 0x1000, buffer, 5);
    let mut scratch = vec![0; BUFFER_BYTES];
    let status = unsafe {
        access::resident::memory_entry(scratch.as_mut_ptr(), 0x1000, request.len(), &environment)
    };
    assert_eq!(status, Error::Permission as u64);
    assert_eq!(unsafe { (target as *const u8).read() }, 101);
}
