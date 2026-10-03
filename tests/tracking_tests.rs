use crate::memory::access::{PhysicalMemory, execute, page_mapping};
use crate::memory::{dump_tracking, tracking_packet, verify_dump};
use crate::protocol::memory::*;
use crate::memory::tracking::{Session, TablePool, TrackingMemory};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

struct Memory {
    pages: BTreeMap<u64, Vec<u8>>,
    leaves: BTreeMap<u64, u64>,
    events: Vec<&'static str>,
    parked: bool,
    fail_barrier: bool,
    fail_split: Option<u64>,
    ticks: u64,
    session: *mut Session,
}

impl Memory {
    fn new() -> Self {
        let mut memory = Self {
            pages: BTreeMap::new(),
            leaves: BTreeMap::new(),
            events: Vec::new(),
            parked: false,
            fail_barrier: false,
            fail_split: None,
            ticks: 100,
            session: std::ptr::null_mut(),
        };
        for address in [0x1000, 0x2000, 0x3000, 0x4000, 0x10000, 0x11000, 0x12000] {
            memory.pages.insert(address, vec![0; 4096]);
        }
        memory.entry(0x1000, 0, 0x2007);
        memory.entry(0x2000, 0, 0x3007);
        memory.entry(0x3000, 0, 0x4007);
        memory.entry(0x4000, 0, 0x10007);
        memory.entry(0x4000, 1, 0x11007);
        memory.entry(0x4000, 2, 0x12007);
        for address in [0x10000, 0x11000, 0x12000] {
            memory.leaves.insert(address, address | 0x337);
        }
        memory
    }

    fn entry(&mut self, table: u64, index: usize, value: u64) {
        self.pages.get_mut(&table).unwrap()[index * 8..index * 8 + 8]
            .copy_from_slice(&value.to_le_bytes());
    }
}

impl PhysicalMemory for Memory {
    fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), Error> {
        let offset = address as usize & 4095;
        let page = self.pages.get(&(address & !4095)).ok_or(Error::Unmapped)?;
        bytes.copy_from_slice(
            page.get(offset..offset + bytes.len())
                .ok_or(Error::Bounds)?,
        );
        Ok(())
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Error> {
        let offset = address as usize & 4095;
        let page = self
            .pages
            .get_mut(&(address & !4095))
            .ok_or(Error::Unmapped)?;
        page.get_mut(offset..offset + bytes.len())
            .ok_or(Error::Bounds)?
            .copy_from_slice(bytes);
        Ok(())
    }
    fn track(&mut self, packet: &mut [u8], la57: bool, physical_bits: u32) -> Result<(), Error> {
        unsafe { crate::memory::tracking::execute(self.session, self, packet, la57, physical_bits) }
    }
}

impl TrackingMemory for Memory {
    fn quiesce(&mut self) -> Result<(), Error> {
        self.events.push("park");
        if self.fail_barrier {
            return Err(Error::Busy);
        }
        assert!(!self.parked);
        self.parked = true;
        self.ticks += 100;
        Ok(())
    }
    fn flush(&mut self) {
        assert!(self.parked);
        self.events.push("invept");
    }
    fn resume(&mut self) {
        assert!(self.parked);
        self.events.push("resume");
        self.parked = false;
    }
    fn prepare_leaf(&mut self, address: u64, pool: &mut TablePool) -> Result<u64, Error> {
        assert!(self.parked);
        self.events.push("split");
        if self.fail_split == Some(address) {
            return Err(Error::Capacity);
        }
        pool.used += 1;
        self.leaves
            .contains_key(&address)
            .then_some(address)
            .ok_or(Error::Permission)
    }
    fn leaf_value(&self, pointer: u64) -> u64 {
        assert!(self.parked);
        self.leaves[&pointer]
    }
    fn clear_leaf(&mut self, pointer: u64) {
        assert!(self.parked);
        self.events.push("clear");
        *self.leaves.get_mut(&pointer).unwrap() &= !0x300;
    }
    fn clock(&self) -> u64 {
        assert!(self.parked);
        self.ticks
    }
}

fn session() -> Box<Session> {
    let layout = std::alloc::Layout::new::<Session>();
    let pointer = unsafe { std::alloc::alloc_zeroed(layout) as *mut Session };
    assert!(!pointer.is_null());
    let mut session = unsafe { Box::from_raw(pointer) };
    session.initialize(0, 2048);
    session
}

fn start(memory: &mut Memory, count: usize) -> Result<Vec<u8>, Error> {
    let mut request = tracking_packet(AD_START, 0, count).unwrap();
    for index in 0..count {
        let offset = HEADER_BYTES + index * TRACK_TARGET_BYTES;
        request[offset..offset + 8].copy_from_slice(&0x1000u64.to_le_bytes());
        request[offset + 8..offset + 16].copy_from_slice(&(index as u64 * 4096).to_le_bytes());
    }
    execute(memory, &mut request, false, 48)?;
    Ok(request)
}

fn command(memory: &mut Memory, operation: u32, id: u64, count: usize) -> Result<Vec<u8>, Error> {
    let mut request = tracking_packet(operation, id, count).unwrap();
    execute(memory, &mut request, false, 48)?;
    Ok(request)
}

#[test]
fn session_clears_before_invept_and_measures_only_the_active_interval() {
    let mut session = session();
    let mut memory = Memory::new();
    memory.session = &mut *session;
    let response = start(&mut memory, 3).unwrap();
    let id = quad(&response, 80);
    assert_eq!(word(&response, 104), TRACK_ACTIVE);
    assert_eq!(quad(&response, 88), 200);
    assert_eq!(
        memory.events,
        [
            "park", "split", "split", "split", "clear", "clear", "clear", "invept", "resume"
        ]
    );
    assert!(memory.leaves.values().all(|entry| entry & 0x300 == 0));
    memory.events.clear();
    *memory.leaves.get_mut(&0x10000).unwrap() |= 0x100;
    *memory.leaves.get_mut(&0x11000).unwrap() |= 0x300;
    memory.pages.get_mut(&0x11000).unwrap()[4095] = 99;
    let stopped = command(&mut memory, AD_STOP, id, 0).unwrap();
    assert_eq!(word(&stopped, 104), TRACK_STOPPED);
    assert_eq!(quad(&stopped, 96), 300);
    assert_eq!(memory.events, ["park", "resume"]);
    // Later writes must not modify a frozen dump or its hash.
    memory.pages.get_mut(&0x11000).unwrap()[4095] = 101;
    let fetched = command(&mut memory, AD_FETCH, id, 3).unwrap();
    let accessed = &fetched[HEADER_BYTES..HEADER_BYTES + TRACK_RECORD_BYTES];
    let dirty = &fetched[HEADER_BYTES + TRACK_RECORD_BYTES..HEADER_BYTES + TRACK_RECORD_BYTES * 2];
    let clean = &fetched[HEADER_BYTES + TRACK_RECORD_BYTES * 2..];
    assert_eq!(word(accessed, 48), TRACK_ACCESSED);
    assert_eq!(
        word(dirty, 48),
        TRACK_ACCESSED | TRACK_DIRTY | TRACK_DUMP_VALID | TRACK_HASH_CHANGED
    );
    assert_eq!(word(clean, 48), 0);
    assert_eq!(dirty[TRACK_RECORD_BYTES - 1], 99);
    assert_eq!(&dirty[56..88], &Sha256::digest([0; 4096])[..]);
    verify_dump(dirty).unwrap();
    let mut corrupted = dirty.to_vec();
    corrupted[120] ^= 1;
    assert!(verify_dump(&corrupted).is_err());
    assert!(clean[120..].iter().all(|byte| *byte == 0));
    assert_eq!(command(&mut memory, AD_FETCH, id, 3).unwrap(), fetched);
}

#[test]
fn remapped_and_unmapped_pages_are_flagged_without_dumping_recycled_frames() {
    for entry in [0x12007, 0] {
        let mut session = session();
        let mut memory = Memory::new();
        memory.session = &mut *session;
        let id = quad(&start(&mut memory, 1).unwrap(), 80);
        *memory.leaves.get_mut(&0x10000).unwrap() |= 0x300;
        memory.entry(0x4000, 0, entry);
        command(&mut memory, AD_STOP, id, 0).unwrap();
        let fetched = command(&mut memory, AD_FETCH, id, 1).unwrap();
        let page = &fetched[HEADER_BYTES..];
        assert_eq!(
            word(page, 48),
            TRACK_ACCESSED | TRACK_DIRTY | TRACK_REMAPPED
        );
        assert_eq!(word(page, 52), Error::Remapped as u32);
        assert_ne!(quad(page, 32), quad(page, 40));
        assert!(page[88..].iter().all(|byte| *byte == 0));
    }
}

#[test]
fn guest_ad_updates_do_not_change_the_pte_fingerprint_but_upper_level_remaps_do() {
    let mut memory = Memory::new();
    let initial = page_mapping(&mut memory, 0x1000, 0, false, 48).unwrap();
    for (table, value) in [
        (0x1000, 0x2067),
        (0x2000, 0x3067),
        (0x3000, 0x4067),
        (0x4000, 0x10067),
    ] {
        memory.entry(table, 0, value);
    }
    let accessed = page_mapping(&mut memory, 0x1000, 0, false, 48).unwrap();
    assert_eq!(initial.pte_fingerprint, accessed.pte_fingerprint);
    memory.pages.insert(0x5000, memory.pages[&0x4000].clone());
    memory.entry(0x3000, 0, 0x5007);
    let moved = page_mapping(&mut memory, 0x1000, 0, false, 48).unwrap();
    assert_eq!(moved.physical_address, initial.physical_address);
    assert_ne!(moved.pte_fingerprint, initial.pte_fingerprint);
}

#[test]
fn session_lifecycle_rejects_overlap_stale_tokens_and_fetch_before_stop() {
    let mut session = session();
    let mut memory = Memory::new();
    memory.session = &mut *session;
    assert!(matches!(
        command(&mut memory, AD_STOP, 1, 0),
        Err(Error::Session)
    ));
    let id = quad(&start(&mut memory, 1).unwrap(), 80);
    assert!(matches!(start(&mut memory, 1), Err(Error::Busy)));
    assert!(matches!(
        command(&mut memory, AD_FETCH, id, 1),
        Err(Error::Session)
    ));
    assert!(matches!(
        command(&mut memory, AD_STOP, id + 1, 0),
        Err(Error::Session)
    ));
    command(&mut memory, AD_STOP, id, 0).unwrap();
    let again = command(&mut memory, AD_STOP, id, 0).unwrap();
    assert_eq!(quad(&again, 96), 300);
    command(&mut memory, AD_RELEASE, id, 0).unwrap();
    assert!(matches!(
        command(&mut memory, AD_FETCH, id, 1),
        Err(Error::Session)
    ));
    let next_id = quad(&start(&mut memory, 1).unwrap(), 80);
    assert_ne!(next_id, id);
    assert!(matches!(
        command(&mut memory, AD_STOP, id, 0),
        Err(Error::Session)
    ));
}

#[test]
fn failed_preflight_or_rendezvous_never_clears_bits_and_releases_any_acquired_barrier() {
    for barrier_failure in [true, false] {
        let mut session = session();
        let mut memory = Memory::new();
        memory.session = &mut *session;
        memory.fail_barrier = barrier_failure;
        memory.fail_split = Some(0x11000);
        let original = memory.leaves.clone();
        assert!(start(&mut memory, 2).is_err());
        assert_eq!(memory.leaves, original);
        assert!(!memory.parked);
        assert!(!memory.events.contains(&"clear"));
        if !barrier_failure {
            assert_eq!(memory.events.last(), Some(&"resume"));
        }
        let response = command(&mut memory, AD_STATUS, 0, 0).unwrap();
        assert_eq!(word(&response, 104), TRACK_IDLE);
    }
}

#[test]
fn process_enumeration_skips_sparse_holes_and_returns_only_resident_user_pages() {
    let mut memory = Memory::new();
    let mut request = tracking_packet(AD_ENUMERATE, 0, 8).unwrap();
    request[64..72].copy_from_slice(&0x1000u64.to_le_bytes());
    execute(&mut memory, &mut request, false, 48).unwrap();
    assert_eq!(word(&request, 32), 3);
    assert_eq!(quad(&request, 16), 1 << 47);
    assert_eq!(quad(&request, 72), 1 << 47);
    for index in 0..3 {
        let offset = HEADER_BYTES + index * TRACK_TARGET_BYTES;
        assert_eq!(quad(&request, offset), 0x1000);
        assert_eq!(quad(&request, offset + 8), index as u64 * 4096);
    }
    assert!(
        request[HEADER_BYTES + 3 * TRACK_TARGET_BYTES..]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn failed_stop_preserves_active_session_and_cancel_allows_a_new_session() {
    let mut session = session();
    let mut memory = Memory::new();
    memory.session = &mut *session;
    let id = quad(&start(&mut memory, 1).unwrap(), 80);
    assert!(matches!(
        command(&mut memory, AD_RELEASE, id, 0),
        Err(Error::Session)
    ));
    memory.fail_barrier = true;
    assert!(matches!(
        command(&mut memory, AD_STOP, id, 0),
        Err(Error::Busy)
    ));
    let status = command(&mut memory, AD_STATUS, 0, 0).unwrap();
    assert_eq!(word(&status, 104), TRACK_ACTIVE);
    memory.events.clear();
    let cancelled = command(&mut memory, AD_CANCEL, id, 0).unwrap();
    assert_eq!(word(&cancelled, 104), TRACK_IDLE);
    assert!(memory.events.is_empty());
    assert!(matches!(
        command(&mut memory, AD_FETCH, id, 1),
        Err(Error::Session)
    ));
    memory.fail_barrier = false;
    assert_ne!(quad(&start(&mut memory, 1).unwrap(), 80), id);
}

#[test]
fn dirty_page_with_identical_content_has_valid_dump_without_hash_change() {
    let mut session = session();
    let mut memory = Memory::new();
    memory.session = &mut *session;
    let id = quad(&start(&mut memory, 3).unwrap(), 80);
    *memory.leaves.get_mut(&0x11000).unwrap() |= 0x300;
    command(&mut memory, AD_STOP, id, 0).unwrap();
    let mut request = tracking_packet(AD_FETCH, id, 2).unwrap();
    request[64..72].copy_from_slice(&1u64.to_le_bytes());
    execute(&mut memory, &mut request, false, 48).unwrap();
    let record = &request[HEADER_BYTES..HEADER_BYTES + TRACK_RECORD_BYTES];
    assert_eq!(
        word(record, 48),
        TRACK_ACCESSED | TRACK_DIRTY | TRACK_DUMP_VALID
    );
    assert_eq!(&record[56..88], &record[88..120]);
    verify_dump(record).unwrap();
    request[64..72].copy_from_slice(&2u64.to_le_bytes());
    execute(&mut memory, &mut request, false, 48).unwrap();
    assert_eq!(word(&request, 32), 1);
    assert!(
        request[HEADER_BYTES + TRACK_RECORD_BYTES..]
            .iter()
            .all(|byte| *byte == 0)
    );
    request[64..72].copy_from_slice(&3u64.to_le_bytes());
    assert!(matches!(
        execute(&mut memory, &mut request, false, 48),
        Err(Error::Bounds)
    ));
}

fn output_directory(name: &str) -> std::path::PathBuf {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../builds/tracking-export-tests")
        .join(format!(
            "{name}-{}-{timestamp}-{sequence}",
            std::process::id()
        ))
}

#[test]
fn export_writes_exact_dirty_data_bitmaps_hashes_and_remap_metadata() {
    let mut session = session();
    let mut memory = Memory::new();
    memory.session = &mut *session;
    let id = quad(&start(&mut memory, 3).unwrap(), 80);
    *memory.leaves.get_mut(&0x10000).unwrap() |= 0x100;
    *memory.leaves.get_mut(&0x11000).unwrap() |= 0x300;
    *memory.leaves.get_mut(&0x12000).unwrap() |= 0x300;
    let expected = vec![79; 4096];
    memory.pages.insert(0x11000, expected.clone());
    memory.entry(0x4000, 2, 0x10007);
    let directory = output_directory("complete");
    let result = dump_tracking(id, &directory, |request| {
        execute(&mut memory, request, false, 48).map_err(|error| format!("{error:?}"))
    })
    .unwrap();
    assert_eq!(result, 1);
    assert_eq!(std::fs::read(directory.join("accessed.bin")).unwrap(), [7]);
    assert_eq!(std::fs::read(directory.join("dirty.bin")).unwrap(), [6]);
    assert_eq!(
        std::fs::read(directory.join("page-0001-0000000000001000.bin")).unwrap(),
        expected
    );
    let manifest = std::fs::read_to_string(directory.join("pages.jsonl")).unwrap();
    let records: Vec<_> = manifest.lines().collect();
    assert_eq!(records.len(), 3);
    let digest: String = Sha256::digest(&expected)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(records[1].contains(&format!("\"sha256\":\"{digest}\"")));
    assert!(records[1].contains("\"hash_changed\":true"));
    assert!(records[2].contains("\"status\":13"));
    assert!(records[2].contains("\"dump\":\"\""));
    let metadata = std::fs::read_to_string(directory.join("session.txt")).unwrap();
    assert!(metadata.contains("t0=200\nt1=300"));
    assert!(metadata.contains("dirty=2\nremapped=1"));
    assert_eq!(
        word(&command(&mut memory, AD_STATUS, 0, 0).unwrap(), 104),
        TRACK_IDLE
    );
}

#[test]
fn export_failure_preserves_frozen_session_for_retry_and_rejects_corrupted_data() {
    let mut session = session();
    let mut memory = Memory::new();
    memory.session = &mut *session;
    let id = quad(&start(&mut memory, 1).unwrap(), 80);
    *memory.leaves.get_mut(&0x10000).unwrap() |= 0x300;
    let occupied = output_directory("occupied");
    std::fs::create_dir_all(&occupied).unwrap();
    assert!(
        dump_tracking(id, &occupied, |request| {
            execute(&mut memory, request, false, 48).map_err(|error| format!("{error:?}"))
        })
        .is_err()
    );
    let corrupt = output_directory("corrupted");
    let error = dump_tracking(id, &corrupt, |request| {
        execute(&mut memory, request, false, 48).map_err(|error| format!("{error:?}"))?;
        if word(request, 12) == AD_FETCH {
            request[HEADER_BYTES + 120] ^= 1;
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.contains("SHA-256"));
    assert_eq!(
        word(&command(&mut memory, AD_STATUS, 0, 0).unwrap(), 104),
        TRACK_STOPPED
    );
    let retry = output_directory("retry");
    assert_eq!(
        dump_tracking(id, &retry, |request| {
            execute(&mut memory, request, false, 48).map_err(|error| format!("{error:?}"))
        })
        .unwrap(),
        0
    );
    assert_eq!(
        std::fs::read(retry.join("page-0000-0000000000000000.bin")).unwrap(),
        vec![0; 4096]
    );
}
