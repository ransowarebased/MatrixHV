use core::sync::atomic::{AtomicU64, Ordering};
use sha2::{Digest, Sha256};

use crate::memory::access::{PhysicalMemory, page_mapping};
use crate::protocol::memory::*;

#[repr(C)]
pub(crate) struct TablePool {
    pub base: u64,
    pub used: usize,
    pub capacity: usize,
}

pub(crate) trait TrackingMemory: PhysicalMemory {
    fn quiesce(&mut self) -> Result<(), Error>;
    fn flush(&mut self);
    fn resume(&mut self);
    fn prepare_leaf(&mut self, address: u64, pool: &mut TablePool) -> Result<u64, Error>;
    fn leaf_value(&self, pointer: u64) -> u64;
    fn clear_leaf(&mut self, pointer: u64);
    fn clock(&self) -> u64;
}

#[repr(C)]
struct TrackedPage {
    cr3: u64,
    gva: u64,
    initial_gpa: u64,
    current_gpa: u64,
    pte_fingerprint: u64,
    current_fingerprint: u64,
    flags: u32,
    status: u32,
    initial_sha256: [u8; 32],
    sha256: [u8; 32],
    data: [u8; 4096],
    ept_leaf: u64,
}

#[repr(C)]
pub(crate) struct Session {
    lock: AtomicU64,
    next_id: u64,
    id: u64,
    state: u32,
    count: u32,
    pid: u64,
    start_tsc: u64,
    stop_tsc: u64,
    la57: bool,
    physical_bits: u32,
    pub pool: TablePool,
    pages: [TrackedPage; TRACK_MAX_PAGES],
}

impl Session {
    pub(crate) fn is_active(&self) -> bool {
        self.state == TRACK_ACTIVE
    }
    // ResidentPages supplies zeroed storage; initialize without placing this
    // multi-megabyte object on the small resident host stack.
    pub(crate) fn initialize(&mut self, pool_base: u64, pool_pages: usize) {
        self.lock.store(0, Ordering::Relaxed);
        self.state = TRACK_IDLE;
        self.pool = TablePool {
            base: pool_base,
            used: 0,
            capacity: pool_pages,
        };
    }
}

fn put_word(packet: &mut [u8], offset: usize, value: u32) {
    packet[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_quad(packet: &mut [u8], offset: usize, value: u64) {
    packet[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn metadata(session: &Session, packet: &mut [u8]) {
    put_quad(packet, 24, session.pid);
    put_quad(packet, 80, session.id);
    put_quad(packet, 88, session.start_tsc);
    put_quad(packet, 96, session.stop_tsc);
    put_word(packet, 104, session.state);
    put_word(packet, 108, session.count);
    put_word(packet, 112, session.pool.used as u32);
}

fn start(
    session: &mut Session,
    memory: &mut impl TrackingMemory,
    packet: &[u8],
    la57: bool,
    physical_bits: u32,
) -> Result<(), Error> {
    let count = word(packet, 32) as usize;
    // Resolve and validate every page before any A/D bit is cleared.
    for index in 0..count {
        let offset = HEADER_BYTES + index * TRACK_TARGET_BYTES;
        let root = quad(packet, offset);
        let gva = quad(packet, offset + 8);
        if gva & 4095 != 0 {
            return Err(Error::Bounds);
        }
        let mapping = page_mapping(memory, root, gva, la57, physical_bits)?;
        if !mapping.present {
            return Err(Error::Unmapped);
        }
        let page = &mut session.pages[index];
        page.cr3 = root;
        page.gva = gva;
        page.initial_gpa = mapping.physical_address;
        page.current_gpa = mapping.physical_address;
        page.pte_fingerprint = mapping.pte_fingerprint;
        page.current_fingerprint = mapping.pte_fingerprint;
        page.flags = 0;
        page.status = 0;
        page.sha256.fill(0);
        memory.read(page.initial_gpa, &mut page.data)?;
        page.initial_sha256 = Sha256::digest(&page.data).into();
        page.data.fill(0);
    }
    for page in &mut session.pages[..count] {
        page.ept_leaf = memory.prepare_leaf(page.initial_gpa, &mut session.pool)?;
    }
    for page in &session.pages[..count] {
        memory.clear_leaf(page.ept_leaf);
    }
    session.count = count as u32;
    session.pid = quad(packet, 24);
    session.la57 = la57;
    session.physical_bits = physical_bits;
    session.next_id = session.next_id.wrapping_add(1).max(1);
    session.id = session.next_id;
    session.stop_tsc = 0;
    Ok(())
}

fn stop(session: &mut Session, memory: &mut impl TrackingMemory) {
    session.stop_tsc = memory.clock();
    for page in &mut session.pages[..session.count as usize] {
        page.flags = ((memory.leaf_value(page.ept_leaf) >> 8)
            & u64::from(TRACK_ACCESSED | TRACK_DIRTY)) as u32;
        page.data.fill(0);
        page.sha256.fill(0);
        let mapping = page_mapping(
            memory,
            page.cr3,
            page.gva,
            session.la57,
            session.physical_bits,
        );
        match mapping {
            Ok(mapping) => {
                page.current_gpa = mapping.physical_address;
                page.current_fingerprint = mapping.pte_fingerprint;
                if !mapping.present
                    || page.current_gpa != page.initial_gpa
                    || page.current_fingerprint != page.pte_fingerprint
                {
                    page.flags |= TRACK_REMAPPED;
                    page.status = Error::Remapped as u32;
                    continue;
                }
            }
            Err(error) => {
                page.current_gpa = 0;
                page.current_fingerprint = 0;
                page.flags |= TRACK_REMAPPED;
                page.status = error as u32;
                continue;
            }
        }
        if page.flags & TRACK_DIRTY != 0 {
            // The barrier holds Windows page tables and CPU writes stable while
            // copying. Remapped frames are never dumped as the original page.
            match memory.read(page.initial_gpa, &mut page.data) {
                Ok(()) => {
                    page.sha256 = Sha256::digest(&page.data).into();
                    page.flags |= TRACK_DUMP_VALID;
                    if page.sha256 != page.initial_sha256 {
                        page.flags |= TRACK_HASH_CHANGED;
                    }
                }
                Err(error) => {
                    page.data.fill(0);
                    page.status = error as u32;
                }
            }
        }
    }
    session.state = TRACK_STOPPED;
}

fn fetch(session: &Session, packet: &mut [u8]) -> Result<(), Error> {
    let first = usize::try_from(quad(packet, 64)).map_err(|_| Error::Bounds)?;
    let requested = word(packet, 32) as usize;
    if first >= session.count as usize {
        return Err(Error::Bounds);
    }
    let count = requested.min(session.count as usize - first);
    packet[HEADER_BYTES..].fill(0);
    for (index, page) in session.pages[first..first + count].iter().enumerate() {
        let offset = HEADER_BYTES + index * TRACK_RECORD_BYTES;
        for (field, value) in [
            page.cr3,
            page.gva,
            page.initial_gpa,
            page.current_gpa,
            page.pte_fingerprint,
            page.current_fingerprint,
        ]
        .iter()
        .enumerate()
        {
            put_quad(packet, offset + field * 8, *value);
        }
        put_word(packet, offset + 48, page.flags);
        put_word(packet, offset + 52, page.status);
        packet[offset + 56..offset + 88].copy_from_slice(&page.initial_sha256);
        packet[offset + 88..offset + 120].copy_from_slice(&page.sha256);
        packet[offset + 120..offset + TRACK_RECORD_BYTES].copy_from_slice(&page.data);
    }
    put_word(packet, 32, count as u32);
    Ok(())
}

// The raw pointer permits locking before creating an exclusive Session reference.
// Callers must supply valid, initialized, resident storage for the entire session.
pub(crate) unsafe fn execute(
    pointer: *mut Session,
    memory: &mut impl TrackingMemory,
    packet: &mut [u8],
    la57: bool,
    physical_bits: u32,
) -> Result<(), Error> {
    if pointer.is_null() {
        return Err(Error::Unsupported);
    }
    let lock = unsafe { core::ptr::addr_of!((*pointer).lock) };
    if unsafe { (&*lock).compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed) }.is_err() {
        return Err(Error::Busy);
    }
    let result = unsafe { run(&mut *pointer, memory, packet, la57, physical_bits) };
    unsafe {
        (&*lock).store(0, Ordering::Release);
    }
    result
}

fn run(
    session: &mut Session,
    memory: &mut impl TrackingMemory,
    packet: &mut [u8],
    la57: bool,
    physical_bits: u32,
) -> Result<(), Error> {
    let operation = word(packet, 12);
    let count = word(packet, 32) as usize;
    let valid_length = match operation {
        AD_START if count > 0 && count <= TRACK_MAX_PAGES => {
            HEADER_BYTES + count * TRACK_TARGET_BYTES
        }
        AD_FETCH if count > 0 && count <= TRACK_FETCH_PAGES => {
            HEADER_BYTES + count * TRACK_RECORD_BYTES
        }
        AD_STOP | AD_RELEASE | AD_STATUS | AD_CANCEL if count == 0 => HEADER_BYTES,
        _ => return Err(Error::Bounds),
    };
    if packet.len() != valid_length {
        return Err(Error::Bounds);
    }
    if operation == AD_START {
        if session.state != TRACK_IDLE {
            return Err(Error::Busy);
        }
        memory.quiesce()?;
        let result = start(session, memory, packet, la57, physical_bits);
        // Flush even on pool exhaustion: any preceding split preserves mapping
        // attributes, but its changed page size must be retired on every CPU.
        memory.flush();
        if result.is_ok() {
            session.start_tsc = memory.clock();
            session.state = TRACK_ACTIVE;
        }
        memory.resume();
        result?;
    } else if operation != AD_STATUS {
        if quad(packet, 80) != session.id || session.state == TRACK_IDLE {
            return Err(Error::Session);
        }
        match operation {
            AD_STOP if session.state == TRACK_ACTIVE => {
                memory.quiesce()?;
                stop(session, memory);
                memory.resume();
            }
            AD_STOP if session.state == TRACK_STOPPED => {}
            AD_FETCH if session.state == TRACK_STOPPED => fetch(session, packet)?,
            AD_CANCEL | AD_RELEASE if operation == AD_CANCEL || session.state == TRACK_STOPPED => {
                for page in &mut session.pages[..session.count as usize] {
                    page.data.fill(0);
                }
                session.state = TRACK_IDLE;
                session.count = 0;
            }
            _ => return Err(Error::Session),
        }
    }
    metadata(session, packet);
    Ok(())
}
