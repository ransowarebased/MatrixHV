use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::memory::access::{PhysicalMemory, transfer};
use crate::protocol::memory::*;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct WatchTarget {
    pub address: u64,
    pub control: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct ContextRecord {
    pub sequence: u64,
    pub tsc: u64,
    pub cr3: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rflags: u64,
    pub gs_base: u64,
    pub thread_teb: u64,
    // Resident frame order: RAX, RCX, RDX, RBX, RBP, RSI, RDI, R8..R15.
    pub gprs: [u64; 15],
    pub cpu: u64,
    pub cpl: u64,
}

impl ContextRecord {
    fn encode(&self, bytes: &mut [u8]) {
        let mut words = [0; CONTEXT_RECORD_BYTES / 8];
        words[..9].copy_from_slice(&[
            self.sequence,
            self.tsc,
            self.cr3,
            self.rip,
            self.rsp,
            self.rbp,
            self.rflags,
            self.gs_base,
            self.thread_teb,
        ]);
        words[9..24].copy_from_slice(&self.gprs);
        words[24..].copy_from_slice(&[self.cpu, self.cpl]);
        for (value, chunk) in words.iter().zip(bytes.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&value.to_le_bytes());
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct WatchRecord {
    context: ContextRecord,
    address: u64,
    hit_count: u64,
    slot: u64,
    flags: u64,
}

#[repr(C)]
struct CpuRecords {
    lock: AtomicU64,
    dropped: AtomicU64,
    records: UnsafeCell<RecordBuffer>,
}

#[repr(C)]
struct RecordBuffer {
    watch_sequence: u64,
    context_sequence: u64,
    watch: [WatchRecord; WATCH_RING_RECORDS],
    contexts: [ContextRecord; CONTEXT_CPU_RECORDS],
    snapshots: [ContextRecord; CONTEXT_CPU_RECORDS],
}

#[repr(C)]
pub(crate) struct Observation {
    pub watch: [WatchTarget; 4],
    pub watch_count: usize,
    pub context_enabled: bool,
    pub sample_ticks: u64,
    pub hook_flags: [u32; HOOK_MAX_PATCHES],
    pub data_pages: [u64; HOOK_MAX_PAGES],
    pub data_count: usize,
    overlays: UnsafeCell<[[u8; 4]; 64]>,
    hits: AtomicU64,
    cpus: [CpuRecords; 64],
}

const _: () = assert!(core::mem::size_of::<ContextRecord>() == CONTEXT_RECORD_BYTES);
const _: () = assert!(core::mem::size_of::<WatchRecord>() == WATCH_RECORD_BYTES);

impl Observation {
    pub fn overlay(&self, cpu: usize) -> [u8; 4] {
        unsafe { (*self.overlays.get())[cpu] }
    }

    pub fn set_overlay(&self, cpu: usize, kinds: [u8; 4]) {
        unsafe {
            (*self.overlays.get())[cpu] = kinds;
        }
    }
    pub fn data_shadow(&self, gpa: u64) -> bool {
        self.data_pages[..self.data_count].contains(&(gpa & !4095))
    }

    pub fn watch_targets(packet: &[u8], la57: bool) -> Result<([WatchTarget; 4], usize), Error> {
        let count = word(packet, 32) as usize;
        if count == 0 || count > 4 || packet.len() != HEADER_BYTES + count * 16 {
            return Err(Error::Bounds);
        }
        let mut targets = [WatchTarget::default(); 4];
        for (index, target) in targets[..count].iter_mut().enumerate() {
            let offset = HEADER_BYTES + index * 16;
            let address = quad(packet, offset);
            let access = word(packet, offset + 8);
            let length = word(packet, offset + 12);
            let shift = if la57 { 7 } else { 16 };
            if ((address << shift) as i64 >> shift) as u64 != address
                || !matches!(access, 1 | 3)
                || !matches!(length, 1 | 2 | 4 | 8)
                || address & (u64::from(length) - 1) != 0
            {
                return Err(Error::Bounds);
            }
            let length_bits = match length {
                1 => 0,
                2 => 1,
                4 => 3,
                _ => 2,
            };
            *target = WatchTarget {
                address,
                control: u64::from(access | length_bits << 2),
            };
        }
        Ok((targets, count))
    }

    pub fn reset_watch(&mut self) {
        self.hits.store(0, Ordering::Relaxed);
        for cpu in &mut self.cpus {
            cpu.records.get_mut().watch_sequence = 0;
            cpu.records.get_mut().watch.fill(WatchRecord::default());
            cpu.dropped.store(0, Ordering::Relaxed);
        }
    }

    pub fn reset_contexts(&mut self) {
        for cpu in &mut self.cpus {
            cpu.records.get_mut().context_sequence = 0;
            cpu.records
                .get_mut()
                .contexts
                .fill(ContextRecord::default());
            cpu.records
                .get_mut()
                .snapshots
                .fill(ContextRecord::default());
        }
    }

    pub fn capture(&self, mut context: ContextRecord, watch_slot: Option<usize>) {
        let Some(cpu) = self.cpus.get(context.cpu as usize) else {
            return;
        };
        if cpu
            .lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            cpu.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let records = unsafe { &mut *cpu.records.get() };
        if let Some(slot) = watch_slot.filter(|slot| *slot < self.watch_count) {
            records.watch_sequence = records.watch_sequence.saturating_add(1);
            context.sequence = records.watch_sequence;
            let index = (context.sequence - 1) as usize % WATCH_RING_RECORDS;
            records.watch[index] = WatchRecord {
                context,
                address: self.watch[slot].address,
                hit_count: self.hits.fetch_add(1, Ordering::Relaxed) + 1,
                slot: slot as u64,
                flags: WATCH_POST_INSTRUCTION,
            };
        } else if self.context_enabled {
            records.context_sequence = records.context_sequence.saturating_add(1);
            context.sequence = records.context_sequence;
            let index = records
                .contexts
                .iter()
                .position(|record| {
                    record.sequence != 0
                        && record.thread_teb == context.thread_teb
                        && record.cr3 == context.cr3
                })
                .unwrap_or_else(|| {
                    records
                        .contexts
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, record)| record.sequence)
                        .unwrap()
                        .0
                });
            records.contexts[index] = context;
        }
        cpu.lock.store(0, Ordering::Release);
    }

    pub fn fetch(&self, packet: &mut [u8]) -> Result<(), Error> {
        let cpu = self
            .cpus
            .get(quad(packet, 24) as usize)
            .ok_or(Error::Bounds)?;
        let operation = word(packet, 12);
        let count = word(packet, 32) as usize;
        let watch = operation == WATCH_FETCH;
        let record_bytes = if watch {
            WATCH_RECORD_BYTES
        } else {
            CONTEXT_RECORD_BYTES
        };
        let capacity = if watch {
            WATCH_RING_RECORDS
        } else {
            CONTEXT_CPU_RECORDS
        };
        if count == 0 || count > capacity || packet.len() != HEADER_BYTES + count * record_bytes {
            return Err(Error::Bounds);
        }
        if cpu
            .lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(Error::Busy);
        }
        let records = unsafe { &mut *cpu.records.get() };
        if !watch {
            records.snapshots.fill(ContextRecord::default());
        }
        let cursor = quad(packet, 64);
        packet[HEADER_BYTES..].fill(0);
        let mut returned = 0;
        let mut next = cursor;
        let oldest = if watch && records.watch_sequence != 0 {
            records
                .watch_sequence
                .saturating_sub(WATCH_RING_RECORDS as u64 - 1)
                .max(1)
        } else {
            0
        };
        while returned < count {
            let selected = if watch {
                records
                    .watch
                    .iter()
                    .map(|record| &record.context)
                    .filter(|record| record.sequence > next)
                    .min_by_key(|record| record.sequence)
            } else {
                records
                    .contexts
                    .iter()
                    .filter(|record| record.sequence > next)
                    .min_by_key(|record| record.sequence)
            };
            let Some(context) = selected.copied() else {
                break;
            };
            next = context.sequence;
            let offset = HEADER_BYTES + returned * record_bytes;
            context.encode(&mut packet[offset..offset + CONTEXT_RECORD_BYTES]);
            if !watch {
                // Preserve the exported sequence while exit sampling updates
                // the latest per-thread record between separate hypercalls.
                records.snapshots[returned] = context;
            }
            if watch {
                let record = &records.watch[(next - 1) as usize % WATCH_RING_RECORDS];
                for (index, value) in [record.address, record.hit_count, record.slot, record.flags]
                    .iter()
                    .enumerate()
                {
                    packet[offset + CONTEXT_RECORD_BYTES + index * 8
                        ..offset + CONTEXT_RECORD_BYTES + index * 8 + 8]
                        .copy_from_slice(&value.to_le_bytes());
                }
            }
            returned += 1;
        }
        cpu.lock.store(0, Ordering::Release);
        packet[32..36].copy_from_slice(&(returned as u32).to_le_bytes());
        packet[88..96].copy_from_slice(&next.to_le_bytes());
        packet[96..104].copy_from_slice(&oldest.to_le_bytes());
        packet[120..128].copy_from_slice(&cpu.dropped.load(Ordering::Relaxed).to_le_bytes());
        Ok(())
    }

    pub fn stack_walk(
        &self,
        memory: &mut impl PhysicalMemory,
        packet: &mut [u8],
        la57: bool,
        physical_bits: u32,
    ) -> Result<(), Error> {
        let cpu = self
            .cpus
            .get(quad(packet, 24) as usize)
            .ok_or(Error::Bounds)?;
        let sequence = quad(packet, 64);
        let count = word(packet, 32) as usize;
        if count == 0 || count > STACK_MAX_FRAMES || packet.len() != HEADER_BYTES + count * 16 {
            return Err(Error::Bounds);
        }
        if cpu
            .lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(Error::Busy);
        }
        let records = unsafe { &*cpu.records.get() };
        let context = records
            .snapshots
            .iter()
            .chain(records.contexts.iter())
            .find(|record| record.sequence == sequence && sequence != 0)
            .copied();
        cpu.lock.store(0, Ordering::Release);
        let context = context.ok_or(Error::Session)?;
        packet[HEADER_BYTES..].fill(0);
        let mut rip = context.rip;
        let mut rsp = context.rsp;
        let mut rbp = context.rbp;
        let mut returned = 0;
        let mut status = 0u32;
        while returned < count {
            let offset = HEADER_BYTES + returned * 16;
            packet[offset..offset + 8].copy_from_slice(&rip.to_le_bytes());
            packet[offset + 8..offset + 16].copy_from_slice(&rsp.to_le_bytes());
            returned += 1;
            // This is a best-effort frame-pointer chain, not Windows unwind metadata.
            if rbp == 0 {
                break;
            }
            if rbp & 7 != 0
                || rbp < rsp
                || rbp - context.rsp > 1024 * 1024
                || rbp.checked_add(16).is_none()
            {
                status = Error::Bounds as u32;
                break;
            }
            let mut frame = [0; 16];
            let (done, result) = transfer(
                memory,
                context.cr3,
                rbp,
                &mut frame,
                la57,
                physical_bits,
                (false, context.cpl == 3),
            );
            if done != frame.len() || result.is_err() {
                status = result.err().unwrap_or(Error::Unmapped) as u32;
                break;
            }
            let next_rbp = quad(&frame, 0);
            let next_rip = quad(&frame, 8);
            if next_rbp != 0 && next_rbp <= rbp {
                status = Error::Bounds as u32;
                break;
            }
            let shift = if la57 { 7 } else { 16 };
            if ((next_rip << shift) as i64 >> shift) as u64 != next_rip {
                status = Error::Bounds as u32;
                break;
            }
            rsp = rbp + 16;
            rbp = next_rbp;
            rip = next_rip;
        }
        packet[32..36].copy_from_slice(&(returned as u32).to_le_bytes());
        packet[72..76].copy_from_slice(&status.to_le_bytes());
        Ok(())
    }
}
