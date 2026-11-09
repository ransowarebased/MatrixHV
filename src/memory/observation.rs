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
#[derive(Clone, Copy, Default)]
struct RipRange {
    start: u64,
    end: u64,
    exclude: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CaptureFilter {
    thread_teb: u64,
    count: usize,
    ranges: [RipRange; OBSERVATION_FILTER_RANGES],
}

impl CaptureFilter {
    fn accepts(&self, context: &ContextRecord) -> bool {
        if self.thread_teb != 0 && self.thread_teb != context.thread_teb {
            return false;
        }
        let mut included = false;
        let mut has_includes = false;
        for range in &self.ranges[..self.count] {
            let matches = (range.start..range.end).contains(&context.rip);
            if range.exclude != 0 && matches {
                return false;
            }
            if range.exclude == 0 {
                has_includes = true;
                included |= matches;
            }
        }
        !has_includes || included
    }
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
    // Append only: old hot-update allocations have a zeroed final-page tail.
    filters: [CaptureFilter; 2],
    pub events: Events,
}

const _: () = assert!(core::mem::size_of::<ContextRecord>() == CONTEXT_RECORD_BYTES);
const _: () = assert!(core::mem::size_of::<WatchRecord>() == WATCH_RECORD_BYTES);
const _: () = assert!(core::mem::offset_of!(Observation, filters) == 1_198_824);

impl Observation {
    pub fn reset_filters(&mut self) {
        self.filters.fill(CaptureFilter::default());
    }

    pub fn set_filter(&mut self, packet: &[u8], la57: bool) -> Result<(), Error> {
        let count = word(packet, 32) as usize;
        if count > OBSERVATION_FILTER_RANGES
            || packet.len() != HEADER_BYTES + count * OBSERVATION_FILTER_BYTES
        {
            return Err(Error::Bounds);
        }
        let shift = if la57 { 7 } else { 16 };
        let canonical = |address: u64| ((address << shift) as i64 >> shift) as u64 == address;
        let mut filter = CaptureFilter {
            thread_teb: quad(packet, 24),
            count,
            ..CaptureFilter::default()
        };
        if !canonical(filter.thread_teb) {
            return Err(Error::Bounds);
        }
        for (index, range) in filter.ranges[..count].iter_mut().enumerate() {
            let offset = HEADER_BYTES + index * OBSERVATION_FILTER_BYTES;
            *range = RipRange {
                start: quad(packet, offset),
                end: quad(packet, offset + 8),
                exclude: quad(packet, offset + 16),
            };
            if range.start >= range.end
                || range.exclude > 1
                || !canonical(range.start)
                || !canonical(range.end - 1)
                || range.start >> 63 != (range.end - 1) >> 63
            {
                return Err(Error::Bounds);
            }
        }
        let index = match word(packet, 12) {
            WATCH_FILTER_SET => 0,
            CONTEXT_FILTER_SET => 1,
            _ => return Err(Error::Format),
        };
        self.filters[index] = filter;
        Ok(())
    }
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

    pub fn capture(
        &self,
        mut context: ContextRecord,
        watch_slot: Option<usize>,
    ) -> Option<ContextRecord> {
        if !self.filters[usize::from(watch_slot.is_none())].accepts(&context) {
            return None;
        }
        let cpu = self.cpus.get(context.cpu as usize)?;
        if cpu
            .lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            cpu.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
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
        Some(context)
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

    fn cached_context(&self, cpu_index: u64, sequence: u64) -> Result<ContextRecord, Error> {
        let cpu = self.cpus.get(cpu_index as usize).ok_or(Error::Bounds)?;
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
        context.ok_or(Error::Session)
    }

    pub fn get_context(&self, packet: &mut [u8]) -> Result<(), Error> {
        if packet.len() != HEADER_BYTES + CONTEXT_RECORD_BYTES || word(packet, 32) != 1 {
            return Err(Error::Bounds);
        }
        let context = self.cached_context(quad(packet, 24), quad(packet, 64))?;
        context.encode(&mut packet[HEADER_BYTES..]);
        Ok(())
    }

    pub fn stack_walk(
        &self,
        memory: &mut impl PhysicalMemory,
        packet: &mut [u8],
        la57: bool,
        physical_bits: u32,
    ) -> Result<(), Error> {
        let sequence = quad(packet, 64);
        let count = word(packet, 32) as usize;
        if count == 0 || count > STACK_MAX_FRAMES || packet.len() != HEADER_BYTES + count * 16 {
            return Err(Error::Bounds);
        }
        let context = self.cached_context(quad(packet, 24), sequence)?;
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

#[derive(Clone, Copy, Default)]
pub(crate) struct EventRegion {
    pub address: u64,
    pub length: usize,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Probe {
    pub address: u64,
    pub kind: u64,
}

#[derive(Default)]
pub(crate) struct EventConfig {
    pub enabled: bool,
    pub sample: bool,
    pub exceptions: u64,
    pub regions: [EventRegion; EVENT_REGIONS],
    pub probes: [Probe; 4],
    pub probe_count: usize,
}

impl EventConfig {
    pub fn parse(packet: &[u8], la57: bool) -> Result<Self, Error> {
        let regions = word(packet, 32) as usize;
        let probe_count = word(packet, 44) as usize;
        let exceptions = quad(packet, 48);
        let flags = quad(packet, 56);
        if regions > EVENT_REGIONS
            || probe_count > 4
            || exceptions & !EVENT_EXCEPTION_MASK != 0
            || flags & !u64::from(EVENT_SAMPLE) != 0
            || packet.len() != HEADER_BYTES + (regions + probe_count) * 16
        {
            return Err(Error::Bounds);
        }
        let user_max = if la57 { 1 << 56 } else { 1 << 47 };
        let mut config = Self {
            enabled: true,
            sample: flags & u64::from(EVENT_SAMPLE) != 0,
            exceptions,
            probe_count,
            ..Self::default()
        };
        for (index, region) in config.regions[..regions].iter_mut().enumerate() {
            let offset = HEADER_BYTES + index * 16;
            let address = quad(packet, offset);
            let length = quad(packet, offset + 8);
            if address == 0
                || length == 0
                || length > EVENT_REGION_BYTES as u64
                || address.checked_add(length).is_none_or(|end| end > user_max)
            {
                return Err(Error::Bounds);
            }
            *region = EventRegion {
                address,
                length: length as usize,
            };
        }
        let mut has_entry = false;
        let mut has_return = false;
        for index in 0..probe_count {
            let offset = HEADER_BYTES + (regions + index) * 16;
            let address = quad(packet, offset);
            let kind = quad(packet, offset + 8);
            if address == 0
                || address >= user_max
                || !matches!(kind, EVENT_ENTRY | EVENT_RETURN | EVENT_SOFTWARE_EXCEPTION)
                || config.probes[..index]
                    .iter()
                    .any(|probe| probe.address == address)
            {
                return Err(Error::Bounds);
            }
            config.probes[index] = Probe { address, kind };
            has_entry |= kind == EVENT_ENTRY;
            has_return |= kind == EVENT_RETURN;
        }
        if has_entry != has_return {
            return Err(Error::Format);
        }
        Ok(config)
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Event {
    pub kind: u64,
    pub invocation: u64,
    pub parent: u64,
    pub detail: u64,
    pub auxiliary: u64,
    pub address: u64,
}

#[derive(Clone, Copy, Default)]
struct Invocation {
    id: u64,
    parent: u64,
    teb: u64,
    stack_base: u64,
    return_rip: u64,
    return_rsp: u64,
    entry: u64,
}

struct Calls {
    next: u64,
    active: [Invocation; 256],
}

struct EventCpu {
    lock: AtomicU64,
    dropped: AtomicU64,
    buffer: UnsafeCell<EventBuffer>,
}

struct EventBuffer {
    next: u64,
    records: [[u8; EVENT_RECORD_BYTES]; EVENT_RING_RECORDS],
}

pub(crate) struct Events {
    pub config: EventConfig,
    call_lock: AtomicU64,
    calls: UnsafeCell<Calls>,
    cpus: [EventCpu; 64],
}

impl Events {
    pub fn reset(&mut self) {
        self.calls.get_mut().active.fill(Invocation::default());
        for cpu in &mut self.cpus {
            cpu.buffer.get_mut().next = 0;
            cpu.dropped.store(0, Ordering::Relaxed);
        }
    }

    pub fn fetch(&self, packet: &mut [u8]) -> Result<(), Error> {
        let cpu = self
            .cpus
            .get(quad(packet, 24) as usize)
            .ok_or(Error::Bounds)?;
        let count = word(packet, 32) as usize;
        if count > EVENT_FETCH_MAX || packet.len() != HEADER_BYTES + count * EVENT_RECORD_BYTES {
            return Err(Error::Bounds);
        }
        if cpu
            .lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(Error::Busy);
        }
        let buffer = unsafe { &*cpu.buffer.get() };
        let cursor = quad(packet, 64);
        let oldest = if buffer.next == 0 {
            0
        } else {
            buffer
                .next
                .saturating_sub(EVENT_RING_RECORDS as u64 - 1)
                .max(1)
        };
        let first = cursor.saturating_add(1).max(oldest);
        let returned = if first <= buffer.next {
            (buffer.next - first + 1).min(count as u64) as usize
        } else {
            0
        };
        packet[HEADER_BYTES..].fill(0);
        for (index, record) in packet[HEADER_BYTES..]
            .chunks_exact_mut(EVENT_RECORD_BYTES)
            .take(returned)
            .enumerate()
        {
            let sequence = first + index as u64;
            record.copy_from_slice(&buffer.records[(sequence - 1) as usize % EVENT_RING_RECORDS]);
        }
        let next = if returned == 0 {
            cursor
        } else {
            first + returned as u64 - 1
        };
        let dropped = cpu.dropped.load(Ordering::Relaxed);
        let buffer_next = buffer.next;
        cpu.lock.store(0, Ordering::Release);
        packet[32..36].copy_from_slice(&(returned as u32).to_le_bytes());
        packet[88..96].copy_from_slice(&next.to_le_bytes());
        packet[96..104].copy_from_slice(&oldest.to_le_bytes());
        packet[104..112].copy_from_slice(&buffer_next.to_le_bytes());
        packet[120..128].copy_from_slice(&dropped.to_le_bytes());
        Ok(())
    }

    #[cfg(any(target_os = "uefi", test))]
    pub fn emit(&self, mut context: ContextRecord, event: Event, capture: impl FnOnce(&mut [u8])) {
        let cpu = &self.cpus[context.cpu as usize];
        if cpu
            .lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            cpu.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let buffer = unsafe { &mut *cpu.buffer.get() };
        buffer.next = buffer.next.saturating_add(1);
        let source = context.sequence;
        context.sequence = buffer.next;
        let record = &mut buffer.records[(buffer.next - 1) as usize % EVENT_RING_RECORDS];
        record.fill(0);
        context.encode(&mut record[..CONTEXT_RECORD_BYTES]);
        for (value, bytes) in [
            event.kind,
            event.invocation,
            event.parent,
            event.detail,
            event.auxiliary,
            source,
            event.address,
        ]
        .into_iter()
        .zip(record[CONTEXT_RECORD_BYTES..EVENT_RECORD_HEADER].chunks_exact_mut(8))
        {
            bytes.copy_from_slice(&value.to_le_bytes());
        }
        capture(&mut record[EVENT_RECORD_HEADER..]);
        cpu.lock.store(0, Ordering::Release);
    }

    #[cfg(any(target_os = "uefi", test))]
    pub fn correlate(
        &self,
        context: ContextRecord,
        mut event: Event,
        return_rip: u64,
        stack_base: u64,
        mut emit: impl FnMut(Event),
    ) {
        if self.config.probe_count == 0
            || context.cpl != 3
            || context.thread_teb == 0
            || stack_base <= context.rsp
        {
            if matches!(event.kind, EVENT_ENTRY | EVENT_RETURN) {
                event.auxiliary = event.kind;
                event.kind = EVENT_UNMATCHED;
            }
            emit(event);
            return;
        }
        if self
            .call_lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            self.cpus[context.cpu as usize]
                .dropped
                .fetch_add(1, Ordering::Relaxed);
            if matches!(event.kind, EVENT_ENTRY | EVENT_RETURN) {
                event.auxiliary = event.kind;
                event.kind = EVENT_UNMATCHED;
            }
            emit(event);
            return;
        }
        let calls = unsafe { &mut *self.calls.get() };
        let teb = context.thread_teb;
        // Match the innermost invocation first. The caller's post-RET RSP
        // disambiguates recursion and shared continuation addresses.
        let top = |calls: &Calls| {
            calls
                .active
                .iter()
                .enumerate()
                .filter(|(_, call)| {
                    call.id != 0 && call.teb == teb && call.stack_base == stack_base
                })
                .max_by_key(|(_, call)| call.id)
                .map(|(index, _)| index)
        };
        let mut matched = false;
        while let Some(index) = top(calls) {
            let call = calls.active[index];
            if event.kind == EVENT_RETURN
                && context.rip == call.return_rip
                && context.rsp == call.return_rsp
            {
                event.invocation = call.id;
                event.parent = call.parent;
                event.address = call.entry;
                calls.active[index].id = 0;
                matched = true;
                break;
            }
            if context.rsp < call.return_rsp
                || context.rsp == call.return_rsp && context.rip == call.return_rip
            {
                break;
            }
            calls.active[index].id = 0;
            emit(Event {
                kind: EVENT_ABANDON,
                invocation: call.id,
                parent: call.parent,
                address: call.entry,
                detail: call.return_rip,
                auxiliary: call.return_rsp,
            });
        }
        if event.kind == EVENT_ENTRY {
            let parent = top(calls).map_or(0, |index| calls.active[index].id);
            event.parent = parent;
            if let Some(slot) = calls
                .active
                .iter_mut()
                .find(|call| call.id == 0)
                .filter(|_| return_rip != 0 && calls.next != u64::MAX)
            {
                calls.next += 1;
                *slot = Invocation {
                    id: calls.next,
                    parent,
                    teb,
                    stack_base,
                    return_rip,
                    return_rsp: context.rsp + 8,
                    entry: context.rip,
                };
                event.invocation = slot.id;
                event.auxiliary = slot.return_rsp;
            } else {
                event.auxiliary = EVENT_ENTRY;
                event.kind = EVENT_UNMATCHED;
            }
            event.detail = return_rip;
        } else if event.kind == EVENT_RETURN && !matched {
            event.auxiliary = EVENT_RETURN;
            event.kind = EVENT_UNMATCHED;
        } else if !matched && let Some(index) = top(calls) {
            event.invocation = calls.active[index].id;
            event.parent = calls.active[index].parent;
        }
        self.call_lock.store(0, Ordering::Release);
        emit(event);
    }
}
