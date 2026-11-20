use crate::protocol::memory::{
    AD_BITMAP, AD_CANCEL, AD_ENUMERATE, AD_FETCH, AD_RELEASE, AD_START, AD_STATUS, AD_STOP,
    BUFFER_BYTES, HEADER_BYTES, INFO, INFO_BYTES, ITEM_BYTES, MAX_ITEMS, MEMORY_LEAF, MEMORY_MAGIC,
    MEMORY_SIGNATURE, MEMORY_VERSION, READ, ROAD_STATUS_DEMAND_ZERO, ROOT_HISTORY_COUNT,
    TRACK_FETCH_PAGES, TRACK_MAX_PAGES, TRACK_RECORD_BYTES, TRACK_TARGET_BYTES, WRITE,
    ad_bitmap_length, quad, word,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub address: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuidRecord {
    pub leaf: u32,
    pub subleaf: u32,
    pub subleaf_mask: u32,
    pub values: [u32; 4],
    pub keep_masks: [u32; 4],
}

#[derive(Clone, Debug, Default)]
pub struct CpuidGate {
    pub dr3: u64,
    pub dr7_mask: u64,
    pub dr7_value: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ObservationFilter {
    pub thread_teb: u64,
    pub ranges: Vec<(u64, u64, bool)>,
}

#[derive(Default)]
pub struct ArgumentCapture {
    /// Architectural GPR number (RAX=0, RCX=1, RSP=4, R8=8), or a stack byte offset.
    pub location: u64,
    pub on_stack: bool,
    pub copy_bytes: usize,
    /// Zero captures the scalar; one copies its pointee; two follows one more pointer.
    pub pointer_depth: usize,
    /// Signed displacement before copying (depth 1) or following the pointer (depth 2).
    pub pointer_offset: i16,
}

#[derive(Default)]
pub struct IdentityGuard {
    pub cr3: u64,
    pub address: u64,
    pub expected: u64,
    pub mask: u64,
}

#[derive(Default)]
pub struct InterceptionRequest {
    pub operation: u32,
    pub cr3: u64,
    pub alternate_cr3: u64,
    pub token: u64,
    pub patch_id: u64,
    pub lease_ms: u32,
    pub flags: u32,
    pub items: Vec<Item>,
    pub redirects: Vec<(u64, u64)>,
    pub contexts: Vec<u64>,
    pub hook_flags: Vec<u32>,
    pub watchpoints: Vec<(u64, u32, u32)>,
    pub callback: u64,
    pub syscall_entry: u64,
    pub cpu: u32,
    pub cursor: u64,
    pub count: usize,
    pub cpuid_records: Vec<CpuidRecord>,
    pub cpuid_gate: Option<CpuidGate>,
    pub filter: ObservationFilter,
    pub event_regions: Vec<(u64, u64)>,
    pub event_probes: Vec<(u64, u64)>,
    pub event_exceptions: u64,
    pub event_sample: bool,
    pub event_limit: u64,
    pub event_arguments: Vec<ArgumentCapture>,
    pub event_stack_bytes: usize,
    pub event_identity: [u64; 3],
    pub event_guards: Vec<IdentityGuard>,
    pub snapshot_arm: bool,
    pub snapshot_after: bool,
    pub thread_id_offset: u32,
}

#[derive(Debug)]
pub struct EventBatch<'a> {
    pub token: u64,
    pub next: u64,
    pub oldest: u64,
    pub head: u64,
    pub dropped: u64,
    pub captured_hits: u64,
    pub hit_limit: u64,
    pub records: Vec<&'a [u8]>,
}

pub fn decode_event_batch(bytes: &[u8]) -> Result<EventBatch<'_>, String> {
    use crate::protocol::memory::{
        CONTEXT_RECORD_BYTES, EVENT_FETCH, EVENT_FETCH_MAX, EVENT_FORMAT_VERSION,
        EVENT_RECORD_BYTES,
    };
    if bytes.len() < HEADER_BYTES
        || bytes.len() > BUFFER_BYTES
        || quad(bytes, 0) != MEMORY_MAGIC
        || word(bytes, 8) != MEMORY_VERSION
        || word(bytes, 12) != EVENT_FETCH
        || word(bytes, 36) as usize != bytes.len()
        || word(bytes, 40) != 0
    {
        return Err("invalid event response header".into());
    }
    let body = &bytes[HEADER_BYTES..];
    let count = word(bytes, 32) as usize;
    if !body.len().is_multiple_of(EVENT_RECORD_BYTES)
        || count > body.len() / EVENT_RECORD_BYTES
        || count > EVENT_FETCH_MAX
        || quad(bytes, 56) != EVENT_FORMAT_VERSION
    {
        return Err("invalid event response size or version".into());
    }
    let mut records: Vec<&[u8]> = Vec::with_capacity(count);
    let mut previous = quad(bytes, 64);
    for record in body.as_chunks::<EVENT_RECORD_BYTES>().0.iter().take(count) {
        let sequence = quad(record, 0);
        if quad(record, CONTEXT_RECORD_BYTES + 56) != EVENT_FORMAT_VERSION
            || sequence == 0
            || sequence <= previous
            || sequence > quad(bytes, 104)
        {
            return Err("invalid event record identity or version".into());
        }
        previous = sequence;
        records.push(record);
    }
    if quad(bytes, 88) != previous {
        return Err("event response cursor does not match its records".into());
    }
    Ok(EventBatch {
        token: quad(bytes, 80),
        next: quad(bytes, 88),
        oldest: quad(bytes, 96),
        head: quad(bytes, 104),
        dropped: quad(bytes, 120),
        captured_hits: quad(bytes, 48),
        hit_limit: quad(bytes, 144),
        records,
    })
}

pub fn interception_packet(request: &InterceptionRequest) -> Result<Vec<u8>, String> {
    use crate::protocol::memory::{
        CONTEXT_CLEAR, CONTEXT_CPU_RECORDS, CONTEXT_RECORD_BYTES, CONTEXT_SET, CONTEXT_SNAPSHOT,
        DEBUG_CLEAR, DEBUG_SET, HOOK_ADD, HOOK_DATA_SHADOW, HOOK_DROP, HOOK_INSTALL, HOOK_LIST,
        HOOK_MAX_PATCHES, HOOK_REMOVE, INTERCEPT_CONTEXT_ADD, INTERCEPT_CONTEXT_LIST,
        INTERCEPT_CONTEXT_REMOVE, INTERCEPT_MAX_LEASE_MS, INTERCEPT_NO_LEASE, INTERCEPT_RELEASE,
        INTERCEPT_RENEW, INTERCEPT_STATUS, STACK_MAX_FRAMES, STACK_WALK, SYSCALL_CLEAR,
        SYSCALL_SET, WATCH_CLEAR, WATCH_FETCH, WATCH_RECORD_BYTES, WATCH_RING_RECORDS, WATCH_SET,
    };
    use crate::protocol::memory::{
        CONTEXT_FILTER_SET, CONTEXT_RECORD_GET, CPUID_CLEAR, CPUID_MAX_RECORDS, CPUID_RECORD_BYTES,
        CPUID_SET, INTERCEPT_CONCURRENT_WRITES, INTERCEPT_PERSISTENT_DATA,
        INTERCEPT_PRIVATE_SHARED_DATA, INTERCEPT_VMFUNC, OBSERVATION_FILTER_BYTES,
        OBSERVATION_FILTER_RANGES, WATCH_FILTER_SET,
    };
    use crate::protocol::memory::{
        EVENT_CLEAR, EVENT_FETCH, EVENT_FETCH_MAX, EVENT_RECORD_BYTES, EVENT_REGIONS, EVENT_SAMPLE,
        EVENT_SET,
    };
    let operation = request.operation;
    let setup = matches!(
        operation,
        HOOK_INSTALL | DEBUG_SET | CPUID_SET | WATCH_SET | CONTEXT_SET | SYSCALL_SET | EVENT_SET
    );
    if request.lease_ms > INTERCEPT_MAX_LEASE_MS
        || request.lease_ms != 0 && !(setup || operation == INTERCEPT_RENEW)
        || request.flags & INTERCEPT_NO_LEASE != 0 && (request.lease_ms != 0 || !setup)
    {
        return Err("invalid interception lease configuration".into());
    }
    if setup && request.cr3 & !4095 == 0
        || request.alternate_cr3 != 0 && request.alternate_cr3 & !4095 == 0
    {
        return Err("CR3 must contain a nonzero page-table root".into());
    }
    if request.flags & INTERCEPT_PRIVATE_SHARED_DATA != 0
        && (operation != HOOK_INSTALL
            || request.flags
                & (INTERCEPT_VMFUNC
                    | INTERCEPT_CONCURRENT_WRITES
                    | INTERCEPT_PERSISTENT_DATA
                    | INTERCEPT_NO_LEASE)
                != 0
            || request
                .items
                .iter()
                .filter(|item| item.address == 0x7ffe0000 && item.bytes.len() == 4096)
                .count()
                != 1
            || request.items.iter().any(|item| {
                item.address & !4095 == 0x7ffe0000
                    && (item.address != 0x7ffe0000 || item.bytes.len() != 4096)
            })
            || request.items.iter().enumerate().any(|(index, item)| {
                item.address == 0x7ffe0000
                    && request.hook_flags.get(index).copied().unwrap_or(0) != 0
            }))
    {
        return Err("private shared data requires a full 4 KiB patch at 0x7ffe0000, a lease, and compatible hook modes".into());
    }
    let mut bytes = match operation {
        CPUID_SET => {
            if request.cpuid_records.is_empty() || request.cpuid_records.len() > CPUID_MAX_RECORDS {
                return Err("invalid CPUID profile: expected 1..16 records".into());
            }
            if let Some(gate) = &request.cpuid_gate
                && (gate.dr3 == 0 || gate.dr7_mask == 0 || gate.dr7_value & !gate.dr7_mask != 0)
            {
                return Err("invalid CPUID debug-register gate".into());
            }
            let mut bytes =
                vec![0; HEADER_BYTES + request.cpuid_records.len() * CPUID_RECORD_BYTES];
            bytes[16..24].copy_from_slice(&request.cr3.to_le_bytes());
            bytes[32..36].copy_from_slice(&(request.cpuid_records.len() as u32).to_le_bytes());
            for (index, record) in request.cpuid_records.iter().enumerate() {
                if record.leaf == 0
                    || record.leaf == 0x8000_0000
                    || (0x4000_0000..0x5000_0000).contains(&record.leaf)
                    || record.subleaf & !record.subleaf_mask != 0
                    || record
                        .values
                        .iter()
                        .zip(record.keep_masks)
                        .any(|(value, keep)| value & keep != 0)
                    || request.cpuid_records[..index].iter().any(|previous| {
                        previous.leaf == record.leaf
                            && (previous.subleaf ^ record.subleaf)
                                & previous.subleaf_mask
                                & record.subleaf_mask
                                == 0
                    })
                {
                    return Err("invalid, reserved, or overlapping CPUID record".into());
                }
                let offset = HEADER_BYTES + index * CPUID_RECORD_BYTES;
                for (slot, value) in [record.leaf, record.subleaf, record.subleaf_mask, 0]
                    .into_iter()
                    .chain(record.values)
                    .chain(record.keep_masks)
                    .enumerate()
                {
                    bytes[offset + slot * 4..offset + slot * 4 + 4]
                        .copy_from_slice(&value.to_le_bytes());
                }
            }
            if let Some(gate) = &request.cpuid_gate {
                bytes[24..32].copy_from_slice(&gate.dr3.to_le_bytes());
                bytes[144..152].copy_from_slice(&gate.dr7_mask.to_le_bytes());
                bytes[152..160].copy_from_slice(&gate.dr7_value.to_le_bytes());
            }
            bytes
        }
        WATCH_FILTER_SET | CONTEXT_FILTER_SET => {
            if request.filter.ranges.len() > OBSERVATION_FILTER_RANGES
                || request
                    .filter
                    .ranges
                    .iter()
                    .any(|(start, end, _)| start >= end)
            {
                return Err(
                    "invalid observation filter: expected at most 16 nonempty RIP ranges".into(),
                );
            }
            let mut bytes =
                vec![0; HEADER_BYTES + request.filter.ranges.len() * OBSERVATION_FILTER_BYTES];
            bytes[24..32].copy_from_slice(&request.filter.thread_teb.to_le_bytes());
            bytes[32..36].copy_from_slice(&(request.filter.ranges.len() as u32).to_le_bytes());
            for (index, (start, end, exclude)) in request.filter.ranges.iter().enumerate() {
                let offset = HEADER_BYTES + index * OBSERVATION_FILTER_BYTES;
                for (slot, value) in [*start, *end, u64::from(*exclude)].into_iter().enumerate() {
                    bytes[offset + slot * 8..offset + slot * 8 + 8]
                        .copy_from_slice(&value.to_le_bytes());
                }
            }
            bytes
        }
        HOOK_INSTALL | HOOK_ADD => {
            if !request.hook_flags.is_empty() && request.hook_flags.len() != request.items.len()
                || request
                    .hook_flags
                    .iter()
                    .any(|flags| flags & !HOOK_DATA_SHADOW != 0)
            {
                return Err("invalid per-descriptor hook flags".into());
            }
            if request.items.len() > HOOK_MAX_PATCHES {
                return Err("hook capacity exceeded".into());
            }
            for item in &request.items {
                if item.bytes.len() > 4096 - (item.address as usize & 4095) {
                    return Err("each patch must fit inside one 4 KiB page".into());
                }
            }
            let mut bytes = packet(
                WRITE,
                0,
                if operation == HOOK_INSTALL {
                    request.cr3
                } else {
                    0
                },
                &request.items,
            )?;
            for (index, flags) in request.hook_flags.iter().enumerate() {
                let offset = HEADER_BYTES + index * ITEM_BYTES + 20;
                bytes[offset..offset + 4].copy_from_slice(&flags.to_le_bytes());
            }
            bytes
        }
        DEBUG_SET => {
            if request.redirects.is_empty() || request.redirects.len() > 4 {
                return Err("debug-registers requires 1..4 address and redirect pairs".into());
            }
            let mut bytes = vec![0; HEADER_BYTES + request.redirects.len() * 16];
            bytes[16..24].copy_from_slice(&request.cr3.to_le_bytes());
            bytes[32..36].copy_from_slice(&(request.redirects.len() as u32).to_le_bytes());
            for (index, (address, redirect)) in request.redirects.iter().enumerate() {
                let offset = HEADER_BYTES + index * 16;
                bytes[offset..offset + 8].copy_from_slice(&address.to_le_bytes());
                bytes[offset + 8..offset + 16].copy_from_slice(&redirect.to_le_bytes());
            }
            bytes
        }
        WATCH_SET => {
            if request.watchpoints.is_empty() || request.watchpoints.len() > 4 {
                return Err("watch requires 1..4 ADDRESS ACCESS LENGTH triples".into());
            }
            let mut bytes = vec![0; HEADER_BYTES + request.watchpoints.len() * 16];
            bytes[32..36].copy_from_slice(&(request.watchpoints.len() as u32).to_le_bytes());
            for (index, (address, access, length)) in request.watchpoints.iter().enumerate() {
                if !matches!(access, 1 | 3)
                    || !matches!(length, 1 | 2 | 4 | 8)
                    || address & (u64::from(*length) - 1) != 0
                {
                    return Err("watch access must be write or read/write and length must be aligned 1/2/4/8".into());
                }
                let offset = HEADER_BYTES + index * 16;
                bytes[offset..offset + 8].copy_from_slice(&address.to_le_bytes());
                bytes[offset + 8..offset + 12].copy_from_slice(&access.to_le_bytes());
                bytes[offset + 12..offset + 16].copy_from_slice(&length.to_le_bytes());
            }
            bytes
        }
        EVENT_SET => {
            use crate::protocol::memory::{
                ARGUMENT_MAX_DEPTH, ARGUMENT_MAX_STACK_OFFSET, ARGUMENT_REGISTER, ARGUMENT_STACK,
                EVENT_INSTRUCTION, EVENT_REGION_BYTES,
            };
            let regions = &request.event_regions;
            let probes = &request.event_probes;
            if regions.len() + request.event_arguments.len() > EVENT_REGIONS || probes.len() > 4 {
                return Err(format!(
                    "event capture accepts up to {EVENT_REGIONS} regions and four probes"
                ));
            }
            if request.flags & INTERCEPT_NO_LEASE != 0
                && probes.iter().any(|&(_, kind)| kind == EVENT_INSTRUCTION)
            {
                return Err("instruction capture requires a lease".into());
            }
            // A noncanonical raw address can alias a tagged argument descriptor.
            if regions.iter().any(|&(address, length)| {
                address == 0
                    || !matches!(address >> 56, 0 | 0xff)
                    || !(1..=EVENT_REGION_BYTES as u64).contains(&length)
                    || address
                        .checked_add(length - 1)
                        .is_none_or(|end| end >> 56 != address >> 56)
            }) {
                return Err("invalid event capture region address or length".into());
            }
            let mut descriptors = regions.clone();
            for argument in &request.event_arguments {
                if argument.pointer_depth > ARGUMENT_MAX_DEPTH
                    || argument.copy_bytes > EVENT_REGION_BYTES
                    || (argument.pointer_depth == 0) != (argument.copy_bytes == 0)
                    || argument.pointer_depth == 0 && argument.pointer_offset != 0
                    || if argument.on_stack {
                        argument.location > ARGUMENT_MAX_STACK_OFFSET
                    } else {
                        argument.location >= 16
                    }
                {
                    return Err("invalid argument location, copy size, or pointer depth".into());
                }
                descriptors.push((
                    (if argument.on_stack {
                        ARGUMENT_STACK
                    } else {
                        ARGUMENT_REGISTER
                    }) | argument.location,
                    argument.copy_bytes as u64
                        | ((argument.pointer_depth as u64) << 32)
                        | (u64::from(argument.pointer_offset as u16) << 48),
                ));
            }
            if request.event_stack_bytes > crate::protocol::memory::EVENT_STACK_BYTES {
                return Err("event stack capture exceeds its capacity".into());
            }
            use crate::protocol::memory::{EVENT_GUARD_BYTES, EVENT_MAX_GUARDS};
            if request.event_guards.len() > EVENT_MAX_GUARDS {
                return Err("event identity has too many validation guards".into());
            }
            let mut bytes = vec![
                0;
                HEADER_BYTES
                    + (descriptors.len() + probes.len()) * 16
                    + request.event_guards.len() * EVENT_GUARD_BYTES
            ];
            bytes[148..152].copy_from_slice(&(request.event_guards.len() as u32).to_le_bytes());
            if request.thread_id_offset > 65528 || request.thread_id_offset & 7 != 0 {
                return Err("invalid thread identity field offset".into());
            }
            bytes[152..156].copy_from_slice(&request.thread_id_offset.to_le_bytes());
            for (value, slot) in request
                .event_identity
                .iter()
                .zip(bytes[96..120].as_chunks_mut::<8>().0.iter_mut())
            {
                slot.copy_from_slice(&value.to_le_bytes());
            }
            if request.event_limit > 1_000_000 {
                return Err("event limit exceeds 1000000".into());
            }
            bytes[24..32].copy_from_slice(&request.event_limit.to_le_bytes());
            bytes[32..36].copy_from_slice(&(descriptors.len() as u32).to_le_bytes());
            bytes[144..148].copy_from_slice(&(request.event_stack_bytes as u32).to_le_bytes());
            bytes[44..48].copy_from_slice(&(probes.len() as u32).to_le_bytes());
            bytes[48..56].copy_from_slice(&request.event_exceptions.to_le_bytes());
            bytes[56..60].copy_from_slice(
                &((if request.event_sample {
                    EVENT_SAMPLE
                } else {
                    0
                }) | (if request.snapshot_arm {
                    crate::protocol::memory::EVENT_SNAPSHOT_ARM
                } else {
                    0
                }) | (if request.snapshot_after {
                    crate::protocol::memory::EVENT_SNAPSHOT_AFTER
                } else {
                    0
                }))
                .to_le_bytes(),
            );
            for (pair, descriptor) in descriptors.iter().chain(probes).zip(
                bytes[HEADER_BYTES..HEADER_BYTES + (descriptors.len() + probes.len()) * 16]
                    .as_chunks_mut::<16>()
                    .0
                    .iter_mut(),
            ) {
                descriptor[..8].copy_from_slice(&pair.0.to_le_bytes());
                descriptor[8..].copy_from_slice(&pair.1.to_le_bytes());
            }
            for (guard, descriptor) in request.event_guards.iter().zip(
                bytes[HEADER_BYTES + (descriptors.len() + probes.len()) * 16..]
                    .as_chunks_mut::<EVENT_GUARD_BYTES>()
                    .0
                    .iter_mut(),
            ) {
                if guard.cr3 & 0x000f_ffff_ffff_f000 == 0
                    || guard.mask == 0
                    || guard.address.checked_add(8).is_none()
                {
                    return Err("invalid event identity guard".into());
                }
                for (value, slot) in [guard.cr3, guard.address, guard.expected, guard.mask]
                    .into_iter()
                    .zip(descriptor.as_chunks_mut::<8>().0.iter_mut())
                {
                    slot.copy_from_slice(&value.to_le_bytes());
                }
            }
            bytes
        }
        WATCH_FETCH | CONTEXT_SNAPSHOT | STACK_WALK | CONTEXT_RECORD_GET | EVENT_FETCH => {
            let (maximum, record_bytes) = match operation {
                WATCH_FETCH => (WATCH_RING_RECORDS, WATCH_RECORD_BYTES),
                EVENT_FETCH => (EVENT_FETCH_MAX, EVENT_RECORD_BYTES),
                CONTEXT_SNAPSHOT => (CONTEXT_CPU_RECORDS, CONTEXT_RECORD_BYTES),
                CONTEXT_RECORD_GET => (1, CONTEXT_RECORD_BYTES),
                _ => (STACK_MAX_FRAMES, 16),
            };
            if request.count == 0 && operation != EVENT_FETCH
                || request.count > maximum
                || request.cpu >= 64
            {
                return Err("invalid observation CPU or record count".into());
            }
            let mut bytes = vec![0; HEADER_BYTES + request.count * record_bytes];
            bytes[24..32].copy_from_slice(&u64::from(request.cpu).to_le_bytes());
            bytes[32..36].copy_from_slice(&(request.count as u32).to_le_bytes());
            bytes
        }
        CONTEXT_SET | CONTEXT_CLEAR | WATCH_CLEAR | SYSCALL_SET | SYSCALL_CLEAR => {
            vec![0; HEADER_BYTES]
        }
        INTERCEPT_CONTEXT_ADD | INTERCEPT_CONTEXT_REMOVE => {
            if request.contexts.is_empty() || request.contexts.len() > ROOT_HISTORY_COUNT - 2 {
                return Err(format!(
                    "context change requires 1..={} CR3 roots",
                    ROOT_HISTORY_COUNT - 2
                ));
            }
            let mut bytes = vec![0; HEADER_BYTES + request.contexts.len() * 8];
            bytes[32..36].copy_from_slice(&(request.contexts.len() as u32).to_le_bytes());
            for (index, root) in request.contexts.iter().enumerate() {
                bytes[HEADER_BYTES + index * 8..HEADER_BYTES + index * 8 + 8]
                    .copy_from_slice(&root.to_le_bytes());
            }
            bytes
        }
        HOOK_LIST => vec![0; HEADER_BYTES + HOOK_MAX_PATCHES * ITEM_BYTES],
        INTERCEPT_CONTEXT_LIST => vec![0; HEADER_BYTES + ROOT_HISTORY_COUNT * 8],
        HOOK_REMOVE | HOOK_DROP | DEBUG_CLEAR | CPUID_CLEAR | INTERCEPT_RENEW
        | INTERCEPT_RELEASE | INTERCEPT_STATUS | EVENT_CLEAR => vec![0; HEADER_BYTES],
        _ => return Err("invalid interception operation".into()),
    };
    bytes[0..8].copy_from_slice(&MEMORY_MAGIC.to_le_bytes());
    bytes[8..12].copy_from_slice(&MEMORY_VERSION.to_le_bytes());
    bytes[12..16].copy_from_slice(&operation.to_le_bytes());
    let length = bytes.len() as u32;
    bytes[36..40].copy_from_slice(&length.to_le_bytes());
    bytes[64..72].copy_from_slice(&request.alternate_cr3.to_le_bytes());
    if matches!(operation, WATCH_SET | CONTEXT_SET | SYSCALL_SET | EVENT_SET) {
        bytes[16..24].copy_from_slice(&request.cr3.to_le_bytes());
    }
    if operation == SYSCALL_SET {
        bytes[24..32].copy_from_slice(&request.callback.to_le_bytes());
        bytes[48..56].copy_from_slice(&request.syscall_entry.to_le_bytes());
    }
    if matches!(
        operation,
        WATCH_FETCH | CONTEXT_SNAPSHOT | STACK_WALK | CONTEXT_RECORD_GET | EVENT_FETCH
    ) {
        bytes[64..72].copy_from_slice(&request.cursor.to_le_bytes());
    }
    bytes[80..88].copy_from_slice(&request.token.to_le_bytes());
    bytes[128..132].copy_from_slice(&request.flags.to_le_bytes());
    bytes[132..136].copy_from_slice(&request.lease_ms.to_le_bytes());
    if operation == HOOK_DROP {
        bytes[144..152].copy_from_slice(&request.patch_id.to_le_bytes());
    }
    Ok(bytes)
}

pub fn start_tracking_packet(pid: u64, targets: &[(u64, u64)]) -> Result<Vec<u8>, String> {
    let mut bytes = tracking_packet(AD_START, 0, targets.len())?;
    bytes[24..32].copy_from_slice(&pid.to_le_bytes());
    for (index, (root, address)) in targets.iter().enumerate() {
        let offset = HEADER_BYTES + index * TRACK_TARGET_BYTES;
        bytes[offset..offset + 8].copy_from_slice(&root.to_le_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&address.to_le_bytes());
    }
    Ok(bytes)
}

pub fn fetch_tracking_packet(session: u64, first: usize, count: usize) -> Result<Vec<u8>, String> {
    if first
        .checked_add(count)
        .is_none_or(|end| end > TRACK_MAX_PAGES)
    {
        return Err("tracking fetch range exceeds session capacity".into());
    }
    let mut bytes = tracking_packet(AD_FETCH, session, count)?;
    bytes[64..72].copy_from_slice(&(first as u64).to_le_bytes());
    Ok(bytes)
}

pub fn packet(operation: u32, pid: u64, cr3: u64, items: &[Item]) -> Result<Vec<u8>, String> {
    if items.len() > MAX_ITEMS || (operation != INFO && items.is_empty()) {
        return Err(format!("memory batches require 1..={MAX_ITEMS} items"));
    }
    let table_end = HEADER_BYTES + items.len() * ITEM_BYTES;
    let length = items.iter().try_fold(table_end, |total, item| {
        if item.bytes.is_empty() || item.address.checked_add(item.bytes.len() as u64).is_none() {
            return Err("memory item has an empty or overflowing range".to_string());
        }
        total
            .checked_add(item.bytes.len())
            .filter(|size| *size <= BUFFER_BYTES)
            .ok_or_else(|| {
                format!("memory batch exceeds {BUFFER_BYTES} bytes including descriptors")
            })
    })?;
    let mut bytes = vec![0; length];
    bytes[0..8].copy_from_slice(&MEMORY_MAGIC.to_le_bytes());
    bytes[8..12].copy_from_slice(&MEMORY_VERSION.to_le_bytes());
    bytes[12..16].copy_from_slice(&operation.to_le_bytes());
    bytes[16..24].copy_from_slice(&cr3.to_le_bytes());
    bytes[24..32].copy_from_slice(&pid.to_le_bytes());
    bytes[32..36].copy_from_slice(&(items.len() as u32).to_le_bytes());
    bytes[36..40].copy_from_slice(&(length as u32).to_le_bytes());
    let mut offset = table_end;
    for (index, item) in items.iter().enumerate() {
        let descriptor = HEADER_BYTES + index * ITEM_BYTES;
        bytes[descriptor..descriptor + 8].copy_from_slice(&item.address.to_le_bytes());
        bytes[descriptor + 8..descriptor + 12].copy_from_slice(&(offset as u32).to_le_bytes());
        bytes[descriptor + 12..descriptor + 16]
            .copy_from_slice(&(item.bytes.len() as u32).to_le_bytes());
        if operation == WRITE {
            bytes[offset..offset + item.bytes.len()].copy_from_slice(&item.bytes);
        }
        offset += item.bytes.len();
    }
    Ok(bytes)
}

pub fn bitmap_packet(start: u64, page_count: usize) -> Result<Vec<u8>, String> {
    let length = ad_bitmap_length(start, page_count)
        .map_err(|_| "A/D bitmap requires an aligned GPA and a nonzero page count within the packet and 48-bit GPA limits".to_string())?;
    let mut bytes = vec![0; length];
    bytes[0..8].copy_from_slice(&MEMORY_MAGIC.to_le_bytes());
    bytes[8..12].copy_from_slice(&MEMORY_VERSION.to_le_bytes());
    bytes[12..16].copy_from_slice(&AD_BITMAP.to_le_bytes());
    bytes[16..24].copy_from_slice(&start.to_le_bytes());
    bytes[32..36].copy_from_slice(&(page_count as u32).to_le_bytes());
    bytes[36..40].copy_from_slice(&(length as u32).to_le_bytes());
    Ok(bytes)
}

pub fn tracking_packet(operation: u32, session: u64, count: usize) -> Result<Vec<u8>, String> {
    let length = match operation {
        AD_START | AD_ENUMERATE if count > 0 && count <= TRACK_MAX_PAGES => {
            HEADER_BYTES + count * TRACK_TARGET_BYTES
        }
        AD_FETCH if count > 0 && count <= TRACK_FETCH_PAGES => {
            HEADER_BYTES + count * TRACK_RECORD_BYTES
        }
        AD_STOP | AD_RELEASE | AD_STATUS | AD_CANCEL if count == 0 => HEADER_BYTES,
        _ => return Err("invalid tracking packet size or operation".into()),
    };
    let mut bytes = vec![0; length];
    bytes[0..8].copy_from_slice(&MEMORY_MAGIC.to_le_bytes());
    bytes[8..12].copy_from_slice(&MEMORY_VERSION.to_le_bytes());
    bytes[12..16].copy_from_slice(&operation.to_le_bytes());
    bytes[32..36].copy_from_slice(&(count as u32).to_le_bytes());
    bytes[36..40].copy_from_slice(&(length as u32).to_le_bytes());
    bytes[80..88].copy_from_slice(&session.to_le_bytes());
    Ok(bytes)
}

pub struct PageBatch {
    pub pages: Vec<(u64, u64)>,
    pub next: u64,
    pub limit: u64,
}

pub fn enumerate_page_batch(root: u64, cursor: u64) -> Result<PageBatch, String> {
    if root & !4095 == 0 || cursor & 4095 != 0 {
        return Err("enumeration requires a valid CR3 and a page-aligned cursor".into());
    }
    let mut bytes = tracking_packet(AD_ENUMERATE, 0, TRACK_MAX_PAGES)?;
    bytes[16..24].copy_from_slice(&cursor.to_le_bytes());
    bytes[64..72].copy_from_slice(&root.to_le_bytes());
    invoke(&mut bytes)?;
    decode_page_batch(&bytes, root, cursor)
}

pub fn decode_page_batch(bytes: &[u8], root: u64, cursor: u64) -> Result<PageBatch, String> {
    if bytes.len() < HEADER_BYTES
        || bytes.len() > BUFFER_BYTES
        || quad(bytes, 0) != MEMORY_MAGIC
        || word(bytes, 8) != MEMORY_VERSION
        || word(bytes, 12) != AD_ENUMERATE
        || word(bytes, 36) as usize != bytes.len()
    {
        return Err("invalid or truncated enumeration response".into());
    }
    let count = word(bytes, 32) as usize;
    let next = quad(bytes, 16);
    let limit = quad(bytes, 72);
    if count > TRACK_MAX_PAGES
        || bytes.len() < HEADER_BYTES + count * TRACK_TARGET_BYTES
        || !matches!(limit, 0x8000_0000_0000 | 0x100_0000_0000_0000)
        || next <= cursor && !(next == limit && cursor == limit && count == 0)
        || next > limit
        || next & 4095 != 0
    {
        return Err("invalid resident enumeration response or cursor".into());
    }
    let mut pages = Vec::with_capacity(count);
    let mut previous = None;
    for index in 0..count {
        let offset = HEADER_BYTES + index * TRACK_TARGET_BYTES;
        let address = quad(bytes, offset + 8);
        if quad(bytes, offset) != root
            || address < cursor
            || address >= next
            || address & 4095 != 0
            || previous.is_some_and(|value| address <= value)
        {
            return Err("invalid resident enumeration entry".into());
        }
        pages.push((root, address));
        previous = Some(address);
    }
    Ok(PageBatch { pages, next, limit })
}

pub fn enumerate_targets(root: u64) -> Result<Vec<(u64, u64)>, String> {
    let mut targets = Vec::new();
    let mut cursor = 0u64;
    loop {
        let batch = enumerate_page_batch(root, cursor)?;
        targets.extend(batch.pages);
        if targets.len() > TRACK_MAX_PAGES {
            return Err(format!(
                "process exceeds {TRACK_MAX_PAGES} resident pages; select a smaller virtual address range"
            ));
        }
        cursor = batch.next;
        if cursor >= batch.limit {
            break;
        }
    }
    if targets.is_empty() {
        return Err("process has no resident user pages".into());
    }
    Ok(targets)
}

pub fn invoke(bytes: &mut [u8]) -> Result<(), String> {
    if bytes.len() < HEADER_BYTES
        || bytes.len() > BUFFER_BYTES
        || quad(bytes, 0) != MEMORY_MAGIC
        || word(bytes, 8) != MEMORY_VERSION
        || word(bytes, 36) as usize != bytes.len()
    {
        return Err("invalid memory transport packet".into());
    }
    #[cfg(target_arch = "x86_64")]
    {
        let mut signature = MEMORY_LEAF;
        let mut status = bytes.as_mut_ptr() as u64;
        // CPUID is the only instruction that submits a memory packet.
        // RBX is nonvolatile in the host ABI and must survive the native fallback.
        unsafe {
            std::arch::asm!(
                "push rbx", "cpuid", "pop rbx",
                inout("eax") signature,
                inout("ecx") MEMORY_VERSION => _,
                inout("rdx") status,
                in("r8") bytes.len(),
            );
        }
        if signature != MEMORY_SIGNATURE {
            let state = crate::runtime::query();
            return Err(if state.present {
                if state.caller_l2 && !state.l2_memory_advertised {
                    "MatrixHV memory transport is unavailable from L2; L0 diagnostics remain available, but L2 memory access is unsupported"
                } else if state.caller_l2 {
                    "MatrixHV memory transport is unavailable from L2 despite advertised support; L0 diagnostics remain available"
                } else {
                    "MatrixHV memory transport is unavailable on this CPU; L0 is present; advertised capabilities do not establish transport availability"
                }
            } else {
                "MatrixHV is not present on this CPU"
            }.into());
        }
        if status != 0 {
            bytes[40..44].copy_from_slice(&(status as u32).to_le_bytes());
            return Err(format!(
                "memory transport failed: {}",
                status_text(status as u32)
            ));
        }
        if word(bytes, 40) != 0 {
            return Err(format!(
                "memory batch rejected: {}",
                status_text(word(bytes, 40))
            ));
        }
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = bytes;
        Err("memory transport requires x86_64".into())
    }
}

pub fn status_text(status: u32) -> &'static str {
    match status {
        0 => "success",
        1 => "invalid packet or page table",
        2 => "invalid range",
        3 => "page is not resident or mapped",
        4 => "page permission, EPT concealment, or non-RAM mapping denied access",
        5 => {
            "unsupported paging mode, nested guest, hardware capability, or conflicting tracking session"
        }
        6 => "prototype PTE could not be resolved",
        7 => "page is backed by the pagefile",
        8 => "copy-on-write requires the Windows memory manager",
        9 => "demand-zero write requires a physical backing page",
        10 => "tracking/interception session or CPU rendezvous is busy; retry",
        11 => "invalid session identifier or lifecycle state",
        12 => "resident EPT table pool is exhausted",
        13 => "virtual page mapping changed during the session",
        14 => "original write committed; a page merge conflict revoked interception",
        15 => "original write committed; interception refresh or retirement failed",
        16 => "L2 target bytes were written but response delivery failed; do not retry blindly",
        ROAD_STATUS_DEMAND_ZERO => "DEMAND_ZERO (zero-filled read)",
        _ => "unknown status",
    }
}

pub fn read_ranges(cr3: u64, ranges: &[(u64, usize)]) -> Result<Vec<Vec<u8>>, String> {
    if ranges.is_empty() || ranges.len() > MAX_ITEMS {
        return Err(format!("memory batches require 1..={MAX_ITEMS} items"));
    }
    let mut total = HEADER_BYTES + ranges.len() * ITEM_BYTES;
    for (_, length) in ranges {
        total = total
            .checked_add(*length)
            .filter(|size| *size <= BUFFER_BYTES)
            .ok_or_else(|| "symbol lookup batch is too large".to_string())?;
    }
    let items: Vec<_> = ranges
        .iter()
        .map(|(address, length)| Item {
            address: *address,
            bytes: vec![0; *length],
        })
        .collect();
    let mut bytes = packet(READ, 0, cr3, &items)?;
    invoke(&mut bytes)?;
    let mut output = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let descriptor = HEADER_BYTES + index * ITEM_BYTES;
        let status = word(&bytes, descriptor + 16);
        let done = word(&bytes, descriptor + 20) as usize;
        if status != 0 || done != item.bytes.len() {
            return Err(format!(
                "symbol lookup at {:#x}: {}; transferred {done}/{} bytes; supply a kernel page-table root when KPTI is enabled",
                item.address,
                status_text(status),
                item.bytes.len()
            ));
        }
        let offset = word(&bytes, descriptor + 8) as usize;
        let end = offset
            .checked_add(done)
            .ok_or("memory response range overflows")?;
        output.push(
            bytes
                .get(offset..end)
                .ok_or("invalid memory response range")?
                .to_vec(),
        );
    }
    Ok(output)
}

pub fn info_packet() -> Result<Vec<u8>, String> {
    let mut bytes = packet(INFO, 0, 0, &[])?;
    bytes.resize(INFO_BYTES, 0);
    bytes[36..40].copy_from_slice(&(INFO_BYTES as u32).to_le_bytes());
    Ok(bytes)
}

/// An observed page-table root whose native Windows PEB and image matched.
///
/// This is an observational match, not a PID binding. The caller must stop
/// using it when the target process exits or its address space changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageRoot {
    pub cr3: u64,
    pub image: u64,
}

fn user_range(address: u64, length: usize) -> bool {
    address >= 0x10000
        && address
            .checked_add(length as u64)
            .is_some_and(|end| end <= 0x0000_8000_0000_0000)
}

fn image_root_candidate(
    root: u64,
    peb: u64,
    image_name: &str,
    read: &mut impl FnMut(u64, u64, usize) -> Option<Vec<u8>>,
) -> Option<ImageRoot> {
    let pointer = |bytes: &[u8]| -> Option<u64> {
        Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?))
    };
    let base = pointer(&read(root, peb.checked_add(0x10)?, 8)?)?;
    if !user_range(base, 64) {
        return None;
    }
    let dos = read(root, base, 64)?;
    if dos.get(..2)? != b"MZ" {
        return None;
    }
    let pe_offset = u32::from_le_bytes(dos.get(60..64)?.try_into().ok()?) as u64;
    if !(64..=1024 * 1024).contains(&pe_offset) {
        return None;
    }
    let pe_address = base.checked_add(pe_offset)?;
    if !user_range(pe_address, 84) {
        return None;
    }
    let pe = read(root, pe_address, 84)?;
    let machine = u16::from_le_bytes(pe.get(4..6)?.try_into().ok()?);
    let magic = u16::from_le_bytes(pe.get(24..26)?.try_into().ok()?);
    let image_size = u32::from_le_bytes(pe.get(80..84)?.try_into().ok()?) as usize;
    if pe.get(..4)? != b"PE\0\0"
        || machine != 0x8664
        || magic != 0x20b
        || image_size < 4096
        || !user_range(base, image_size)
    {
        return None;
    }

    let parameters = pointer(&read(root, peb.checked_add(0x20)?, 8)?)?;
    let path_address = parameters.checked_add(0x60)?;
    if !user_range(path_address, 16) {
        return None;
    }
    let descriptor = read(root, path_address, 16)?;
    let length = u16::from_le_bytes(descriptor.get(..2)?.try_into().ok()?) as usize;
    let capacity = u16::from_le_bytes(descriptor.get(2..4)?.try_into().ok()?) as usize;
    let buffer = pointer(descriptor.get(8..16)?)?;
    if length == 0
        || length > 32766
        || length > capacity
        || !length.is_multiple_of(2)
        || !user_range(buffer, length)
    {
        return None;
    }
    let encoded = read(root, buffer, length)?;
    let units: Vec<u16> = encoded
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let path = String::from_utf16(&units).ok()?;
    let name = path.rsplit(['\\', '/']).next()?;
    if !name.eq_ignore_ascii_case(image_name) {
        return None;
    }
    Some(ImageRoot {
        cr3: root,
        image: base,
    })
}

fn match_image_roots(
    candidates: &[u64],
    peb: u64,
    image_name: &str,
    read: &mut impl FnMut(u64, u64, usize) -> Option<Vec<u8>>,
) -> Option<ImageRoot> {
    for (index, candidate) in candidates.iter().enumerate() {
        let root = candidate & !4095;
        if root == 0
            || candidates[..index]
                .iter()
                .any(|previous| previous & !4095 == root)
        {
            continue;
        }
        if let Some(found) = image_root_candidate(root, peb, image_name, read) {
            return Some(found);
        }
    }
    None
}

/// Find a currently observed root that maps a native 64-bit Windows PEB and
/// an image with the requested file name. Hints are validated like observed
/// roots, and failed candidates are retried until `timeout` expires.
pub fn find_pe_image_root(
    peb: u64,
    image_name: &str,
    hints: &[u64],
    timeout: std::time::Duration,
) -> Result<Option<ImageRoot>, String> {
    if !user_range(peb, 0x28) || image_name.is_empty() || image_name.contains(['\\', '/', '\0']) {
        return Err("expected a native user PEB and an image file name".into());
    }
    let start = std::time::Instant::now();
    loop {
        let mut info = info_packet()?;
        if let Err(error) = invoke(&mut info) {
            let remaining = timeout.saturating_sub(start.elapsed());
            if word(&info, 40) != crate::protocol::memory::Error::Busy as u32 || remaining.is_zero()
            {
                return Err(error);
            }
            std::thread::sleep(remaining.min(std::time::Duration::from_millis(20)));
            continue;
        }
        let mut candidates = Vec::with_capacity(hints.len() + ROOT_HISTORY_COUNT + 2);
        candidates.extend_from_slice(hints);
        candidates
            .extend((0..ROOT_HISTORY_COUNT).map(|index| quad(&info, HEADER_BYTES + index * 8)));
        candidates.extend([quad(&info, 64), quad(&info, 48)]);
        if let Some(found) =
            match_image_roots(&candidates, peb, image_name, &mut |cr3, address, length| {
                read_ranges(cr3, &[(address, length)])
                    .ok()?
                    .into_iter()
                    .next()
            })
        {
            return Ok(Some(found));
        }
        let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
            return Ok(None);
        };
        if remaining.is_zero() {
            return Ok(None);
        }
        std::thread::sleep(remaining.min(std::time::Duration::from_millis(20)));
    }
}

#[cfg(test)]
#[path = "../../tests/image_root_tests.rs"]
mod image_root_tests;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub address: u64,
    pub status: u32,
    pub transferred: usize,
    pub requested: usize,
    pub bytes: Vec<u8>,
}

impl Transfer {
    pub fn is_complete(&self) -> bool {
        (self.status == 0 || self.status == ROAD_STATUS_DEMAND_ZERO)
            && self.transferred == self.requested
    }
}

pub fn decode_transfers(bytes: &[u8]) -> Result<Vec<Transfer>, String> {
    if bytes.len() < HEADER_BYTES
        || bytes.len() > BUFFER_BYTES
        || quad(bytes, 0) != MEMORY_MAGIC
        || word(bytes, 8) != MEMORY_VERSION
        || word(bytes, 36) as usize != bytes.len()
        || !matches!(word(bytes, 12), READ | WRITE)
    {
        return Err("invalid memory transfer response".into());
    }
    let count = word(bytes, 32) as usize;
    let table_end = HEADER_BYTES + count * ITEM_BYTES;
    if count == 0 || count > MAX_ITEMS || table_end > bytes.len() {
        return Err("invalid memory response descriptor count".into());
    }
    let mut transfers = Vec::with_capacity(count);
    for index in 0..count {
        let descriptor = HEADER_BYTES + index * ITEM_BYTES;
        let offset = word(bytes, descriptor + 8) as usize;
        let requested = word(bytes, descriptor + 12) as usize;
        let transferred = word(bytes, descriptor + 20) as usize;
        let end = offset
            .checked_add(requested)
            .ok_or("memory response range overflows")?;
        if offset < table_end || end > bytes.len() || transferred > requested {
            return Err("invalid memory response data range".into());
        }
        transfers.push(Transfer {
            address: quad(bytes, descriptor),
            status: word(bytes, descriptor + 16),
            transferred,
            requested,
            bytes: if word(bytes, 12) == READ {
                bytes[offset..offset + transferred].to_vec()
            } else {
                Vec::new()
            },
        });
    }
    Ok(transfers)
}
pub fn transfer_present(cr3: u64, items: &[Item]) -> Result<Vec<Transfer>, String> {
    // Resident scans revalidate mappings without synthesizing demand-zero pages
    // or walking the VAD tree for every page in a batch.
    let mut bytes = packet(READ, 0, cr3, items)?;
    invoke(&mut bytes)?;
    decode_transfers(&bytes)
}
