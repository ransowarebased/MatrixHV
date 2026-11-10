use matrixhv_protocol::memory::{
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
    pub callback: u64,
    pub syscall_entry: u64,
    pub cpuid_records: Vec<CpuidRecord>,
    pub cpuid_gate: Option<CpuidGate>,
}

pub fn interception_packet(request: &InterceptionRequest) -> Result<Vec<u8>, String> {
    use matrixhv_protocol::memory::{
        CPUID_CLEAR, CPUID_MAX_RECORDS, CPUID_RECORD_BYTES, CPUID_SET, DEBUG_CLEAR, DEBUG_SET,
        HOOK_ADD, HOOK_DATA_SHADOW, HOOK_DROP, HOOK_INSTALL, HOOK_LIST, HOOK_MAX_PATCHES,
        HOOK_REMOVE, INTERCEPT_CONCURRENT_WRITES, INTERCEPT_CONTEXT_ADD, INTERCEPT_CONTEXT_LIST,
        INTERCEPT_CONTEXT_REMOVE, INTERCEPT_MAX_LEASE_MS, INTERCEPT_NO_LEASE,
        INTERCEPT_PERSISTENT_DATA, INTERCEPT_PRIVATE_SHARED_DATA, INTERCEPT_RELEASE,
        INTERCEPT_RENEW, INTERCEPT_STATUS, INTERCEPT_VMFUNC, SYSCALL_CLEAR, SYSCALL_SET,
    };
    let operation = request.operation;
    let setup = matches!(
        operation,
        HOOK_INSTALL | DEBUG_SET | CPUID_SET | SYSCALL_SET
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
            if let Some(gate) = &request.cpuid_gate {
                if gate.dr3 == 0 || gate.dr7_mask == 0 || gate.dr7_value & !gate.dr7_mask != 0 {
                    return Err("invalid CPUID debug-register gate".into());
                }
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
        SYSCALL_SET | SYSCALL_CLEAR => {
            vec![0; HEADER_BYTES]
        }
        INTERCEPT_CONTEXT_ADD | INTERCEPT_CONTEXT_REMOVE => {
            if request.contexts.is_empty() || request.contexts.len() > ROOT_HISTORY_COUNT - 2 {
                return Err("context change requires 1..14 CR3 roots".into());
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
        | INTERCEPT_RELEASE | INTERCEPT_STATUS => vec![0; HEADER_BYTES],
        _ => return Err("invalid interception operation".into()),
    };
    bytes[0..8].copy_from_slice(&MEMORY_MAGIC.to_le_bytes());
    bytes[8..12].copy_from_slice(&MEMORY_VERSION.to_le_bytes());
    bytes[12..16].copy_from_slice(&operation.to_le_bytes());
    let length = bytes.len() as u32;
    bytes[36..40].copy_from_slice(&length.to_le_bytes());
    bytes[64..72].copy_from_slice(&request.alternate_cr3.to_le_bytes());
    if operation == SYSCALL_SET {
        bytes[16..24].copy_from_slice(&request.cr3.to_le_bytes());
        bytes[24..32].copy_from_slice(&request.callback.to_le_bytes());
        bytes[48..56].copy_from_slice(&request.syscall_entry.to_le_bytes());
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
        || next <= cursor
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
            return Err("MatrixHV memory transport is unavailable; boot the updated EFI and enable MatrixHV on this CPU".into());
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
