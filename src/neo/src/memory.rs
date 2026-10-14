use crate::protocol::memory::{
    AD_BITMAP, AD_CANCEL, AD_ENUMERATE, AD_FETCH, AD_RELEASE, AD_START, AD_STATUS, AD_STOP,
    BUFFER_BYTES, HEADER_BYTES, INFO, INFO_BYTES, ITEM_BYTES, MAX_ITEMS, MEMORY_LEAF, MEMORY_MAGIC,
    MEMORY_SIGNATURE, MEMORY_VERSION, READ, ROAD_STATUS_DEMAND_ZERO, ROOT_HISTORY_COUNT,
    TRACK_FETCH_PAGES, TRACK_MAX_PAGES, TRACK_RECORD_BYTES, TRACK_TARGET_BYTES, WRITE,
    ad_bitmap_length, quad, word,
};
use crate::symbols::{KernelSymbols, Process};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub address: u64,
    pub bytes: Vec<u8>,
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
}

pub fn interception_packet(request: &InterceptionRequest) -> Result<Vec<u8>, String> {
    use crate::protocol::memory::{
        DEBUG_CLEAR, DEBUG_SET, HOOK_ADD, HOOK_DROP, HOOK_INSTALL, HOOK_LIST, HOOK_MAX_PATCHES,
        HOOK_REMOVE, INTERCEPT_CONTEXT_ADD, INTERCEPT_CONTEXT_LIST, INTERCEPT_CONTEXT_REMOVE,
        INTERCEPT_MAX_LEASE_MS, INTERCEPT_NO_LEASE, INTERCEPT_RELEASE, INTERCEPT_RENEW,
        INTERCEPT_STATUS,
    };
    let operation = request.operation;
    if request.lease_ms > INTERCEPT_MAX_LEASE_MS
        || request.lease_ms != 0 && !matches!(operation, HOOK_INSTALL | DEBUG_SET | INTERCEPT_RENEW)
        || request.flags & INTERCEPT_NO_LEASE != 0
            && (request.lease_ms != 0 || !matches!(operation, HOOK_INSTALL | DEBUG_SET))
    {
        return Err("invalid interception lease configuration".into());
    }
    if matches!(operation, HOOK_INSTALL | DEBUG_SET) && request.cr3 & !4095 == 0
        || request.alternate_cr3 != 0 && request.alternate_cr3 & !4095 == 0
    {
        return Err("CR3 must contain a nonzero page-table root".into());
    }
    let mut bytes = match operation {
        HOOK_INSTALL | HOOK_ADD => {
            if request.items.len() > HOOK_MAX_PATCHES {
                return Err("hook capacity exceeded".into());
            }
            for item in &request.items {
                if item.bytes.len() > 4096 - (item.address as usize & 4095) {
                    return Err("each patch must fit inside one 4 KiB page".into());
                }
            }
            packet(
                WRITE,
                0,
                if operation == HOOK_INSTALL {
                    request.cr3
                } else {
                    0
                },
                &request.items,
            )?
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
        HOOK_REMOVE | HOOK_DROP | DEBUG_CLEAR | INTERCEPT_RENEW | INTERCEPT_RELEASE
        | INTERCEPT_STATUS => vec![0; HEADER_BYTES],
        _ => return Err("invalid interception operation".into()),
    };
    bytes[0..8].copy_from_slice(&MEMORY_MAGIC.to_le_bytes());
    bytes[8..12].copy_from_slice(&MEMORY_VERSION.to_le_bytes());
    bytes[12..16].copy_from_slice(&operation.to_le_bytes());
    let length = bytes.len() as u32;
    bytes[36..40].copy_from_slice(&length.to_le_bytes());
    bytes[64..72].copy_from_slice(&request.alternate_cr3.to_le_bytes());
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

pub fn enumerate_targets(root: u64) -> Result<Vec<(u64, u64)>, String> {
    let mut targets = Vec::new();
    let mut cursor = 0u64;
    loop {
        let mut bytes = tracking_packet(AD_ENUMERATE, 0, TRACK_MAX_PAGES)?;
        bytes[16..24].copy_from_slice(&cursor.to_le_bytes());
        bytes[64..72].copy_from_slice(&root.to_le_bytes());
        invoke(&mut bytes)?;
        let count = word(&bytes, 32) as usize;
        if count > TRACK_MAX_PAGES {
            return Err("invalid resident enumeration response".into());
        }
        for index in 0..count {
            let offset = HEADER_BYTES + index * TRACK_TARGET_BYTES;
            targets.push((quad(&bytes, offset), quad(&bytes, offset + 8)));
        }
        if targets.len() > TRACK_MAX_PAGES {
            return Err(format!(
                "process exceeds {TRACK_MAX_PAGES} resident pages; select a smaller virtual address range"
            ));
        }
        let next = quad(&bytes, 16);
        if next == cursor {
            return Err("resident enumeration made no progress".into());
        }
        cursor = next;
        if !matches!(quad(&bytes, 72), 0x8000_0000_0000 | 0x100_0000_0000_0000) {
            return Err("invalid resident user address limit".into());
        }
        if cursor >= quad(&bytes, 72) {
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

pub fn resolve_process(
    symbols: &KernelSymbols,
    selector: &str,
    target_cr3: u64,
    kernel_cr3: Option<u64>,
) -> Result<Process, String> {
    let mut info = info_packet()?;
    invoke(&mut info)?;
    let preferred = kernel_cr3.unwrap_or_else(|| {
        let observed = quad(&info, 64);
        if observed != 0 {
            observed
        } else if target_cr3 != 0 {
            target_cr3
        } else {
            quad(&info, 48)
        }
    });
    let mut roots = vec![preferred];
    if kernel_cr3.is_none() {
        roots.extend((0..ROOT_HISTORY_COUNT).map(|index| quad(&info, HEADER_BYTES + index * 8)));
        roots.extend([quad(&info, 48), target_cr3]);
    }
    roots.retain(|root| *root & !4095 != 0);
    roots.sort_unstable();
    roots.dedup();
    symbols.resolve(selector, target_cr3, &roots, quad(&info, 56))
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

pub fn process_packet(
    symbols: &KernelSymbols,
    process: &Process,
    operation: u32,
    target_cr3: Option<u64>,
    items: &[Item],
) -> Result<Vec<u8>, String> {
    if !matches!(operation, READ | WRITE) {
        return Err("process memory operation must be read or write".into());
    }
    let mut bytes = packet(
        operation,
        process.pid,
        target_cr3.unwrap_or(process.kernel_cr3),
        items,
    )?;
    bytes[64..72].copy_from_slice(&process.kernel_cr3.to_le_bytes());
    if target_cr3.is_none() {
        bytes[72..80].copy_from_slice(&process.user_cr3.to_le_bytes());
    }
    for (index, field) in symbols.soft_layout.fields().iter().enumerate() {
        bytes[80 + index * 8..88 + index * 8].copy_from_slice(&field.to_le_bytes());
    }
    for (index, item) in items.iter().enumerate() {
        if let Ok(Some(protection)) =
            symbols.committed_protection(process, item.address, item.bytes.len())
        {
            let descriptor = HEADER_BYTES + index * ITEM_BYTES;
            bytes[descriptor + 16..descriptor + 20].copy_from_slice(&1u32.to_le_bytes());
            bytes[descriptor + 20..descriptor + 24].copy_from_slice(&protection.to_le_bytes());
        }
    }
    Ok(bytes)
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

pub fn transfer(
    symbols: &KernelSymbols,
    process: &Process,
    operation: u32,
    target_cr3: Option<u64>,
    items: &[Item],
) -> Result<Vec<Transfer>, String> {
    let mut bytes = process_packet(symbols, process, operation, target_cr3, items)?;
    invoke(&mut bytes)?;
    decode_transfers(&bytes)
}
