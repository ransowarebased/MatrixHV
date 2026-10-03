#[cfg(test)]
#[path = "../../memory/access.rs"]
pub(crate) mod access;

#[cfg(test)]
#[path = "../../memory/tracking.rs"]
pub(crate) mod tracking;

use crate::protocol::memory::{
    AD_BITMAP, AD_CANCEL, AD_ENABLED, AD_ENUMERATE, AD_FETCH, AD_LARGE_PAGE, AD_RELEASE, AD_START,
    AD_STATUS, AD_STOP, BUFFER_BYTES, HEADER_BYTES, INFO, INFO_BYTES, ITEM_BYTES, MAX_ITEMS,
    MEMORY_LEAF, MEMORY_MAGIC, MEMORY_SIGNATURE, MEMORY_VERSION, READ, ROAD_STATUS_DEMAND_ZERO,
    ROOT_HISTORY_COUNT, TRACK_ACCESSED, TRACK_DIRTY, TRACK_DUMP_VALID, TRACK_FETCH_PAGES,
    TRACK_HASH_CHANGED, TRACK_MAX_PAGES, TRACK_RECORD_BYTES, TRACK_REMAPPED, TRACK_TARGET_BYTES,
    WRITE, ad_bitmap_length, quad, word,
};
use crate::symbols;

pub(crate) struct Item {
    pub address: u64,
    pub bytes: Vec<u8>,
}

pub(crate) fn number(text: &str) -> Result<u64, String> {
    let value = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        text.parse()
    };
    value.map_err(|_| format!("invalid integer: {text}; use decimal or 0x-prefixed hexadecimal"))
}

pub(crate) fn packet(
    operation: u32,
    pid: u64,
    cr3: u64,
    items: &[Item],
) -> Result<Vec<u8>, String> {
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

pub(crate) fn bitmap_packet(start: u64, page_count: usize) -> Result<Vec<u8>, String> {
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

pub(crate) fn run_bitmap(arguments: &[String]) -> Result<i32, String> {
    if matches!(
        arguments.get(1).map(String::as_str),
        Some("start" | "stop" | "dump" | "release" | "status" | "cancel")
    ) {
        return run_tracking(&arguments[1..]);
    }
    if arguments.len() != 3 && arguments.len() != 5
        || arguments.len() == 5 && arguments[3] != "--output"
    {
        return Err("usage: neo ad-bitmap GPA PAGE_COUNT [--output FILE]".into());
    }
    let start = number(&arguments[1])?;
    let page_count = usize::try_from(number(&arguments[2])?)
        .map_err(|_| "page count exceeds the host address space".to_string())?;
    let mut bytes = bitmap_packet(start, page_count)?;
    invoke(&mut bytes)?;
    let flags = word(&bytes, 72);
    if flags & AD_ENABLED == 0 {
        return Err("EPT accessed/dirty tracking is unavailable on this CPU".into());
    }
    let bitmap_bytes = page_count.div_ceil(8);
    let accessed = &bytes[HEADER_BYTES..HEADER_BYTES + bitmap_bytes];
    let dirty = &bytes[HEADER_BYTES + bitmap_bytes..];
    println!(
        "gpa={start:#x} pages={page_count} accessed={} dirty={} large_page_coverage={} scope=L1 snapshot=observational",
        accessed.iter().map(|byte| byte.count_ones()).sum::<u32>(),
        dirty.iter().map(|byte| byte.count_ones()).sum::<u32>(),
        flags & AD_LARGE_PAGE != 0,
    );
    if let Some(path) = arguments.get(4) {
        std::fs::write(path, &bytes).map_err(|error| format!("cannot save A/D bitmap: {error}"))?;
        println!("output={path}");
    } else {
        for (name, bitmap) in [("accessed", accessed), ("dirty", dirty)] {
            print!("{name}=");
            for byte in bitmap {
                print!("{byte:02x}");
            }
            println!();
        }
    }
    Ok(0)
}

pub(crate) fn tracking_packet(
    operation: u32,
    session: u64,
    count: usize,
) -> Result<Vec<u8>, String> {
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

fn enumerate_targets(root: u64) -> Result<Vec<(u64, u64)>, String> {
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
                "process exceeds {TRACK_MAX_PAGES} resident pages; select a range with --gva and --pages"
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

fn start_tracking(arguments: &[String]) -> Result<i32, String> {
    let mut pid = None;
    let mut cr3 = None;
    let mut gva = None;
    let mut pages = None;
    let mut kernel_cr3 = 0;
    let mut image = None;
    let mut cache = None;
    let mut index = 1;
    while index < arguments.len() {
        let option = &arguments[index];
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{option} requires a value"))?;
        match option.as_str() {
            "--pid" => pid = Some(number(value)?),
            "--cr3" => cr3 = Some(number(value)?),
            "--gva" => gva = Some(number(value)?),
            "--pages" => {
                pages = Some(usize::try_from(number(value)?).map_err(|_| "page count overflow")?)
            }
            "--kernel-cr3" => kernel_cr3 = number(value)?,
            "--kernel-image" => image = Some(std::path::PathBuf::from(value)),
            "--symbols" => cache = Some(std::path::PathBuf::from(value)),
            _ => return Err(format!("unknown tracking option: {option}")),
        }
        index += 2;
    }
    if pid.is_some() == cr3.is_some() || pid == Some(0) || gva.is_some() != pages.is_some() {
        return Err("start requires either --pid PID or --cr3 CR3; supply --gva GVA and --pages COUNT together".into());
    }
    if let (Some(address), Some(count)) = (gva, pages) {
        if address & 4095 != 0
            || count == 0
            || count > TRACK_MAX_PAGES
            || address.checked_add(count as u64 * 4096).is_none()
        {
            return Err(format!(
                "tracking range requires an aligned GVA and 1..={TRACK_MAX_PAGES} pages"
            ));
        }
    }
    let (kernel_root, user_root) = if let Some(pid) = pid {
        let mut info = packet(INFO, 0, 0, &[])?;
        info.resize(INFO_BYTES, 0);
        info[36..40].copy_from_slice(&(INFO_BYTES as u32).to_le_bytes());
        invoke(&mut info)?;
        let mut roots = vec![kernel_cr3, quad(&info, 64), quad(&info, 48)];
        roots.extend((0..ROOT_HISTORY_COUNT).map(|entry| quad(&info, HEADER_BYTES + entry * 8)));
        roots.retain(|root| root & !4095 != 0);
        roots.sort_unstable();
        roots.dedup();
        let image = image
            .map(Ok)
            .unwrap_or_else(symbols::default_kernel_image)?;
        let cache = cache.map(Ok).unwrap_or_else(symbols::default_cache)?;
        let database = symbols::KernelSymbols::load(&image, &cache)?;
        let process = database.resolve(&pid.to_string(), 0, &roots, quad(&info, 56))?;
        (
            process.kernel_cr3,
            if process.user_cr3 == 0 {
                process.kernel_cr3
            } else {
                process.user_cr3
            },
        )
    } else {
        let root = cr3.unwrap();
        if root & !4095 == 0 || gva.is_none() {
            return Err("--cr3 requires a nonzero root, --gva and --pages".into());
        }
        (root, root)
    };
    let targets = if let (Some(address), Some(count)) = (gva, pages) {
        (0..count)
            .map(|page| {
                let address = address + page as u64 * 4096;
                (
                    if address >> 63 != 0 {
                        kernel_root
                    } else {
                        user_root
                    },
                    address,
                )
            })
            .collect()
    } else {
        enumerate_targets(user_root)?
    };
    let mut bytes = tracking_packet(AD_START, 0, targets.len())?;
    bytes[24..32].copy_from_slice(&pid.unwrap_or(0).to_le_bytes());
    for (index, (root, address)) in targets.iter().enumerate() {
        let offset = HEADER_BYTES + index * TRACK_TARGET_BYTES;
        bytes[offset..offset + 8].copy_from_slice(&root.to_le_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&address.to_le_bytes());
    }
    invoke(&mut bytes)?;
    println!(
        "session={} state=ACTIVE pages={} t0={} scope=L1 precision=4096",
        quad(&bytes, 80),
        word(&bytes, 108),
        quad(&bytes, 88)
    );
    Ok(0)
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn verify_dump(record: &[u8]) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    if record.len() != TRACK_RECORD_BYTES {
        return Err("invalid tracking record size".into());
    }
    if word(record, 48) & TRACK_DUMP_VALID != 0 {
        let digest = Sha256::digest(&record[120..]);
        if digest[..] != record[88..120] {
            return Err("dirty page SHA-256 verification failed".into());
        }
    }
    Ok(())
}

pub(crate) fn dump_tracking(
    session: u64,
    directory: &std::path::Path,
    mut submit: impl FnMut(&mut [u8]) -> Result<(), String>,
) -> Result<i32, String> {
    use std::io::Write;
    let mut status = tracking_packet(AD_STOP, session, 0)?;
    submit(&mut status)?;
    if let Some(parent) = directory
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::create_dir(directory).map_err(|error| {
        format!("dump directory must be new: {error}; frozen session remains available")
    })?;
    let mut manifest = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("pages.jsonl"))
        .map_err(|error| error.to_string())?;
    let total = word(&status, 108) as usize;
    if total == 0 || total > TRACK_MAX_PAGES {
        return Err("invalid stopped session size".into());
    }
    let mut first = 0;
    let mut accessed_bitmap = vec![0u8; total.div_ceil(8)];
    let mut dirty_bitmap = vec![0u8; total.div_ceil(8)];
    let mut dirty = 0;
    let mut remapped = 0;
    let mut failed = false;
    while first < total {
        let requested = (total - first).min(TRACK_FETCH_PAGES);
        let mut bytes = tracking_packet(AD_FETCH, session, requested)?;
        bytes[64..72].copy_from_slice(&(first as u64).to_le_bytes());
        submit(&mut bytes)?;
        let count = word(&bytes, 32) as usize;
        if count != requested {
            return Err("incomplete frozen session response".into());
        }
        for index in 0..count {
            let offset = HEADER_BYTES + index * TRACK_RECORD_BYTES;
            let record = &bytes[offset..offset + TRACK_RECORD_BYTES];
            verify_dump(record)?;
            let flags = word(record, 48);
            let page_index = first + index;
            if flags & TRACK_ACCESSED != 0 {
                accessed_bitmap[page_index / 8] |= 1 << (page_index & 7);
            }
            if flags & TRACK_DIRTY != 0 {
                dirty_bitmap[page_index / 8] |= 1 << (page_index & 7);
            }
            let status = word(record, 52);
            dirty += usize::from(flags & TRACK_DIRTY != 0);
            remapped += usize::from(flags & TRACK_REMAPPED != 0);
            failed |= status != 0;
            let filename = if flags & TRACK_DUMP_VALID != 0 {
                let name = format!("page-{:04}-{:016x}.bin", first + index, quad(record, 8));
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(directory.join(&name))
                    .map_err(|error| error.to_string())?;
                file.write_all(&record[120..])
                    .map_err(|error| error.to_string())?;
                file.sync_all().map_err(|error| error.to_string())?;
                name
            } else {
                String::new()
            };
            writeln!(manifest,
                "{{\"index\":{},\"cr3\":{},\"gva\":{},\"initial_gpa\":{},\"current_gpa\":{},\"pte_fingerprint\":{},\"current_fingerprint\":{},\"flags\":{},\"status\":{},\"hash_changed\":{},\"initial_sha256\":\"{}\",\"sha256\":\"{}\",\"dump\":\"{}\"}}",
                first + index, quad(record, 0), quad(record, 8), quad(record, 16), quad(record, 24),
                quad(record, 32), quad(record, 40), flags, status, flags & TRACK_HASH_CHANGED != 0,
                hex_bytes(&record[56..88]), hex_bytes(&record[88..120]), filename)
                .map_err(|error| error.to_string())?;
        }
        first += count;
    }
    manifest.sync_all().map_err(|error| error.to_string())?;
    std::fs::write(directory.join("accessed.bin"), accessed_bitmap)
        .map_err(|error| error.to_string())?;
    std::fs::write(directory.join("dirty.bin"), dirty_bitmap).map_err(|error| error.to_string())?;
    std::fs::write(directory.join("session.txt"), format!("session={session}\npid={}\npages={total}\nt0={}\nt1={}\nscope=L1\nprecision=4096\ndirty={dirty}\nremapped={remapped}\n",
        quad(&status, 24), quad(&status, 88), quad(&status, 96))).map_err(|error| error.to_string())?;
    let mut release = tracking_packet(AD_RELEASE, session, 0)?;
    submit(&mut release)?;
    println!(
        "session={session} state=IDLE captured_state=STOPPED pages={total} dirty={dirty} remapped={remapped} output={}",
        directory.display()
    );
    if remapped != 0 {
        eprintln!(
            "tracking warning: {remapped} page mappings changed; their frames were excluded from the dump"
        );
    }
    Ok(i32::from(failed))
}

fn run_tracking(arguments: &[String]) -> Result<i32, String> {
    match arguments[0].as_str() {
        "start" => start_tracking(arguments),
        "status" if arguments.len() == 1 => {
            let mut bytes = tracking_packet(AD_STATUS, 0, 0)?;
            invoke(&mut bytes)?;
            println!("session={} state={} pages={} t0={} t1={} split_tables={}",
                quad(&bytes, 80), word(&bytes, 104), word(&bytes, 108), quad(&bytes, 88), quad(&bytes, 96), word(&bytes, 112));
            Ok(0)
        }
        "release" | "cancel" if arguments.len() == 2 => {
            let operation = if arguments[0] == "cancel" { AD_CANCEL } else { AD_RELEASE };
            let mut bytes = tracking_packet(operation, number(&arguments[1])?, 0)?;
            invoke(&mut bytes)?;
            Ok(0)
        }
        "stop" | "dump" if arguments.len() == 4 && arguments[2] == "--output" => {
            dump_tracking(number(&arguments[1])?, std::path::Path::new(&arguments[3]), invoke)
        }
        "stop" if arguments.len() == 2 => {
            let mut bytes = tracking_packet(AD_STOP, number(&arguments[1])?, 0)?;
            invoke(&mut bytes)?;
            println!("session={} state=STOPPED pages={} t0={} t1={}; use dump SESSION --output DIRECTORY to export",
                quad(&bytes, 80), word(&bytes, 108), quad(&bytes, 88), quad(&bytes, 96));
            Ok(0)
        }
        _ => Err("usage: neo ad-bitmap start (--pid PID [--gva GVA --pages COUNT] | --cr3 CR3 --gva GVA --pages COUNT); stop SESSION [--output DIRECTORY]; dump SESSION --output DIRECTORY; release SESSION; cancel SESSION; status".into()),
    }
}

pub(crate) fn invoke(bytes: &mut [u8]) -> Result<(), String> {
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

fn status_text(status: u32) -> &'static str {
    match status {
        0 => "success",
        1 => "invalid packet or page table",
        2 => "invalid range",
        3 => "page is not resident or mapped",
        4 => "page permission, EPT concealment, or non-RAM mapping denied access",
        5 => "unsupported paging mode, nested guest, or EPT A/D capability",
        6 => "prototype PTE could not be resolved",
        7 => "page is backed by the pagefile",
        8 => "copy-on-write requires the Windows memory manager",
        9 => "demand-zero write requires a physical backing page",
        10 => "tracking session or CPU rendezvous is busy; retry",
        11 => "invalid session identifier or lifecycle state",
        12 => "resident EPT split pool is exhausted",
        13 => "virtual page mapping changed during the session",
        ROAD_STATUS_DEMAND_ZERO => "DEMAND_ZERO (zero-filled read)",
        _ => "unknown status",
    }
}

pub(crate) fn read_ranges(cr3: u64, ranges: &[(u64, usize)]) -> Result<Vec<Vec<u8>>, String> {
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
                "symbol lookup at {:#x}: {}; transferred {done}/{} bytes; supply --kernel-cr3 with a kernel page-table root when KPTI is enabled",
                item.address,
                status_text(status),
                item.bytes.len()
            ));
        }
        let offset = word(&bytes, descriptor + 8) as usize;
        output.push(bytes[offset..offset + done].to_vec());
    }
    Ok(output)
}

pub(crate) fn parse_items(operation: u32, arguments: &[String]) -> Result<Vec<Item>, String> {
    if !arguments.len().is_multiple_of(2) {
        return Err("memory items require ADDRESS SIZE or ADDRESS HEX pairs".into());
    }
    if arguments.len() / 2 > MAX_ITEMS {
        return Err(format!("memory batches support at most {MAX_ITEMS} items"));
    }
    let mut total = HEADER_BYTES + arguments.len() / 2 * ITEM_BYTES;
    let mut items = Vec::new();
    for pair in arguments.as_chunks::<2>().0 {
        let address = number(&pair[0])?;
        let bytes = if operation == READ {
            let length =
                usize::try_from(number(&pair[1])?).map_err(|_| "read size is too large")?;
            if length == 0 || length > BUFFER_BYTES {
                return Err("read size must be 1..=65536 bytes".into());
            }
            vec![0; length]
        } else {
            let hex = pair[1].strip_prefix("0x").unwrap_or(&pair[1]);
            if hex.is_empty()
                || !hex.len().is_multiple_of(2)
                || hex.len() > BUFFER_BYTES * 2
                || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(
                    "write data must contain an even, nonzero number of hexadecimal digits".into(),
                );
            }
            hex.as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|digits| u8::from_str_radix(std::str::from_utf8(digits).unwrap(), 16).unwrap())
                .collect()
        };
        total = total
            .checked_add(bytes.len())
            .filter(|size| *size <= BUFFER_BYTES)
            .ok_or_else(|| "memory batch exceeds 65536 bytes including descriptors".to_string())?;
        if address.checked_add(bytes.len() as u64).is_none() {
            return Err("memory address range overflows".into());
        }
        items.push(Item { address, bytes });
    }
    Ok(items)
}

pub fn run(arguments: &[String]) -> Result<i32, String> {
    if arguments.len() < 2 {
        return Err("usage: neo read PID|NAME CR3|auto [ADDRESS SIZE ...] or neo write PID|NAME CR3|auto ADDRESS HEX [...]; options: --kernel-cr3 CR3 --kernel-image PATH --symbols DIRECTORY".into());
    }
    let operation = if arguments[0] == "read" { READ } else { WRITE };
    let selector = &arguments[1];
    let cr3 = match arguments.get(2).map(String::as_str) {
        None | Some("auto") => 0,
        Some(value) => number(value)?,
    };
    if cr3 != 0 && cr3 & !4095 == 0 {
        return Err("CR3 must contain a nonzero page-table root".into());
    }
    let mut kernel_cr3 = 0;
    let mut image = symbols::default_kernel_image()?;
    let mut cache = symbols::default_cache()?;
    let mut operands = Vec::new();
    let mut index = 3;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--kernel-cr3" | "--kernel-image" | "--symbols" => {
                let option = &arguments[index];
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| format!("{option} requires a value"))?;
                match option.as_str() {
                    "--kernel-cr3" => kernel_cr3 = number(value)?,
                    "--kernel-image" => image = value.into(),
                    _ => cache = value.into(),
                }
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown memory option: {value}"));
            }
            value => operands.push(value.to_string()),
        }
        index += 1;
    }
    let items = parse_items(operation, &operands)?;
    if operation == WRITE && items.is_empty() {
        return Err("write requires at least one ADDRESS HEX pair".into());
    }
    let mut info = packet(INFO, 0, 0, &[])?;
    info.resize(INFO_BYTES, 0);
    info[36..40].copy_from_slice(&(INFO_BYTES as u32).to_le_bytes());
    invoke(&mut info)?;
    if kernel_cr3 == 0 {
        kernel_cr3 = quad(&info, 64);
        if kernel_cr3 == 0 {
            kernel_cr3 = if cr3 != 0 { cr3 } else { quad(&info, 48) };
        }
    }
    let symbols = symbols::KernelSymbols::load(&image, &cache)?;
    let mut roots = vec![kernel_cr3];
    if !arguments.iter().any(|value| value == "--kernel-cr3") {
        roots.extend((0..ROOT_HISTORY_COUNT).map(|index| quad(&info, HEADER_BYTES + index * 8)));
        roots.push(quad(&info, 48));
        roots.push(cr3);
    }
    roots.retain(|root| *root & !4095 != 0);
    roots.sort_unstable();
    roots.dedup();
    let process = symbols.resolve(selector, cr3, &roots, quad(&info, 56))?;
    let target_cr3 = if cr3 == 0 { process.kernel_cr3 } else { cr3 };
    println!(
        "pid={} name={} cr3={target_cr3:#x} kernel_cr3={:#x} user_cr3={:#x}",
        process.pid, process.name, process.kernel_cr3, process.user_cr3
    );
    if items.is_empty() {
        return Ok(0);
    }
    let mut bytes = packet(operation, process.pid, target_cr3, &items)?;
    bytes[64..72].copy_from_slice(&process.kernel_cr3.to_le_bytes());
    if cr3 == 0 {
        bytes[72..80].copy_from_slice(&process.user_cr3.to_le_bytes());
    }
    for (index, field) in symbols.soft_layout.fields().iter().enumerate() {
        bytes[80 + index * 8..88 + index * 8].copy_from_slice(&field.to_le_bytes());
    }
    for (index, item) in items.iter().enumerate() {
        if let Ok(Some(protection)) =
            symbols.committed_protection(&process, item.address, item.bytes.len())
        {
            let descriptor = HEADER_BYTES + index * ITEM_BYTES;
            bytes[descriptor + 16..descriptor + 20].copy_from_slice(&1u32.to_le_bytes());
            bytes[descriptor + 20..descriptor + 24].copy_from_slice(&protection.to_le_bytes());
        }
    }
    invoke(&mut bytes)?;
    let mut failed = false;
    for (index, item) in items.iter().enumerate() {
        let descriptor = HEADER_BYTES + index * ITEM_BYTES;
        let status = word(&bytes, descriptor + 16);
        let done = word(&bytes, descriptor + 20) as usize;
        failed |= (status != 0 && status != ROAD_STATUS_DEMAND_ZERO) || done != item.bytes.len();
        print!(
            "address={:#x} status={} transferred={done}/{}",
            item.address,
            status_text(status),
            item.bytes.len()
        );
        if operation == READ {
            let offset = word(&bytes, descriptor + 8) as usize;
            print!(" data=");
            for byte in &bytes[offset..offset + done] {
                print!("{byte:02x}");
            }
        }
        println!();
    }
    Ok(i32::from(failed))
}
