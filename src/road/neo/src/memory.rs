use crate::protocol::memory::{
    BUFFER_BYTES, HEADER_BYTES, INFO, INFO_BYTES, ITEM_BYTES, MAX_ITEMS, MEMORY_LEAF, MEMORY_MAGIC,
    MEMORY_SIGNATURE, MEMORY_VERSION, READ, ROAD_STATUS_DEMAND_ZERO, ROOT_HISTORY_COUNT, WRITE,
    quad, word,
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
        5 => "unsupported paging mode or nested guest",
        6 => "prototype PTE could not be resolved",
        7 => "page is backed by the pagefile",
        8 => "copy-on-write requires the Windows memory manager",
        9 => "demand-zero write requires a physical backing page",
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
