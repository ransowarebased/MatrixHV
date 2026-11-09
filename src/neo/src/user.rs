use crate::protocol::memory::{BUFFER_BYTES, HEADER_BYTES, ITEM_BYTES};
use std::collections::{HashMap, HashSet};
use yaxpeax_arch::LengthedInstruction;
use yaxpeax_x86::long_mode::{InstDecoder, Operand, RegSpec};

pub trait MemoryReader {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String>;
}

impl<F: FnMut(u64, usize) -> Result<Vec<u8>, String>> MemoryReader for F {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        self(address, length)
    }
}

pub fn read_exact(
    reader: &mut impl MemoryReader,
    address: u64,
    length: usize,
) -> Result<Vec<u8>, String> {
    if length > 16 * 1024 * 1024 || address.checked_add(length as u64).is_none() {
        return Err("analysis read exceeds its bounded address range".into());
    }
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        let count = (length - bytes.len()).min(BUFFER_BYTES - HEADER_BYTES - ITEM_BYTES);
        let chunk = reader.read(address + bytes.len() as u64, count)?;
        if chunk.len() != count {
            return Err("partial analysis memory read".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(crate) fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let value = bytes
        .get(offset..offset.checked_add(2).ok_or("offset overflow")?)
        .ok_or("truncated PE data")?;
    Ok(u16::from_le_bytes(
        value.try_into().map_err(|_| "invalid word")?,
    ))
}

pub(crate) fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or("offset overflow")?)
        .ok_or("truncated PE data")?;
    Ok(u32::from_le_bytes(
        value.try_into().map_err(|_| "invalid dword")?,
    ))
}

pub(crate) fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let value = bytes
        .get(offset..offset.checked_add(8).ok_or("offset overflow")?)
        .ok_or("truncated memory data")?;
    Ok(u64::from_le_bytes(
        value.try_into().map_err(|_| "invalid qword")?,
    ))
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "cli", derive(serde::Deserialize, serde::Serialize))]
pub struct Section {
    pub name: String,
    pub start: u64,
    pub size: u32,
    pub characteristics: u32,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "cli", derive(serde::Deserialize, serde::Serialize))]
pub struct Export {
    pub name: Option<String>,
    pub ordinal: u32,
    pub address: Option<u64>,
    pub forwarder: Option<String>,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "cli", derive(serde::Deserialize, serde::Serialize))]
pub struct Module {
    pub base: u64,
    pub size: u32,
    pub entry_point: u64,
    pub name: String,
    pub path: String,
    pub sections: Vec<Section>,
    pub exports: Vec<Export>,
    #[cfg_attr(
        feature = "cli",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub export_error: Option<String>,
    pub exception_rva: u32,
    pub exception_size: u32,
}

impl Module {
    pub fn address(&self, rva: u32, size: usize) -> Result<u64, String> {
        if u64::from(rva) + size as u64 > u64::from(self.size) {
            return Err(format!("PE range exceeds image {}", self.name));
        }
        self.base
            .checked_add(u64::from(rva))
            .ok_or_else(|| "PE address overflow".into())
    }

    pub fn contains(&self, address: u64) -> bool {
        address >= self.base && address - self.base < u64::from(self.size)
    }
}

fn c_string(
    reader: &mut impl MemoryReader,
    module: &Module,
    rva: u32,
    maximum: usize,
) -> Result<String, String> {
    let maximum = maximum
        .min(module.size.saturating_sub(rva) as usize)
        .min(4096);
    let mut bytes = Vec::new();
    let address = module.address(rva, maximum)?;
    while bytes.len() < maximum {
        let current = address + bytes.len() as u64;
        let count = (maximum - bytes.len())
            .min(128)
            .min(4096 - (current as usize & 4095));
        let chunk = read_exact(reader, current, count)?;
        if let Some(end) = chunk.iter().position(|byte| *byte == 0) {
            bytes.extend_from_slice(&chunk[..end]);
            return String::from_utf8(bytes).map_err(|_| "invalid PE string encoding".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Err("unterminated or oversized PE string".into())
}

pub fn read_module(
    reader: &mut impl MemoryReader,
    base: u64,
    loader_size: u32,
    name: String,
    path: String,
) -> Result<Module, String> {
    if base == 0 || base & 4095 != 0 || base >= 0x8000_0000_0000 {
        return Err("invalid x64 user module base".into());
    }
    let dos = read_exact(reader, base, 64)?;
    if &dos[..2] != b"MZ" {
        return Err("module has no DOS header".into());
    }
    let pe_offset = u32_at(&dos, 60)?;
    if !(64..=1024 * 1024).contains(&pe_offset) || pe_offset >= loader_size {
        return Err("invalid PE header offset".into());
    }
    let header = read_exact(reader, base + u64::from(pe_offset), 24)?;
    if &header[..4] != b"PE\0\0" || u16_at(&header, 4)? != 0x8664 {
        return Err("analysis currently supports AMD64 PE32+ modules only".into());
    }
    let section_count = u16_at(&header, 6)? as usize;
    let optional_size = u16_at(&header, 20)? as usize;
    if section_count == 0 || section_count > 96 || !(240..=4096).contains(&optional_size) {
        return Err("invalid PE section or optional-header size".into());
    }
    let table_size = optional_size + section_count * 40;
    if u64::from(pe_offset) + 24 + table_size as u64 > u64::from(loader_size) {
        return Err("PE headers exceed the loader image size".into());
    }
    let bytes = read_exact(reader, base + u64::from(pe_offset) + 24, table_size)?;
    let size = u32_at(&bytes, 56)?;
    let directory_count = u32_at(&bytes, 108)?;
    if u16_at(&bytes, 0)? != 0x20b
        || size == 0
        || size > 0x8000_0000
        || size != loader_size
        || base + u64::from(size) > 0x8000_0000_0000
        || directory_count > 16
    {
        return Err("invalid or changing PE image layout".into());
    }
    let entry_rva = u32_at(&bytes, 16)?;
    let mut module = Module {
        base,
        size,
        name,
        path,
        entry_point: if entry_rva == 0 {
            0
        } else {
            base + u64::from(entry_rva)
        },
        sections: Vec::new(),
        exports: Vec::new(),
        export_error: None,
        exception_rva: if directory_count >= 4 {
            u32_at(&bytes, 112 + 3 * 8)?
        } else {
            0
        },
        exception_size: if directory_count >= 4 {
            u32_at(&bytes, 116 + 3 * 8)?
        } else {
            0
        },
    };
    module.address(entry_rva, usize::from(entry_rva != 0))?;
    module.address(module.exception_rva, module.exception_size as usize)?;
    for index in 0..section_count {
        let offset = optional_size + index * 40;
        let raw_name = &bytes[offset..offset + 8];
        let end = raw_name.iter().position(|byte| *byte == 0).unwrap_or(8);
        let section_size = u32_at(&bytes, offset + 8)?;
        let rva = u32_at(&bytes, offset + 12)?;
        module.sections.push(Section {
            name: String::from_utf8_lossy(&raw_name[..end]).into_owned(),
            start: module.address(rva, section_size as usize)?,
            size: section_size,
            characteristics: u32_at(&bytes, offset + 36)?,
        });
    }
    let export_rva = if directory_count != 0 {
        u32_at(&bytes, 112)?
    } else {
        0
    };
    let export_size = if directory_count != 0 {
        u32_at(&bytes, 116)?
    } else {
        0
    };
    if export_rva != 0 || export_size != 0 {
        match read_exports(reader, &module, export_rva, export_size) {
            Ok((exports, error)) => {
                module.exports = exports;
                module.export_error = error;
            }
            Err(error) => module.export_error = Some(error),
        }
    }
    Ok(module)
}

fn read_exports(
    reader: &mut impl MemoryReader,
    module: &Module,
    export_rva: u32,
    export_size: u32,
) -> Result<(Vec<Export>, Option<String>), String> {
    if export_rva == 0 {
        return Err("invalid PE export directory address".into());
    }
    if export_size < 40 {
        return Err("truncated PE export directory".into());
    }
    let directory = read_exact(
        reader,
        module.address(export_rva, export_size as usize)?,
        40,
    )?;
    let ordinal_base = u32_at(&directory, 16)?;
    let count = u32_at(&directory, 20)? as usize;
    let name_count = u32_at(&directory, 24)? as usize;
    if count > 65536 || name_count > 65536 {
        return Err("oversized export table".into());
    }
    let functions = read_exact(
        reader,
        module.address(u32_at(&directory, 28)?, count * 4)?,
        count * 4,
    )?;
    let names = read_exact(
        reader,
        module.address(u32_at(&directory, 32)?, name_count * 4)?,
        name_count * 4,
    )?;
    let ordinals = read_exact(
        reader,
        module.address(u32_at(&directory, 36)?, name_count * 2)?,
        name_count * 2,
    )?;
    let mut named: HashMap<usize, Vec<String>> = HashMap::new();
    let mut export_error = None;
    for index in 0..name_count {
        let ordinal = u16_at(&ordinals, index * 2)? as usize;
        if ordinal >= count {
            return Err("export name ordinal exceeds function table".into());
        }
        match c_string(reader, module, u32_at(&names, index * 4)?, 4096) {
            Ok(name) => named.entry(ordinal).or_default().push(name),
            Err(error) => {
                export_error.get_or_insert(error);
            }
        }
    }
    let mut exports = Vec::new();
    for index in 0..count {
        let rva = u32_at(&functions, index * 4)?;
        if rva == 0 {
            continue;
        }
        let forwarded = u64::from(rva) >= u64::from(export_rva)
            && u64::from(rva) < u64::from(export_rva) + u64::from(export_size);
        let forwarder = if forwarded {
            match c_string(
                reader,
                module,
                rva,
                (u64::from(export_rva) + u64::from(export_size) - u64::from(rva)) as usize,
            ) {
                Ok(forwarder) => Some(forwarder),
                Err(error) => {
                    export_error.get_or_insert(error);
                    None
                }
            }
        } else {
            None
        };
        let address = if forwarded {
            None
        } else {
            Some(module.address(rva, 1)?)
        };
        let ordinal = ordinal_base
            .checked_add(index as u32)
            .ok_or("export ordinal overflow")?;
        for name in named
            .remove(&index)
            .map(|names| names.into_iter().map(Some).collect::<Vec<_>>())
            .unwrap_or_else(|| vec![None])
        {
            exports.push(Export {
                name,
                ordinal,
                address,
                forwarder: forwarder.clone(),
            });
        }
    }
    Ok((exports, export_error))
}

fn user_pointer(address: u64) -> bool {
    address != 0 && address < 0x8000_0000_0000 && address & 7 == 0
}

fn unicode_string(
    reader: &mut impl MemoryReader,
    record: &[u8],
    offset: usize,
) -> Result<String, String> {
    let length = u16_at(record, offset)? as usize;
    let maximum = u16_at(record, offset + 2)? as usize;
    let pointer = u64_at(record, offset + 8)?;
    if length == 0 {
        return Ok(String::new());
    }
    if length > maximum
        || length > 32768
        || length & 1 != 0
        || pointer == 0
        || pointer
            .checked_add(length as u64)
            .is_none_or(|end| end > 0x8000_0000_0000)
    {
        return Err("invalid loader Unicode string".into());
    }
    let bytes = read_exact(reader, pointer, length)?;
    String::from_utf16(
        &bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    )
    .map_err(|_| "invalid loader UTF-16 string".into())
}

pub fn modules(reader: &mut impl MemoryReader, peb: u64) -> Result<Vec<Module>, String> {
    if !user_pointer(peb) {
        return Err("process has no valid native x64 PEB".into());
    }
    let ldr = u64_at(&read_exact(reader, peb, 0x20)?, 0x18)?;
    if !user_pointer(ldr) {
        return Err("loader is not initialized".into());
    }
    let head = ldr.checked_add(0x20).ok_or("loader list overflow")?;
    let initial = read_exact(reader, head, 16)?;
    let mut link = u64_at(&initial, 0)?;
    let mut previous = head;
    let mut visited = HashSet::new();
    let mut result = Vec::new();
    while link != head {
        if !user_pointer(link) || !visited.insert(link) || visited.len() > 4096 {
            return Err("invalid, changing, or oversized loader list".into());
        }
        let entry = link.checked_sub(0x10).ok_or("loader pointer underflow")?;
        let bytes = read_exact(reader, entry, 0x68)?;
        if u64_at(&bytes, 0x18)? != previous {
            return Err("loader list changed; retry the query".into());
        }
        let name = unicode_string(reader, &bytes, 0x58)?;
        let path = unicode_string(reader, &bytes, 0x48)?;
        result.push(read_module(
            reader,
            u64_at(&bytes, 0x30)?,
            u32_at(&bytes, 0x40)?,
            name,
            path,
        )?);
        previous = link;
        link = u64_at(&bytes, 0x10)?;
    }
    let final_head = read_exact(reader, head, 16)?;
    if initial != final_head || u64_at(&final_head, 8)? != previous {
        return Err("loader list changed during enumeration; retry the query".into());
    }
    result.sort_by_key(|module| module.base);
    if result
        .windows(2)
        .any(|pair| pair[0].base + u64::from(pair[0].size) > pair[1].base)
    {
        return Err("overlapping loaded modules".into());
    }
    Ok(result)
}

fn module_matches(name: &str, query: &str) -> bool {
    name.eq_ignore_ascii_case(query)
        || name.rsplit_once('.').is_some_and(|(stem, extension)| {
            matches!(extension.to_ascii_lowercase().as_str(), "dll" | "exe")
                && stem.eq_ignore_ascii_case(query)
        })
}

pub fn resolve_address(modules: &[Module], expression: &str) -> Result<u64, String> {
    if let Some(hex) = expression
        .strip_prefix("0x")
        .or_else(|| expression.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).map_err(|_| "invalid hexadecimal address".into());
    }
    if let Ok(address) = expression.parse() {
        return Ok(address);
    }
    let (module_name, tail, export) = if let Some((name, tail)) = expression.split_once('!') {
        (name, tail, true)
    } else if let Some((name, tail)) = expression.rsplit_once('+') {
        (name, tail, false)
    } else {
        return Err("address requires an integer, module!export, or module+offset".into());
    };
    let mut matches = modules
        .iter()
        .filter(|module| module_matches(&module.name, module_name));
    let module = matches
        .next()
        .ok_or_else(|| format!("module {module_name} is not loaded"))?;
    if matches.next().is_some() {
        return Err("ambiguous module name; use its full filename".into());
    }
    if !export {
        let offset = resolve_address(&[], tail)?;
        if offset >= u64::from(module.size) {
            return Err("module offset exceeds image size".into());
        }
        return module
            .base
            .checked_add(offset)
            .ok_or_else(|| "module offset overflow".into());
    }
    resolve_export(modules, module, tail, &mut HashSet::new())
}

fn resolve_export(
    modules: &[Module],
    module: &Module,
    name: &str,
    visited: &mut HashSet<(u64, String)>,
) -> Result<u64, String> {
    if visited.len() >= 16 || !visited.insert((module.base, name.to_string())) {
        return Err("cyclic or excessively chained export forwarder".into());
    }
    let ordinal = name
        .strip_prefix('#')
        .and_then(|value| value.parse::<u32>().ok());
    let export = module
        .exports
        .iter()
        .find(|export| {
            ordinal.map_or_else(
                || export.name.as_deref() == Some(name),
                |ordinal| export.ordinal == ordinal,
            )
        })
        .ok_or_else(|| match &module.export_error {
            Some(error) => format!(
                "cannot resolve {}!{name}; export table is incomplete: {error}",
                module.name
            ),
            None => format!("export {}!{name} was not found", module.name),
        })?;
    if let Some(address) = export.address {
        return Ok(address);
    }
    let forwarder = export
        .forwarder
        .as_ref()
        .ok_or_else(|| match &module.export_error {
            Some(error) => format!("cannot read forwarder for {}!{name}: {error}", module.name),
            None => "export has no address".into(),
        })?;
    let (target_name, target_export) = forwarder
        .rsplit_once('.')
        .ok_or("invalid export forwarder")?;
    let mut targets = modules
        .iter()
        .filter(|target| module_matches(&target.name, target_name));
    let target = targets.next().ok_or_else(|| {
        format!("forwarded module {target_name} is not loaded; API-set mapping is unavailable")
    })?;
    if targets.next().is_some() {
        return Err("ambiguous forwarded module".into());
    }
    resolve_export(modules, target, target_export, visited)
}

pub fn symbolize(modules: &[Module], address: u64) -> String {
    let Some(module) = modules.iter().find(|module| module.contains(address)) else {
        return format!("{address:#x}");
    };
    if let Some(export) = module
        .exports
        .iter()
        .filter(|export| export.address.is_some_and(|value| value <= address))
        .max_by_key(|export| export.address)
    {
        let name = export
            .name
            .clone()
            .unwrap_or_else(|| format!("#{}", export.ordinal));
        format!(
            "{}!{}+{:#x}",
            module.name,
            name,
            address - export.address.unwrap_or(module.base)
        )
    } else {
        format!("{}+{:#x}", module.name, address - module.base)
    }
}

#[derive(Clone, Debug)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub text: String,
    pub symbol: String,
    pub targets: Vec<(u64, String)>,
}

pub fn disassemble(
    modules: &[Module],
    address: u64,
    bytes: &[u8],
    maximum: usize,
) -> Vec<Instruction> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() && result.len() < maximum {
        let Some(ip) = address.checked_add(offset as u64) else {
            break;
        };
        let Ok(instruction) = InstDecoder::default().decode_slice(&bytes[offset..]) else {
            break;
        };
        let length = instruction.len().to_const() as usize;
        if length == 0 || length > bytes.len() - offset {
            break;
        }
        let Some(next_ip) = ip.checked_add(length as u64) else {
            break;
        };
        let mut targets = Vec::new();
        // Only relative control-flow immediates and RIP-relative memory have an
        // address interpretation; ordinary immediates must remain literal values.
        let opcode = instruction.opcode().to_string();
        for index in 0..instruction.operand_count() {
            let target = match instruction.operand(index) {
                Operand::ImmediateI8 { imm }
                    if opcode.starts_with('j')
                        || opcode == "call"
                        || opcode.starts_with("loop") =>
                {
                    Some(next_ip.wrapping_add_signed(i64::from(imm)))
                }
                Operand::ImmediateI32 { imm } if opcode.starts_with('j') || opcode == "call" => {
                    Some(next_ip.wrapping_add_signed(i64::from(imm)))
                }
                Operand::Disp { base, disp } if base == RegSpec::rip() => {
                    Some(next_ip.wrapping_add_signed(i64::from(disp)))
                }
                _ => None,
            };
            if let Some(target) = target {
                targets.push((target, symbolize(modules, target)));
            }
        }
        result.push(Instruction {
            address: ip,
            bytes: bytes[offset..offset + length].to_vec(),
            text: instruction.to_string(),
            symbol: symbolize(modules, ip),
            targets,
        });
        offset += length;
    }
    result
}

#[derive(Clone, Debug)]
pub struct Pattern {
    bytes: Vec<Option<u8>>,
}

impl Pattern {
    pub fn parse(text: &str) -> Result<Self, String> {
        let bytes = text
            .split_whitespace()
            .map(|token| {
                if token == "??" {
                    Ok(None)
                } else if token.len() == 2 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    u8::from_str_radix(token, 16)
                        .map(Some)
                        .map_err(|_| "invalid pattern byte".to_string())
                } else {
                    Err(
                        "invalid pattern: use hexadecimal byte pairs or ?? separated by spaces"
                            .into(),
                    )
                }
            })
            .collect::<Result<Vec<_>, String>>()?;
        if bytes.is_empty() || bytes.len() > 4096 || bytes.iter().all(Option::is_none) {
            return Err(
                "invalid pattern: expected 1..4096 bytes and at least one concrete byte".into(),
            );
        }
        Ok(Self { bytes })
    }
}

pub struct PatternScanner {
    pattern: Pattern,
    tail: Vec<u8>,
    next: Option<u64>,
}

impl PatternScanner {
    pub fn new(pattern: Pattern) -> Self {
        Self {
            pattern,
            tail: Vec::new(),
            next: None,
        }
    }

    pub fn feed(&mut self, address: u64, bytes: &[u8], maximum: usize) -> Vec<u64> {
        if self.next != Some(address) {
            self.tail.clear();
        }
        let base = address.saturating_sub(self.tail.len() as u64);
        let old_length = self.tail.len();
        self.tail.extend_from_slice(bytes);
        let width = self.pattern.bytes.len();
        let mut hits = Vec::new();
        if self.tail.len() >= width {
            for offset in 0..=self.tail.len() - width {
                if offset + width <= old_length {
                    continue;
                }
                if self
                    .pattern
                    .bytes
                    .iter()
                    .zip(&self.tail[offset..offset + width])
                    .all(|(expected, value)| expected.is_none_or(|expected| expected == *value))
                {
                    if hits.len() == maximum {
                        break;
                    }
                    hits.push(base + offset as u64);
                }
            }
        }
        let keep = (width - 1).min(self.tail.len());
        self.tail.drain(..self.tail.len() - keep);
        self.next = address.checked_add(bytes.len() as u64);
        hits
    }

    pub fn gap(&mut self) {
        self.tail.clear();
        self.next = None;
    }
}
