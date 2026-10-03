use crate::memory::read_ranges;
use crate::protocol::memory::SoftPteLayout;
use pdb::{FallibleIterator, SymbolData, TypeData, TypeIndex};
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "windows")]
use std::fs::OpenOptions;
use std::fs::{self, File};
#[cfg(target_os = "windows")]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) fn default_kernel_image() -> Result<PathBuf, String> {
    let root = std::env::var_os("SystemRoot")
        .ok_or_else(|| "memory commands require Windows and a SystemRoot directory".to_string())?;
    Ok(PathBuf::from(root).join("System32/ntoskrnl.exe"))
}

pub(crate) fn default_cache() -> Result<PathBuf, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    Ok(executable
        .parent()
        .ok_or("neo executable has no directory")?
        .join("symbols"))
}

fn bytes_at(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], String> {
    bytes
        .get(offset..offset.checked_add(length).ok_or("PE range overflow")?)
        .ok_or_else(|| "truncated PE or process structure".to_string())
}

fn short(bytes: &[u8], offset: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        bytes_at(bytes, offset, 2)?.try_into().unwrap(),
    ))
}

fn word(bytes: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        bytes_at(bytes, offset, 4)?.try_into().unwrap(),
    ))
}

fn quad(bytes: &[u8], offset: usize) -> Result<u64, String> {
    Ok(u64::from_le_bytes(
        bytes_at(bytes, offset, 8)?.try_into().unwrap(),
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub guid: String,
    pub age: u32,
    pub name: String,
}

impl Identity {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes_at(bytes, 0, 4)? != b"RSDS" {
            return Err("kernel has no RSDS debug identity".into());
        }
        let mut guid = format!(
            "{:08X}{:04X}{:04X}",
            word(bytes, 4)?,
            short(bytes, 8)?,
            short(bytes, 10)?
        );
        for byte in bytes_at(bytes, 12, 8)? {
            guid.push_str(&format!("{byte:02X}"));
        }
        let path = bytes.get(24..).ok_or("truncated RSDS record")?;
        let end = path
            .iter()
            .position(|byte| *byte == 0)
            .ok_or("unterminated RSDS name")?;
        let path = std::str::from_utf8(&path[..end]).map_err(|_| "invalid RSDS name")?;
        let name = path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or_default()
            .to_string();
        if name.is_empty()
            || !name.ends_with(".pdb")
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || name.contains("..")
        {
            return Err("invalid symbol-server PDB filename".into());
        }
        Ok(Self {
            guid,
            age: word(bytes, 20)?,
            name,
        })
    }

    #[cfg(any(target_os = "windows", test))]
    pub(crate) fn key(&self) -> String {
        format!("{}{:X}", self.guid, self.age)
    }
}

struct ImageIdentity {
    identity: Identity,
    record_rva: u32,
    record_bytes: usize,
    timestamp: u32,
    image_bytes: u32,
}

impl ImageIdentity {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes_at(bytes, 0, 2)? != b"MZ" {
            return Err("kernel image has no DOS header".into());
        }
        let pe = word(bytes, 60)? as usize;
        if bytes_at(bytes, pe, 4)? != b"PE\0\0"
            || short(bytes, pe + 4)? != 0x8664
            || short(bytes, pe + 24)? != 0x20b
        {
            return Err("kernel image is not an x86_64 PE32+ image".into());
        }
        let optional_bytes = short(bytes, pe + 20)? as usize;
        if optional_bytes < 168 || word(bytes, pe + 24 + 108)? < 7 {
            return Err("kernel image has no debug directory".into());
        }
        let debug_rva = word(bytes, pe + 24 + 112 + 6 * 8)?;
        let debug_bytes = word(bytes, pe + 24 + 116 + 6 * 8)? as usize;
        let section_table = pe + 24 + optional_bytes;
        let section_count = short(bytes, pe + 6)? as usize;
        let file_offset = |rva: u32, length: usize| -> Result<usize, String> {
            for index in 0..section_count {
                let section = section_table + index * 40;
                let base = word(bytes, section + 12)?;
                let size = word(bytes, section + 16)?;
                if let Some(delta) = rva.checked_sub(base)
                    && u64::from(delta) + length as u64 <= u64::from(size)
                {
                    let offset = word(bytes, section + 20)? as usize + delta as usize;
                    bytes_at(bytes, offset, length)?;
                    return Ok(offset);
                }
            }
            Err("debug RVA is outside the kernel file sections".into())
        };
        if debug_bytes == 0 || debug_bytes > 28 * 256 || !debug_bytes.is_multiple_of(28) {
            return Err("invalid kernel debug directory size".into());
        }
        let debug_offset = file_offset(debug_rva, debug_bytes)?;
        for entry in (debug_offset..debug_offset + debug_bytes).step_by(28) {
            if word(bytes, entry + 12)? != 2 {
                continue;
            }
            let record_rva = word(bytes, entry + 20)?;
            let record_bytes = word(bytes, entry + 16)? as usize;
            if !(25..=4096).contains(&record_bytes) {
                return Err("invalid RSDS record size".into());
            }
            let record_offset = file_offset(record_rva, record_bytes)?;
            let record = bytes_at(bytes, record_offset, record_bytes)?;
            if &record[..4] != b"RSDS" {
                continue;
            }
            return Ok(Self {
                identity: Identity::parse(record)?,
                record_rva,
                record_bytes,
                timestamp: word(bytes, pe + 8)?,
                image_bytes: word(bytes, pe + 24 + 56)?,
            });
        }
        Err("kernel image has no PDB identity".into())
    }
}

#[cfg(target_os = "windows")]
fn validate_pdb(path: &Path, identity: &Identity) -> Result<(), String> {
    let mut database = pdb::PDB::open(File::open(path).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let information = database
        .pdb_information()
        .map_err(|error| error.to_string())?;
    let guid = information.guid.simple().to_string().to_ascii_uppercase();
    let age = database
        .debug_information()
        .map_err(|error| error.to_string())?
        .age()
        .unwrap_or(information.age);
    if guid != identity.guid || age != identity.age {
        return Err("PDB GUID/age does not match the kernel image".into());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn download(identity: &Identity, cache: &Path) -> Result<PathBuf, String> {
    let directory = cache.join(&identity.name).join(identity.key());
    fs::create_dir_all(&directory)
        .map_err(|error| format!("failed to create symbol cache: {error}"))?;
    let path = directory.join(&identity.name);
    if path.exists() {
        validate_pdb(&path, identity)?;
        return Ok(path);
    }
    let url = format!(
        "https://msdl.microsoft.com/download/symbols/{}/{}/{}",
        identity.name,
        identity.key(),
        identity.name
    );
    eprintln!("Downloading matching kernel PDB: {url}");
    let response = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(180))
        .build()
        .get(&url)
        .call()
        .map_err(|error| format!("PDB download failed: {error}"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = directory.join(format!("download-{}-{nonce}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        let limit = 512 * 1024 * 1024;
        let copied = std::io::copy(&mut response.into_reader().take(limit + 1), &mut file)
            .map_err(|error| error.to_string())?;
        if copied > limit {
            return Err("PDB download exceeds 512 MiB".into());
        }
        file.flush().map_err(|error| error.to_string())?;
        drop(file);
        validate_pdb(&temporary, identity)?;
        match fs::rename(&temporary, &path) {
            Ok(()) => Ok(()),
            Err(_) if path.exists() => validate_pdb(&path, identity),
            Err(error) => Err(format!("failed to publish PDB cache: {error}")),
        }
    })();
    let _ = fs::remove_file(&temporary);
    result?;
    Ok(path)
}

#[cfg(not(target_os = "windows"))]
fn download(_identity: &Identity, _cache: &Path) -> Result<PathBuf, String> {
    Err("automatic Windows kernel symbol resolution requires Windows".into())
}

struct Layout {
    size: usize,
    fields: HashMap<String, (usize, TypeIndex)>,
}

struct VadLayout {
    root_offset: usize,
    node_offset: usize,
    left_offset: usize,
    right_offset: usize,
    start_offset: usize,
    end_offset: usize,
    start_high_offset: usize,
    end_high_offset: usize,
    flags_offset: usize,
    commit: VadCommit,
    protection_mask: u64,
    private_mask: u64,
    bytes: usize,
}

enum VadCommit {
    Flag { offset: usize, mask: u64 },
    Charge { offset: usize, high_offset: usize },
}

fn layouts(
    database: &mut pdb::PDB<'_, File>,
) -> Result<(Layout, Layout, usize, SoftPteLayout, VadLayout), String> {
    let types = database
        .type_information()
        .map_err(|error| error.to_string())?;
    let mut finder = types.finder();
    let mut iterator = types.iter();
    let mut classes = HashMap::new();
    while let Some(record) = iterator.next().map_err(|error| error.to_string())? {
        finder.update(&iterator);
        if let Ok(TypeData::Class(class)) = record.parse() {
            let name = class.name.to_string().into_owned();
            if matches!(
                name.as_str(),
                "_EPROCESS"
                    | "_KPROCESS"
                    | "_MMPTE_SOFTWARE"
                    | "_MMPTE_TRANSITION"
                    | "_MMPTE_PROTOTYPE"
                    | "_MMPTE_HARDWARE"
                    | "_MMVAD_SHORT"
                    | "_MMVAD_FLAGS"
                    | "_MMVAD_FLAGS1"
                    | "_MMVAD_FLAGS_PRIVATE"
                    | "_RTL_AVL_TREE"
                    | "_RTL_BALANCED_NODE"
            ) && !class.properties.forward_reference()
            {
                classes.insert(name, (class.size as usize, class.fields));
            }
        }
    }
    let layout = |name: &str| -> Result<Layout, String> {
        let (size, mut next) = *classes
            .get(name)
            .ok_or_else(|| format!("PDB is missing {name} type information"))?;
        if size == 0 || size > 16384 {
            return Err(format!("invalid {name} size in PDB"));
        }
        let mut fields = HashMap::new();
        let mut visited = HashSet::new();
        while let Some(index) = next {
            if !visited.insert(index) {
                return Err("cyclic PDB field-list continuation".into());
            }
            let record = finder.find(index).map_err(|error| error.to_string())?;
            let TypeData::FieldList(list) = record.parse().map_err(|error| error.to_string())?
            else {
                return Err("invalid PDB field list".into());
            };
            for field in list.fields {
                if let TypeData::Member(member) = field {
                    let offset =
                        usize::try_from(member.offset).map_err(|_| "PDB field offset overflow")?;
                    if offset >= size {
                        return Err("PDB field is outside its structure".into());
                    }
                    fields.insert(
                        member.name.to_string().into_owned(),
                        (offset, member.field_type),
                    );
                }
            }
            next = list.continuation;
        }
        Ok(Layout { size, fields })
    };
    let process = layout("_EPROCESS")?;
    let kernel = layout("_KPROCESS")?;
    let (_, name_type) = process
        .fields
        .get("ImageFileName")
        .ok_or("PDB is missing _EPROCESS.ImageFileName")?;
    let name_record = finder.find(*name_type).map_err(|error| error.to_string())?;
    let TypeData::Array(array) = name_record.parse().map_err(|error| error.to_string())? else {
        return Err("PDB ImageFileName is not an array".into());
    };
    let name_bytes = *array
        .dimensions
        .last()
        .ok_or("PDB ImageFileName has no array size")? as usize;
    if !(1..=256).contains(&name_bytes) {
        return Err("invalid PDB ImageFileName size".into());
    }
    let mask = |type_name: &str, field_name: &str| -> Result<u64, String> {
        let record = layout(type_name)?;
        let (offset, field_type) = record
            .fields
            .get(field_name)
            .ok_or_else(|| format!("PDB is missing {type_name}.{field_name}"))?;
        let data = finder
            .find(*field_type)
            .map_err(|error| error.to_string())?;
        let TypeData::Bitfield(bitfield) = data.parse().map_err(|error| error.to_string())? else {
            return Err(format!("PDB {type_name}.{field_name} is not a bitfield"));
        };
        let position = offset * 8 + usize::from(bitfield.position);
        let length = u32::from(bitfield.length);
        if length == 0 || length > 64 || position + length as usize > 64 {
            return Err("invalid PDB PTE bitfield range".into());
        }
        let bits = u64::MAX >> (64 - length);
        Ok(bits << position)
    };
    let soft = SoftPteLayout {
        transition: mask("_MMPTE_TRANSITION", "Transition")?,
        prototype: mask("_MMPTE_PROTOTYPE", "Prototype")?,
        software_protection: mask("_MMPTE_SOFTWARE", "Protection")?,
        transition_protection: mask("_MMPTE_TRANSITION", "Protection")?,
        transition_frame: mask("_MMPTE_TRANSITION", "PageFrameNumber")?,
        prototype_address: mask("_MMPTE_PROTOTYPE", "ProtoAddress")?,
        prototype_read_only: mask("_MMPTE_PROTOTYPE", "ReadOnly")?,
        pagefile: mask("_MMPTE_SOFTWARE", "PageFileLow")?
            | mask("_MMPTE_SOFTWARE", "PageFileHigh")?,
        hardware_copy_on_write: mask("_MMPTE_HARDWARE", "CopyOnWrite")?,
        prototype_protection: mask("_MMPTE_PROTOTYPE", "Protection")?,
    };
    if !soft.validate() {
        return Err("PDB contains an unsupported Windows software PTE layout".into());
    }
    let offset = |record: &Layout, field: &str| -> Result<usize, String> {
        record
            .fields
            .get(field)
            .map(|value| value.0)
            .ok_or_else(|| {
                format!(
                    "PDB is missing VAD field {field}; available fields: {:?}",
                    record.fields.keys().collect::<Vec<_>>()
                )
            })
    };
    let vad = layout("_MMVAD_SHORT")?;
    let node = layout("_RTL_BALANCED_NODE")?;
    let tree = layout("_RTL_AVL_TREE")?;
    let commit = match mask("_MMVAD_FLAGS", "MemCommit")
        .or_else(|_| mask("_MMVAD_FLAGS_PRIVATE", "MemCommit"))
    {
        Ok(commit_mask) => VadCommit::Flag {
            offset: offset(&vad, "u")?,
            mask: commit_mask,
        },
        Err(_) => match (offset(&vad, "u1"), mask("_MMVAD_FLAGS1", "MemCommit")) {
            (Ok(commit_offset), Ok(commit_mask)) => VadCommit::Flag {
                offset: commit_offset,
                mask: commit_mask,
            },
            _ => VadCommit::Charge {
                offset: offset(&vad, "CommitCharge")?,
                high_offset: offset(&vad, "CommitChargeHigh")?,
            },
        },
    };
    let vad_layout = VadLayout {
        root_offset: offset(&process, "VadRoot")? + offset(&tree, "Root")?,
        node_offset: offset(&vad, "VadNode")?,
        left_offset: offset(&node, "Left")?,
        right_offset: offset(&node, "Right")?,
        start_offset: offset(&vad, "StartingVpn")?,
        end_offset: offset(&vad, "EndingVpn")?,
        start_high_offset: offset(&vad, "StartingVpnHigh")?,
        end_high_offset: offset(&vad, "EndingVpnHigh")?,
        flags_offset: offset(&vad, "u")?,
        commit,
        protection_mask: mask("_MMVAD_FLAGS", "Protection")?,
        private_mask: mask("_MMVAD_FLAGS", "PrivateMemory")?,
        bytes: vad.size,
    };
    Ok((process, kernel, name_bytes, soft, vad_layout))
}

pub(crate) struct Process {
    object: u64,
    pub pid: u64,
    pub name: String,
    pub kernel_cr3: u64,
    pub user_cr3: u64,
}

pub(crate) struct KernelSymbols {
    vad: VadLayout,
    image: ImageIdentity,
    initial_process: u32,
    syscall_rvas: Vec<u32>,
    process_bytes: usize,
    pid_offset: usize,
    links_offset: usize,
    name_offset: usize,
    name_bytes: usize,
    directory_offset: usize,
    user_directory_offset: Option<usize>,
    pub soft_layout: SoftPteLayout,
}

impl KernelSymbols {
    pub(crate) fn load(image_path: &Path, cache: &Path) -> Result<Self, String> {
        let bytes = fs::read(image_path)
            .map_err(|error| format!("failed to read {}: {error}", image_path.display()))?;
        let image = ImageIdentity::parse(&bytes)?;
        let pdb_path = download(&image.identity, cache)?;
        let mut database =
            pdb::PDB::open(File::open(&pdb_path).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        let address_map = database.address_map().map_err(|error| error.to_string())?;
        let symbols = database
            .global_symbols()
            .map_err(|error| error.to_string())?;
        let mut iterator = symbols.iter();
        let mut initial_process = None;
        let mut syscall_rvas = Vec::new();
        while let Some(symbol) = iterator.next().map_err(|error| error.to_string())? {
            let (name, offset) = match symbol.parse() {
                Ok(SymbolData::Public(data)) => (data.name, data.offset),
                Ok(SymbolData::Data(data)) => (data.name, data.offset),
                _ => continue,
            };
            let name = name.to_string();
            if matches!(
                name.as_ref(),
                "PsInitialSystemProcess" | "KiSystemCall64" | "KiSystemCall64Shadow"
            ) {
                let rva = offset
                    .to_rva(&address_map)
                    .ok_or("kernel symbol has no loaded RVA")?
                    .0;
                if rva >= image.image_bytes {
                    return Err("kernel symbol is outside its image".into());
                }
                if name == "PsInitialSystemProcess" {
                    initial_process = Some(rva);
                } else {
                    syscall_rvas.push(rva);
                }
            }
        }
        if syscall_rvas.is_empty() {
            return Err("PDB is missing kernel syscall entry symbols".into());
        }
        let (process, kernel, name_bytes, soft_layout, vad) = layouts(&mut database)?;
        let field = |layout: &Layout, name: &str| -> Result<usize, String> {
            layout
                .fields
                .get(name)
                .map(|field| field.0)
                .ok_or_else(|| format!("PDB is missing field {name}"))
        };
        let pcb = field(&process, "Pcb")?;
        let result = Self {
            vad,
            image,
            initial_process: initial_process.ok_or("PDB is missing PsInitialSystemProcess")?,
            syscall_rvas,
            process_bytes: process.size,
            pid_offset: field(&process, "UniqueProcessId")?,
            links_offset: field(&process, "ActiveProcessLinks")?,
            name_offset: field(&process, "ImageFileName")?,
            soft_layout,
            name_bytes,
            directory_offset: pcb + field(&kernel, "DirectoryTableBase")?,
            user_directory_offset: kernel
                .fields
                .get("UserDirectoryTableBase")
                .map(|field| pcb + field.0),
        };
        for (offset, length) in [
            (result.pid_offset, 8),
            (result.links_offset, 16),
            (result.name_offset, name_bytes),
            (result.directory_offset, 8),
        ] {
            if offset
                .checked_add(length)
                .is_none_or(|end| end > result.process_bytes)
            {
                return Err("PDB process fields exceed _EPROCESS size".into());
            }
        }
        if result
            .user_directory_offset
            .is_some_and(|offset| offset + 8 > result.process_bytes)
        {
            return Err("PDB user directory field exceeds _EPROCESS size".into());
        }
        Ok(result)
    }

    fn kernel_base(&self, kernel_cr3: u64, syscall: u64) -> Result<u64, String> {
        for rva in &self.syscall_rvas {
            let Some(base) = syscall.checked_sub(u64::from(*rva)) else {
                continue;
            };
            if base & 4095 != 0 || base >> 63 == 0 {
                continue;
            }
            let Ok(headers) = read_ranges(kernel_cr3, &[(base, 4096)]) else {
                continue;
            };
            let header = &headers[0];
            if bytes_at(header, 0, 2)? != b"MZ" {
                continue;
            }
            let pe = word(header, 60)? as usize;
            if bytes_at(header, pe, 4)? != b"PE\0\0"
                || word(header, pe + 8)? != self.image.timestamp
                || word(header, pe + 24 + 56)? != self.image.image_bytes
            {
                continue;
            }
            let record = read_ranges(
                kernel_cr3,
                &[(
                    base + u64::from(self.image.record_rva),
                    self.image.record_bytes,
                )],
            )?;
            if Identity::parse(&record[0])? != self.image.identity {
                return Err("loaded kernel GUID/age differs from the kernel file; use --kernel-image with the exact running image".into());
            }
            return Ok(base);
        }
        Err("cannot locate and validate the loaded kernel from IA32_LSTAR; check --kernel-cr3 and --kernel-image (KPTI, pending updates, and syscall hooks can change this mapping)".into())
    }

    pub(crate) fn committed_protection(
        &self,
        process: &Process,
        address: u64,
        length: usize,
    ) -> Result<Option<u32>, String> {
        if address >> 63 != 0 || length == 0 {
            return Ok(None);
        }
        let end_address = address
            .checked_add(length as u64 - 1)
            .ok_or("VAD range overflow")?;
        let root = read_ranges(
            process.kernel_cr3,
            &[(process.object + self.vad.root_offset as u64, 8)],
        )?;
        let mut node = quad(&root[0], 0)?;
        let mut visited = HashSet::new();
        for _ in 0..64 {
            if node == 0 {
                return Ok(None);
            }
            if node >> 63 == 0 || node & 7 != 0 || !visited.insert(node) {
                return Err("invalid or changing VAD tree".into());
            }
            let object = node
                .checked_sub(self.vad.node_offset as u64)
                .ok_or("VAD pointer underflow")?;
            let rows = read_ranges(process.kernel_cr3, &[(object, self.vad.bytes)])?;
            let row = &rows[0];
            let start = (u64::from(word(row, self.vad.start_offset)?)
                | (u64::from(row[self.vad.start_high_offset]) << 32))
                << 12;
            let end = (((u64::from(word(row, self.vad.end_offset)?)
                | (u64::from(row[self.vad.end_high_offset]) << 32))
                + 1)
                << 12)
                - 1;
            if start > end || end >> 63 != 0 {
                return Err("invalid VAD address range".into());
            }
            if address < start {
                node = quad(row, self.vad.node_offset + self.vad.left_offset)?;
            } else if address > end {
                node = quad(row, self.vad.node_offset + self.vad.right_offset)?;
            } else {
                let flags = u64::from(word(row, self.vad.flags_offset)?);
                let committed = match self.vad.commit {
                    VadCommit::Flag { offset, mask } => u64::from(word(row, offset)?) & mask != 0,
                    VadCommit::Charge {
                        offset,
                        high_offset,
                    } => {
                        let charge =
                            u64::from(word(row, offset)?) | (u64::from(row[high_offset]) << 32);
                        charge == ((end - start) >> 12) + 1
                    }
                };
                if end_address > end || flags & self.vad.private_mask == 0 || !committed {
                    return Ok(None);
                }
                let protection = ((flags & self.vad.protection_mask)
                    >> self.vad.protection_mask.trailing_zeros())
                    as u32;
                return Ok(Some(protection));
            }
        }
        Err("VAD traversal exceeded its depth limit".into())
    }

    pub(crate) fn resolve(
        &self,
        selector: &str,
        target_cr3: u64,
        kernel_roots: &[u64],
        syscall: u64,
    ) -> Result<Process, String> {
        // A CPL0 observation can still use a KPTI or firmware runtime root.
        // Accept a candidate only after validating the live kernel identity.
        let (kernel_cr3, base) = kernel_roots
            .iter()
            .find_map(|root| {
                self.kernel_base(*root, syscall)
                    .ok()
                    .map(|base| (*root, base))
            })
            .ok_or(
                "no observed CR3 maps the matching running kernel; retry or supply --kernel-cr3",
            )?;
        let initial = read_ranges(kernel_cr3, &[(base + u64::from(self.initial_process), 8)])?;
        let first = quad(&initial[0], 0)?;
        let numeric = crate::memory::number(selector).ok();
        let mut visited = HashSet::new();
        let mut current = first;
        let mut matched = None;
        for _ in 0..65536 {
            if current >> 63 == 0 || current & 7 != 0 || !visited.insert(current) {
                return Err(
                    "process list changed or contains an invalid pointer; retry the query".into(),
                );
            }
            let row = read_ranges(kernel_cr3, &[(current, self.process_bytes)])?;
            let row = &row[0];
            let pid = quad(row, self.pid_offset)?;
            let raw_name = bytes_at(row, self.name_offset, self.name_bytes)?;
            let end = raw_name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(raw_name.len());
            let name = String::from_utf8_lossy(&raw_name[..end]).into_owned();
            let selected = numeric.map_or_else(
                || name.eq_ignore_ascii_case(selector),
                |wanted| pid == wanted,
            );
            if selected {
                if matched.is_some() {
                    return Err(format!(
                        "multiple processes are named {selector}; specify the PID"
                    ));
                }
                let directory = quad(row, self.directory_offset)? & !4095;
                let user_directory = self
                    .user_directory_offset
                    .map(|offset| quad(row, offset))
                    .transpose()?
                    .unwrap_or(0)
                    & !4095;
                if target_cr3 != 0
                    && target_cr3 & !4095 != directory
                    && target_cr3 & !4095 != user_directory
                {
                    return Err(format!(
                        "CR3 does not belong to pid={pid} name={name}; kernel_cr3={directory:#x} user_cr3={user_directory:#x}"
                    ));
                }
                matched = Some(Process {
                    object: current,
                    pid,
                    name,
                    kernel_cr3: directory,
                    user_cr3: user_directory,
                });
                if numeric.is_some() {
                    return Ok(matched.unwrap());
                }
            }
            let next_link = quad(row, self.links_offset)?;
            let next = next_link
                .checked_sub(self.links_offset as u64)
                .ok_or("invalid process list link")?;
            if next == first {
                return matched.ok_or_else(|| format!("process {selector} was not found"));
            }
            // Verify the next node's backlink before following a concurrently changing list.
            let backlink = read_ranges(kernel_cr3, &[(next_link + 8, 8)])?;
            if quad(&backlink[0], 0)? != current + self.links_offset as u64 {
                return Err("process list changed during resolution; retry the query".into());
            }
            current = next;
        }
        Err("process list traversal exceeded its bounded query limit".into())
    }
}
