use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const PACKAGE_MAGIC: &[u8; 8] = b"MATRIXUP";
pub const PACKAGE_VERSION: u32 = 1;
// Expanded events, root history and 32 KiB host stacks require fresh allocations.
// Live updates retain the boot-time stacks and cannot upgrade a 16 KiB host.
// ABI 9 also removes compensation fields from the boot and interception state.
pub const STATE_ABI_INITIAL: u32 = 1;
pub const STATE_ABI_DATA_SHADOW: u32 = 2;
pub const STATE_ABI_VIRTUAL_TSC: u32 = 3;
pub const STATE_ABI_GUEST_TIME_TSC: u32 = 4;
pub const STATE_ABI_DEBUGGER: u32 = 5;
pub const STATE_ABI_EXTENDED_HOOKS: u32 = 6;
pub const STATE_ABI_EXTENDED_CAPTURE: u32 = 7;
pub const STATE_ABI_HOST_STACK: u32 = 8;
pub const STATE_ABI_UNCOMPENSATED_TSC: u32 = 9;
pub const STATE_ABI: u32 = STATE_ABI_UNCOMPENSATED_TSC;
pub const HEADER_BYTES: usize = 256;
pub const BANK_BYTES: usize = 256 * 1024;
pub const BANK_PAGES: usize = BANK_BYTES / 4096;
pub const MAX_PACKAGE_BYTES: usize = BANK_BYTES + 4096;
pub const CHUNK_BYTES: usize = 1024;
pub const REQUEST_BYTES: usize = 48;
pub const REQUEST_MAGIC: u64 = 0x4d41_5452_4958_5550;
pub const UPDATE_VMCALL: u64 = 0x4d41_5452_4958_5556;
pub const UPDATE_RESULT: u64 = 0x4d41_5452_4958_5552;
pub const PREPARE: u32 = 4;
pub const UPLOAD: u32 = 5;
pub const VALIDATE: u32 = 6;
pub const CHECK_CPU: u32 = 7;
pub const BEGIN_OFF: u32 = 8;
pub const COMMIT: u32 = 9;
pub const PROBE_CPU: u32 = 10;
pub const FINISH: u32 = 11;
pub const CANCEL: u32 = 12;
pub const RECOVER: u32 = 13;
pub const RECOVERED: u32 = 14;
pub const QUERY: u32 = 15;

pub const fn supports_state_abi(state_abi: u32) -> bool {
    matches!(
        state_abi,
        STATE_ABI_INITIAL
            | STATE_ABI_DATA_SHADOW
            | STATE_ABI_VIRTUAL_TSC
            | STATE_ABI_GUEST_TIME_TSC
            | STATE_ABI_DEBUGGER
            | STATE_ABI_EXTENDED_HOOKS
            | STATE_ABI_EXTENDED_CAPTURE
            | STATE_ABI_HOST_STACK
            | STATE_ABI_UNCOMPENSATED_TSC
    )
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    None = 0,
    Bounds = 1,
    Format = 2,
    Abi = 3,
    Signature = 4,
    Integrity = 5,
    Region = 6,
    Relocation = 7,
    Busy = 8,
    Transaction = 9,
    State = 10,
    Chunk = 11,
    Incomplete = 12,
    Cpu = 13,
    NestedL2 = 14,
    HyperV = 15,
    Probe = 16,
    Retained = 17,
    Version = 18,
}

impl Error {
    pub fn description(code: u32) -> &'static str {
        match code {
            0 => "none",
            1 => "package or request bounds exceeded",
            2 => "invalid package or request format",
            3 => "resident state or preserved bridge ABI is incompatible",
            4 => "package is not signed by the boot trust key",
            5 => "package integrity check failed",
            6 => "invalid, overlapping, or writable executable regions",
            7 => "invalid, overlapping, or unsupported relocation",
            8 => "another runtime transaction is active",
            9 => "transaction identity mismatch",
            10 => "operation is invalid in the current transaction phase",
            11 => "conflicting, misaligned, or incorrectly sized upload block",
            12 => "upload or CPU confirmations are incomplete",
            13 => "CPU topology, masks, or transition state changed",
            14 => {
                "Windows is executing as L2; withdrawing its L1 requires a supported host handoff"
            }
            15 => "active Hyper-V or enlightened VMCS has no supported native host handoff",
            16 => "new core identity or CPU probe did not match",
            17 => "a bank still has live CPU or transition references",
            18 => "package version does not advance the resident core",
            _ => "unknown runtime update error",
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Idle = 0,
    Uploading = 1,
    Prepared = 2,
    Stopping = 3,
    Activating = 4,
    Complete = 5,
    Recovering = 6,
    Recovered = 7,
    Cancelled = 8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Status {
    pub transaction: u64,
    pub phase: u32,
    pub error: u32,
    pub total_bytes: u32,
    pub received_bytes: u32,
    pub previous_version: u64,
    pub next_version: u64,
    pub checked_mask: u64,
    pub verified_mask: u64,
    pub retained_banks: u64,
    pub previous_identity: [u8; 32],
    pub next_identity: [u8; 32],
    pub cpu_errors: [u32; 64],
}

impl Default for Status {
    fn default() -> Self {
        Self {
            transaction: 0,
            phase: 0,
            error: 0,
            total_bytes: 0,
            received_bytes: 0,
            previous_version: 0,
            next_version: 0,
            checked_mask: 0,
            verified_mask: 0,
            retained_banks: 0,
            previous_identity: [0; 32],
            next_identity: [0; 32],
            cpu_errors: [0; 64],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Abi {
    pub bridge: u32,
    pub boot_bytes: u32,
    pub event_bytes: u32,
    pub nested_bytes: u32,
    pub cpu_bytes: u32,
}

pub fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn package_identity(bytes: &[u8]) -> Result<[u8; 32], Error> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_PACKAGE_BYTES {
        return Err(Error::Bounds);
    }
    let mut digest = Sha256::new();
    digest.update(b"MatrixHV runtime core package v1\0");
    digest.update(&bytes[..192]);
    digest.update(&bytes[HEADER_BYTES..]);
    Ok(digest.finalize().into())
}

fn word(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Bounds)?
            .try_into()
            .map_err(|_| Error::Bounds)?,
    ))
}

fn quad(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(Error::Bounds)?
            .try_into()
            .map_err(|_| Error::Bounds)?,
    ))
}

#[derive(Debug)]
pub struct Package<'a> {
    bytes: &'a [u8],
    pub image: &'a [u8],
    pub identity: [u8; 32],
    pub version: u64,
    pub dispatch: u32,
    pub exception_entries: [u32; 3],
    pub code_bytes: usize,
    region_count: usize,
    relocation_count: usize,
    relocation_offset: usize,
}

impl<'a> Package<'a> {
    pub fn parse(bytes: &'a [u8], abi: Abi, public_key: &[u8; 32]) -> Result<Self, Error> {
        Self::parse_for_state(bytes, abi, public_key, STATE_ABI)
    }

    pub fn parse_for_state(
        bytes: &'a [u8],
        abi: Abi,
        public_key: &[u8; 32],
        state_abi: u32,
    ) -> Result<Self, Error> {
        let identity = package_identity(bytes)?;
        if &bytes[..8] != PACKAGE_MAGIC
            || word(bytes, 8)? != PACKAGE_VERSION
            || word(bytes, 12)? as usize != HEADER_BYTES
            || word(bytes, 16)? as usize != bytes.len()
            || bytes[168..192].iter().any(|byte| *byte != 0)
        {
            return Err(Error::Format);
        }
        if !supports_state_abi(state_abi)
            || word(bytes, 28)? != state_abi
            || word(bytes, 40)? != abi.bridge
            || word(bytes, 80)? != abi.boot_bytes
            || word(bytes, 84)? != abi.event_bytes
            || word(bytes, 88)? != abi.nested_bytes
            || word(bytes, 92)? != abi.cpu_bytes
        {
            return Err(Error::Abi);
        }
        if bytes[104..136] != hash(public_key) {
            return Err(Error::Signature);
        }
        let key = VerifyingKey::from_bytes(public_key).map_err(|_| Error::Signature)?;
        let signature = Signature::from_slice(&bytes[192..256]).map_err(|_| Error::Signature)?;
        key.verify_strict(&identity, &signature)
            .map_err(|_| Error::Signature)?;
        let image_offset = word(bytes, 20)? as usize;
        let image_bytes = word(bytes, 24)? as usize;
        let region_count = word(bytes, 44)? as usize;
        let relocation_count = word(bytes, 48)? as usize;
        let relocation_offset = word(bytes, 100)? as usize;
        if image_bytes == 0
            || image_bytes > BANK_BYTES
            || !(1..=8).contains(&region_count)
            || relocation_count > 32
            || word(bytes, 52)? != 5
            || word(bytes, 96)? as usize != HEADER_BYTES
            || relocation_offset != HEADER_BYTES + region_count * 16
            || image_offset != relocation_offset + relocation_count * 16
            || image_offset.checked_add(image_bytes) != Some(bytes.len())
        {
            return Err(Error::Bounds);
        }
        let image = &bytes[image_offset..];
        if hash(image) != bytes[136..168] {
            return Err(Error::Integrity);
        }
        let mut covered = 0;
        let mut code_bytes = 0;
        for index in 0..region_count {
            let offset = HEADER_BYTES + index * 16;
            let start = word(bytes, offset)? as usize;
            let length = word(bytes, offset + 4)? as usize;
            let flags = word(bytes, offset + 8)?;
            if start != covered
                || length == 0
                || !start.is_multiple_of(4096)
                || (index + 1 != region_count && !length.is_multiple_of(4096))
                || !matches!(flags, 3 | 5)
                || word(bytes, offset + 12)? != 0
                || start
                    .checked_add(length)
                    .is_none_or(|end| end > image_bytes)
            {
                return Err(Error::Region);
            }
            if flags == 5 {
                if start != code_bytes {
                    return Err(Error::Region);
                }
                code_bytes += length;
            }
            covered += length;
        }
        if covered != image_bytes || code_bytes == 0 {
            return Err(Error::Region);
        }
        for offset in (56..76).step_by(4) {
            if word(bytes, offset)? as usize >= code_bytes {
                return Err(Error::Region);
            }
        }
        if word(bytes, 76)? != 0 {
            return Err(Error::Format);
        }
        let mut previous_end = code_bytes;
        let mut kinds = 0_u32;
        for index in 0..relocation_count {
            let offset = relocation_offset + index * 16;
            let target = word(bytes, offset)? as usize;
            let kind = word(bytes, offset + 4)?;
            let addend = quad(bytes, offset + 8)?;
            let width = if kind == 7 { 32 } else { 8 };
            if !(1..=7).contains(&kind)
                || !target.is_multiple_of(8)
                || target < previous_end
                || target
                    .checked_add(width)
                    .is_none_or(|end| end > image_bytes)
                || kinds & (1 << kind) != 0
                || addend != 0
                || image[target..target + width].iter().any(|byte| *byte != 0)
            {
                return Err(Error::Relocation);
            }
            kinds |= 1 << kind;
            previous_end = target + width;
        }
        if kinds != 0xfe {
            return Err(Error::Relocation);
        }
        let version = quad(bytes, 32)?;
        if version == 0 {
            return Err(Error::Format);
        }
        if word(bytes, 68)? as usize + 512 > code_bytes {
            return Err(Error::Region);
        }
        Ok(Self {
            bytes,
            image,
            identity,
            version,
            dispatch: word(bytes, 56)?,
            exception_entries: [word(bytes, 60)?, word(bytes, 64)?, word(bytes, 68)?],
            code_bytes,
            region_count,
            relocation_count,
            relocation_offset,
        })
    }

    pub fn relocate(&self, destination: &mut [u8], bindings: &[u64; 6]) -> Result<(), Error> {
        if destination.len() < self.image.len() {
            return Err(Error::Bounds);
        }
        destination.fill(0);
        destination[..self.image.len()].copy_from_slice(self.image);
        for index in 0..self.relocation_count {
            let offset = self.relocation_offset + index * 16;
            let target = word(self.bytes, offset)? as usize;
            let kind = word(self.bytes, offset + 4)? as usize;
            if kind == 7 {
                destination[target..target + 32].copy_from_slice(&self.identity);
            } else {
                destination[target..target + 8].copy_from_slice(&bindings[kind - 1].to_le_bytes());
            }
        }
        Ok(())
    }

    pub fn page_flags(&self, page: usize) -> u64 {
        let address = page * 4096;
        for index in 0..self.region_count {
            let offset = HEADER_BYTES + index * 16;
            if let (Ok(start), Ok(length), Ok(flags)) = (
                word(self.bytes, offset),
                word(self.bytes, offset + 4),
                word(self.bytes, offset + 8),
            ) && address >= start as usize
                && address < (start + length) as usize
            {
                return if flags == 5 { 1 } else { 3 | (1 << 63) };
            }
        }
        3 | (1 << 63)
    }
}

#[derive(Debug)]
pub struct Request<'a> {
    pub operation: u32,
    pub transaction: u64,
    pub expected_apic_id: u32,
    pub offset: usize,
    pub total_bytes: usize,
    pub payload: &'a [u8],
}

impl<'a> Request<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if !(REQUEST_BYTES..=REQUEST_BYTES + CHUNK_BYTES).contains(&bytes.len()) {
            return Err(Error::Bounds);
        }
        if quad(bytes, 0)? != REQUEST_MAGIC
            || word(bytes, 8)? != PACKAGE_VERSION
            || !(PREPARE..=QUERY).contains(&word(bytes, 12)?)
            || quad(bytes, 16)? == 0
            || word(bytes, 28)? != 0
            || word(bytes, 36)? as usize != bytes.len() - REQUEST_BYTES
            || word(bytes, 44)? != 0
        {
            return Err(Error::Format);
        }
        let operation = word(bytes, 12)?;
        if (operation != UPLOAD && (word(bytes, 32)? != 0 || bytes.len() != REQUEST_BYTES))
            || (operation != PREPARE && word(bytes, 40)? != 0)
        {
            return Err(Error::Format);
        }
        Ok(Self {
            operation: word(bytes, 12)?,
            transaction: quad(bytes, 16)?,
            expected_apic_id: word(bytes, 24)?,
            offset: word(bytes, 32)? as usize,
            total_bytes: word(bytes, 40)? as usize,
            payload: &bytes[REQUEST_BYTES..],
        })
    }
}

#[repr(C)]
pub struct Upload {
    pub transaction: u64,
    pub total_bytes: usize,
    pub received_bytes: usize,
    blocks: [u64; MAX_PACKAGE_BYTES.div_ceil(CHUNK_BYTES).div_ceil(64)],
}

impl Default for Upload {
    fn default() -> Self {
        Self {
            transaction: 0,
            total_bytes: 0,
            received_bytes: 0,
            blocks: [0; MAX_PACKAGE_BYTES.div_ceil(CHUNK_BYTES).div_ceil(64)],
        }
    }
}

impl Upload {
    pub fn prepare(&mut self, transaction: u64, total_bytes: usize) -> Result<(), Error> {
        if transaction == 0 || !(HEADER_BYTES..=MAX_PACKAGE_BYTES).contains(&total_bytes) {
            return Err(Error::Bounds);
        }
        *self = Self {
            transaction,
            total_bytes,
            ..Self::default()
        };
        Ok(())
    }

    pub fn write(
        &mut self,
        transaction: u64,
        offset: usize,
        payload: &[u8],
        staging: &mut [u8],
    ) -> Result<(), Error> {
        if transaction != self.transaction {
            return Err(Error::Transaction);
        }
        if offset >= self.total_bytes
            || !offset.is_multiple_of(CHUNK_BYTES)
            || payload.len() != CHUNK_BYTES.min(self.total_bytes - offset)
            || offset
                .checked_add(payload.len())
                .is_none_or(|end| end > staging.len())
        {
            return Err(Error::Chunk);
        }
        let block = offset / CHUNK_BYTES;
        let bit = 1_u64 << (block % 64);
        if self.blocks[block / 64] & bit != 0 {
            return if staging[offset..offset + payload.len()] == *payload {
                Ok(())
            } else {
                Err(Error::Chunk)
            };
        }
        staging[offset..offset + payload.len()].copy_from_slice(payload);
        self.blocks[block / 64] |= bit;
        self.received_bytes += payload.len();
        Ok(())
    }

    pub fn complete(&self) -> bool {
        self.total_bytes != 0 && self.total_bytes == self.received_bytes
    }
}

#[derive(Clone, Copy, Default)]
pub struct CpuMasks {
    pub expected: u64,
    pub active: u64,
    pub stopped: u64,
    pub failed: u64,
    pub rearm: u64,
}

impl CpuMasks {
    pub fn consistent(self) -> bool {
        self.expected != 0
            && self.failed == 0
            && self.rearm == 0
            && self.active & self.stopped == 0
            && self.active | self.stopped == self.expected
    }
}

#[repr(C)]
pub struct Transaction {
    pub status: Status,
    pub upload: Upload,
    pub expected_mask: u64,
    pub current_bank: usize,
    pub previous_bank: usize,
    pub current_version: u64,
    pub current_identity: [u8; 32],
    pub pending_dispatch: u64,
    pub previous_host_rips: [u64; 64],
    pub previous_idts: [u64; 64],
}

impl Transaction {
    pub fn prepare(
        &mut self,
        transaction: u64,
        total_bytes: usize,
        masks: CpuMasks,
    ) -> Result<(), Error> {
        if !matches!(self.status.phase, 0 | 5 | 7 | 8) {
            return Err(Error::Busy);
        }
        if !masks.consistent() || masks.active != masks.expected {
            return Err(Error::Cpu);
        }
        self.upload.prepare(transaction, total_bytes)?;
        self.expected_mask = masks.expected;
        self.previous_bank = self.current_bank;
        self.status = Status {
            transaction,
            phase: Phase::Uploading as u32,
            total_bytes: total_bytes as u32,
            previous_version: self.current_version,
            previous_identity: self.current_identity,
            retained_banks: 1 << self.current_bank,
            ..Status::default()
        };
        Ok(())
    }

    pub fn require(&self, transaction: u64, phase: Phase) -> Result<(), Error> {
        if self.status.transaction != transaction {
            return Err(Error::Transaction);
        }
        if self.status.phase != phase as u32 {
            return Err(Error::State);
        }
        Ok(())
    }

    pub fn validated(
        &mut self,
        transaction: u64,
        package: &Package<'_>,
        dispatch: u64,
    ) -> Result<(), Error> {
        self.require(transaction, Phase::Uploading)?;
        if !self.upload.complete() {
            return Err(Error::Incomplete);
        }
        if package.version <= self.current_version {
            return Err(Error::Version);
        }
        self.status.next_version = package.version;
        self.status.next_identity = package.identity;
        self.status.phase = Phase::Prepared as u32;
        self.status.retained_banks = 3;
        self.pending_dispatch = dispatch;
        Ok(())
    }

    pub fn check_cpu(&mut self, transaction: u64, cpu: usize, blocker: Error) -> Result<(), Error> {
        self.require(transaction, Phase::Prepared)?;
        if cpu >= 64 || self.expected_mask & (1 << cpu) == 0 {
            return Err(Error::Cpu);
        }
        self.status.cpu_errors[cpu] = blocker as u32;
        if blocker != Error::None {
            return Err(blocker);
        }
        self.status.checked_mask |= 1 << cpu;
        Ok(())
    }

    pub fn begin_off(&mut self, transaction: u64, masks: CpuMasks) -> Result<(), Error> {
        self.require(transaction, Phase::Prepared)?;
        if self.status.checked_mask != self.expected_mask {
            return Err(Error::Incomplete);
        }
        if !masks.consistent()
            || masks.expected != self.expected_mask
            || masks.active != self.expected_mask
        {
            return Err(Error::Cpu);
        }
        self.status.phase = Phase::Stopping as u32;
        Ok(())
    }

    pub fn commit(&mut self, transaction: u64, masks: CpuMasks) -> Result<(), Error> {
        self.require(transaction, Phase::Stopping)?;
        if !masks.consistent()
            || masks.expected != self.expected_mask
            || masks.active != 0
            || masks.stopped != self.expected_mask
        {
            return Err(Error::Incomplete);
        }
        self.current_bank = 1 - self.previous_bank;
        self.status.phase = Phase::Activating as u32;
        Ok(())
    }

    pub fn probe_cpu(
        &mut self,
        transaction: u64,
        cpu: usize,
        identity: &[u8; 32],
        masks: CpuMasks,
    ) -> Result<(), Error> {
        if transaction != self.status.transaction {
            return Err(Error::Transaction);
        }
        if !matches!(self.status.phase, 4 | 6) {
            return Err(Error::State);
        }
        if cpu >= 64
            || masks.expected != self.expected_mask
            || masks.failed != 0
            || masks.active & (1 << cpu) == 0
            || masks.stopped & (1 << cpu) != 0
            || masks.rearm & (1 << cpu) != 0
        {
            return Err(Error::Cpu);
        }
        let expected_identity = if self.status.phase == Phase::Recovering as u32 {
            self.status.previous_identity
        } else {
            self.status.next_identity
        };
        if *identity != expected_identity {
            self.status.cpu_errors[cpu] = Error::Probe as u32;
            return Err(Error::Probe);
        }
        self.status.verified_mask |= 1 << cpu;
        Ok(())
    }

    pub fn finish(&mut self, transaction: u64, masks: CpuMasks) -> Result<(), Error> {
        self.require(transaction, Phase::Activating)?;
        if !masks.consistent()
            || masks.expected != self.expected_mask
            || masks.active != self.expected_mask
            || self.status.verified_mask != self.expected_mask
        {
            return Err(Error::Retained);
        }
        self.current_version = self.status.next_version;
        self.current_identity = self.status.next_identity;
        self.status.phase = Phase::Complete as u32;
        self.status.retained_banks = 1 << self.current_bank;
        Ok(())
    }

    pub fn cancel(&mut self, transaction: u64) -> Result<(), Error> {
        if transaction != self.status.transaction {
            return Err(Error::Transaction);
        }
        if !matches!(self.status.phase, 1 | 2) {
            return Err(Error::State);
        }
        self.status.phase = Phase::Cancelled as u32;
        self.status.retained_banks = 1 << self.current_bank;
        self.upload = Upload::default();
        Ok(())
    }

    pub fn recover(&mut self, transaction: u64, masks: CpuMasks) -> Result<(), Error> {
        if transaction != self.status.transaction {
            return Err(Error::Transaction);
        }
        if !matches!(self.status.phase, 3 | 4 | 6) {
            return Err(Error::State);
        }
        if !masks.consistent() || masks.expected != self.expected_mask {
            return Err(Error::Retained);
        }
        if self.status.phase == Phase::Activating as u32 && masks.stopped != self.expected_mask {
            return Err(Error::Retained);
        }
        self.current_bank = self.previous_bank;
        self.status.phase = Phase::Recovering as u32;
        self.status.retained_banks = 3;
        self.status.verified_mask = 0;
        Ok(())
    }

    pub fn recovered(&mut self, transaction: u64, masks: CpuMasks) -> Result<(), Error> {
        self.require(transaction, Phase::Recovering)?;
        if !masks.consistent()
            || masks.expected != self.expected_mask
            || masks.active != self.expected_mask
            || self.status.verified_mask != self.expected_mask
        {
            return Err(Error::Retained);
        }
        self.status.phase = Phase::Recovered as u32;
        self.status.retained_banks = 1 << self.previous_bank;
        Ok(())
    }
}

pub struct EmbeddedImage<'a> {
    pub bytes: &'a [u8],
    pub relocations: core::ops::Range<usize>,
    section_table: usize,
    section_count: usize,
}

impl<'a> EmbeddedImage<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.get(..2) != Some(b"MZ") || bytes.len() > 16 * 1024 * 1024 {
            return Err(Error::Format);
        }
        let pe = word(bytes, 60)? as usize;
        let optional = pe + 24;
        if bytes.get(pe..pe + 4) != Some(b"PE\0\0")
            || bytes.get(pe + 4..pe + 6) != Some(&[0x64, 0x86])
            || bytes.get(optional..optional + 2) != Some(&[0x0b, 0x02])
        {
            return Err(Error::Format);
        }
        let section_count = u16::from_le_bytes(
            bytes
                .get(pe + 6..pe + 8)
                .ok_or(Error::Bounds)?
                .try_into()
                .map_err(|_| Error::Bounds)?,
        ) as usize;
        let optional_bytes = u16::from_le_bytes(
            bytes
                .get(pe + 20..pe + 22)
                .ok_or(Error::Bounds)?
                .try_into()
                .map_err(|_| Error::Bounds)?,
        ) as usize;
        let section_table = optional + optional_bytes;
        if !(1..=32).contains(&section_count)
            || optional_bytes < 240
            || word(bytes, optional + 56)? as usize != bytes.len()
            || section_table + section_count * 40 > bytes.len()
            || word(bytes, optional + 120)? != 0
            || word(bytes, optional + 124)? != 0
        {
            return Err(Error::Bounds);
        }
        let start = word(bytes, optional + 152)? as usize;
        let length = word(bytes, optional + 156)? as usize;
        let end = start
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(Error::Bounds)?;
        let image = Self {
            bytes,
            relocations: start..end,
            section_table,
            section_count,
        };
        let mut previous_end = 4096;
        for index in 0..section_count {
            let offset = section_table + index * 40;
            let start = word(bytes, offset + 12)? as usize;
            let length = word(bytes, offset + 8)? as usize;
            let flags = word(bytes, offset + 36)?;
            let end = start
                .checked_add(length)
                .filter(|end| *end <= bytes.len())
                .ok_or(Error::Bounds)?;
            if !start.is_multiple_of(4096)
                || length == 0
                || start < previous_end
                || flags & 0xa000_0000 == 0xa000_0000
            {
                return Err(Error::Region);
            }
            previous_end = end.next_multiple_of(4096);
        }
        image.for_each_relocation(|_| Ok(()))?;
        Ok(image)
    }

    pub fn for_each_relocation(
        &self,
        mut apply: impl FnMut(usize) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut cursor = self.relocations.start;
        let mut previous_page = None;
        while cursor < self.relocations.end {
            let page = word(self.bytes, cursor)? as usize;
            let length = word(self.bytes, cursor + 4)? as usize;
            if !page.is_multiple_of(4096)
                || previous_page.is_some_and(|previous| page <= previous)
                || length < 8
                || !length.is_multiple_of(2)
                || cursor
                    .checked_add(length)
                    .is_none_or(|end| end > self.relocations.end)
            {
                return Err(Error::Relocation);
            }
            let mut previous_target = None;
            for offset in (cursor + 8..cursor + length).step_by(2) {
                let fixup = u16::from_le_bytes(
                    self.bytes[offset..offset + 2]
                        .try_into()
                        .map_err(|_| Error::Bounds)?,
                );
                if fixup >> 12 == 0 {
                    continue;
                }
                let target = page + (fixup & 4095) as usize;
                if fixup >> 12 != 10
                    || target
                        .checked_add(8)
                        .is_none_or(|end| end > self.bytes.len())
                    || previous_target.is_some_and(|previous| target < previous + 8)
                {
                    return Err(Error::Relocation);
                }
                apply(target)?;
                previous_target = Some(target);
            }
            previous_page = Some(page);
            cursor += length;
        }
        Ok(())
    }

    pub fn copy_relocated(
        &self,
        destination: &mut [u8],
        source_base: u64,
        destination_base: u64,
    ) -> Result<(), Error> {
        if destination.len() < self.bytes.len() {
            return Err(Error::Bounds);
        }
        self.for_each_relocation(|target| {
            let value = quad(self.bytes, target)?;
            if value < source_base || value - source_base > self.bytes.len() as u64 {
                return Err(Error::Relocation);
            }
            Ok(())
        })?;
        destination.fill(0);
        destination[..self.bytes.len()].copy_from_slice(self.bytes);
        self.for_each_relocation(|target| {
            let value = quad(self.bytes, target)? - source_base + destination_base;
            destination[target..target + 8].copy_from_slice(&value.to_le_bytes());
            Ok(())
        })
    }

    pub fn page_flags(&self, page: usize) -> u64 {
        let address = page * 4096;
        for index in 0..self.section_count {
            let offset = self.section_table + index * 40;
            if let (Ok(start), Ok(length), Ok(flags)) = (
                word(self.bytes, offset + 12),
                word(self.bytes, offset + 8),
                word(self.bytes, offset + 36),
            ) && address >= start as usize
                && address < start as usize + length as usize
            {
                return 1
                    | if flags & 0x8000_0000 != 0 { 2 } else { 0 }
                    | if flags & 0x2000_0000 == 0 { 1 << 63 } else { 0 };
            }
        }
        1 | (1 << 63)
    }
}
