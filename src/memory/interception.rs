use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::memory::access::{PhysicalMemory, page_mapping};
use crate::protocol::memory::*;

const MASK: u64 = 0x000f_ffff_ffff_f000;
const OPTIONS: u32 = INTERCEPT_VMFUNC
    | INTERCEPT_TSC_OFFSET
    | INTERCEPT_CONCURRENT_WRITES
    | INTERCEPT_PERSISTENT_DATA
    | INTERCEPT_NO_LEASE
    | INTERCEPT_PRIVATE_SHARED_DATA;

#[derive(Clone, Copy, Default)]
pub(crate) struct DebugTarget {
    pub address: u64,
    pub redirect: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct CpuidRecord {
    pub leaf: u32,
    pub subleaf: u32,
    pub subleaf_mask: u32,
    pub values: [u32; 4],
    pub keep_masks: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct CpuidProfile {
    pub records: [CpuidRecord; CPUID_MAX_RECORDS],
    pub count: usize,
    pub dr3: u64,
    pub dr7_mask: u64,
    pub dr7_value: u64,
    pub token: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct SyscallProfile {
    pub entry: u64,
    pub callback: u64,
    pub token: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RoadEptProfile {
    pub roots: [u64; 2],
    pub ept: u64,
    pub data_ept: u64,
    pub token: u64,
    pub hook_count: usize,
    pub debug_count: usize,
    pub pages: [u64; HOOK_MAX_PAGES],
    pub base_leaves: [u64; HOOK_MAX_PAGES],
    pub data_leaves: [u64; HOOK_MAX_PAGES],
    pub patch_mask: [[u64; 64]; HOOK_MAX_PAGES],
    pub debug: [DebugTarget; 4],
    pub pool_base: u64,
    pub cpu_mask: u64,
    pub pool_used: usize,
    pub base_pool_used: usize,
    pub vmfunc: u64,
    pub eptp_list: u64,
    pub bank: usize,
    pub timer_rate: u32,
    pub generation: u64,
    pub timing: u64,
    pub options: u32,
    pub cpu_data: [u64; 64],
    pub cpu_lists: [u64; 64],
    pub cpu_leaves: [[u64; HOOK_MAX_PAGES]; 64],
    pub extra_roots: [u64; ROOT_HISTORY_COUNT - 2],
}

impl RoadEptProfile {
    fn registered_roots(&self) -> impl Iterator<Item = u64> + '_ {
        self.roots
            .iter()
            .chain(&self.extra_roots)
            .copied()
            .enumerate()
            .filter(|(index, root)| *root != 0 && (*index != 1 || *root != self.roots[0]))
            .map(|(_, root)| root)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Hook {
    id: u64,
    address: u64,
    physical_address: u64,
    length: usize,
    bytes: [u8; 4096],
}

#[derive(Clone, Copy, Default)]
struct BaseSplit {
    parent: u64,
    original: u64,
    linked: u64,
    gpa: u64,
    shift: u32,
    retired_epoch: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Cr3Targets {
    saved: [u64; 4],
    cached: [u64; 4],
    count: usize,
    cursor: usize,
    generation: u64,
    token: u64,
}

#[repr(C)]
pub(crate) struct Session {
    pub active: AtomicU64,
    lock: AtomicU64,
    pub hits: AtomicU64,
    pub cause: AtomicU64,
    pub data_exits: AtomicU64,
    pub write_windows: AtomicU64,
    pub configuration: UnsafeCell<RoadEptProfile>,
    staging: UnsafeCell<RoadEptProfile>,
    hooks: UnsafeCell<[Hook; HOOK_MAX_PATCHES]>,
    staged_hooks: UnsafeCell<[Hook; HOOK_MAX_PATCHES]>,
    hook_records: AtomicU64,
    next_id: AtomicU64,
    pub lease_deadline: AtomicU64,
    pub lease_ms: AtomicU64,
    pub tsc_hz: AtomicU64,
    pub timing_ticks: AtomicU64,
    refresh_lock: AtomicU64,
    splits: UnsafeCell<[BaseSplit; INTERCEPT_BASE_TABLE_PAGES]>,
    pub split_epoch: AtomicU64,
    cr3_targets: UnsafeCell<[Cr3Targets; 64]>,
    pub cpuid: UnsafeCell<CpuidProfile>,
    pub syscall: UnsafeCell<SyscallProfile>,
    pub exit_debug: [AtomicU64; 64],
}
const _: () = assert!(core::mem::offset_of!(Session, active) == 0);
// Hot updates preserve every existing field and use only the zeroed tail of
// the original page allocation. Increasing the allocation requires a new ABI.
const _: () = assert!(
    core::mem::size_of::<Session>().div_ceil(4096)
        == core::mem::offset_of!(Session, cpuid).div_ceil(4096)
);
const _: () = assert!(core::mem::offset_of!(Session, cpuid) == 346_352);

impl Session {
    pub(crate) fn initialize(&mut self, pool_base: u64, cpu_mask: u64) {
        self.active
            .store(u64::from(INTERCEPT_DISABLED), Ordering::Relaxed);
        self.lock.store(0, Ordering::Relaxed);
        self.hits.store(0, Ordering::Relaxed);
        self.cause.store(0, Ordering::Relaxed);
        self.data_exits.store(0, Ordering::Relaxed);
        self.write_windows.store(0, Ordering::Relaxed);
        self.configuration.get_mut().pool_base = pool_base;
        self.configuration.get_mut().cpu_mask = cpu_mask;
        self.hook_records.store(0, Ordering::Relaxed);
        self.next_id.store(1, Ordering::Relaxed);
        self.lease_deadline.store(0, Ordering::Relaxed);
        self.lease_ms.store(0, Ordering::Relaxed);
        self.tsc_hz.store(0, Ordering::Relaxed);
        self.timing_ticks.store(0, Ordering::Relaxed);
        self.refresh_lock.store(0, Ordering::Relaxed);
        self.splits.get_mut().fill(BaseSplit::default());
        self.split_epoch.store(0, Ordering::Relaxed);
        self.cr3_targets.get_mut().fill(Cr3Targets::default());
        *self.cpuid.get_mut() = CpuidProfile::default();
        *self.syscall.get_mut() = SyscallProfile::default();
        for owned in &self.exit_debug {
            owned.store(0, Ordering::Relaxed);
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire) == u64::from(INTERCEPT_ACTIVE)
    }
}

pub(crate) trait InterceptionMemory: PhysicalMemory {
    fn syscall_context(&self) -> [u64; 3];
    fn quiesce(&mut self) -> Result<(), Error>;
    fn flush(&mut self);
    fn resume(&mut self);
    fn base_ept(&self) -> u64;
    fn table_entry(&self, address: u64) -> Result<u64, Error>;
    fn store_entry(&mut self, address: u64, value: u64) -> Result<(), Error>;
    fn store_page(&mut self, address: u64, bytes: &[u8; 4096]) -> Result<(), Error>;
    fn available(&self) -> bool;
    fn split_available(&self) -> bool;
    fn split_reclamation_allowed(&self) -> bool;
    fn split_reclamation_ready(&self, epoch: u64, cpu_mask: u64) -> bool;
    fn vmfunc_available(&self) -> bool;
    fn write_original(&mut self, address: u64, bytes: &[u8]) -> Result<(), Error>;
    fn clock(&self) -> u64;
    fn clock_hz(&self) -> u64;
    fn timer_rate(&self) -> u32;
    fn lease_available(&self) -> bool;
    fn timing_available(&self) -> bool;
}

fn expired(session: &Session, now: u64) -> bool {
    session.tsc_hz.load(Ordering::Acquire) != 0
        && now.wrapping_sub(session.lease_deadline.load(Ordering::Acquire)) as i64 >= 0
}

fn lock_refresh(session: &Session) -> Result<(), Error> {
    for _ in 0..100_000 {
        if session
            .refresh_lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(Error::Busy)
}

#[cfg(target_os = "uefi")]
fn data_root(configuration: &RoadEptProfile, cpu_index: usize) -> u64 {
    if configuration.cpu_data[cpu_index] != 0 {
        configuration.cpu_data[cpu_index]
    } else {
        configuration.data_ept
    }
}

#[cfg(target_os = "uefi")]
fn data_leaves(configuration: &RoadEptProfile, cpu_index: usize) -> impl Iterator<Item = &u64> {
    let leaves = if configuration.cpu_data[cpu_index] != 0 {
        &configuration.cpu_leaves[cpu_index]
    } else {
        &configuration.data_leaves
    };
    leaves[..configuration.hook_count].iter().zip(&configuration.base_leaves)
        .filter(|(_, base)| **base != 0).map(|(pointer, _)| pointer)
}

#[cfg(any(target_os = "uefi", test))]
fn root_matches(configuration: &RoadEptProfile, cr3: u64) -> bool {
    let cr3 = cr3 & MASK;
    cr3 != 0 && configuration.registered_roots().any(|root| root == cr3)
}

fn baseline_page(configuration: &RoadEptProfile, index: usize) -> u64 {
    bank_base(configuration) + (INTERCEPT_TABLE_PAGES + HOOK_MAX_PAGES + index) as u64 * 4096
}

fn merge_byte(baseline: u8, original: u8, patched: u8, protected: bool) -> Result<u8, Error> {
    if !protected || patched == baseline {
        Ok(original)
    } else if original == baseline || original == patched {
        Ok(patched)
    } else {
        Err(Error::MergeConflict)
    }
}

fn lease_duration(
    packet: &[u8],
    memory: &impl InterceptionMemory,
    default_ms: u32,
) -> Result<(u32, u64), Error> {
    if word(packet, 128) & INTERCEPT_NO_LEASE != 0 {
        return if word(packet, 132) == 0 && matches!(word(packet, 12), HOOK_INSTALL | DEBUG_SET | CPUID_SET | SYSCALL_SET) {
            Ok((0, 0))
        } else {
            Err(Error::Format)
        };
    }
    if default_ms == 0 {
        return Err(Error::Session);
    }
    let requested = word(packet, 132);
    let duration = if requested == 0 {
        default_ms
    } else {
        requested
    };
    let ticks = memory
        .clock_hz()
        .checked_mul(u64::from(duration))
        .map(|value| value / 1000)
        .filter(|value| *value != 0 && *value < i64::MAX as u64);
    if duration > INTERCEPT_MAX_LEASE_MS {
        return Err(Error::Bounds);
    }
    if !memory.lease_available() {
        return Err(Error::Unsupported);
    }
    Ok((duration, ticks.ok_or(Error::Bounds)?))
}

fn arm_lease(session: &Session, memory: &impl InterceptionMemory, duration: u32, ticks: u64) {
    session
        .lease_ms
        .store(u64::from(duration), Ordering::Relaxed);
    session
        .lease_deadline
        .store(memory.clock().wrapping_add(ticks), Ordering::Release);
    session.tsc_hz.store(
        if duration == 0 { 0 } else { memory.clock_hz() },
        Ordering::Release,
    );
}

fn bank_base(configuration: &RoadEptProfile) -> u64 {
    configuration.pool_base
        + (configuration.bank * intercept_bank_pages(configuration.cpu_mask)) as u64 * 4096
}

fn split_page(configuration: &RoadEptProfile, slot: usize) -> u64 {
    configuration.pool_base
        + (2 * intercept_bank_pages(configuration.cpu_mask) + slot) as u64 * 4096
}

fn retire_splits(
    session: &Session,
    configuration: &RoadEptProfile,
    memory: &mut impl InterceptionMemory,
    keep: &[Hook],
) -> Result<(), Error> {
    if !memory.split_reclamation_allowed() {
        return Ok(());
    }
    let splits = unsafe { &mut *session.splits.get() };
    let mut epoch = 0;
    // Restore PTs before PDs. Only tables allocated by this session are owned.
    for shift in [21, 30] {
        for (slot, split) in splits.iter_mut().enumerate() {
            if split.retired_epoch != 0 || split.shift != shift {
                continue;
            }
            let size = 1u64 << shift;
            if keep
                .iter()
                .any(|hook| (split.gpa..split.gpa + size).contains(&hook.physical_address))
            {
                continue;
            }
            let parent = memory.table_entry(split.parent)?;
            let table = split_page(configuration, slot);
            if parent & MASK != table || parent & !0x100 != split.linked & !0x100 {
                continue;
            }
            let attributes = split.original & !MASK & if shift == 21 { !128 } else { u64::MAX };
            let mut accessed_dirty = (parent | split.original) & 0x300;
            let mut uniform = true;
            for index in 0..512 {
                let entry = memory.table_entry(table + index * 8)?;
                let expected = (split.gpa + index * (size / 512)) | attributes;
                if entry & !0x300 != expected & !0x300 {
                    uniform = false;
                    break;
                }
                accessed_dirty |= entry & 0x300;
            }
            if !uniform {
                continue;
            }
            if epoch == 0 {
                epoch = session
                    .split_epoch
                    .load(Ordering::Relaxed)
                    .checked_add(1)
                    .ok_or(Error::Capacity)?;
            }
            memory.store_entry(split.parent, split.original | accessed_dirty)?;
            split.retired_epoch = epoch;
            // Publish even if a subsequent parent write fails: every detached
            // table needs a grace period before its slot can be reused.
            session.split_epoch.store(epoch, Ordering::Release);
        }
    }
    Ok(())
}

fn rollback_splits(
    session: &Session,
    memory: &mut impl InterceptionMemory,
    previous_epoch: u64,
) -> Result<(), Error> {
    let splits = unsafe { &mut *session.splits.get() };
    // Reattach the outer tables before restoring the old 4 KiB guard set.
    for shift in [30, 21] {
        for split in splits
            .iter_mut()
            .filter(|split| split.shift == shift && split.retired_epoch > previous_epoch)
        {
            let accessed = memory.table_entry(split.parent)? & 0x100;
            memory.store_entry(split.parent, split.linked | accessed)?;
            split.retired_epoch = 0;
        }
    }
    Ok(())
}

fn reclaim_splits(session: &Session, memory: &mut impl InterceptionMemory) -> bool {
    if !unsafe { &*session.splits.get() }
        .iter()
        .any(|split| split.retired_epoch != 0)
    {
        return true;
    }
    // Peers complete the previous release's flush before acknowledging this
    // barrier. Flush the owner too, then require positive per-CPU completion.
    memory.flush();
    let epoch = session.split_epoch.load(Ordering::Acquire);
    let cpu_mask = unsafe { &*session.configuration.get() }.cpu_mask;
    if !memory.split_reclamation_ready(epoch, cpu_mask) {
        return false;
    }
    let configuration = unsafe { &mut *session.configuration.get() };
    for (slot, split) in unsafe { &mut *session.splits.get() }.iter_mut().enumerate() {
        if split.retired_epoch != 0 && split.retired_epoch <= epoch {
            let table = split_page(configuration, slot);
            // A failed rollback can leave revoked leaf references behind.
            // Keep their storage until a later transaction clears that set.
            if configuration.base_leaves[..configuration.hook_count]
                .iter()
                .any(|pointer| (table..table + 4096).contains(pointer))
            {
                continue;
            }
            *split = BaseSplit::default();
            configuration.base_pool_used -= 1;
        }
    }
    true
}

fn allocate(configuration: &mut RoadEptProfile) -> Result<u64, Error> {
    if configuration.pool_used >= INTERCEPT_TABLE_PAGES {
        return Err(Error::Capacity);
    }
    let address = bank_base(configuration) + configuration.pool_used as u64 * 4096;
    configuration.pool_used += 1;
    Ok(address)
}

fn clone_root(
    memory: &mut impl InterceptionMemory,
    configuration: &mut RoadEptProfile,
    source: u64,
) -> Result<u64, Error> {
    let destination = allocate(configuration)?;
    copy_table(memory, source, destination)?;
    Ok(destination)
}

fn leaf(
    memory: &mut impl InterceptionMemory,
    configuration: &mut RoadEptProfile,
    splits: &mut [BaseSplit; INTERCEPT_BASE_TABLE_PAGES],
    gpa: u64,
    ept: u64,
    permanent: bool,
) -> Result<u64, Error> {
    let mut table = ept & MASK;
    for shift in [39, 30, 21, 12] {
        let pointer = table + ((gpa >> shift) & 511) * 8;
        let entry = memory.table_entry(pointer)?;
        if entry & 7 != 7 {
            return Err(Error::Permission);
        }
        if shift == 12 || entry & 128 != 0 {
            let size = 1u64 << shift;
            let base = entry & MASK & !(size - 1);
            if base | (gpa & (size - 1)) != gpa || (entry >> 3) & 7 != 6 {
                return Err(Error::Permission);
            }
            if shift == 12 {
                return Ok(pointer);
            }
            let slot = if permanent {
                if configuration.base_pool_used >= INTERCEPT_BASE_TABLE_PAGES {
                    return Err(Error::Capacity);
                }
                Some(
                    splits
                        .iter()
                        .position(|split| split.shift == 0)
                        .ok_or(Error::Capacity)?,
                )
            } else {
                None
            };
            let child = if let Some(slot) = slot {
                split_page(configuration, slot)
            } else {
                allocate(configuration)?
            };
            let attributes = entry & !MASK & if shift == 21 { !128 } else { u64::MAX };
            for index in 0..512 {
                memory.store_entry(
                    child + index * 8,
                    (base + index * (size / 512)) | attributes,
                )?;
            }
            let linked = child | (entry & (7 | 0x100 | 0x400));
            memory.store_entry(pointer, linked)?;
            if let Some(slot) = slot {
                splits[slot] = BaseSplit {
                    parent: pointer,
                    original: entry,
                    linked,
                    gpa: gpa & !(size - 1),
                    shift,
                    retired_epoch: 0,
                };
                configuration.base_pool_used += 1;
            }
            table = child;
        } else {
            let source = entry & MASK;
            let start = bank_base(configuration);
            // Copy a shared child only when this profile changes its subtree.
            // Untouched paths retain the base EPT's tables and A/D attributes.
            table = if !permanent
                && !(start..start + configuration.pool_used as u64 * 4096).contains(&source)
            {
                let child = allocate(configuration)?;
                copy_table(memory, source, child)?;
                memory.store_entry(pointer, child | (entry & !MASK))?;
                child
            } else {
                source
            };
        }
    }
    Err(Error::Unmapped)
}

fn canonical(address: u64, la57: bool) -> bool {
    let shift = if la57 { 7 } else { 16 };
    ((address << shift) as i64 >> shift) as u64 == address
}

fn root(value: u64, physical_bits: u32) -> Result<u64, Error> {
    if !(32..=52).contains(&physical_bits) || value >> physical_bits != 0 || value & MASK == 0 {
        return Err(Error::Bounds);
    }
    Ok(value & MASK)
}

fn copy_table(
    memory: &mut impl InterceptionMemory,
    source: u64,
    destination: u64,
) -> Result<(), Error> {
    for index in 0..512 {
        memory.store_entry(
            destination + index * 8,
            memory.table_entry(source + index * 8)?,
        )?;
    }
    Ok(())
}

fn cpu_views(
    configuration: &mut RoadEptProfile,
    memory: &mut impl InterceptionMemory,
    count: usize,
) -> Result<(), Error> {
    configuration.cpu_data.fill(0);
    configuration.cpu_lists.fill(0);
    configuration.cpu_leaves.fill([0; HOOK_MAX_PAGES]);
    // Read-only mixed instructions also need CPU-private execute permissions.
    let mut cpu_slot = 0;
    for cpu_index in 0..64 {
        if configuration.cpu_mask & (1u64 << cpu_index) == 0 {
            continue;
        }
        let start = bank_base(configuration)
            + (INTERCEPT_TABLE_PAGES + 2 * HOOK_MAX_PAGES + 1 + cpu_slot * INTERCEPT_CPU_VIEW_PAGES)
                as u64
                * 4096;
        let end = start + INTERCEPT_CPU_TABLE_PAGES as u64 * 4096;
        let mut next = start + 4096;
        copy_table(memory, configuration.data_ept & MASK, start)?;
        for page_index in 0..count {
            let mut table = start;
            let page = configuration.pages[page_index];
            if page == 0 {
                continue;
            }
            for shift in [39, 30, 21] {
                let pointer = table + ((page >> shift) & 511) * 8;
                let entry = memory.table_entry(pointer)?;
                let mut child = entry & MASK;
                if !(start..end).contains(&child) {
                    if next >= end {
                        return Err(Error::Capacity);
                    }
                    copy_table(memory, child, next)?;
                    child = next;
                    next += 4096;
                    memory.store_entry(pointer, child | (entry & !MASK))?;
                }
                table = child;
            }
            let pointer = table + ((page >> 12) & 511) * 8;
            configuration.cpu_leaves[cpu_index][page_index] = pointer;
        }
        configuration.cpu_data[cpu_index] = start | (configuration.data_ept & !MASK);
        configuration.cpu_lists[cpu_index] = end;
        let mut list = [0; 4096];
        list[..8].copy_from_slice(&configuration.ept.to_le_bytes());
        list[8..16].copy_from_slice(&configuration.cpu_data[cpu_index].to_le_bytes());
        memory.store_page(end, &list)?;
        cpu_slot += 1;
    }
    Ok(())
}

fn install(
    configuration: &mut RoadEptProfile,
    memory: &mut impl InterceptionMemory,
    splits: &mut [BaseSplit; INTERCEPT_BASE_TABLE_PAGES],
    hooks: &[Hook],
    flags: u32,
    la57: bool,
    physical_bits: u32,
) -> Result<(), Error> {
    if flags & !OPTIONS != 0 {
        return Err(Error::Format);
    }
    if flags & INTERCEPT_VMFUNC != 0 && !memory.vmfunc_available() {
        return Err(Error::Unsupported);
    }
    if flags & INTERCEPT_TSC_OFFSET != 0 && !memory.timing_available() {
        return Err(Error::Unsupported);
    }
    if hooks.is_empty() || hooks.len() > HOOK_MAX_PATCHES {
        return Err(Error::Bounds);
    }
    let private_data = flags & INTERCEPT_PRIVATE_SHARED_DATA != 0;
    if private_data
        && (hooks.iter().filter(|hook| hook.address == 0x7ffe0000 && hook.length == 4096).count() != 1
            || hooks.iter().any(|hook| hook.address & !4095 == 0x7ffe0000 && (hook.address != 0x7ffe0000 || hook.length != 4096))
            || flags & (INTERCEPT_VMFUNC | INTERCEPT_CONCURRENT_WRITES | INTERCEPT_PERSISTENT_DATA | INTERCEPT_NO_LEASE) != 0)
    {
        return Err(Error::Format);
    }
    configuration.pool_used = 0;
    configuration.ept =
        clone_root(memory, configuration, memory.base_ept() & MASK)? | (memory.base_ept() & !MASK);
    configuration.data_ept =
        clone_root(memory, configuration, memory.base_ept() & MASK)? | (memory.base_ept() & !MASK);
    configuration.patch_mask.fill([0; 64]);
    let mut page_count = 0;
    for hook in hooks {
        let address = hook.address;
        let length = hook.length;
        let private_page = private_data && address == 0x7ffe0000;
        let mapping = page_mapping(memory, configuration.roots[0], address, la57, physical_bits)?;
        if !mapping.present {
            return Err(Error::Unmapped);
        }
        if mapping.physical_address != hook.physical_address {
            return Err(Error::Remapped);
        }
        let gpa = mapping.physical_address & !4095;
        let existing_page = configuration.pages[..page_count]
            .iter()
            .position(|page| *page == gpa);
        if let Some(index) = existing_page {
            if (configuration.base_leaves[index] == 0) != private_page {
                return Err(Error::Format);
            }
        }
        for alternate_root in configuration
            .roots
            .iter()
            .chain(&configuration.extra_roots)
            .copied()
            .filter(|root| *root != 0 && *root != configuration.roots[0])
        {
            let alternate = page_mapping(memory, alternate_root, address, la57, physical_bits)?;
            if !alternate.present || alternate.physical_address != mapping.physical_address {
                return Err(Error::Unmapped);
            }
        }
        let page_index = existing_page.unwrap_or(page_count);
        let shadow = bank_base(configuration) + (INTERCEPT_TABLE_PAGES + page_index) as u64 * 4096;
        let mut bytes = [0u8; 4096];
        if existing_page.is_some() {
            for (index, chunk) in bytes.as_chunks_mut::<8>().0.iter_mut().enumerate() {
                *chunk = memory.table_entry(shadow + index as u64 * 8)?.to_le_bytes();
            }
        } else {
            memory.read(gpa, &mut bytes)?;
            memory.store_page(baseline_page(configuration, page_index), &bytes)?;
        }
        let start = address as usize & 4095;
        bytes[start..start + length].copy_from_slice(&hook.bytes[..length]);
        for byte in start..start + length {
            configuration.patch_mask[page_index][byte / 64] |= 1 << (byte % 64);
        }
        memory.store_page(shadow, &bytes)?;
        if existing_page.is_none() {
            let execute_leaf = leaf(memory, configuration, splits, gpa, configuration.ept, false)?;
            let entry = memory.table_entry(execute_leaf)?;
            memory.store_entry(execute_leaf, shadow | (entry & !MASK & !7) | if private_page { 3 } else { 4 })?;
            let data_leaf = leaf(
                memory,
                configuration,
                splits,
                gpa,
                configuration.data_ept,
                false,
            )?;
            let entry = memory.table_entry(data_leaf)?;
            memory.store_entry(data_leaf, if private_page {
                shadow | (entry & !MASK & !7) | 3
            } else {
                (entry & !7) | 1
            })?;
            configuration.data_leaves[page_count] = data_leaf;
            configuration.base_leaves[page_count] = if private_page { 0 } else {
                leaf(memory, configuration, splits, gpa, memory.base_ept(), true)?
            };
            configuration.pages[page_count] = gpa;
            page_count += 1;
        }
    }
    configuration.eptp_list =
        bank_base(configuration) + (INTERCEPT_TABLE_PAGES + 2 * HOOK_MAX_PAGES) as u64 * 4096;
    let mut list = [0; 4096];
    let execute = INTERCEPT_EXECUTE_SLOT as usize * 8;
    let data = INTERCEPT_DATA_SLOT as usize * 8;
    list[execute..execute + 8].copy_from_slice(&configuration.ept.to_le_bytes());
    list[data..data + 8].copy_from_slice(&configuration.data_ept.to_le_bytes());
    memory.store_page(configuration.eptp_list, &list)?;
    configuration.vmfunc = u64::from(flags & INTERCEPT_VMFUNC != 0);
    configuration.timing = u64::from(flags & INTERCEPT_TSC_OFFSET != 0);
    configuration.options = flags;
    cpu_views(configuration, memory, page_count)?;
    // Revoke the write bit only after all descriptors and private roots pass.
    let mut original_entries = [0; HOOK_MAX_PAGES];
    for (index, entry) in original_entries[..page_count].iter_mut().enumerate() {
        if configuration.base_leaves[index] != 0 {
            *entry = memory.table_entry(configuration.base_leaves[index])?;
        }
    }
    // Keep the validated guard set available to the transaction's cleanup even
    // if a later table write fails before publication.
    configuration.hook_count = page_count;
    for index in 0..page_count {
        let pointer = configuration.base_leaves[index];
        if pointer != 0 {
            memory.store_entry(pointer, original_entries[index] & !2)?;
        }
    }
    Ok(())
}

fn restore_base(
    configuration: &RoadEptProfile,
    memory: &mut impl InterceptionMemory,
) -> Result<(), Error> {
    let mut result = Ok(());
    for pointer in &configuration.base_leaves[..configuration.hook_count] {
        if *pointer == 0 { continue; }
        let restored = memory
            .table_entry(*pointer)
            .and_then(|entry| memory.store_entry(*pointer, entry | 2));
        if restored.is_err() {
            result = restored;
        }
    }
    result
}

fn refresh_page(
    configuration: &RoadEptProfile,
    memory: &mut impl InterceptionMemory,
    index: usize,
) -> Result<(), Error> {
    if configuration.base_leaves[index] == 0 {
        return Ok(());
    }
    let shadow = bank_base(configuration) + (INTERCEPT_TABLE_PAGES + index) as u64 * 4096;
    let baseline = baseline_page(configuration, index);
    let mut original = [0; 4096];
    memory.read(configuration.pages[index], &mut original)?;
    let mut merged = original;
    for (chunk_index, chunk) in merged.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        let patched = memory
            .table_entry(shadow + chunk_index as u64 * 8)?
            .to_le_bytes();
        let previous = memory
            .table_entry(baseline + chunk_index as u64 * 8)?
            .to_le_bytes();
        for byte_index in 0..8 {
            let offset = chunk_index * 8 + byte_index;
            chunk[byte_index] = merge_byte(
                previous[byte_index],
                original[offset],
                patched[byte_index],
                configuration.patch_mask[index][offset / 64] & (1 << (offset % 64)) != 0,
            )?;
        }
    }
    memory.store_page(shadow, &merged)?;
    memory.store_page(baseline, &original)
}

// Root writes share refresh serialization with CPU-private write windows.
// The legacy shared data root retains its rendezvous before changing bytes.
pub(crate) unsafe fn write_original(
    session: *mut Session,
    memory: &mut impl InterceptionMemory,
    address: u64,
    bytes: &[u8],
) -> Result<(), Error> {
    if bytes.len() > 4096 - (address as usize & 4095) {
        return Err(Error::Bounds);
    }
    let session = unsafe { &*session };
    if session
        .lock
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(Error::Busy);
    }
    let result = (|| {
        let configuration = unsafe { &*session.configuration.get() };
        if configuration.options & INTERCEPT_CONCURRENT_WRITES != 0 {
            lock_refresh(session)?;
            let result = (|| {
                memory.write_original(address, bytes)?;
                if session.is_active() {
                    if let Some(index) = configuration.pages[..configuration.hook_count]
                        .iter()
                        .position(|page| *page == address & !4095)
                    {
                        refresh_page(configuration, memory, index)?;
                    }
                }
                Ok(())
            })();
            session.refresh_lock.store(0, Ordering::Release);
            if let Err(error) = result {
                session.cause.store(
                    u64::from(if error == Error::MergeConflict {
                        INTERCEPT_CAUSE_MERGE
                    } else {
                        INTERCEPT_CAUSE_RUNTIME
                    }),
                    Ordering::Release,
                );
                session
                    .active
                    .store(u64::from(INTERCEPT_REVOKED), Ordering::Release);
                memory.quiesce()?;
                let restored = restore_base(configuration, memory);
                memory.flush();
                memory.resume();
                restored?;
            }
            return result;
        }
        memory.quiesce()?;
        let result = (|| {
            memory.write_original(address, bytes)?;
            let configuration = unsafe { &*session.configuration.get() };
            if session.is_active() {
                if let Some(index) = configuration.pages[..configuration.hook_count]
                    .iter()
                    .position(|page| *page == address & !4095)
                {
                    refresh_page(configuration, memory, index)?;
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            session.cause.store(
                u64::from(if error == Error::MergeConflict {
                    INTERCEPT_CAUSE_MERGE
                } else {
                    INTERCEPT_CAUSE_RUNTIME
                }),
                Ordering::Release,
            );
            session
                .active
                .store(u64::from(INTERCEPT_REVOKED), Ordering::Release);
            // Complete the retirement before releasing parked peers, even when
            // a shadow refresh failed after the original write committed.
            let restored = restore_base(configuration, memory);
            memory.flush();
            memory.resume();
            restored?;
            return Err(error);
        }
        memory.flush();
        memory.resume();
        result
    })();
    session.lock.store(0, Ordering::Release);
    result
}

fn cpuid_profile(packet: &[u8], la57: bool) -> Result<CpuidProfile, Error> {
    let count = word(packet, 32) as usize;
    if count == 0
        || count > CPUID_MAX_RECORDS
        || packet.len() != HEADER_BYTES + count * CPUID_RECORD_BYTES
    {
        return Err(Error::Bounds);
    }
    let mut profile = CpuidProfile {
        count,
        dr3: quad(packet, 24),
        dr7_mask: quad(packet, 144),
        dr7_value: quad(packet, 152),
        ..CpuidProfile::default()
    };
    if profile.dr3 == 0
        || !canonical(profile.dr3, la57)
        || profile.dr7_mask == 0
        || profile.dr7_value & !profile.dr7_mask != 0
    {
        return Err(Error::Bounds);
    }
    for index in 0..count {
        let offset = HEADER_BYTES + index * CPUID_RECORD_BYTES;
        let mut record = CpuidRecord {
            leaf: word(packet, offset),
            subleaf: word(packet, offset + 4),
            subleaf_mask: word(packet, offset + 8),
            ..CpuidRecord::default()
        };
        // Keep the native discovery and MatrixHV transport leaves available.
        if record.leaf == 0
            || record.leaf == 0x8000_0000
            || (0x4000_0000..0x5000_0000).contains(&record.leaf)
            || word(packet, offset + 12) != 0
            || record.subleaf & !record.subleaf_mask != 0
        {
            return Err(Error::Format);
        }
        for register in 0..4 {
            record.values[register] = word(packet, offset + 16 + register * 4);
            record.keep_masks[register] = word(packet, offset + 32 + register * 4);
            if record.values[register] & record.keep_masks[register] != 0 {
                return Err(Error::Format);
            }
        }
        if profile.records[..index].iter().any(|previous| {
            previous.leaf == record.leaf
                && (previous.subleaf ^ record.subleaf)
                    & previous.subleaf_mask & record.subleaf_mask == 0
        }) {
            return Err(Error::Format);
        }
        profile.records[index] = record;
    }
    Ok(profile)
}

#[cfg(any(target_os = "uefi", test))]
pub(crate) fn cpuid_values(
    configuration: &RoadEptProfile,
    profile: &CpuidProfile,
    cr3: u64,
    cpl: u64,
    debug: [u64; 2],
    selector: [u32; 2],
    native: [u32; 4],
) -> Option<[u32; 4]> {
    if profile.token != configuration.token
        || cpl == 0
        || !root_matches(configuration, cr3)
        || debug[0] != profile.dr3
        || debug[1] & profile.dr7_mask != profile.dr7_value
    {
        return None;
    }
    profile.records[..profile.count]
        .iter()
        .find(|record| {
            record.leaf == selector[0] && selector[1] & record.subleaf_mask == record.subleaf
        })
        .map(|record| {
            core::array::from_fn(|index| {
                native[index] & record.keep_masks[index] | record.values[index]
            })
        })
}

fn set_debug(configuration: &mut RoadEptProfile, packet: &[u8], la57: bool) -> Result<(), Error> {
    let count = word(packet, 32) as usize;
    if count == 0 || count > 4 || packet.len() != HEADER_BYTES + count * 16 {
        return Err(Error::Bounds);
    }
    let mut targets = [DebugTarget::default(); 4];
    for (index, target) in targets[..count].iter_mut().enumerate() {
        target.address = quad(packet, HEADER_BYTES + index * 16);
        target.redirect = quad(packet, HEADER_BYTES + index * 16 + 8);
        if !canonical(target.address, la57)
            || !canonical(target.redirect, la57)
            || target.address == target.redirect
        {
            return Err(Error::Bounds);
        }
    }
    for index in 0..count {
        if targets[..index]
            .iter()
            .any(|target| target.address == targets[index].address)
        {
            return Err(Error::Bounds);
        }
    }
    configuration.debug = targets;
    configuration.debug_count = count;
    Ok(())
}

fn syscall_profile(
    packet: &[u8],
    memory: &mut impl InterceptionMemory,
    physical_bits: u32,
) -> Result<SyscallProfile, Error> {
    if packet.len() != HEADER_BYTES || word(packet, 32) != 0 {
        return Err(Error::Bounds);
    }
    let [entry, kernel_cr3, cr4] = memory.syscall_context();
    let callback = quad(packet, 24);
    if cr4 & ((1 << 12) | (1 << 23)) != 0 {
        // CET changes SSP across SYSCALL/SYSRET. This profile supports the
        // recovered four-level, non-CET kernel entry only.
        return Err(Error::Unsupported);
    }
    if entry != quad(packet, 48) || entry < 0xffff_8000_0000_0000
        || !canonical(entry, false) || entry & 4095 > 4093
        || callback == 0 || callback >> 47 != 0
    {
        return Err(Error::Bounds);
    }
    let mapping = page_mapping(memory, kernel_cr3, entry, false, physical_bits)?;
    if !mapping.present {
        return Err(Error::Unmapped);
    }
    let mut prefix = [0; 3];
    memory.read(mapping.physical_address, &mut prefix)?;
    if prefix != [0x0f, 0x01, 0xf8] {
        return Err(Error::Unsupported);
    }
    let mut table = root(quad(packet, 16), physical_bits)?;
    for shift in [39, 30, 21, 12] {
        let mut bytes = [0; 8];
        memory.read(table + ((callback >> shift) & 511) * 8, &mut bytes)?;
        let entry = u64::from_le_bytes(bytes);
        if entry & 1 == 0 {
            return Err(Error::Unmapped);
        }
        if entry & 4 == 0 || entry & (1 << 63) != 0 {
            return Err(Error::Permission);
        }
        if shift == 12 || shift <= 30 && entry & 128 != 0 {
            // Also validate reserved physical bits and large-page alignment.
            if !page_mapping(memory, quad(packet, 16), callback, false, physical_bits)?.present {
                return Err(Error::Unmapped);
            }
            return Ok(SyscallProfile { entry: quad(packet, 48), callback, token: 0 });
        }
        table = entry & MASK;
    }
    Err(Error::Unmapped)
}

fn change_hooks(
    session: &Session,
    configuration: &mut RoadEptProfile,
    memory: &mut impl InterceptionMemory,
    packet: &mut [u8],
    la57: bool,
    physical_bits: u32,
) -> Result<(), Error> {
    let staged = unsafe { &mut *session.staging.get() };
    let hooks = unsafe { &*session.hooks.get() };
    let pending = unsafe { &mut *session.staged_hooks.get() };
    let operation = word(packet, 12);
    let generation = configuration
        .generation
        .checked_add(1)
        .ok_or(Error::Capacity)?;
    let previous_count = session.hook_records.load(Ordering::Relaxed) as usize;
    let mut count = if operation == HOOK_INSTALL {
        0
    } else {
        previous_count
    };
    pending[..count].copy_from_slice(&hooks[..count]);
    if operation != HOOK_INSTALL && configuration.options & INTERCEPT_PRIVATE_SHARED_DATA != 0 {
        if let Some(index) = configuration.base_leaves[..configuration.hook_count].iter().position(|pointer| *pointer == 0) {
            let shadow = bank_base(configuration) + (INTERCEPT_TABLE_PAGES + index) as u64 * 4096;
            if let Some(hook) = pending[..count].iter_mut().find(|hook| hook.address == 0x7ffe0000) {
                for (index, bytes) in hook.bytes.as_chunks_mut::<8>().0.iter_mut().enumerate() {
                    *bytes = memory.table_entry(shadow + index as u64 * 8)?.to_le_bytes();
                }
            }
        }
    }
    let mut next_id = session.next_id.load(Ordering::Relaxed);
    let added = if operation == HOOK_DROP {
        if packet.len() != HEADER_BYTES {
            return Err(Error::Bounds);
        }
        let index = pending[..count]
            .iter()
            .position(|hook| hook.id == quad(packet, 144))
            .ok_or(Error::Session)?;
        pending.copy_within(index + 1..count, index);
        count -= 1;
        0
    } else {
        let added = word(packet, 32) as usize;
        if added == 0 || packet.len() < HEADER_BYTES + added * ITEM_BYTES {
            return Err(Error::Bounds);
        }
        if added > HOOK_MAX_PATCHES - count {
            return Err(Error::Capacity);
        }
        for index in 0..added {
            let descriptor = HEADER_BYTES + index * ITEM_BYTES;
            let address = quad(packet, descriptor);
            let offset = word(packet, descriptor + 8) as usize;
            let length = word(packet, descriptor + 12) as usize;
            if !canonical(address, la57)
                || length == 0
                || length > 4096 - (address as usize & 4095)
                || offset < HEADER_BYTES + added * ITEM_BYTES
                || offset
                    .checked_add(length)
                    .is_none_or(|end| end > packet.len())
            {
                return Err(Error::Bounds);
            }
            let mapping =
                page_mapping(memory, configuration.roots[0], address, la57, physical_bits)?;
            if !mapping.present {
                return Err(Error::Unmapped);
            }
            let physical = mapping.physical_address;
            if pending[..count].iter().any(|hook| {
                physical < hook.physical_address + hook.length as u64
                    && hook.physical_address < physical + length as u64
            }) {
                return Err(Error::Bounds);
            }
            let hook = &mut pending[count];
            hook.id = next_id;
            next_id = next_id.checked_add(1).ok_or(Error::Capacity)?;
            hook.address = address;
            hook.physical_address = physical;
            hook.length = length;
            hook.bytes[..length].copy_from_slice(&packet[offset..offset + length]);
            count += 1;
        }
        added
    };
    *staged = *configuration;
    staged.bank = if configuration.hook_count == 0 {
        configuration.bank
    } else {
        configuration.bank ^ 1
    };
    staged.hook_count = 0;
    staged.vmfunc = 0;
    let flags = if operation == HOOK_INSTALL {
        word(packet, 128)
    } else {
        (if configuration.vmfunc != 0 {
            INTERCEPT_VMFUNC
        } else {
            0
        }) | (configuration.options
            & (INTERCEPT_CONCURRENT_WRITES | INTERCEPT_PERSISTENT_DATA | INTERCEPT_NO_LEASE | INTERCEPT_PRIVATE_SHARED_DATA))
            | (if configuration.timing != 0 {
                INTERCEPT_TSC_OFFSET
            } else {
                0
            })
    };
    // Peers remain parked while guards are restored and the spare bank is built.
    // Retire both old roots before publication; failed builds retain the old bank.
    if let Err(error) = restore_base(configuration, memory) {
        session
            .cause
            .store(u64::from(INTERCEPT_CAUSE_RUNTIME), Ordering::Release);
        session
            .active
            .store(u64::from(INTERCEPT_REVOKED), Ordering::Release);
        return Err(error);
    }
    let previous_epoch = session.split_epoch.load(Ordering::Relaxed);
    let result = retire_splits(session, configuration, memory, &pending[..count]).and_then(|()| {
        if count == 0 {
            return Ok(());
        }
        install(
            staged,
            memory,
            unsafe { &mut *session.splits.get() },
            &pending[..count],
            flags,
            la57,
            physical_bits,
        )
    });
    configuration.base_pool_used = staged.base_pool_used;
    if let Err(error) = result {
        let mut restored = restore_base(staged, memory);
        if let Err(rollback_error) = rollback_splits(session, memory, previous_epoch) {
            restored = Err(rollback_error);
        }
        for pointer in configuration.base_leaves[..configuration.hook_count].iter().filter(|pointer| **pointer != 0) {
            let guarded = memory
                .table_entry(*pointer)
                .and_then(|entry| memory.store_entry(*pointer, entry & !2));
            if guarded.is_err() {
                restored = guarded;
            }
        }
        if let Err(rollback_error) = restored {
            session
                .cause
                .store(u64::from(INTERCEPT_CAUSE_RUNTIME), Ordering::Release);
            session
                .active
                .store(u64::from(INTERCEPT_REVOKED), Ordering::Release);
            let _ = restore_base(configuration, memory);
            return Err(rollback_error);
        }
        return Err(error);
    }
    *configuration = *staged;
    configuration.generation = generation;
    (unsafe { &mut *session.hooks.get() })[..count].copy_from_slice(&pending[..count]);
    session.hook_records.store(count as u64, Ordering::Relaxed);
    session.next_id.store(next_id, Ordering::Relaxed);
    for index in 0..added {
        let descriptor = HEADER_BYTES + index * ITEM_BYTES + 16;
        packet[descriptor..descriptor + 8]
            .copy_from_slice(&pending[count - added + index].id.to_le_bytes());
    }
    Ok(())
}

// Writers own both this lock and the resident CPU barrier before changing any
// configuration or table. Readers run only outside the barrier's parked interval.
pub(crate) unsafe fn execute(
    session: *mut Session,
    memory: &mut impl InterceptionMemory,
    packet: &mut [u8],
    la57: bool,
    physical_bits: u32,
) -> Result<(), Error> {
    if session.is_null() {
        return Err(Error::Unsupported);
    }
    if packet.len() < HEADER_BYTES
        || packet.len() > BUFFER_BYTES
        || quad(packet, 0) != MEMORY_MAGIC
        || word(packet, 8) != MEMORY_VERSION
        || word(packet, 36) as usize != packet.len()
    {
        return Err(Error::Format);
    }
    let session = unsafe { &*session };
    if session
        .lock
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(Error::Busy);
    }
    let result = (|| {
        let operation = word(packet, 12);
        if session.is_active() && expired(session, memory.clock()) {
            memory.quiesce()?;
            session
                .cause
                .store(u64::from(INTERCEPT_CAUSE_LEASE), Ordering::Release);
            session
                .active
                .store(u64::from(INTERCEPT_REVOKED), Ordering::Release);
            let restored = restore_base(unsafe { &*session.configuration.get() }, memory);
            memory.flush();
            memory.resume();
            restored?;
        }
        if operation != INTERCEPT_STATUS
            && operation != HOOK_LIST
            && operation != INTERCEPT_CONTEXT_LIST
        {
            memory.quiesce()?;
            let result = (|| {
                if !reclaim_splits(session, memory)
                    && matches!(operation, HOOK_INSTALL | HOOK_ADD | HOOK_DROP)
                {
                    // The spare private bank can still contain links into
                    // quarantined tables. Do not overwrite it after a failed flush.
                    return Err(Error::Busy);
                }
                if matches!(operation, HOOK_INSTALL | HOOK_ADD | DEBUG_SET | CPUID_SET | SYSCALL_SET) && !memory.available() {
                    return Err(Error::Unsupported);
                }
                if matches!(operation, HOOK_INSTALL | HOOK_ADD) && !memory.split_available() {
                    return Err(Error::Unsupported);
                }
                if matches!(operation, HOOK_INSTALL | HOOK_ADD | HOOK_DROP)
                    && unsafe { &*session.configuration.get() }.hook_count != 0
                {
                    // Flush callbacks inspect the published configuration, so
                    // finish them before borrowing it for the transaction.
                    memory.flush();
                }
                let configuration = unsafe { &mut *session.configuration.get() };
                if session.is_active() && expired(session, memory.clock()) {
                    restore_base(configuration, memory)?;
                    session
                        .cause
                        .store(u64::from(INTERCEPT_CAUSE_LEASE), Ordering::Release);
                    session
                        .active
                        .store(u64::from(INTERCEPT_REVOKED), Ordering::Release);
                }
                match operation {
                    HOOK_INSTALL | DEBUG_SET | CPUID_SET | SYSCALL_SET => {
                        let cpuid = if operation == CPUID_SET {
                            Some(cpuid_profile(packet, la57)?)
                        } else {
                            None
                        };
                        if matches!(operation, CPUID_SET | SYSCALL_SET) && session.is_active()
                            && quad(packet, 80) != configuration.token
                        {
                            return Err(Error::Session);
                        }
                        let syscall = if operation == SYSCALL_SET {
                            if session.is_active() && configuration.debug_count != 0
                                && unsafe { &*session.syscall.get() }.token != configuration.token
                            {
                                return Err(Error::Busy);
                            }
                            Some(syscall_profile(packet, memory, physical_bits)?)
                        } else {
                            if operation == DEBUG_SET && session.is_active()
                                && unsafe { &*session.syscall.get() }.entry != 0
                            {
                                return Err(Error::Busy);
                            }
                            None
                        };
                        let (duration, ticks) =
                            lease_duration(packet, memory, INTERCEPT_DEFAULT_LEASE_MS)?;
                        let token = configuration.token.checked_add(1).ok_or(Error::Capacity)?;
                        let flags = word(packet, 128);
                        if flags & !OPTIONS != 0
                            || matches!(operation, DEBUG_SET | CPUID_SET | SYSCALL_SET)
                                && flags
                                    & (INTERCEPT_VMFUNC
                                        | INTERCEPT_CONCURRENT_WRITES
                                        | INTERCEPT_PERSISTENT_DATA)
                                    != 0
                            || operation == SYSCALL_SET
                                && flags & !(INTERCEPT_TSC_OFFSET | INTERCEPT_NO_LEASE) != 0
                        {
                            return Err(Error::Format);
                        }
                        if flags & INTERCEPT_TSC_OFFSET != 0 && !memory.timing_available() {
                            return Err(Error::Unsupported);
                        }
                        let roots = [
                            root(quad(packet, 16), physical_bits)?,
                            if quad(packet, 64) == 0 {
                                0
                            } else {
                                root(quad(packet, 64), physical_bits)?
                            },
                        ];
                        if session.is_active() && configuration.roots != roots {
                            return Err(Error::Busy);
                        }
                        if !session.is_active() {
                            restore_base(configuration, memory)?;
                            configuration.roots = roots;
                            configuration.hook_count = 0;
                            configuration.debug_count = 0;
                            unsafe { *session.cpuid.get() = CpuidProfile::default(); }
                            unsafe { *session.syscall.get() = SyscallProfile::default(); }
                            configuration.timing = 0;
                            configuration.extra_roots.fill(0);
                            session.hook_records.store(0, Ordering::Relaxed);
                            retire_splits(session, configuration, memory, &[])?;
                        }
                        // An active EPT root is never rebuilt in place. A failed
                        // first installation remains unpublished with hook_count zero.
                        if operation == HOOK_INSTALL {
                            if configuration.hook_count != 0 {
                                return Err(Error::Busy);
                            }
                            change_hooks(
                                session,
                                configuration,
                                memory,
                                packet,
                                la57,
                                physical_bits,
                            )?;
                        } else if let Some(syscall) = syscall {
                            configuration.debug.fill(DebugTarget::default());
                            configuration.debug[0] = DebugTarget {
                                address: syscall.entry, redirect: syscall.callback,
                            };
                            configuration.debug_count = 1;
                            unsafe { *session.syscall.get() = syscall; }
                            if flags & INTERCEPT_TSC_OFFSET != 0 {
                                configuration.timing = 1;
                            }
                        } else if let Some(cpuid) = cpuid {
                            unsafe { *session.cpuid.get() = cpuid; }
                            if flags & INTERCEPT_TSC_OFFSET != 0 {
                                configuration.timing = 1;
                            }
                        } else {
                            set_debug(configuration, packet, la57)?;
                            if flags & INTERCEPT_TSC_OFFSET != 0 {
                                configuration.timing = 1;
                            }
                        }
                        let profile = unsafe { &mut *session.cpuid.get() };
                        if operation == CPUID_SET || profile.token == configuration.token {
                            profile.token = token;
                        }
                        let syscall = unsafe { &mut *session.syscall.get() };
                        if syscall.entry != 0 && (operation == SYSCALL_SET || syscall.token == configuration.token) {
                            syscall.token = token;
                        }
                        configuration.token = token;
                        session
                            .cause
                            .store(u64::from(INTERCEPT_CAUSE_NONE), Ordering::Relaxed);
                        session
                            .active
                            .store(u64::from(INTERCEPT_ACTIVE), Ordering::Release);
                        configuration.timer_rate = memory.timer_rate();
                        arm_lease(session, memory, duration, ticks);
                    }
                    HOOK_ADD | HOOK_DROP | INTERCEPT_RENEW => {
                        if !session.is_active() || quad(packet, 80) != configuration.token {
                            return Err(Error::Session);
                        }
                        if operation == INTERCEPT_RENEW {
                            if packet.len() != HEADER_BYTES {
                                return Err(Error::Bounds);
                            }
                            let (duration, ticks) = lease_duration(
                                packet,
                                memory,
                                session.lease_ms.load(Ordering::Acquire) as u32,
                            )?;
                            arm_lease(session, memory, duration, ticks);
                        } else {
                            change_hooks(
                                session,
                                configuration,
                                memory,
                                packet,
                                la57,
                                physical_bits,
                            )?;
                            if configuration.hook_count == 0 && configuration.debug_count == 0
                                && unsafe { &*session.cpuid.get() }.count == 0 {
                                session.active.store(0, Ordering::Release);
                            }
                        }
                    }
                    INTERCEPT_CONTEXT_ADD | INTERCEPT_CONTEXT_REMOVE => {
                        if !session.is_active() || quad(packet, 80) != configuration.token {
                            return Err(Error::Session);
                        }
                        let count = word(packet, 32) as usize;
                        if count == 0
                            || count > ROOT_HISTORY_COUNT - 2
                            || packet.len() != HEADER_BYTES + count * 8
                        {
                            return Err(Error::Bounds);
                        }
                        let generation = configuration
                            .generation
                            .checked_add(1)
                            .ok_or(Error::Capacity)?;
                        let mut roots = configuration.extra_roots;
                        for index in 0..count {
                            let cr3 = root(quad(packet, HEADER_BYTES + index * 8), physical_bits)?;
                            if operation == INTERCEPT_CONTEXT_ADD {
                                if configuration.roots.contains(&cr3) || roots.contains(&cr3) {
                                    return Err(Error::Format);
                                }
                                let hooks = unsafe { &*session.hooks.get() };
                                for hook in
                                    &hooks[..session.hook_records.load(Ordering::Acquire) as usize]
                                {
                                    let mapping = page_mapping(
                                        memory,
                                        cr3,
                                        hook.address,
                                        la57,
                                        physical_bits,
                                    )?;
                                    if !mapping.present
                                        || mapping.physical_address != hook.physical_address
                                    {
                                        return Err(Error::Remapped);
                                    }
                                }
                                let slot = roots
                                    .iter_mut()
                                    .find(|value| **value == 0)
                                    .ok_or(Error::Capacity)?;
                                *slot = cr3;
                            } else {
                                let slot = roots
                                    .iter_mut()
                                    .find(|value| **value == cr3)
                                    .ok_or(Error::Session)?;
                                *slot = 0;
                            }
                        }
                        configuration.extra_roots = roots;
                        configuration.generation = generation;
                    }
                    HOOK_REMOVE | DEBUG_CLEAR | CPUID_CLEAR | SYSCALL_CLEAR | INTERCEPT_RELEASE => {
                        if packet.len() != HEADER_BYTES || quad(packet, 80) != configuration.token {
                            return Err(Error::Session);
                        }
                        if operation == HOOK_REMOVE || operation == INTERCEPT_RELEASE {
                            restore_base(configuration, memory)?;
                            configuration.hook_count = 0;
                            configuration.vmfunc = 0;
                            session.hook_records.store(0, Ordering::Relaxed);
                        }
                        if matches!(operation, DEBUG_CLEAR | SYSCALL_CLEAR | INTERCEPT_RELEASE) {
                            if operation == SYSCALL_CLEAR && unsafe { &*session.syscall.get() }.entry == 0 {
                                return Err(Error::Session);
                            }
                            configuration.debug_count = 0;
                            unsafe { *session.syscall.get() = SyscallProfile::default(); }
                        }
                        if operation == CPUID_CLEAR || operation == INTERCEPT_RELEASE {
                            unsafe { *session.cpuid.get() = CpuidProfile::default(); }
                        }
                        if configuration.hook_count == 0 && configuration.debug_count == 0
                            && unsafe { &*session.cpuid.get() }.count == 0 {
                            session.active.store(0, Ordering::Release);
                        }
                        if operation == HOOK_REMOVE || operation == INTERCEPT_RELEASE {
                            // No published leaf pointer remains in a detached
                            // table. Existing translations retire on release.
                            retire_splits(session, configuration, memory, &[])?;
                        }
                    }
                    _ => return Err(Error::Format),
                }
                Ok(())
            })();
            memory.flush();
            memory.resume();
            result?;
        } else {
            if operation == INTERCEPT_STATUS && packet.len() != HEADER_BYTES {
                return Err(Error::Bounds);
            }
            if operation == HOOK_LIST {
                if quad(packet, 80) != unsafe { &*session.configuration.get() }.token {
                    return Err(Error::Session);
                }
                if packet.len() != HEADER_BYTES + HOOK_MAX_PATCHES * ITEM_BYTES {
                    return Err(Error::Bounds);
                }
                packet[HEADER_BYTES..].fill(0);
                let count = session.hook_records.load(Ordering::Relaxed) as usize;
                let hooks = unsafe { &*session.hooks.get() };
                for (index, hook) in hooks[..count].iter().enumerate() {
                    let descriptor = HEADER_BYTES + index * ITEM_BYTES;
                    packet[descriptor..descriptor + 8].copy_from_slice(&hook.id.to_le_bytes());
                    packet[descriptor + 8..descriptor + 16]
                        .copy_from_slice(&hook.address.to_le_bytes());
                    packet[descriptor + 16..descriptor + 20]
                        .copy_from_slice(&(hook.length as u32).to_le_bytes());
                }
                packet[32..36].copy_from_slice(&(count as u32).to_le_bytes());
            }
            if operation == INTERCEPT_CONTEXT_LIST {
                if quad(packet, 80) != unsafe { &*session.configuration.get() }.token {
                    return Err(Error::Session);
                }
                if packet.len() != HEADER_BYTES + ROOT_HISTORY_COUNT * 8 {
                    return Err(Error::Bounds);
                }
                let configuration = unsafe { &*session.configuration.get() };
                packet[HEADER_BYTES..].fill(0);
                let mut count = 0;
                for cr3 in configuration.registered_roots() {
                    packet[HEADER_BYTES + count * 8..HEADER_BYTES + count * 8 + 8]
                        .copy_from_slice(&cr3.to_le_bytes());
                    count += 1;
                }
                packet[32..36].copy_from_slice(&(count as u32).to_le_bytes());
            }
        }
        let configuration = unsafe { &*session.configuration.get() };
        packet[16..24].copy_from_slice(&configuration.roots[0].to_le_bytes());
        packet[24..28].copy_from_slice(&(unsafe { &*session.cpuid.get() }.count as u32).to_le_bytes());
        packet[64..72].copy_from_slice(&configuration.roots[1].to_le_bytes());
        packet[80..88].copy_from_slice(&configuration.token.to_le_bytes());
        packet[88..96].copy_from_slice(&session.hits.load(Ordering::Relaxed).to_le_bytes());
        packet[104..108].copy_from_slice(&(configuration.hook_count as u32).to_le_bytes());
        packet[108..112].copy_from_slice(&(configuration.debug_count as u32).to_le_bytes());
        packet[112..116]
            .copy_from_slice(&(session.active.load(Ordering::Acquire) as u32).to_le_bytes());
        packet[116..120]
            .copy_from_slice(&(session.cause.load(Ordering::Acquire) as u32).to_le_bytes());
        packet[96..104].copy_from_slice(&session.data_exits.load(Ordering::Relaxed).to_le_bytes());
        packet[120..128]
            .copy_from_slice(&session.write_windows.load(Ordering::Relaxed).to_le_bytes());
        packet[128..132].copy_from_slice(
            &((if session.is_active() && configuration.hook_count != 0 && configuration.vmfunc != 0
            {
                INTERCEPT_VMFUNC
            } else {
                0
            }) | (if session.is_active() && configuration.hook_count != 0 {
                configuration.options & (INTERCEPT_CONCURRENT_WRITES | INTERCEPT_PERSISTENT_DATA | INTERCEPT_PRIVATE_SHARED_DATA)
            } else {
                0
            }) | (if session.is_active() && configuration.timing != 0 {
                INTERCEPT_TSC_OFFSET
            } else {
                0
            }) | (if session.is_active() && session.lease_ms.load(Ordering::Acquire) == 0 {
                INTERCEPT_NO_LEASE
            } else {
                0
            }) | (if session.is_active() && unsafe { &*session.syscall.get() }.entry != 0 {
                INTERCEPT_SYSCALL
            } else {
                0
            }))
            .to_le_bytes(),
        );
        packet[132..136]
            .copy_from_slice(&(session.lease_ms.load(Ordering::Acquire) as u32).to_le_bytes());
        let hz = session.tsc_hz.load(Ordering::Acquire);
        let now = memory.clock();
        let remaining = if session.is_active() && hz != 0 && !expired(session, now) {
            session
                .lease_deadline
                .load(Ordering::Acquire)
                .wrapping_sub(now)
                .saturating_mul(1000)
                / hz
        } else {
            0
        };
        packet[136..144].copy_from_slice(&remaining.to_le_bytes());
        packet[144..152].copy_from_slice(&configuration.generation.to_le_bytes());
        packet[152..160]
            .copy_from_slice(&session.hook_records.load(Ordering::Relaxed).to_le_bytes());
        packet[72..80].copy_from_slice(&session.timing_ticks.load(Ordering::Relaxed).to_le_bytes());
        packet[44..48]
            .copy_from_slice(&(configuration.registered_roots().count() as u32).to_le_bytes());
        Ok(())
    })();
    session.lock.store(0, Ordering::Release);
    result
}

#[cfg(target_os = "uefi")]
pub(crate) mod runtime {
    use super::*;
    use crate::vmx::resident::abi::{
        InterceptionCpuState, ResidentBootContext, ResidentEventContext,
    };
    use crate::vmx::vmcs::*;

    const PRIMARY_BITS: u64 = (1 << 15) | (1 << 23) | (1 << 27);
    type Synchronize = unsafe extern "efiapi" fn(u64, u64) -> u64;

    fn read(field: u64) -> Result<u64, ()> {
        vmread(field).map_err(|_| ())
    }
    fn write(field: u64, value: u64) -> Result<(), ()> {
        vmwrite(field, value).map_err(|_| ())
    }

    fn clock() -> u64 {
        unsafe {
            core::arch::x86_64::_mm_lfence();
            let now = core::arch::x86_64::_rdtsc();
            core::arch::x86_64::_mm_lfence();
            now
        }
    }

    fn syscall_msrs() -> [u64; 2] {
        unsafe { [crate::arch::read_msr(0xc000_0081), crate::arch::read_msr(0xc000_0082)] }
    }

    fn syscall_gate(registers: &[u64; 6]) -> bool {
        registers[3] == 0x7ffe_0ff0 && registers[5] & 0xffff_ffff_f000_0040 == 0x40
    }

    fn route_syscall(
        profile: &SyscallProfile,
        frame: &mut [u64],
        fx_state: &mut [u8; 512],
    ) -> Result<u64, ()> {
        let [star, lstar] = syscall_msrs();
        let kernel_cs = (star >> 32) as u16 & !3;
        if lstar != profile.entry || read(GUEST_RIP)? != lstar
            || read(GUEST_CR4)? & ((1 << 12) | (1 << 23)) != 0
            || read(GUEST_IA32_EFER)? & 0x401 != 0x401
            || read(GUEST_CS_SELECTOR)? != u64::from(kernel_cs)
            || read(GUEST_SS_SELECTOR)? != u64::from(kernel_cs.wrapping_add(8))
            || read(GUEST_CS_AR_BYTES)? & 0x60ff != 0x209b
            || read(GUEST_INTERRUPTIBILITY_INFO)? != 0
            || profile.callback == 0 || profile.callback >> 47 != 0
            || frame[1] >> 47 != 0
        {
            write(GUEST_RFLAGS, read(GUEST_RFLAGS)? | (1 << 16))?;
            return Ok(1);
        }
        let bypass = u64::from_le_bytes(fx_state[240..248].try_into().map_err(|_| ())?);
        if bypass == 0x1337_1337_1337_1337 {
            // RF permits exactly one native LSTAR instruction with the owned
            // execution breakpoint still armed. SWAPGS remains native code.
            write(GUEST_RFLAGS, read(GUEST_RFLAGS)? | (1 << 16))?;
            fx_state[240..256].fill(0);
            return Ok(1);
        }
        let user_selector = (star >> 48) as u16;
        let values = [
            (GUEST_CS_SELECTOR, u64::from(user_selector.wrapping_add(16) | 3)),
            (GUEST_SS_SELECTOR, u64::from(user_selector.wrapping_add(8) | 3)),
            (GUEST_CS_BASE, 0), (GUEST_SS_BASE, 0),
            (GUEST_CS_LIMIT, 0xffff_ffff), (GUEST_SS_LIMIT, 0xffff_ffff),
            (GUEST_CS_AR_BYTES, 0xa0fb), (GUEST_SS_AR_BYTES, 0xc0f3),
            (GUEST_RFLAGS, (frame[10] & 0x3c7fd7) | 2),
            (GUEST_RIP, profile.callback),
        ];
        let mut saved = [0; 10];
        for (index, (field, _)) in values.iter().enumerate() {
            saved[index] = read(*field)?;
        }
        for (index, (field, value)) in values.iter().enumerate() {
            if write(*field, *value).is_err() {
                for prior in (0..index).rev() {
                    if write(values[prior].0, saved[prior]).is_err() {
                        // A partial privilege transition must halt rather than
                        // pass through the ordinary base-profile recovery.
                        return Ok(u64::MAX);
                    }
                }
                return Err(());
            }
        }
        // This runs before SWAPGS: RSP, FS and GS already belong to the user.
        // Intel SYSRET64 sets descriptor caches directly, without a GDT load.
        fx_state[224..240].fill(0);
        fx_state[224..228].copy_from_slice(&(frame[0] as u32).to_le_bytes());
        frame[0] = frame[1];
        frame[1] = profile.callback;
        Ok(1)
    }

    fn configure_timing(boot: &mut ResidentBootContext, enabled: bool) -> Result<(), ()> {
        let cpu = &mut boot.interception;
        if enabled {
            if cpu.timing_saved == 0 {
                cpu.timing_offset = read(TSC_OFFSET)?;
                cpu.timing_start = 0;
                cpu.timing_saved = 1;
            }
        } else if cpu.timing_saved != 0 {
            write(TSC_OFFSET, cpu.timing_offset)?;
            cpu.timing_saved = 0;
            cpu.timing_start = 0;
        }
        Ok(())
    }

    fn compensate_timing(session: &Session, boot: &mut ResidentBootContext) -> Result<(), ()> {
        let cpu = &mut boot.interception;
        let start = core::mem::replace(&mut cpu.timing_start, 0);
        if cpu.timing_saved == 0 || start == 0 || !session.is_active() {
            return Ok(());
        }
        let elapsed = clock().wrapping_sub(start);
        if elapsed as i64 > 0 {
            write(TSC_OFFSET, read(TSC_OFFSET)?.wrapping_sub(elapsed))?;
            session.timing_ticks.fetch_add(elapsed, Ordering::Relaxed);
        }
        Ok(())
    }

    fn configure_timer(
        session: &Session,
        boot: &mut ResidentBootContext,
        active: bool,
    ) -> Result<(), ()> {
        let cpu = &mut boot.interception;
        let pin = read(PIN_BASED_VM_EXEC_CONTROL)?;
        if boot.diagnostic_expired != 0 {
            cpu.timer_pin = 0;
        }
        if active && session.tsc_hz.load(Ordering::Acquire) != 0 {
            if cpu.timer_saved == 0 {
                cpu.timer_pin = pin & (1 << 6);
                cpu.timer_value = read(VMX_PREEMPTION_TIMER_VALUE)?;
                cpu.timer_saved = 1;
            }
            let remaining = session
                .lease_deadline
                .load(Ordering::Acquire)
                .wrapping_sub(clock());
            let remaining = if remaining as i64 <= 0 { 2 } else { remaining };
            let rate = unsafe { &*session.configuration.get() }.timer_rate;
            let mut ticks = (remaining >> rate).clamp(2, u64::from(u32::MAX));
            let configuration = unsafe { &*session.configuration.get() };
            if configuration.options & INTERCEPT_PRIVATE_SHARED_DATA != 0 {
                ticks = ticks.min(((session.tsc_hz.load(Ordering::Acquire) / 1000) >> rate).max(2));
            }
            if cpu.timer_pin != 0 && boot.diagnostic_interval_tsc != 0 {
                ticks = ticks.min(read(VMX_PREEMPTION_TIMER_VALUE)?.max(2));
            }
            write(VMX_PREEMPTION_TIMER_VALUE, ticks)?;
            write(PIN_BASED_VM_EXEC_CONTROL, pin | (1 << 6))?;
            cpu.timer_armed = 1;
        } else {
            cpu.timer_armed = 0;
            if cpu.timer_saved != 0 {
                write(PIN_BASED_VM_EXEC_CONTROL, (pin & !(1 << 6)) | cpu.timer_pin)?;
                if boot.diagnostic_interval_tsc == 0 {
                    write(VMX_PREEMPTION_TIMER_VALUE, cpu.timer_value)?;
                }
                cpu.timer_saved = 0;
            }
        }
        Ok(())
    }

    fn debug_registers() -> [u64; 5] {
        let mut registers = [0; 5];
        unsafe {
            core::arch::asm!("mov {value}, dr0", value = out(reg) registers[0], options(nostack, preserves_flags));
            core::arch::asm!("mov {value}, dr1", value = out(reg) registers[1], options(nostack, preserves_flags));
            core::arch::asm!("mov {value}, dr2", value = out(reg) registers[2], options(nostack, preserves_flags));
            core::arch::asm!("mov {value}, dr3", value = out(reg) registers[3], options(nostack, preserves_flags));
            core::arch::asm!("mov {value}, dr6", value = out(reg) registers[4], options(nostack, preserves_flags));
        }
        registers
    }

    fn load_debug(registers: &[u64; 5]) {
        unsafe {
            core::arch::asm!("mov dr0, {value}", value = in(reg) registers[0], options(nostack, preserves_flags));
            core::arch::asm!("mov dr1, {value}", value = in(reg) registers[1], options(nostack, preserves_flags));
            core::arch::asm!("mov dr2, {value}", value = in(reg) registers[2], options(nostack, preserves_flags));
            core::arch::asm!("mov dr3, {value}", value = in(reg) registers[3], options(nostack, preserves_flags));
            core::arch::asm!("mov dr6, {value}", value = in(reg) registers[4], options(nostack, preserves_flags));
        }
    }

    fn restore_debug(cpu: &mut InterceptionCpuState) -> Result<(), ()> {
        let registers = debug_registers();
        if cpu.debug_armed != 0 {
            load_debug(cpu.guest_debug[..5].try_into().map_err(|_| ())?);
            write(GUEST_DR7, cpu.guest_debug[5])?;
            cpu.debug_armed = 0;
        } else {
            cpu.guest_debug[..5].copy_from_slice(&registers);
            cpu.guest_debug[5] = read(GUEST_DR7)?;
        }
        Ok(())
    }

    fn invalidate(ept: u64) -> Result<(), ()> {
        #[repr(C, align(16))]
        struct Descriptor([u64; 2]);
        let descriptor = Descriptor([ept, 0]);
        let failed: u8;
        unsafe {
            core::arch::asm!("invept {kind}, [{descriptor}]", "setna {failed}",
                kind = in(reg) 1u64, descriptor = in(reg) &descriptor,
                failed = lateout(reg_byte) failed, options(nostack));
        }
        if failed == 0 { Ok(()) } else { Err(()) }
    }

    fn entry_bits(pointer: u64, set: u64, clear: u64) {
        let entry = unsafe { &*(pointer as *const AtomicU64) };
        entry
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some((value | set) & !clear)
            })
            .unwrap();
    }

    fn page_byte(address: u64, value: Option<u8>) -> u8 {
        unsafe {
            let pointer = address as *mut u8;
            if let Some(value) = value {
                pointer.write_volatile(value);
            }
            pointer.read_volatile()
        }
    }

    fn refresh(configuration: &RoadEptProfile) -> Result<(), Error> {
        // Original writes are serialized across the full MTF window. Validate
        // all pages before publishing bytes so a conflict cannot partially merge.
        for index in 0..configuration.hook_count {
            if configuration.base_leaves[index] == 0 { continue; }
            let original = configuration.pages[index];
            let shadow = bank_base(configuration) + (INTERCEPT_TABLE_PAGES + index) as u64 * 4096;
            let baseline = baseline_page(configuration, index);
            for offset in 0..4096 {
                merge_byte(
                    page_byte(baseline + offset, None),
                    page_byte(original + offset, None),
                    page_byte(shadow + offset, None),
                    configuration.patch_mask[index][offset as usize / 64] & (1 << (offset % 64))
                        != 0,
                )?;
            }
        }
        for index in 0..configuration.hook_count {
            if configuration.base_leaves[index] == 0 { continue; }
            let original = configuration.pages[index];
            let shadow = bank_base(configuration) + (INTERCEPT_TABLE_PAGES + index) as u64 * 4096;
            let baseline = baseline_page(configuration, index);
            for offset in 0..4096 {
                let current = page_byte(original + offset, None);
                let merged = merge_byte(
                    page_byte(baseline + offset, None),
                    current,
                    page_byte(shadow + offset, None),
                    configuration.patch_mask[index][offset as usize / 64] & (1 << (offset % 64))
                        != 0,
                )?;
                page_byte(shadow + offset, Some(merged));
                page_byte(baseline + offset, Some(current));
            }
        }
        Ok(())
    }

    fn release_refresh(session: &Session, boot: &mut ResidentBootContext) {
        if core::mem::replace(&mut boot.interception.refresh_owned, 0) != 0 {
            session.refresh_lock.store(0, Ordering::Release);
        }
    }

    fn reset_step(boot: &mut ResidentBootContext) -> Result<(), ()> {
        boot.interception.step_active = 0;
        if boot.interception.controls_saved == 0 {
            return Ok(());
        }
        let primary = read(CPU_BASED_VM_EXEC_CONTROL)?;
        write(
            CPU_BASED_VM_EXEC_CONTROL,
            (primary & !(1 << 27)) | (boot.interception.primary_bits & (1 << 27)),
        )
    }

    fn finish_step(
        session: &Session,
        boot: &mut ResidentBootContext,
        synchronize: Synchronize,
    ) -> Result<(), ()> {
        let reading = boot.interception.step_active == 4;
        let writing = matches!(boot.interception.step_active, 2 | 3);
        if boot.interception.step_active == 0 {
            return Ok(());
        }
        let configuration = unsafe { &*session.configuration.get() };
        let concurrent = configuration.options & INTERCEPT_CONCURRENT_WRITES != 0;
        let cooperative_data = boot.interception.cooperative_data;
        let cooperative_cr3 = boot.interception.cooperative_cr3;
        let result = (|| {
            reset_step(boot)?;
            base(boot)?;
            if reading {
                for pointer in data_leaves(configuration, boot.processor_number as usize) {
                    entry_bits(*pointer, 0, 6);
                }
                invalidate(data_root(configuration, boot.processor_number as usize))?;
            }
            if writing {
                for pointer in data_leaves(configuration, boot.processor_number as usize) {
                    entry_bits(*pointer, 0, 6);
                }
                if refresh(configuration).is_err() {
                    session
                        .cause
                        .store(u64::from(INTERCEPT_CAUSE_MERGE), Ordering::Release);
                    session
                        .active
                        .store(u64::from(INTERCEPT_REVOKED), Ordering::Release);
                }
                invalidate(data_root(configuration, boot.processor_number as usize))?;
            }
            Ok(())
        })();
        release_refresh(session, boot);
        if writing && !concurrent {
            unsafe {
                synchronize(boot as *mut _ as u64, 1);
                synchronize(boot as *mut _ as u64, 2);
            }
            boot.interception.cooperative_data = cooperative_data;
            boot.interception.cooperative_cr3 = cooperative_cr3;
        }
        if !session.is_active() || result.is_err() {
            // The window and its lock are already closed, so retirement cannot
            // recurse into an outstanding writer or leak the rendezvous owner.
            revoke(session, boot, synchronize)?;
        }
        result
    }

    fn base(boot: &mut ResidentBootContext) -> Result<(), ()> {
        if boot.interception.applied_ept != 0 {
            write(EPT_POINTER, boot.cache_ept_pointer)?;
            invalidate(boot.interception.applied_ept)?;
            boot.interception.applied_ept = 0;
        }
        Ok(())
    }

    fn configure_vmfunc(
        boot: &mut ResidentBootContext,
        configuration: &RoadEptProfile,
        enable: bool,
    ) -> Result<(), ()> {
        let cpu = &mut boot.interception;
        if enable {
            if cpu.vmfunc_saved == 0 {
                cpu.vmfunc_secondary = read(SECONDARY_VM_EXEC_CONTROL)? & (1 << 13);
                cpu.vmfunc_control = read(VM_FUNCTION_CONTROL)?;
                cpu.vmfunc_list = read(EPTP_LIST_ADDRESS)?;
                cpu.vmfunc_saved = 1;
            }
            // Only two validated roots are admitted. Zero list entries take
            // the VMFUNC exit path and never select an unrelated address space.
            let list = if configuration.cpu_lists[boot.processor_number as usize] != 0 {
                configuration.cpu_lists[boot.processor_number as usize]
            } else {
                configuration.eptp_list
            };
            write(EPTP_LIST_ADDRESS, list)?;
            write(VM_FUNCTION_CONTROL, 1)?;
            write(
                SECONDARY_VM_EXEC_CONTROL,
                read(SECONDARY_VM_EXEC_CONTROL)? | (1 << 13),
            )?;
            cpu.vmfunc_armed = 1;
        } else {
            cpu.vmfunc_armed = 0;
            if cpu.vmfunc_saved != 0 {
                write(
                    SECONDARY_VM_EXEC_CONTROL,
                    (read(SECONDARY_VM_EXEC_CONTROL)? & !(1 << 13)) | cpu.vmfunc_secondary,
                )?;
                write(VM_FUNCTION_CONTROL, cpu.vmfunc_control)?;
                write(EPTP_LIST_ADDRESS, cpu.vmfunc_list)?;
                cpu.vmfunc_saved = 0;
            }
        }
        Ok(())
    }

    fn observe_exit(
        session: &Session,
        boot: &mut ResidentBootContext,
        synchronize: Synchronize,
    ) -> Result<(), ()> {
        if boot.nested.l2_active != 0 {
            return Ok(());
        }
        if boot.processor_number >= 64 {
            return Err(());
        }
        // Revocation can restore DRs before dispatch sees the queued #DB.
        // Capture ownership per CPU before lease checks or barrier callbacks.
        session.exit_debug[boot.processor_number as usize]
            .store(boot.interception.debug_armed, Ordering::Release);
        boot.interception.exit_timer = boot.interception.timer_armed;
        if boot.interception.data_pending != 0 && read(GUEST_RIP)? != boot.interception.data_rip {
            boot.interception.data_pending = 0;
        }
        if boot.interception.vmfunc_armed != 0 {
            // VMFUNC changes EPTP without visiting the dispatcher. Snapshot it
            // before a peer's barrier can remove or rebuild the scoped roots.
            let selected = read(EPT_POINTER)?;
            let configuration = unsafe { &*session.configuration.get() };
            let cpu = &mut boot.interception;
            cpu.exit_ept = selected;
            cpu.applied_ept = if selected == boot.cache_ept_pointer {
                0
            } else {
                selected
            };
            if cpu.step_active == 0 {
                cpu.cooperative_data = u64::from(
                    selected == data_root(configuration, boot.processor_number as usize)
                        && cpu.hook_token == configuration.token
                        && cpu.hook_generation == configuration.generation,
                );
                cpu.cooperative_cr3 = read(GUEST_CR3)? & MASK;
            }
        }
        // Synchronization NMIs can bypass L1 dispatch. Close every MTF window
        // before root handlers or barrier polling run, including those exits.
        finish_step(session, boot, synchronize)?;
        if session.is_active() && expired(session, clock()) {
            session
                .cause
                .store(u64::from(INTERCEPT_CAUSE_LEASE), Ordering::Release);
            revoke(session, boot, synchronize)?;
        }
        Ok(())
    }

    fn revoke(
        session: &Session,
        boot: &mut ResidentBootContext,
        synchronize: Synchronize,
    ) -> Result<(), ()> {
        finish_step(session, boot, synchronize)?;
        let acquired = unsafe { synchronize(boot as *mut _ as u64, 0) } != 0;
        session
            .active
            .store(u64::from(INTERCEPT_REVOKED), Ordering::Release);
        let configuration = unsafe { &*session.configuration.get() };
        boot.interception.cooperative_data = 0;
        boot.interception.data_pending = 0;
        for pointer in configuration.base_leaves[..configuration.hook_count].iter().filter(|pointer| **pointer != 0) {
            entry_bits(*pointer, 2, 0);
        }
        let mut result = Ok(());
        for outcome in [
            configure_vmfunc(boot, configuration, false),
            configure_timing(boot, false),
            configure_timer(session, boot, false),
            restore_debug(&mut boot.interception),
            base(boot),
            invalidate(boot.cache_ept_pointer),
        ] {
            if outcome.is_err() {
                result = Err(());
            }
        }
        // Revocation never reuses storage. A competing barrier owner can park
        // this CPU at its entry gate after the local view has been retired.
        if acquired {
            unsafe {
                synchronize(boot as *mut _ as u64, 1);
                synchronize(boot as *mut _ as u64, 2);
            }
        }
        result
    }

    fn apply(
        session: &Session,
        boot: &mut ResidentBootContext,
        synchronize: Synchronize,
    ) -> Result<(), ()> {
        if boot.nested.l2_active != 0 {
            return Ok(());
        }
        restore_debug(&mut boot.interception)?;
        if session.is_active() && expired(session, clock()) {
            session
                .cause
                .store(u64::from(INTERCEPT_CAUSE_LEASE), Ordering::Release);
            revoke(session, boot, synchronize)?;
        }
        let active = session.is_active() && boot.nested.active == 0;
        if !session.is_active() {
            // Another CPU may revoke while a rendezvous is already owned. Each
            // returning CPU restores guards before invalidating its base view.
            let configuration = unsafe { &*session.configuration.get() };
            for pointer in configuration.base_leaves[..configuration.hook_count].iter().filter(|pointer| **pointer != 0) {
                entry_bits(*pointer, 2, 0);
            }
        }
        configure_timer(session, boot, active)?;
        configure_timing(
            boot,
            active && unsafe { &*session.configuration.get() }.timing != 0,
        )?;
        let primary = read(CPU_BASED_VM_EXEC_CONTROL)?;
        let exceptions = read(EXCEPTION_BITMAP)?;
        let cpu = &mut boot.interception;
        if active && cpu.controls_saved == 0 {
            let cache = unsafe { &mut (*session.cr3_targets.get())[boot.processor_number as usize] };
            for (index, saved) in cache.saved.iter_mut().enumerate() {
                *saved = read(0x6008 + index as u64 * 2)?;
            }
            cache.count = 0;
            cache.generation = 0;
            cpu.primary_bits = primary & PRIMARY_BITS;
            cpu.exception_bit = exceptions & 2;
            cpu.controls_saved = 1;
            cpu.cr3_target_count = read(CR3_TARGET_COUNT)?;
        }
        if cpu.controls_saved != 0 {
            write(
                CR3_TARGET_COUNT,
                if active { 0 } else { cpu.cr3_target_count },
            )?;
            let configuration = unsafe { &*session.configuration.get() };
            let mut bits = cpu.primary_bits;
            let mut exception_bit = cpu.exception_bit;
            if active {
                bits |= 1 << 15;
                if configuration.debug_count != 0 {
                    bits |= 1 << 23;
                    exception_bit |= 2;
                }
                if cpu.step_active != 0 {
                    bits |= 1 << 27;
                }
            }
            write(CPU_BASED_VM_EXEC_CONTROL, (primary & !PRIMARY_BITS) | bits)?;
            write(EXCEPTION_BITMAP, (exceptions & !2) | exception_bit)?;
            if !active {
                let cache = unsafe { &(*session.cr3_targets.get())[boot.processor_number as usize] };
                for (index, saved) in cache.saved.iter().enumerate() {
                    write(0x6008 + index as u64 * 2, *saved)?;
                }
                invalidate(boot.cache_ept_pointer)?;
                cpu.controls_saved = 0;
            }
        }
        let configuration = unsafe { &*session.configuration.get() };
        if boot.processor_number >= 64 {
            return Err(());
        }
        if active && configuration.cpu_mask & (1u64 << boot.processor_number) == 0 {
            return Err(());
        }
        let cr3 = read(GUEST_CR3)? & MASK;
        let target =
            active && root_matches(configuration, cr3) && read(GUEST_IA32_EFER)? & 0x400 != 0;
        let native = target && configuration.hook_count != 0 && configuration.vmfunc != 0;
        let persistent = target && configuration.options & INTERCEPT_PERSISTENT_DATA != 0;
        if !(native || persistent)
            || cpu.cooperative_cr3 != cr3
            || cpu.hook_token != configuration.token
            || cpu.hook_generation != configuration.generation
        {
            cpu.cooperative_data = 0;
            cpu.data_pending = 0;
        }
        let selected = if active {
            let configuration = unsafe { &*session.configuration.get() };
            if configuration.hook_count != 0 {
                cpu.hook_pages = configuration.pages;
                cpu.hook_count = configuration.hook_count;
                cpu.hook_token = configuration.token;
                cpu.hook_generation = configuration.generation;
            }
            let syscall = unsafe { &*session.syscall.get() };
            if target && syscall.entry != 0 && syscall.token == configuration.token
                && syscall_gate(&cpu.guest_debug) && cpu.guest_debug[5] & 0x2003 == 0
                && syscall_msrs()[1] == syscall.entry
                && read(GUEST_CR4)? & ((1 << 12) | (1 << 23)) == 0
            {
                let mut registers: [u64; 5] = cpu.guest_debug[..5].try_into().map_err(|_| ())?;
                registers[0] = syscall.entry;
                registers[4] &= !1;
                load_debug(&registers);
                write(GUEST_DR7, (cpu.guest_debug[5] & !0x000f_0003) | 2)?;
                cpu.debug_targets[0] = [syscall.entry, syscall.callback];
                cpu.debug_targets[3] = [syscall.entry, u64::MAX];
                cpu.debug_armed = 1;
                cpu.debug_count = 1;
                cpu.debug_token = configuration.token;
                cpu.debug_generation = configuration.generation;
            } else if target && syscall.entry == 0 && configuration.debug_count != 0 && cpu.guest_debug[5] & 0x20ff == 0 {
                // Existing guest breakpoints and general-detect own their registers.
                // Suspend our overlay until the guest releases those resources.
                let mut registers = [0; 5];
                let mut dr7 = 0x400;
                cpu.debug_targets.fill([0; 2]);
                for (index, debug) in configuration.debug[..configuration.debug_count]
                    .iter()
                    .enumerate()
                {
                    registers[index] = debug.address;
                    cpu.debug_targets[index] = [debug.address, debug.redirect];
                    dr7 |= 2 << (index * 2);
                }
                registers[4] = cpu.guest_debug[4] & !15;
                load_debug(&registers);
                write(GUEST_DR7, dr7)?;
                cpu.debug_armed = 1;
                cpu.debug_count = configuration.debug_count;
                cpu.debug_token = configuration.token;
                cpu.debug_generation = configuration.generation;
            }
            if cpu.step_active != 0 && cpu.step_cr3 == cr3 && configuration.hook_count != 0 {
                data_root(configuration, boot.processor_number as usize)
            } else if (native || persistent) && cpu.cooperative_data != 0 {
                data_root(configuration, boot.processor_number as usize)
            } else if target && configuration.hook_count != 0 {
                configuration.ept
            } else {
                boot.cache_ept_pointer
            }
        } else {
            boot.cache_ept_pointer
        };
        configure_vmfunc(
            boot,
            configuration,
            native && boot.interception.step_active == 0,
        )?;
        if read(EPT_POINTER)? != selected {
            write(EPT_POINTER, selected)?;
            if boot.telemetry_active != 0 {
                boot.eptp_switches += 1;
            }
        }
        boot.interception.applied_ept = if selected == boot.cache_ept_pointer {
            0
        } else {
            selected
        };
        if active {
            configure_cr3_targets(session, boot, configuration, selected, target)?;
        }
        Ok(())
    }

    fn configure_cr3_targets(
        session: &Session,
        boot: &ResidentBootContext,
        configuration: &RoadEptProfile,
        selected: u64,
        target: bool,
    ) -> Result<(), ()> {
        // Cache exact CR3 values only when a load cannot change the EPT view.
        // PCID aliases are learned independently. VMFUNC and data windows still
        // require every CR3 exit because a reload clears their cooperative view.
        let capacity = ((boot.nested.host_misc >> 16) & 0x1ff).min(4) as usize;
        if capacity == 0 || boot.interception.step_active != 0
            || boot.interception.cooperative_data != 0 || configuration.vmfunc != 0
        {
            return Ok(());
        }
        let cache = unsafe { &mut (*session.cr3_targets.get())[boot.processor_number as usize] };
        let cr3 = read(GUEST_CR3)?;
        if cache.token != configuration.token || cache.generation != configuration.generation {
            cache.count = 0;
            cache.cursor = 0;
            cache.token = configuration.token;
            cache.generation = configuration.generation;
        }
        if target {
            // Do not mix scoped roots with the background cache.
            write(0x6008, cr3)?;
            write(CR3_TARGET_COUNT, 1)?;
        } else if selected == boot.cache_ept_pointer {
            if !cache.cached[..cache.count].contains(&cr3) {
                let index = if cache.count < capacity {
                    let index = cache.count;
                    cache.count += 1;
                    index
                } else {
                    let index = cache.cursor;
                    cache.cursor = (cache.cursor + 1) % capacity;
                    index
                };
                cache.cached[index] = cr3;
            }
            for (index, value) in cache.cached[..cache.count].iter().enumerate() {
                write(0x6008 + index as u64 * 2, *value)?;
            }
            write(CR3_TARGET_COUNT, cache.count as u64)?;
        }
        Ok(())
    }

    fn cr3_write(boot: &mut ResidentBootContext, frame: &mut [u64]) -> Result<u64, ()> {
        let qualification = boot.last_qualification;
        if qualification & 0x3f != 3 {
            return Ok(0);
        }
        if read(GUEST_SS_AR_BYTES)? & 0x60 != 0 {
            return Ok(3);
        }
        let register = ((qualification >> 8) & 15) as usize;
        let offsets = [0, 1, 2, 3, 0, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let value = if register == 4 {
            read(GUEST_RSP)?
        } else {
            frame[offsets[register]]
        };
        let physical_bits = crate::arch::leaf(0x8000_0008).eax & 255;
        let pcid = read(GUEST_CR4)? & (1 << 17) != 0;
        let no_flush = pcid && value >> 63 != 0;
        let allowed =
            ((1u64 << physical_bits) - 1) & !4095 | if pcid { 4095 | (1 << 63) } else { 0x18 };
        if value & !allowed != 0 {
            return Ok(3);
        }
        write(GUEST_CR3, value & !(1 << 63))?;
        if !no_flush && read(SECONDARY_VM_EXEC_CONTROL)? & (1 << 5) != 0 {
            #[repr(C, align(16))]
            struct Descriptor([u64; 2]);
            let descriptor = Descriptor([read(VIRTUAL_PROCESSOR_ID)?, 0]);
            let failed: u8;
            unsafe {
                core::arch::asm!("invvpid {kind}, [{descriptor}]", "setna {failed}",
                    kind = in(reg) 1u64, descriptor = in(reg) &descriptor,
                    failed = lateout(reg_byte) failed, options(nostack));
            }
            if failed != 0 {
                return Err(());
            }
        }
        Ok(2)
    }

    fn debug_access(boot: &mut ResidentBootContext, frame: &mut [u64]) -> Result<u64, ()> {
        if read(GUEST_SS_AR_BYTES)? & 0x60 != 0 {
            return Ok(3);
        }
        let qualification = boot.last_qualification;
        let mut register = (qualification & 7) as usize;
        if boot.interception.guest_debug[5] & (1 << 13) != 0 {
            boot.interception.guest_debug[5] &= !(1 << 13);
            boot.interception.guest_debug[4] |= 1 << 13;
            write(GUEST_DR7, boot.interception.guest_debug[5])?;
            load_debug(
                boot.interception.guest_debug[..5]
                    .try_into()
                    .map_err(|_| ())?,
            );
            write(VM_ENTRY_INTR_INFO_FIELD, 0x80000301)?;
            return Ok(1);
        }
        if register == 4 || register == 5 {
            if read(GUEST_CR4)? & 8 != 0 {
                return Ok(4);
            }
            register += 2;
        }
        let debug_index = if register < 4 { register } else { register - 2 };
        let gpr = ((qualification >> 8) & 15) as usize;
        let offsets = [0, 1, 2, 3, 0, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let long_mode =
            read(GUEST_IA32_EFER)? & 0x400 != 0 && read(GUEST_CS_AR_BYTES)? & 0x2000 != 0;
        if qualification & 16 != 0 {
            let value = boot.interception.guest_debug[debug_index];
            let value = if long_mode {
                value
            } else {
                value as u32 as u64
            };
            if gpr == 4 {
                write(GUEST_RSP, value)?;
            } else {
                frame[offsets[gpr]] = value;
            }
        } else {
            let value = if gpr == 4 {
                read(GUEST_RSP)?
            } else {
                frame[offsets[gpr]]
            };
            let value = if long_mode {
                value
            } else {
                value as u32 as u64
            };
            if register >= 6 && value >> 32 != 0
                || register < 4 && long_mode && !canonical(value, read(GUEST_CR4)? & (1 << 12) != 0)
            {
                return Ok(3);
            }
            boot.interception.guest_debug[debug_index] = if register == 7 {
                (value & 0xffff_2bff) | 0x400
            } else {
                value
            };
            if register == 7 {
                write(GUEST_DR7, boot.interception.guest_debug[5])?;
            } else {
                load_debug(
                    boot.interception.guest_debug[..5]
                        .try_into()
                        .map_err(|_| ())?,
                );
            }
        }
        Ok(2)
    }

    fn fetch_instruction(
        boot: &ResidentBootContext,
        configuration: &RoadEptProfile,
        rip: u64,
        execution: &mut [u8; 15],
        original: &mut [u8; 15],
    ) -> usize {
        crate::memory::access::resident::instruction_bytes(
            boot,
            configuration,
            rip,
            execution,
            original,
        )
    }

    fn original_value(address: u64, width: usize, value: Option<u64>) -> u64 {
        if address as usize % width == 0 {
            // Match aligned x86 scalar-load atomicity when peers are running.
            // A byte-at-a-time emulated load could tear across a concurrent store.
            unsafe {
                if let Some(value) = value {
                    match width {
                        1 => (address as *mut u8).write_volatile(value as u8),
                        2 => (address as *mut u16).write_volatile(value as u16),
                        4 => (address as *mut u32).write_volatile(value as u32),
                        8 => (address as *mut u64).write_volatile(value),
                        _ => return 0,
                    }
                }
                return match width {
                    1 => u64::from((address as *const u8).read_volatile()),
                    2 => u64::from((address as *const u16).read_volatile()),
                    4 => u64::from((address as *const u32).read_volatile()),
                    8 => (address as *const u64).read_volatile(),
                    _ => 0,
                };
            }
        }
        let mut bytes = [0; 8];
        for (index, byte) in bytes[..width].iter_mut().enumerate() {
            let pointer = (address + index as u64) as *mut u8;
            unsafe {
                if let Some(value) = value {
                    pointer.write_volatile((value >> (index * 8)) as u8);
                }
                *byte = pointer.read_volatile();
            }
        }
        u64::from_le_bytes(bytes)
    }

    fn refresh_shared_data(session: &Session) {
        let configuration = unsafe { &*session.configuration.get() };
        if configuration.options & INTERCEPT_PRIVATE_SHARED_DATA == 0
            || lock_refresh(session).is_err()
        {
            return;
        }
        let Some(index) = configuration.base_leaves[..configuration.hook_count].iter().position(|pointer| *pointer == 0) else {
            session.refresh_lock.store(0, Ordering::Release);
            return;
        };
        let source = configuration.pages[index];
        let destination = bank_base(configuration) + (INTERCEPT_TABLE_PAGES + index) as u64 * 4096;
        for offset in [0x8, 0x14, 0x320] {
            // KSYSTEM_TIME readers compare High1Time and High2Time. Publish
            // High2Time first and High1Time last using aligned scalar stores.
            for _ in 0..8 {
                let high = original_value(source + offset + 4, 4, None);
                let low = original_value(source + offset, 4, None);
                if high == original_value(source + offset + 8, 4, None) {
                    original_value(destination + offset + 8, 4, Some(high));
                    original_value(destination + offset, 4, Some(low));
                    original_value(destination + offset + 4, 4, Some(high));
                    break;
                }
            }
        }
        for (offset, width) in [(0x2e4, 4), (0x340, 8), (0x348, 8), (0x350, 8)] {
            let source_offset = if offset == 0x350 { 0x348 } else { offset };
            let value = original_value(source + source_offset, width, None);
            original_value(destination + offset, width, Some(value));
        }
        session.refresh_lock.store(0, Ordering::Release);
    }

    fn register_location(reg: yaxpeax_x86::long_mode::RegSpec) -> Option<(usize, usize, u32)> {
        use yaxpeax_x86::long_mode::register_class as class;
        let kind = reg.class();
        if ![class::Q, class::D, class::W, class::B, class::RB].contains(&kind) {
            return None;
        }
        let mut number = usize::from(reg.num());
        let shift = if kind == class::B && number >= 4 {
            number -= 4;
            8
        } else {
            0
        };
        (number < 16).then_some((number, usize::from(reg.width()), shift))
    }

    fn register_value(frame: &[u64], reg: yaxpeax_x86::long_mode::RegSpec) -> Result<u64, ()> {
        use yaxpeax_x86::long_mode::register_class as class;
        if reg.class() == class::RIP || reg.class() == class::EIP {
            return read(GUEST_RIP);
        }
        let (number, width, shift) = register_location(reg).ok_or(())?;
        let value = if number == 4 {
            read(GUEST_RSP)?
        } else {
            frame[[0, 1, 2, 3, 0, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14][number]]
        };
        Ok((value >> shift) & (u64::MAX >> (64 - width * 8)))
    }

    fn set_register(
        frame: &mut [u64],
        reg: yaxpeax_x86::long_mode::RegSpec,
        value: u64,
    ) -> Result<(), ()> {
        let (number, width, shift) = register_location(reg).ok_or(())?;
        let index = [0, 1, 2, 3, 0, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14][number];
        let old = if number == 4 {
            read(GUEST_RSP)?
        } else {
            frame[index]
        };
        let mask = u64::MAX >> (64 - width * 8);
        let result = if width >= 4 {
            value & mask
        } else {
            (old & !(mask << shift)) | ((value & mask) << shift)
        };
        if number == 4 {
            write(GUEST_RSP, result)
        } else {
            frame[index] = result;
            Ok(())
        }
    }

    fn effective_address(
        frame: &[u64],
        instruction: &yaxpeax_x86::long_mode::Instruction,
        operand_index: u8,
        length: u64,
    ) -> Result<u64, ()> {
        use yaxpeax_x86::long_mode::{Operand, Segment, register_class as class};
        let register = |reg: yaxpeax_x86::long_mode::RegSpec| -> Result<u64, ()> {
            let value = register_value(frame, reg)?;
            Ok(if [class::RIP, class::EIP].contains(&reg.class()) {
                value.wrapping_add(length)
            } else {
                value
            })
        };
        let mut address = match instruction.operand(operand_index) {
            Operand::AbsoluteU32 { addr } => u64::from(addr),
            Operand::AbsoluteU64 { addr } => addr,
            Operand::MemDeref { base } => register(base)?,
            Operand::Disp { base, disp } => register(base)?.wrapping_add(disp as u64),
            Operand::MemIndexScale { index, scale } => {
                register(index)?.wrapping_mul(u64::from(scale))
            }
            Operand::MemIndexScaleDisp { index, scale, disp } => register(index)?
                .wrapping_mul(u64::from(scale))
                .wrapping_add(disp as u64),
            Operand::MemBaseIndexScale { base, index, scale } => {
                register(base)?.wrapping_add(register(index)?.wrapping_mul(u64::from(scale)))
            }
            Operand::MemBaseIndexScaleDisp {
                base,
                index,
                scale,
                disp,
            } => register(base)?
                .wrapping_add(register(index)?.wrapping_mul(u64::from(scale)))
                .wrapping_add(disp as u64),
            _ => return Err(()),
        };
        if instruction.prefixes.address_size() {
            address &= u64::from(u32::MAX);
        }
        address = address.wrapping_add(match instruction.segment_override_for_op(operand_index) {
            Some(Segment::FS) => read(GUEST_FS_BASE)?,
            Some(Segment::GS) => read(GUEST_GS_BASE)?,
            _ => 0,
        });
        Ok(address)
    }

    fn immediate(operand: yaxpeax_x86::long_mode::Operand) -> Option<u64> {
        use yaxpeax_x86::long_mode::Operand;
        Some(match operand {
            Operand::ImmediateI8 { imm } => imm as u64,
            Operand::ImmediateU8 { imm } => u64::from(imm),
            Operand::ImmediateI16 { imm } => imm as u64,
            Operand::ImmediateU16 { imm } => u64::from(imm),
            Operand::ImmediateI32 { imm } => imm as u64,
            Operand::ImmediateU32 { imm } => u64::from(imm),
            Operand::ImmediateI64 { imm } => imm as u64,
            Operand::ImmediateU64 { imm } => imm,
            _ => return None,
        })
    }

    // Emulate scalar patched instructions against the GPA already translated by
    // hardware. No speculative guest walks, partial cross-page writes or MMIO.
    fn emulate_mixed(
        boot: &ResidentBootContext,
        frame: &mut [u64],
        instruction: &yaxpeax_x86::long_mode::Instruction,
        length: u64,
    ) -> Result<bool, ()> {
        use yaxpeax_x86::long_mode::{Opcode, Operand};
        let opcode = instruction.opcode();
        if instruction.operand_count() != 2
            || instruction.prefixes.lock()
            || instruction.prefixes.rep_any()
            || read(GUEST_RFLAGS)? & 0x100 != 0
            || read(GUEST_DR7)? & 0xff != 0
            || boot.interception.data_qualification & 0x180 != 0x180
        {
            return Ok(false);
        }
        if !matches!(
            opcode,
            Opcode::MOV
                | Opcode::MOVZX
                | Opcode::MOVSX
                | Opcode::MOVSXD
                | Opcode::ADD
                | Opcode::SUB
                | Opcode::CMP
                | Opcode::AND
                | Opcode::OR
                | Opcode::XOR
                | Opcode::TEST
        ) {
            return Ok(false);
        }
        let left = instruction.operand(0);
        let right = instruction.operand(1);
        let memory_index = if left.is_memory() && !right.is_memory() {
            0
        } else if right.is_memory() && !left.is_memory() {
            1
        } else {
            return Ok(false);
        };
        let Some(size) = instruction.mem_size() else {
            return Ok(false);
        };
        let Some(width) = size.bytes_size() else {
            return Ok(false);
        };
        let width = usize::from(width);
        if ![1, 2, 4, 8].contains(&width) {
            return Ok(false);
        }
        let address = boot.interception.data_address;
        if width > 4096 - (address as usize & 4095)
            || effective_address(frame, instruction, memory_index, length).ok()
                != Some(boot.interception.data_linear)
        {
            return Ok(false);
        }
        if read(GUEST_CS_AR_BYTES)? & 0x2000 == 0 {
            return Ok(false);
        }
        let mask = u64::MAX >> (64 - width * 8);
        let mut flags = read(GUEST_RFLAGS)?;
        let memory = original_value(address, width, None);
        let operand_value = |operand: &Operand| -> Result<u64, ()> {
            if operand.is_memory() {
                Ok(memory)
            } else if let Operand::Register { reg } = operand {
                register_value(frame, *reg)
            } else {
                immediate(operand.clone()).ok_or(())
            }
        };
        let a = match operand_value(&left) {
            Ok(value) => value & mask,
            Err(()) => return Ok(false),
        };
        let b = match operand_value(&right) {
            Ok(value) => value & mask,
            Err(()) => return Ok(false),
        };
        // Reject non-GPR destinations before writing any architectural state.
        if let Operand::Register { reg } = &left {
            if register_location(*reg).is_none() {
                return Ok(false);
            }
        }
        let sign = 1u64 << (width * 8 - 1);
        let result = match opcode {
            Opcode::MOV | Opcode::MOVZX => b,
            Opcode::MOVSX | Opcode::MOVSXD => {
                ((b << (64 - width * 8)) as i64 >> (64 - width * 8)) as u64
            }
            Opcode::ADD => a.wrapping_add(b) & mask,
            Opcode::SUB | Opcode::CMP => a.wrapping_sub(b) & mask,
            Opcode::AND | Opcode::TEST => a & b,
            Opcode::OR => a | b,
            Opcode::XOR => a ^ b,
            _ => return Ok(false),
        };
        if !matches!(
            opcode,
            Opcode::MOV | Opcode::MOVZX | Opcode::MOVSX | Opcode::MOVSXD
        ) {
            flags &= !0x8d5;
            if result == 0 {
                flags |= 0x40;
            }
            if result & sign != 0 {
                flags |= 0x80;
            }
            if (result as u8).count_ones().is_multiple_of(2) {
                flags |= 4;
            }
            if matches!(opcode, Opcode::ADD | Opcode::SUB | Opcode::CMP) {
                if (a ^ b ^ result) & 0x10 != 0 {
                    flags |= 0x10;
                }
                let carry = if opcode == Opcode::ADD {
                    (a as u128 + b as u128) > mask as u128
                } else {
                    a < b
                };
                if carry {
                    flags |= 1;
                }
                let overflow = if opcode == Opcode::ADD {
                    !(a ^ b) & (a ^ result)
                } else {
                    (a ^ b) & (a ^ result)
                };
                if overflow & sign != 0 {
                    flags |= 0x800;
                }
            }
        }
        if !matches!(opcode, Opcode::CMP | Opcode::TEST) {
            if memory_index == 0 {
                if boot.interception.data_qualification & 2 == 0 {
                    return Ok(false);
                }
                original_value(address, width, Some(result));
            } else if let Operand::Register { reg } = left {
                set_register(frame, reg, result)?;
            } else {
                return Ok(false);
            }
        }
        write(GUEST_RFLAGS, flags & !0x10000)?;
        write(
            GUEST_INTERRUPTIBILITY_INFO,
            read(GUEST_INTERRUPTIBILITY_INFO)? & !3,
        )?;
        write(GUEST_RIP, read(GUEST_RIP)?.wrapping_add(length))?;
        Ok(true)
    }

    fn emulate_scalar_read(
        boot: &mut ResidentBootContext,
        configuration: &RoadEptProfile,
        frame: &mut [u64],
    ) -> Result<bool, ()> {
        use yaxpeax_arch::LengthedInstruction;
        use yaxpeax_x86::long_mode::{InstDecoder, Opcode, Operand};
        if boot.interception.data_qualification & 7 != 1
            || read(GUEST_CS_AR_BYTES)? & 0x2000 == 0
        {
            return Ok(false);
        }
        let mut execution = [0; 15];
        let mut original = [0; 15];
        let rip = read(GUEST_RIP)?;
        let count = fetch_instruction(boot, configuration, rip, &mut execution, &mut original);
        let Ok(instruction) = InstDecoder::default().decode_slice(&execution[..count]) else {
            return Ok(false);
        };
        if !matches!(instruction.opcode(), Opcode::MOV | Opcode::MOVZX | Opcode::MOVSX | Opcode::MOVSXD)
            || !matches!(instruction.operand(0), Operand::Register { .. })
            || !instruction.operand(1).is_memory()
        {
            return Ok(false);
        }
        let Some(width) = instruction.mem_size().and_then(|size| size.bytes_size()) else {
            return Ok(false);
        };
        if ![1, 2, 4, 8].contains(&width)
            || boot.interception.data_address % u64::from(width) != 0
        {
            return Ok(false);
        }
        // A scalar load has no shared EPT mutation and requires no parked peer,
        // refresh merge, or guest MTF instruction window.
        if emulate_mixed(boot, frame, &instruction, instruction.len().to_const() as u64)? {
            boot.interception.cooperative_data = 0;
            boot.interception.data_pending = 0;
            return Ok(true);
        }
        Ok(false)
    }

    fn mixed_access(
        session: &Session,
        boot: &mut ResidentBootContext,
        frame: &mut [u64],
        synchronize: Synchronize,
    ) -> Result<u64, ()> {
        use yaxpeax_arch::LengthedInstruction;
        // Shared roots park peers; private roots own refresh serialization across
        // the instruction window so original data and snapshots remain stable.
        let configuration = unsafe { &*session.configuration.get() };
        if emulate_scalar_read(boot, configuration, frame)? {
            return Ok(1);
        }
        let mut execution = [0; 15];
        let mut original = [0; 15];
        let access = read(GUEST_CS_AR_BYTES)?;
        let rip = read(GUEST_RIP)?;
        let linear = if access & 0x2000 != 0 {
            rip
        } else {
            read(GUEST_CS_BASE)?.wrapping_add(rip)
        };
        let count = fetch_instruction(boot, configuration, linear, &mut execution, &mut original);
        let length = if access & 0x2000 != 0 {
            yaxpeax_x86::long_mode::InstDecoder::default()
                .decode_slice(&execution[..count])
                .ok()
                .map(|instruction| instruction.len().to_const() as usize)
        } else if access & 0x4000 != 0 {
            yaxpeax_x86::protected_mode::InstDecoder::default()
                .decode_slice(&execution[..count])
                .ok()
                .map(|instruction| instruction.len().to_const() as usize)
        } else {
            yaxpeax_x86::real_mode::InstDecoder::default()
                .decode_slice(&execution[..count])
                .ok()
                .map(|instruction| instruction.len().to_const() as usize)
        };
        if let Some(length) = length {
            let private = configuration.cpu_data[boot.processor_number as usize];
            if access & 0x2000 != 0
                && private != 0
                && private != configuration.data_ept
                && boot.interception.data_qualification & 7 == 1
                && execution[..length] == original[..length]
            {
                use yaxpeax_x86::long_mode::{InstDecoder, Opcode, Operand};
                if let Ok(instruction) = InstDecoder::default().decode_slice(&execution[..count]) {
                    if !instruction.prefixes.lock()
                        && !instruction.prefixes.rep_any()
                        && matches!(instruction.operand(0), Operand::Register { .. })
                        && instruction.operand(1).is_memory()
                        && matches!(instruction.opcode(), Opcode::MOV | Opcode::MOVZX | Opcode::MOVSX
                            | Opcode::MOVSXD | Opcode::ADD | Opcode::SUB | Opcode::CMP
                            | Opcode::AND | Opcode::OR | Opcode::XOR | Opcode::TEST)
                    {
                        // Execute exactly one unchanged, read-only instruction on
                        // this CPU's original view. Peers keep the patched view.
                        for pointer in data_leaves(configuration, boot.processor_number as usize) {
                            entry_bits(*pointer, 4, 2);
                        }
                        boot.interception.step_active = 4;
                        boot.interception.step_cr3 = read(GUEST_CR3)? & MASK;
                        boot.interception.cooperative_data = 0;
                        boot.interception.data_pending = 0;
                        invalidate(private)?;
                        return Ok(1);
                    }
                }
            }
        }
        let concurrent = configuration.options & INTERCEPT_CONCURRENT_WRITES != 0;
        if !concurrent && unsafe { synchronize(boot as *mut _ as u64, 0) } == 0 {
            session.cause.store(u64::from(INTERCEPT_CAUSE_RENDEZVOUS), Ordering::Release);
            revoke(session, boot, synchronize)?;
            return Ok(1);
        }
        if concurrent {
            if lock_refresh(session).is_err() {
                session.cause.store(u64::from(INTERCEPT_CAUSE_RENDEZVOUS), Ordering::Release);
                revoke(session, boot, synchronize)?;
                return Ok(1);
            }
            boot.interception.refresh_owned = 1;
        }
        boot.interception.step_active = 3;
        if let Some(length) = length {
            if execution[..length] == original[..length] {
                for pointer in data_leaves(configuration, boot.processor_number as usize) {
                    entry_bits(*pointer, 6, 0);
                }
                boot.interception.step_active = 3;
                invalidate(data_root(configuration, boot.processor_number as usize))?;
                boot.interception.step_cr3 = read(GUEST_CR3)? & MASK;
                session.write_windows.fetch_add(1, Ordering::Relaxed);
                return Ok(1);
            }
            if access & 0x2000 != 0 {
                if let Ok(instruction) =
                    yaxpeax_x86::long_mode::InstDecoder::default().decode_slice(&execution[..count])
                {
                    if emulate_mixed(boot, frame, &instruction, length as u64)? {
                        if refresh(configuration).is_err() {
                            session
                                .cause
                                .store(u64::from(INTERCEPT_CAUSE_MERGE), Ordering::Release);
                            session
                                .active
                                .store(u64::from(INTERCEPT_REVOKED), Ordering::Release);
                        }
                        release_refresh(session, boot);
                        reset_step(boot)?;
                        if !concurrent {
                            unsafe {
                                synchronize(boot as *mut _ as u64, 1);
                                synchronize(boot as *mut _ as u64, 2);
                            }
                        }
                        if !session.is_active() {
                            revoke(session, boot, synchronize)?;
                        }
                        return Ok(1);
                    }
                }
            }
        }
        release_refresh(session, boot);
        reset_step(boot)?;
        if !concurrent {
            unsafe {
                synchronize(boot as *mut _ as u64, 2);
            }
        }
        session
            .cause
            .store(u64::from(INTERCEPT_CAUSE_MIXED_ACCESS), Ordering::Release);
        revoke(session, boot, synchronize)?;
        Ok(1)
    }

    fn dispatch(
        session: &Session,
        boot: &mut ResidentBootContext,
        frame: &mut [u64],
        synchronize: Synchronize,
        fx_state: &mut [u8; 512],
    ) -> Result<u64, ()> {
        if boot.processor_number >= 64 {
            return Err(());
        }
        let exit_armed = session.exit_debug[boot.processor_number as usize].swap(0, Ordering::AcqRel);
        let armed = boot.interception.debug_armed != 0 || exit_armed != 0;
        let syscall_armed = armed && boot.interception.debug_count == 1
            && boot.interception.debug_targets[3][1] == u64::MAX;
        restore_debug(&mut boot.interception)?;
        let reason = boot.last_reason & 0xffff;
        let stepped = boot.interception.exit_step != 0;
        finish_step(session, boot, synchronize)?;
        if reason == 10 && session.is_active() && boot.nested.active == 0 {
            let configuration = unsafe { &*session.configuration.get() };
            let profile = unsafe { &*session.cpuid.get() };
            let selector = [frame[0] as u32, frame[1] as u32];
            if profile.records[..profile.count].iter().any(|record| {
                record.leaf == selector[0] && selector[1] & record.subleaf_mask == record.subleaf
            }) && read(GUEST_IA32_EFER)? & 0x400 != 0 {
                let native = core::arch::x86_64::__cpuid_count(selector[0], selector[1]);
                if let Some(values) = cpuid_values(
                    configuration,
                    profile,
                    read(GUEST_CR3)?,
                    read(GUEST_CS_SELECTOR)? & 3,
                    [boot.interception.guest_debug[3], boot.interception.guest_debug[5]],
                    selector,
                    [native.eax, native.ebx, native.ecx, native.edx],
                ) {
                    frame[0] = u64::from(values[0]);
                    frame[3] = u64::from(values[1]);
                    frame[1] = u64::from(values[2]);
                    frame[2] = u64::from(values[3]);
                    session.hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(2);
                }
            }
        }
        if reason == 52 && boot.interception.exit_timer != 0 {
            if session.is_active() {
                refresh_shared_data(session);
            }
            if boot.diagnostic_interval_tsc == 0 {
                return Ok(1);
            }
        }
        if reason == 37 && stepped {
            if boot.telemetry_active != 0 {
                boot.mtf_exits += 1;
            }
            return Ok(1);
        }
        if reason == 48 {
            let gpa = read(GUEST_PHYSICAL_ADDRESS)? & !4095;
            let access = boot.last_qualification & 7;
            if boot.interception.hook_pages[..boot.interception.hook_count].contains(&gpa) {
                let configuration = unsafe { &*session.configuration.get() };
                if !session.is_active()
                    || configuration.hook_count == 0
                    || configuration.token != boot.interception.hook_token
                    || configuration.generation != boot.interception.hook_generation
                {
                    base(boot)?;
                    invalidate(boot.cache_ept_pointer)?;
                    return Ok(1);
                }
                let pending = boot.interception.data_pending != 0
                    && read(GUEST_RIP)? == boot.interception.data_rip;
                if (stepped || pending) && access & 4 != 0 {
                    return mixed_access(session, boot, frame, synchronize);
                }
                if access & 4 != 0 && boot.interception.cooperative_data != 0 {
                    boot.interception.cooperative_data = 0;
                    boot.interception.data_pending = 0;
                    return Ok(1);
                }
                if access & 3 != 0 {
                    boot.interception.data_address = read(GUEST_PHYSICAL_ADDRESS)?;
                    boot.interception.data_linear = read(GUEST_LINEAR_ADDRESS)?;
                    boot.interception.data_qualification = boot.last_qualification;
                    let writing = access & 2 != 0;
                    let concurrent = configuration.options & INTERCEPT_CONCURRENT_WRITES != 0;
                    if !writing && emulate_scalar_read(boot, configuration, frame)? {
                        session.data_exits.fetch_add(1, Ordering::Relaxed);
                        return Ok(1);
                    }
                    if configuration.options & INTERCEPT_PERSISTENT_DATA != 0 {
                        boot.interception.cooperative_data = 1;
                        boot.interception.cooperative_cr3 = read(GUEST_CR3)? & MASK;
                        boot.interception.data_pending = 1;
                        boot.interception.data_rip = read(GUEST_RIP)?;
                    }
                    if writing {
                        if !concurrent && unsafe { synchronize(boot as *mut _ as u64, 0) } == 0 {
                            session
                                .cause
                                .store(u64::from(INTERCEPT_CAUSE_RENDEZVOUS), Ordering::Release);
                            revoke(session, boot, synchronize)?;
                            return Ok(1);
                        }
                        if concurrent {
                            if lock_refresh(session).is_err() {
                                session.cause.store(
                                    u64::from(INTERCEPT_CAUSE_RENDEZVOUS),
                                    Ordering::Release,
                                );
                                revoke(session, boot, synchronize)?;
                                return Ok(1);
                            }
                            boot.interception.refresh_owned = 1;
                        }
                        for pointer in data_leaves(configuration, boot.processor_number as usize) {
                            entry_bits(*pointer, 2, 0);
                        }
                        boot.interception.step_active = 2;
                        invalidate(data_root(configuration, boot.processor_number as usize))?;
                        session.write_windows.fetch_add(1, Ordering::Relaxed);
                    }
                    boot.interception.step_active = if writing {
                        2
                    } else if configuration.options & INTERCEPT_PERSISTENT_DATA != 0 {
                        0
                    } else {
                        1
                    };
                    boot.interception.step_cr3 = read(GUEST_CR3)? & MASK;
                    session.data_exits.fetch_add(1, Ordering::Relaxed);
                    return Ok(1);
                }
            }
        }
        if reason == 28
            && boot.last_qualification & 0x3f == 3
            && boot.interception.controls_saved != 0
        {
            boot.interception.cooperative_data = 0;
            if read(GUEST_IA32_EFER)? & 0x400 == 0 {
                if session.is_active() {
                    revoke(session, boot, synchronize)?;
                }
                return Ok(1);
            }
            return cr3_write(boot, frame);
        }
        if reason == 29 && boot.interception.controls_saved != 0 {
            return debug_access(boot, frame);
        }
        if reason == 59 && boot.interception.exit_vmfunc != 0 {
            let configuration = unsafe { &*session.configuration.get() };
            let function = frame[0] as u32;
            let slot = frame[1] as u32;
            if !session.is_active()
                || configuration.vmfunc == 0
                || boot.interception.hook_token != configuration.token
                || boot.interception.hook_generation != configuration.generation
                || !root_matches(configuration, read(GUEST_CR3)?)
            {
                return Ok(4);
            }
            if function != 0 || !matches!(slot, INTERCEPT_EXECUTE_SLOT | INTERCEPT_DATA_SLOT) {
                return Ok(4);
            }
            boot.interception.cooperative_data = u64::from(slot == INTERCEPT_DATA_SLOT);
            boot.interception.cooperative_cr3 = read(GUEST_CR3)? & MASK;
            return Ok(2);
        }
        if reason == 0 && read(VM_EXIT_INTR_INFO)? & 0x800007ff == 0x80000301 {
            let configuration = unsafe { &*session.configuration.get() };
            let rip = read(GUEST_RIP)?;
            // An intercepted #DB leaves hardware DR6 unchanged. VMX reports
            // breakpoint and single-step causes in the exit qualification.
            let debug_status = boot.last_qualification;
            if armed && debug_status & 0x1e800 == 0 {
                for (index, target) in boot.interception.debug_targets
                    [..boot.interception.debug_count]
                    .iter()
                    .enumerate()
                {
                    if debug_status & (1 << index) != 0 && rip == target[0] {
                        let syscall = unsafe { &*session.syscall.get() };
                        if syscall_armed {
                            // Foreign breakpoint causes still belong to the guest.
                            if debug_status & 14 != 0 {
                                break;
                            }
                            write(GUEST_PENDING_DBG_EXCEPTIONS, read(GUEST_PENDING_DBG_EXCEPTIONS)? & !1)?;
                            if session.is_active() && syscall.token == configuration.token
                                && syscall.entry == target[0] && syscall.callback == target[1]
                                && boot.interception.debug_token == configuration.token
                                && boot.interception.debug_generation == configuration.generation
                                && root_matches(configuration, read(GUEST_CR3)?)
                                && syscall_gate(&boot.interception.guest_debug)
                            {
                                let outcome = route_syscall(syscall, frame, fx_state)?;
                                if outcome == u64::MAX {
                                    session.cause.store(u64::from(INTERCEPT_CAUSE_RUNTIME), Ordering::Release);
                                    session.active.store(u64::from(INTERCEPT_REVOKED), Ordering::Release);
                                } else {
                                    session.hits.fetch_add(1, Ordering::Relaxed);
                                }
                                return Ok(outcome);
                            }
                            write(GUEST_RFLAGS, read(GUEST_RFLAGS)? | (1 << 16))?;
                            return Ok(1);
                        }
                        write(
                            GUEST_PENDING_DBG_EXCEPTIONS,
                            read(GUEST_PENDING_DBG_EXCEPTIONS)? & !15,
                        )?;
                        if session.is_active()
                            && boot.interception.debug_token == configuration.token
                            && boot.interception.debug_generation == configuration.generation
                            && root_matches(configuration, read(GUEST_CR3)?)
                        {
                            write(GUEST_RIP, target[1])?;
                            session.hits.fetch_add(1, Ordering::Relaxed);
                        }
                        return Ok(1);
                    }
                }
            }
            let mut registers: [u64; 5] = boot.interception.guest_debug[..5]
                .try_into()
                .map_err(|_| ())?;
            registers[4] |= debug_status & if syscall_armed { 0xe00e } else if armed { 0xe000 } else { 0xe00f };
            for bit in [11, 16] {
                if debug_status & (1 << bit) != 0 {
                    registers[4] &= !(1 << bit);
                }
            }
            boot.interception.guest_debug[4] = registers[4];
            load_debug(&registers);
        }
        if !session.is_active() {
            return Ok(0);
        }
        if matches!(reason, 19..=27) {
            session
                .cause
                .store(u64::from(INTERCEPT_CAUSE_CONTEXT), Ordering::Release);
            revoke(session, boot, synchronize)?;
            return Ok(0);
        }
        Ok(0)
    }

    fn diagnostic_attempt(boot: &mut ResidentBootContext, phase: usize) {
        if boot.telemetry_active != 0 && phase < INTERCEPT_RUNTIME_PHASES {
            let counter = &mut boot.interception.runtime_diagnostics[phase * 3];
            *counter = counter.wrapping_add(1);
        }
    }

    fn diagnostic_result(boot: &mut ResidentBootContext, phase: usize, succeeded: bool) {
        if boot.telemetry_active != 0 && phase < INTERCEPT_RUNTIME_PHASES {
            let counter = &mut boot.interception.runtime_diagnostics
                [phase * 3 + if succeeded { 1 } else { 2 }];
            *counter = counter.wrapping_add(1);
        }
        if !succeeded {
            let rip = read(GUEST_RIP).unwrap_or(0);
            let gpa = if boot.last_reason & 0xffff == 48 {
                read(GUEST_PHYSICAL_ADDRESS).unwrap_or(0)
            } else {
                0
            };
            let details =
                &mut boot.interception.runtime_diagnostics[INTERCEPT_RUNTIME_PHASES * 3..];
            details.copy_from_slice(&[(phase as u64).saturating_add(1), rip, gpa]);
        }
    }

    pub unsafe extern "efiapi" fn interception_entry(
        boot: *mut ResidentBootContext,
        phase: u64,
        frame: *mut u64,
        synchronize: Synchronize,
        fx_state: *mut u8,
    ) -> u64 {
        let boot = unsafe { &mut *boot };
        let event = unsafe { &*(boot.event_context as *const ResidentEventContext) };
        let session = unsafe { &*(event.interception_context_physical as *const Session) };
        diagnostic_attempt(boot, phase as usize);
        let result = match phase {
            0 => dispatch(
                session,
                boot,
                unsafe { core::slice::from_raw_parts_mut(frame, 15) },
                synchronize,
                unsafe { &mut *fx_state.cast::<[u8; 512]>() },
            ),
            1 => apply(session, boot, synchronize).map(|()| 0),
            2 => {
                let _ = session.cause.compare_exchange(
                    u64::from(INTERCEPT_CAUSE_NONE), u64::from(INTERCEPT_CAUSE_CONTEXT),
                    Ordering::AcqRel, Ordering::Acquire,
                );
                revoke(session, boot, synchronize).map(|()| 0)
            }
            3 => reset_step(boot)
                .and_then(|()| {
                    release_refresh(session, boot);
                    let configuration = unsafe { &*session.configuration.get() };
                    configure_vmfunc(boot, configuration, false)?;
                    boot.interception.cooperative_data = 0;
                    base(boot)
                })
                .and_then(|()| {
                    let configuration = unsafe { &*session.configuration.get() };
                    if configuration.ept != 0 {
                        invalidate(configuration.ept)?;
                    }
                    if configuration.data_ept != 0 {
                        invalidate(configuration.data_ept)?;
                    }
                    if configuration.options & INTERCEPT_CONCURRENT_WRITES != 0 {
                        invalidate(data_root(configuration, boot.processor_number as usize))?;
                    }
                    let epoch = session.split_epoch.load(Ordering::Acquire);
                    if boot.interception.split_flush_epoch.load(Ordering::Relaxed) != epoch {
                        let cpu_index = boot.processor_number as usize;
                        if cpu_index >= 64 || configuration.cpu_mask & (1u64 << cpu_index) == 0 {
                            return Err(());
                        }
                        let cpu_slot = (configuration.cpu_mask & ((1u64 << cpu_index) - 1))
                            .count_ones() as usize;
                        let flags = boot.cache_ept_pointer & !MASK;
                        for bank in 0..2 {
                            let start = configuration.pool_base
                                + (bank * intercept_bank_pages(configuration.cpu_mask)) as u64
                                    * 4096;
                            // VMFUNC and obsolete banks can retain translations
                            // even when they are not the VMCS's selected EPTP.
                            invalidate(start | flags)?;
                            invalidate((start + 4096) | flags)?;
                            let data = start
                                + (INTERCEPT_TABLE_PAGES
                                    + 2 * HOOK_MAX_PAGES
                                    + 1
                                    + cpu_slot * INTERCEPT_CPU_VIEW_PAGES)
                                    as u64
                                    * 4096;
                            invalidate(data | flags)?;
                        }
                        invalidate(boot.cache_ept_pointer)?;
                        // Recovery of a partial flush must not certify retirement.
                        boot.interception
                            .split_flush_epoch
                            .store(epoch, Ordering::Release);
                    }
                    Ok(0)
                }),
            4 => observe_exit(session, boot, synchronize).map(|()| 0),
            5 => compensate_timing(session, boot).map(|()| 0),
            _ => Err(()),
        };
        diagnostic_result(boot, phase as usize, result.as_ref().is_ok_and(|value| *value != u64::MAX));
        match result {
            Ok(value) => value,
            Err(()) => {
                if session.cause.load(Ordering::Acquire) == u64::from(INTERCEPT_CAUSE_NONE) {
                    session
                        .cause
                        .store(u64::from(INTERCEPT_CAUSE_RUNTIME), Ordering::Release);
                }
                session
                    .active
                    .store(u64::from(INTERCEPT_REVOKED), Ordering::Release);
                // Never reenter with a partially configured profile. A VMCS
                // failure is fatal only when restoring the base also fails.
                diagnostic_attempt(boot, 6);
                let retired = revoke(session, boot, synchronize)
                    .and_then(|()| apply(session, boot, synchronize));
                diagnostic_result(boot, 6, retired.is_ok());
                if retired.is_ok() { 0 } else { u64::MAX }
            }
        }
    }
}
