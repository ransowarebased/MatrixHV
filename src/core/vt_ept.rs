extern crate alloc;

use alloc::vec::Vec;
use core::ptr::NonNull;

use uefi::Status;
use uefi::boot;
use uefi::mem::memory_map::{MemoryAttribute, MemoryDescriptor, MemoryMap, MemoryType};

use crate::arch::x86_64::msr;
use crate::memory::resident::{AddressConstraint, PAGE_SIZE, ResidentPages};

const EPT_READ: u64 = 1 << 0;
const EPT_WRITE: u64 = 1 << 1;
const EPT_EXECUTE: u64 = 1 << 2;
const EPT_PERMISSIONS: u64 = EPT_READ | EPT_WRITE | EPT_EXECUTE;
const EPT_LARGE_PAGE: u64 = 1 << 7;
const EPT_MEMORY_TYPE_SHIFT: u64 = 3;
const EPT_PAGE_WALK_LENGTH_SHIFT: u64 = 3;
const EPT_PAGE_WALK_LENGTH_4: u64 = 3;
const EPT_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const EPT_GUEST_PHYSICAL_LIMIT: u64 = 1 << 48;
const EPT_MINIMUM_MAPPED_END: u64 = 1 << 32;
const EPT_2MB_PAGE_SIZE: u64 = 2 * 1024 * 1024;
const EPT_1GB_PAGE_SIZE: u64 = 1024 * 1024 * 1024;
const EPT_512GB_PAGE_SIZE: u64 = 512 * EPT_1GB_PAGE_SIZE;
const EPT_ENTRY_COUNT: usize = 512;
const EPT_PROTECTION_TABLE_PAGES: usize = 128;

const EPT_CAP_PAGE_WALK_LENGTH_4: u64 = 1 << 6;
const EPT_CAP_MEMORY_TYPE_UC: u64 = 1 << 8;
const EPT_CAP_MEMORY_TYPE_WB: u64 = 1 << 14;
const EPT_CAP_2MB_PAGE: u64 = 1 << 16;

#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EptMemoryType {
    Uncacheable = 0,
    WriteCombining = 1,
    WriteThrough = 4,
    WriteBack = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EptError {
    Allocation(Status),
    EmptyMemoryMap,
    InvalidMemoryMap,
    AddressOverflow,
    GuestPhysicalAddressTooWide(u64),
    FourLevelWalkUnavailable,
    UncacheableUnavailable,
    WriteBackUnavailable,
    InvalidProtectionAddress(u64),
    InvalidPageTable,
    ProtectionTableCapacityExceeded,
}

pub struct IdentityEpt {
    pages: Vec<ResidentPages>,
    protection_pool: ProtectionTablePool,
    root: TablePage,
    ept_pointer: u64,
    mapped_end: u64,
}

#[derive(Clone, Copy)]
struct TablePage {
    physical_address: u64,
    entries: NonNull<u64>,
}

struct ProtectionTablePool {
    pages: ResidentPages,
    used_pages: usize,
}

impl ProtectionTablePool {
    fn allocate() -> Result<Self, EptError> {
        let pages = ResidentPages::allocate(EPT_PROTECTION_TABLE_PAGES, AddressConstraint::Any)
            .map_err(EptError::Allocation)?;
        Ok(Self {
            pages,
            used_pages: 0,
        })
    }

    fn allocate_table(&mut self) -> Result<TablePage, EptError> {
        if self.used_pages >= self.pages.pages() {
            return Err(EptError::ProtectionTableCapacityExceeded);
        }
        let page_offset = self.used_pages * PAGE_SIZE;
        self.used_pages += 1;
        let physical_address = self.pages.physical_address() + page_offset as u64;
        let entries = unsafe {
            NonNull::new_unchecked(self.pages.pointer().as_ptr().add(page_offset).cast::<u64>())
        };
        Ok(TablePage {
            physical_address,
            entries,
        })
    }
}

impl IdentityEpt {
    pub fn build() -> Result<Self, EptError> {
        let capabilities = unsafe { msr::read(msr::IA32_VMX_EPT_VPID_CAP) };
        if capabilities & EPT_CAP_PAGE_WALK_LENGTH_4 == 0 {
            return Err(EptError::FourLevelWalkUnavailable);
        }
        if capabilities & EPT_CAP_MEMORY_TYPE_UC == 0 {
            return Err(EptError::UncacheableUnavailable);
        }
        if capabilities & EPT_CAP_MEMORY_TYPE_WB == 0 {
            return Err(EptError::WriteBackUnavailable);
        }
        let large_pages_supported = capabilities & EPT_CAP_2MB_PAGE != 0;
        let protection_pool = ProtectionTablePool::allocate()?;

        let memory_map = boot::memory_map(MemoryType::LOADER_DATA)
            .map_err(|error| EptError::Allocation(error.status()))?;
        let mut descriptors: Vec<MemoryDescriptor> = memory_map.entries().copied().collect();
        drop(memory_map);
        descriptors.retain(|descriptor| descriptor.page_count != 0);
        if descriptors.is_empty() {
            return Err(EptError::EmptyMemoryMap);
        }
        descriptors.sort_unstable_by_key(|descriptor| descriptor.phys_start);

        let mut previous_end = 0_u64;
        let mut maximum_end = 0_u64;
        for descriptor in &descriptors {
            let byte_len = descriptor
                .page_count
                .checked_mul(PAGE_SIZE as u64)
                .ok_or(EptError::AddressOverflow)?;
            let descriptor_end = descriptor
                .phys_start
                .checked_add(byte_len)
                .ok_or(EptError::AddressOverflow)?;
            if descriptor.phys_start < previous_end {
                return Err(EptError::InvalidMemoryMap);
            }
            previous_end = descriptor_end;
            maximum_end = maximum_end.max(descriptor_end);
        }

        let mapped_end = align_up(maximum_end.max(EPT_MINIMUM_MAPPED_END), EPT_2MB_PAGE_SIZE)?;
        if mapped_end > EPT_GUEST_PHYSICAL_LIMIT {
            return Err(EptError::GuestPhysicalAddressTooWide(mapped_end));
        }

        let mut pages = Vec::new();
        let root = allocate_table(&mut pages)?;
        let ept_pointer = root.physical_address
            | (EptMemoryType::WriteBack as u64)
            | (EPT_PAGE_WALK_LENGTH_4 << EPT_PAGE_WALK_LENGTH_SHIFT);

        let mut current_pml4_index = usize::MAX;
        let mut current_pdpt = None;
        let mut current_pdpt_index = usize::MAX;
        let mut current_pd = None;
        let mut descriptor_cursor = 0_usize;
        let mut page_types = [EptMemoryType::Uncacheable; EPT_ENTRY_COUNT];

        let mut guest_address = 0_u64;
        while guest_address < mapped_end {
            let pml4_index = ((guest_address / EPT_512GB_PAGE_SIZE) & 0x1ff) as usize;
            if pml4_index != current_pml4_index {
                let pdpt = allocate_table(&mut pages)?;
                write_entry(root, pml4_index, table_entry(pdpt.physical_address));
                current_pml4_index = pml4_index;
                current_pdpt = Some(pdpt);
                current_pdpt_index = usize::MAX;
                current_pd = None;
            }

            let pdpt_index = ((guest_address / EPT_1GB_PAGE_SIZE) & 0x1ff) as usize;
            if pdpt_index != current_pdpt_index {
                let pd = allocate_table(&mut pages)?;
                write_entry(
                    current_pdpt.ok_or(EptError::InvalidMemoryMap)?,
                    pdpt_index,
                    table_entry(pd.physical_address),
                );
                current_pdpt_index = pdpt_index;
                current_pd = Some(pd);
            }

            let pd_index = ((guest_address / EPT_2MB_PAGE_SIZE) & 0x1ff) as usize;
            for (page_index, page_type) in page_types.iter_mut().enumerate() {
                let page_address = guest_address + (page_index * PAGE_SIZE) as u64;
                *page_type = memory_type_at(&descriptors, &mut descriptor_cursor, page_address)?;
            }
            let uniform_type = page_types
                .iter()
                .all(|page_type| *page_type == page_types[0]);

            if large_pages_supported && uniform_type {
                write_entry(
                    current_pd.ok_or(EptError::InvalidMemoryMap)?,
                    pd_index,
                    leaf_entry(guest_address, page_types[0]) | EPT_LARGE_PAGE,
                );
            } else {
                let pt = allocate_table(&mut pages)?;
                for (page_index, page_type) in page_types.iter().copied().enumerate() {
                    let page_address = guest_address + (page_index * PAGE_SIZE) as u64;
                    write_entry(pt, page_index, leaf_entry(page_address, page_type));
                }
                write_entry(
                    current_pd.ok_or(EptError::InvalidMemoryMap)?,
                    pd_index,
                    table_entry(pt.physical_address),
                );
            }

            guest_address = guest_address
                .checked_add(EPT_2MB_PAGE_SIZE)
                .ok_or(EptError::AddressOverflow)?;
        }

        Ok(Self {
            pages,
            protection_pool,
            root,
            ept_pointer,
            mapped_end,
        })
    }

    pub fn ept_pointer(&self) -> u64 {
        self.ept_pointer
    }

    pub fn deny_guest_access(
        &mut self,
        physical_address: u64,
        page_count: usize,
    ) -> Result<(), EptError> {
        if physical_address & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(EptError::InvalidProtectionAddress(physical_address));
        }
        for page_index in 0..page_count {
            let page_address = physical_address
                .checked_add((page_index * PAGE_SIZE) as u64)
                .ok_or(EptError::AddressOverflow)?;
            self.deny_guest_access_page(page_address)?;
        }
        Ok(())
    }

    pub fn deny_guest_access_to_tables(&mut self) -> Result<(), EptError> {
        for page_index in 0..self.pages.len() {
            let physical_address = self.pages[page_index].physical_address();
            let page_count = self.pages[page_index].pages();
            self.deny_guest_access(physical_address, page_count)?;
        }
        let protection_pool_address = self.protection_pool.pages.physical_address();
        let protection_pool_pages = self.protection_pool.pages.pages();
        self.deny_guest_access(protection_pool_address, protection_pool_pages)?;
        Ok(())
    }

    fn deny_guest_access_page(&mut self, physical_address: u64) -> Result<(), EptError> {
        if physical_address >= self.mapped_end {
            return Err(EptError::InvalidProtectionAddress(physical_address));
        }

        let pml4_index = ((physical_address / EPT_512GB_PAGE_SIZE) & 0x1ff) as usize;
        let pdpt_index = ((physical_address / EPT_1GB_PAGE_SIZE) & 0x1ff) as usize;
        let pd_index = ((physical_address / EPT_2MB_PAGE_SIZE) & 0x1ff) as usize;
        let pt_index = ((physical_address / PAGE_SIZE as u64) & 0x1ff) as usize;

        let pml4_entry = read_entry(self.root, pml4_index);
        let pdpt = table_from_entry(pml4_entry)?;
        let pdpt_entry = read_entry(pdpt, pdpt_index);
        if pdpt_entry & EPT_LARGE_PAGE != 0 {
            return Err(EptError::InvalidPageTable);
        }
        let pd = table_from_entry(pdpt_entry)?;
        let pd_entry = read_entry(pd, pd_index);
        let pt = if pd_entry & EPT_LARGE_PAGE != 0 {
            let pt = self.protection_pool.allocate_table()?;
            let base_address = (pd_entry & EPT_ADDRESS_MASK) & !(EPT_2MB_PAGE_SIZE - 1);
            let leaf_attributes = pd_entry & (EPT_PERMISSIONS | (0x7 << EPT_MEMORY_TYPE_SHIFT));
            for page_index in 0..EPT_ENTRY_COUNT {
                let page_address = base_address + (page_index * PAGE_SIZE) as u64;
                write_entry(
                    pt,
                    page_index,
                    (page_address & EPT_ADDRESS_MASK) | leaf_attributes,
                );
            }
            write_entry(pd, pd_index, table_entry(pt.physical_address));
            pt
        } else {
            table_from_entry(pd_entry)?
        };

        let leaf = read_entry(pt, pt_index);
        write_entry(pt, pt_index, leaf & !EPT_PERMISSIONS);
        Ok(())
    }
}

fn allocate_table(pages: &mut Vec<ResidentPages>) -> Result<TablePage, EptError> {
    let page = ResidentPages::allocate(1, AddressConstraint::Any).map_err(EptError::Allocation)?;
    let physical_address = page.physical_address();
    let entries = page.pointer().cast::<u64>();
    pages.push(page);
    Ok(TablePage {
        physical_address,
        entries,
    })
}

fn write_entry(table: TablePage, index: usize, value: u64) {
    debug_assert!(index < EPT_ENTRY_COUNT);
    unsafe {
        table.entries.as_ptr().add(index).write(value);
    }
}

fn read_entry(table: TablePage, index: usize) -> u64 {
    debug_assert!(index < EPT_ENTRY_COUNT);
    unsafe { table.entries.as_ptr().add(index).read() }
}

fn table_from_entry(entry: u64) -> Result<TablePage, EptError> {
    if entry & EPT_PERMISSIONS == 0 || entry & EPT_LARGE_PAGE != 0 {
        return Err(EptError::InvalidPageTable);
    }
    let physical_address = entry & EPT_ADDRESS_MASK;
    let entries = NonNull::new(physical_address as *mut u64).ok_or(EptError::InvalidPageTable)?;
    Ok(TablePage {
        physical_address,
        entries,
    })
}

fn table_entry(physical_address: u64) -> u64 {
    (physical_address & EPT_ADDRESS_MASK) | EPT_PERMISSIONS
}

fn leaf_entry(physical_address: u64, memory_type: EptMemoryType) -> u64 {
    (physical_address & EPT_ADDRESS_MASK)
        | EPT_PERMISSIONS
        | ((memory_type as u64) << EPT_MEMORY_TYPE_SHIFT)
}

fn memory_type_at(
    descriptors: &[MemoryDescriptor],
    cursor: &mut usize,
    physical_address: u64,
) -> Result<EptMemoryType, EptError> {
    while *cursor < descriptors.len() {
        let descriptor = descriptors[*cursor];
        let byte_len = descriptor
            .page_count
            .checked_mul(PAGE_SIZE as u64)
            .ok_or(EptError::AddressOverflow)?;
        let descriptor_end = descriptor
            .phys_start
            .checked_add(byte_len)
            .ok_or(EptError::AddressOverflow)?;
        if physical_address < descriptor.phys_start {
            return Ok(EptMemoryType::Uncacheable);
        }
        if physical_address < descriptor_end {
            return Ok(descriptor_memory_type(descriptor));
        }
        *cursor += 1;
    }
    Ok(EptMemoryType::Uncacheable)
}

fn descriptor_memory_type(descriptor: MemoryDescriptor) -> EptMemoryType {
    if descriptor.ty == MemoryType::MMIO {
        if descriptor.att.contains(MemoryAttribute::WRITE_COMBINE)
            && !descriptor.att.contains(MemoryAttribute::UNCACHEABLE)
        {
            return EptMemoryType::WriteCombining;
        }
        return EptMemoryType::Uncacheable;
    }
    if descriptor.ty == MemoryType::MMIO_PORT_SPACE
        || descriptor.ty == MemoryType::RESERVED
        || descriptor.ty == MemoryType::UNUSABLE
        || descriptor.ty == MemoryType::UNACCEPTED
    {
        return EptMemoryType::Uncacheable;
    }
    if is_ram_type(descriptor.ty) {
        if descriptor.att.contains(MemoryAttribute::WRITE_BACK) {
            return EptMemoryType::WriteBack;
        }
        if descriptor.att.contains(MemoryAttribute::WRITE_THROUGH) {
            return EptMemoryType::WriteThrough;
        }
        if descriptor.att.contains(MemoryAttribute::WRITE_COMBINE) {
            return EptMemoryType::WriteCombining;
        }
        if descriptor.att.contains(MemoryAttribute::UNCACHEABLE)
            || descriptor
                .att
                .contains(MemoryAttribute::UNCACHABLE_EXPORTED)
        {
            return EptMemoryType::Uncacheable;
        }
        return EptMemoryType::WriteBack;
    }
    EptMemoryType::Uncacheable
}

fn is_ram_type(memory_type: MemoryType) -> bool {
    memory_type == MemoryType::LOADER_CODE
        || memory_type == MemoryType::LOADER_DATA
        || memory_type == MemoryType::BOOT_SERVICES_CODE
        || memory_type == MemoryType::BOOT_SERVICES_DATA
        || memory_type == MemoryType::RUNTIME_SERVICES_CODE
        || memory_type == MemoryType::RUNTIME_SERVICES_DATA
        || memory_type == MemoryType::CONVENTIONAL
        || memory_type == MemoryType::ACPI_RECLAIM
        || memory_type == MemoryType::ACPI_NON_VOLATILE
        || memory_type == MemoryType::PERSISTENT_MEMORY
}

fn align_up(value: u64, alignment: u64) -> Result<u64, EptError> {
    debug_assert!(alignment.is_power_of_two());
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
        .ok_or(EptError::AddressOverflow)
}
