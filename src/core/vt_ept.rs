extern crate alloc;

use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::NonNull;

use uefi::Status;
use uefi::boot;
use uefi::boot::{OpenProtocolAttributes, OpenProtocolParams};
use uefi::mem::memory_map::{MemoryAttribute, MemoryDescriptor, MemoryMap, MemoryType};
use uefi::proto::unsafe_protocol;

use crate::arch::x86_64::{cpuid, msr};
use crate::memory::resident::{AddressConstraint, PAGE_SIZE, ResidentPages};

const EPT_READ: u64 = 1 << 0;
const EPT_WRITE: u64 = 1 << 1;
const EPT_EXECUTE: u64 = 1 << 2;
const EPT_PERMISSIONS: u64 = EPT_READ | EPT_WRITE | EPT_EXECUTE;
const EPT_LARGE_PAGE: u64 = 1 << 7;
const EPT_MEMORY_TYPE_SHIFT: u64 = 3;
// Bits 54:52 are ignored by EPT hardware. Retain the firmware cache ceiling
// so an MTRR disable/enable cycle can restore cacheability without allocation.
const EPT_FIRMWARE_TYPE_SHIFT: u64 = 52;
const EPT_FIRMWARE_TYPE_MASK: u64 = 7 << EPT_FIRMWARE_TYPE_SHIFT;
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
const PCI_BAR_DESCRIPTOR_SIZE: usize = 46;

const EPT_CAP_PAGE_WALK_LENGTH_4: u64 = 1 << 6;
const EPT_CAP_MEMORY_TYPE_UC: u64 = 1 << 8;
const EPT_CAP_MEMORY_TYPE_WB: u64 = 1 << 14;
const EPT_CAP_2MB_PAGE: u64 = 1 << 16;
const EPT_CAP_1GB_PAGE: u64 = 1 << 17;

#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EptMemoryType {
    Uncacheable = 0,
    WriteCombining = 1,
    WriteThrough = 4,
    WriteProtected = 5,
    WriteBack = 6,
}

#[repr(C)]
struct MtrrState {
    capability: u64,
    default_type: u64,
    physical_mask: u64,
    fixed_types: [u64; 11],
    variable_ranges: [[u64; 2]; 255],
}
const _: () = assert!(size_of::<MtrrState>() == 4192);
const _: () = assert!(core::mem::offset_of!(MtrrState, variable_ranges) == 112);

impl MtrrState {
    fn capture() -> Self {
        let physical_bits = (cpuid::leaf(0x8000_0008).eax & 0xff).clamp(32, 52);
        let mut state = Self {
            capability: unsafe { msr::read(0xfe) },
            default_type: unsafe { msr::read(0x2ff) },
            physical_mask: ((1_u64 << physical_bits) - 1) & !0xfff,
            fixed_types: [0; 11],
            variable_ranges: [[0, 0]; 255],
        };
        if state.capability & (1 << 8) != 0 {
            for (index, register) in [0x250, 0x258, 0x259]
                .into_iter()
                .chain(0x268..=0x26f)
                .enumerate()
            {
                state.fixed_types[index] = unsafe { msr::read(register) };
            }
        }
        for index in 0..(state.capability & 0xff) as usize {
            let register = 0x200 + index as u32 * 2;
            state.variable_ranges[index] =
                unsafe { [msr::read(register), msr::read(register + 1)] };
        }
        state
    }

    fn memory_type(&self, address: u64, size: u64) -> EptMemoryType {
        if self.default_type & (1 << 11) == 0 {
            return EptMemoryType::Uncacheable;
        }
        if address < 0x10_0000
            && self.default_type & (1 << 10) != 0
            && self.capability & (1 << 8) != 0
        {
            let (register, shift) = if address < 0x8_0000 {
                (0, (address >> 16) * 8)
            } else if address < 0xc_0000 {
                (1 + ((address - 0x8_0000) >> 17), ((address >> 14) & 7) * 8)
            } else {
                (3 + ((address - 0xc_0000) >> 15), ((address >> 12) & 7) * 8)
            };
            return decode_memory_type((self.fixed_types[register as usize] >> shift) as u8);
        }
        let mut selected = None;
        for &[base, mask] in &self.variable_ranges[..(self.capability & 0xff) as usize] {
            if mask & (1 << 11) == 0 {
                continue;
            }
            let address_mask = mask & self.physical_mask;
            let start = base & address_mask;
            let end = start + ((!address_mask & self.physical_mask) | 0xfff) + 1;
            if start >= address + size || end <= address {
                continue;
            }
            // A later MTRR boundary may bisect an existing large EPT leaf.
            // UC for that leaf is safe and requires no post-EBS table allocation.
            if start > address || end < address + size {
                return EptMemoryType::Uncacheable;
            }
            let memory_type = decode_memory_type(base as u8);
            selected = Some(match selected {
                None => memory_type,
                Some(previous) if previous == memory_type => memory_type,
                Some(EptMemoryType::WriteBack) if memory_type == EptMemoryType::WriteThrough => {
                    EptMemoryType::WriteThrough
                }
                Some(EptMemoryType::WriteThrough) if memory_type == EptMemoryType::WriteBack => {
                    EptMemoryType::WriteThrough
                }
                Some(_) => EptMemoryType::Uncacheable,
            });
            if selected == Some(EptMemoryType::Uncacheable) {
                break;
            }
        }
        selected.unwrap_or_else(|| decode_memory_type(self.default_type as u8))
    }
}

fn decode_memory_type(value: u8) -> EptMemoryType {
    match value {
        1 => EptMemoryType::WriteCombining,
        4 => EptMemoryType::WriteThrough,
        5 => EptMemoryType::WriteProtected,
        6 => EptMemoryType::WriteBack,
        _ => EptMemoryType::Uncacheable,
    }
}

fn combine_memory_types(firmware: EptMemoryType, mtrr: EptMemoryType) -> EptMemoryType {
    if firmware == mtrr || mtrr == EptMemoryType::WriteBack {
        firmware
    } else if firmware == EptMemoryType::WriteBack {
        mtrr
    } else {
        EptMemoryType::Uncacheable
    }
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
    InveptUnavailable,
    MtrrUnavailable,
    InvalidProtectionAddress(u64),
    InvalidRemapAddress(u64),
    InvalidPageTable,
    InvalidPciBar,
    PciBar(Status),
    ProtectionTableCapacityExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EptComposition {
    pub l2_guest_physical_address: u64,
    pub l1_guest_physical_address: u64,
    pub host_physical_address: u64,
    pub permissions: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EptTranslation {
    physical_address: u64,
    permissions: u64,
    memory_type: u64,
}

pub struct IdentityEpt {
    pages: Vec<ResidentPages>,
    protection_pool: ProtectionTablePool,
    root: TablePage,
    ept_pointer: u64,
    mapped_end: u64,
    large_pages_supported: bool,
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

#[repr(C)]
#[unsafe_protocol("4cf5b200-68b8-4ca5-9eec-b23e3f50029a")]
struct PciIoProtocol {
    // EFI_PCI_IO_PROTOCOL places GetBarAttributes after sixteen function slots.
    _preceding_functions: [usize; 16],
    get_bar_attributes:
        unsafe extern "efiapi" fn(*mut PciIoProtocol, u8, *mut u64, *mut *mut c_void) -> Status,
}
const _: () =
    assert!(core::mem::offset_of!(PciIoProtocol, get_bar_attributes) == 16 * size_of::<usize>());

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
        unsafe {
            entries.as_ptr().write_bytes(0, EPT_ENTRY_COUNT);
        }
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
        if capabilities & ((1 << 20) | (1 << 25)) != ((1 << 20) | (1 << 25)) {
            return Err(EptError::InveptUnavailable);
        }
        if cpuid::leaf(1).edx & (1 << 12) == 0 {
            return Err(EptError::MtrrUnavailable);
        }
        let mtrrs = MtrrState::capture();
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
            if descriptor.phys_start & (PAGE_SIZE as u64 - 1) != 0 {
                return Err(EptError::InvalidMemoryMap);
            }
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
        let mut page_types =
            [(EptMemoryType::Uncacheable, EptMemoryType::Uncacheable); EPT_ENTRY_COUNT];

        let mut guest_address = 0_u64;
        while guest_address < mapped_end {
            guest_address = next_mapped_chunk(&descriptors, &mut descriptor_cursor, guest_address)?;
            if guest_address >= mapped_end {
                break;
            }
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
                let firmware = memory_type_at(&descriptors, &mut descriptor_cursor, page_address)?;
                let effective = combine_memory_types(
                    firmware,
                    mtrrs.memory_type(page_address, PAGE_SIZE as u64),
                );
                *page_type = (firmware, effective);
            }
            let uniform_type = page_types
                .iter()
                .all(|page_type| *page_type == page_types[0]);

            if large_pages_supported && uniform_type && guest_address >= EPT_2MB_PAGE_SIZE {
                write_entry(
                    current_pd.ok_or(EptError::InvalidMemoryMap)?,
                    pd_index,
                    leaf_entry(guest_address, page_types[0].0, page_types[0].1) | EPT_LARGE_PAGE,
                );
            } else {
                let pt = allocate_table(&mut pages)?;
                for (page_index, page_type) in page_types.iter().copied().enumerate() {
                    let page_address = guest_address + (page_index * PAGE_SIZE) as u64;
                    write_entry(
                        pt,
                        page_index,
                        leaf_entry(page_address, page_type.0, page_type.1),
                    );
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
            large_pages_supported,
        })
    }

    pub fn ept_pointer(&self) -> u64 {
        self.ept_pointer
    }

    pub fn clone_identity_tables(&self) -> Result<Self, EptError> {
        let table_page_count = self.pages.iter().try_fold(0_usize, |total, page| {
            total
                .checked_add(page.pages())
                .ok_or(EptError::AddressOverflow)
        })?;
        let table_pages = ResidentPages::allocate(table_page_count, AddressConstraint::Any)
            .map_err(EptError::Allocation)?;
        let mut next_table_index = 0;
        let root = clone_table_tree(self.root, 4, &table_pages, &mut next_table_index)?;
        if next_table_index != table_page_count {
            return Err(EptError::InvalidPageTable);
        }
        let protection_pool = ProtectionTablePool::allocate()?;
        let ept_pointer = root.physical_address | (self.ept_pointer & !EPT_ADDRESS_MASK);
        Ok(Self {
            pages: alloc::vec![table_pages],
            protection_pool,
            root,
            ept_pointer,
            mapped_end: self.mapped_end,
            large_pages_supported: self.large_pages_supported,
        })
    }

    pub fn sparse_shadow(&self) -> Result<Self, EptError> {
        let protection_pool = ProtectionTablePool::allocate()?;
        let mut pages = Vec::new();
        let root = allocate_table(&mut pages)?;
        let ept_pointer = root.physical_address | (self.ept_pointer & !EPT_ADDRESS_MASK);
        Ok(Self {
            pages,
            protection_pool,
            root,
            ept_pointer,
            mapped_end: self.mapped_end,
            large_pages_supported: self.large_pages_supported,
        })
    }

    pub fn map_pci_bars(&mut self) -> Result<Vec<(u64, u64)>, EptError> {
        let handles = match boot::find_handles::<PciIoProtocol>() {
            Ok(handles) => handles,
            Err(error) if error.status() == Status::NOT_FOUND => return Ok(Vec::new()),
            Err(error) => return Err(EptError::Allocation(error.status())),
        };
        let mut ranges = Vec::new();
        for handle in handles {
            let params = OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            };
            let pci_io = unsafe {
                boot::open_protocol::<PciIoProtocol>(params, OpenProtocolAttributes::GetProtocol)
            }
            .map_err(|error| EptError::PciBar(error.status()))?;
            let mut device_ranges = Vec::new();
            for bar_index in 0..6 {
                let mut resources = core::ptr::null_mut();
                let status = unsafe {
                    (pci_io.get_bar_attributes)(
                        (&*pci_io as *const PciIoProtocol).cast_mut(),
                        bar_index,
                        core::ptr::null_mut(),
                        &mut resources,
                    )
                };
                if status == Status::UNSUPPORTED {
                    continue;
                }
                if status != Status::SUCCESS {
                    return Err(EptError::PciBar(status));
                }
                let resource_pointer =
                    NonNull::new(resources.cast::<u8>()).ok_or(EptError::InvalidPciBar)?;
                let range = read_pci_bar_range(resource_pointer.as_ptr());
                unsafe { boot::free_pool(resource_pointer) }
                    .map_err(|error| EptError::PciBar(error.status()))?;
                if let Some(range) = range? {
                    device_ranges.push(range);
                }
            }
            drop(pci_io);
            for (start, end) in device_ranges {
                self.map_uncacheable_range(start, end)?;
                ranges.push((start, end));
            }
        }
        Ok(ranges)
    }

    // Firmware BARs do not describe addresses assigned by the guest OS later.
    pub fn map_high_address_gaps(&mut self) -> Result<u64, EptError> {
        if !self.large_pages_supported {
            return Ok(self.mapped_end);
        }
        let physical_bits = (cpuid::leaf(0x8000_0008).eax & 0xff).clamp(32, 48);
        let end = high_address_mapping_end(self.mapped_end, physical_bits)?;
        let one_gb_pages_supported =
            unsafe { msr::read(msr::IA32_VMX_EPT_VPID_CAP) } & EPT_CAP_1GB_PAGE != 0;
        let mut address = EPT_MINIMUM_MAPPED_END;
        while address < end {
            let pml4_index = ((address / EPT_512GB_PAGE_SIZE) & 0x1ff) as usize;
            let pdpt_index = ((address / EPT_1GB_PAGE_SIZE) & 0x1ff) as usize;
            let pml4_entry = read_entry(self.root, pml4_index);
            let pdpt = if pml4_entry & EPT_PERMISSIONS == 0 {
                let table = allocate_table(&mut self.pages)?;
                write_entry(self.root, pml4_index, table_entry(table.physical_address));
                table
            } else {
                table_from_entry(pml4_entry)?
            };
            let pdpt_entry = read_entry(pdpt, pdpt_index);
            if pdpt_entry & EPT_PERMISSIONS == 0 && one_gb_pages_supported {
                write_entry(
                    pdpt,
                    pdpt_index,
                    leaf_entry(
                        address,
                        EptMemoryType::Uncacheable,
                        EptMemoryType::Uncacheable,
                    ) | EPT_LARGE_PAGE,
                );
            } else if pdpt_entry & EPT_LARGE_PAGE == 0 {
                let pd = if pdpt_entry & EPT_PERMISSIONS == 0 {
                    let table = allocate_table(&mut self.pages)?;
                    write_entry(pdpt, pdpt_index, table_entry(table.physical_address));
                    table
                } else {
                    table_from_entry(pdpt_entry)?
                };
                for pd_index in 0..EPT_ENTRY_COUNT {
                    if read_entry(pd, pd_index) & EPT_PERMISSIONS == 0 {
                        let page_address = address + pd_index as u64 * EPT_2MB_PAGE_SIZE;
                        write_entry(
                            pd,
                            pd_index,
                            leaf_entry(
                                page_address,
                                EptMemoryType::Uncacheable,
                                EptMemoryType::Uncacheable,
                            ) | EPT_LARGE_PAGE,
                        );
                    }
                }
            }
            address += EPT_1GB_PAGE_SIZE;
        }
        self.mapped_end = self.mapped_end.max(end);
        Ok(end)
    }

    fn map_uncacheable_range(&mut self, start: u64, end: u64) -> Result<(), EptError> {
        let bar_end = end;
        let mut address = start & !(EPT_2MB_PAGE_SIZE - 1);
        let end = align_up(end, EPT_2MB_PAGE_SIZE)?;
        if end > EPT_GUEST_PHYSICAL_LIMIT || address >= end {
            return Err(EptError::GuestPhysicalAddressTooWide(end));
        }
        while address < end {
            self.map_uncacheable_2mb(address, start, bar_end)?;
            address += EPT_2MB_PAGE_SIZE;
        }
        self.mapped_end = self.mapped_end.max(end);
        Ok(())
    }

    fn map_uncacheable_2mb(
        &mut self,
        address: u64,
        bar_start: u64,
        bar_end: u64,
    ) -> Result<(), EptError> {
        let pml4_index = ((address / EPT_512GB_PAGE_SIZE) & 0x1ff) as usize;
        let pdpt_index = ((address / EPT_1GB_PAGE_SIZE) & 0x1ff) as usize;
        let pd_index = ((address / EPT_2MB_PAGE_SIZE) & 0x1ff) as usize;
        let pml4_entry = read_entry(self.root, pml4_index);
        let pdpt = if pml4_entry & EPT_PERMISSIONS == 0 {
            let table = allocate_table(&mut self.pages)?;
            write_entry(self.root, pml4_index, table_entry(table.physical_address));
            table
        } else {
            table_from_entry(pml4_entry)?
        };
        let pdpt_entry = read_entry(pdpt, pdpt_index);
        let pd = if pdpt_entry & EPT_PERMISSIONS == 0 {
            let table = allocate_table(&mut self.pages)?;
            write_entry(pdpt, pdpt_index, table_entry(table.physical_address));
            table
        } else {
            table_from_entry(pdpt_entry)?
        };
        let existing = read_entry(pd, pd_index);
        if existing & EPT_PERMISSIONS != 0 {
            let cache_mask = (7 << EPT_MEMORY_TYPE_SHIFT) | EPT_FIRMWARE_TYPE_MASK;
            if existing & EPT_LARGE_PAGE != 0
                && bar_start <= address
                && bar_end >= address + EPT_2MB_PAGE_SIZE
            {
                write_entry(pd, pd_index, existing & !cache_mask);
            } else {
                let (pt, _) = self.ensure_4k_leaf(address)?;
                let first = ((bar_start.max(address) - address) / PAGE_SIZE as u64) as usize;
                let last = (bar_end.min(address + EPT_2MB_PAGE_SIZE) - address)
                    .div_ceil(PAGE_SIZE as u64) as usize;
                for index in first..last {
                    write_entry(pt, index, read_entry(pt, index) & !cache_mask);
                }
            }
            return Ok(());
        }
        if self.large_pages_supported {
            write_entry(
                pd,
                pd_index,
                leaf_entry(
                    address,
                    EptMemoryType::Uncacheable,
                    EptMemoryType::Uncacheable,
                ) | EPT_LARGE_PAGE,
            );
        } else {
            let pt = allocate_table(&mut self.pages)?;
            for page_index in 0..EPT_ENTRY_COUNT {
                let page_address = address + (page_index * PAGE_SIZE) as u64;
                write_entry(
                    pt,
                    page_index,
                    leaf_entry(
                        page_address,
                        EptMemoryType::Uncacheable,
                        EptMemoryType::Uncacheable,
                    ),
                );
            }
            write_entry(pd, pd_index, table_entry(pt.physical_address));
        }
        Ok(())
    }

    pub fn remap_page(
        &mut self,
        guest_physical_address: u64,
        target_physical_address: u64,
    ) -> Result<(), EptError> {
        if guest_physical_address & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(EptError::InvalidRemapAddress(guest_physical_address));
        }
        if target_physical_address & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(EptError::InvalidRemapAddress(target_physical_address));
        }
        if guest_physical_address >= self.mapped_end || target_physical_address >= self.mapped_end {
            return Err(EptError::InvalidRemapAddress(
                guest_physical_address.max(target_physical_address),
            ));
        }
        let (table, index) = self.ensure_4k_leaf(guest_physical_address)?;
        let leaf = read_entry(table, index);
        write_entry(
            table,
            index,
            (target_physical_address & EPT_ADDRESS_MASK) | (leaf & !EPT_ADDRESS_MASK),
        );
        Ok(())
    }

    pub fn leaf_entry_physical_address(
        &mut self,
        guest_physical_address: u64,
    ) -> Result<u64, EptError> {
        if guest_physical_address & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(EptError::InvalidRemapAddress(guest_physical_address));
        }
        if guest_physical_address >= self.mapped_end {
            return Err(EptError::InvalidRemapAddress(guest_physical_address));
        }
        let (table, index) = self.ensure_4k_leaf(guest_physical_address)?;
        Ok(table.physical_address + (index * size_of::<u64>()) as u64)
    }

    pub fn leaf_entry_value(&mut self, guest_physical_address: u64) -> Result<u64, EptError> {
        if guest_physical_address & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(EptError::InvalidRemapAddress(guest_physical_address));
        }
        if guest_physical_address >= self.mapped_end {
            return Err(EptError::InvalidRemapAddress(guest_physical_address));
        }
        let (table, index) = self.ensure_4k_leaf(guest_physical_address)?;
        Ok(read_entry(table, index))
    }

    pub fn compose_page(
        &mut self,
        ept12: &Self,
        ept01: &Self,
        l2_guest_physical_address: u64,
    ) -> Result<EptComposition, EptError> {
        if l2_guest_physical_address & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(EptError::InvalidRemapAddress(l2_guest_physical_address));
        }
        let l1_translation = ept12.translate(l2_guest_physical_address)?;
        let l1_guest_physical_address = l1_translation.physical_address & EPT_ADDRESS_MASK;
        let host_translation = ept01.translate(l1_guest_physical_address)?;
        let host_physical_address = host_translation.physical_address & EPT_ADDRESS_MASK;
        let permissions = l1_translation.permissions & host_translation.permissions;
        let (table, index) = self.ensure_4k_leaf(l2_guest_physical_address)?;
        write_entry(
            table,
            index,
            host_physical_address
                | permissions
                | (host_translation.memory_type << EPT_MEMORY_TYPE_SHIFT),
        );
        Ok(EptComposition {
            l2_guest_physical_address,
            l1_guest_physical_address,
            host_physical_address,
            permissions,
        })
    }

    pub fn table_regions(&self) -> Vec<(u64, usize)> {
        let mut regions = Vec::with_capacity(self.pages.len() + 1);
        for page in &self.pages {
            regions.push((page.physical_address(), page.pages()));
        }
        regions.push((
            self.protection_pool.pages.physical_address(),
            self.protection_pool.pages.pages(),
        ));
        regions
    }

    pub fn protection_table_pool(&self) -> (u64, usize, usize) {
        (
            self.protection_pool.pages.physical_address(),
            self.protection_pool.pages.pages(),
            self.protection_pool.used_pages,
        )
    }

    pub fn conceal_guest_access_to_regions(
        &mut self,
        regions: &[(u64, usize)],
        zero_page_physical_address: u64,
    ) -> Result<(), EptError> {
        for &(physical_address, page_count) in regions {
            self.conceal_guest_access(physical_address, page_count, zero_page_physical_address)?;
        }
        Ok(())
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

    pub fn conceal_guest_access(
        &mut self,
        physical_address: u64,
        page_count: usize,
        zero_page_physical_address: u64,
    ) -> Result<(), EptError> {
        if physical_address & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(EptError::InvalidProtectionAddress(physical_address));
        }
        if zero_page_physical_address & (PAGE_SIZE as u64 - 1) != 0
            || zero_page_physical_address >= self.mapped_end
        {
            return Err(EptError::InvalidRemapAddress(zero_page_physical_address));
        }
        for page_index in 0..page_count {
            let page_address = physical_address
                .checked_add((page_index * PAGE_SIZE) as u64)
                .ok_or(EptError::AddressOverflow)?;
            self.conceal_guest_access_page(page_address, zero_page_physical_address)?;
        }
        Ok(())
    }

    pub fn conceal_guest_access_to_tables(
        &mut self,
        zero_page_physical_address: u64,
    ) -> Result<(), EptError> {
        for page_index in 0..self.pages.len() {
            let physical_address = self.pages[page_index].physical_address();
            let page_count = self.pages[page_index].pages();
            self.conceal_guest_access(physical_address, page_count, zero_page_physical_address)?;
        }
        let protection_pool_address = self.protection_pool.pages.physical_address();
        let protection_pool_pages = self.protection_pool.pages.pages();
        self.conceal_guest_access(
            protection_pool_address,
            protection_pool_pages,
            zero_page_physical_address,
        )?;
        Ok(())
    }

    fn deny_guest_access_page(&mut self, physical_address: u64) -> Result<(), EptError> {
        if physical_address >= self.mapped_end {
            return Err(EptError::InvalidProtectionAddress(physical_address));
        }

        let pt_index = ((physical_address / PAGE_SIZE as u64) & 0x1ff) as usize;
        let (pt, _) = self.ensure_4k_leaf(physical_address)?;

        let leaf = read_entry(pt, pt_index);
        write_entry(pt, pt_index, leaf & !EPT_PERMISSIONS);
        Ok(())
    }

    fn conceal_guest_access_page(
        &mut self,
        physical_address: u64,
        zero_page_physical_address: u64,
    ) -> Result<(), EptError> {
        if physical_address >= self.mapped_end {
            return Err(EptError::InvalidProtectionAddress(physical_address));
        }

        let pt_index = ((physical_address / PAGE_SIZE as u64) & 0x1ff) as usize;
        let (pt, _) = self.ensure_4k_leaf(physical_address)?;
        let leaf = read_entry(pt, pt_index);
        let memory_type = leaf & ((0x7 << EPT_MEMORY_TYPE_SHIFT) | EPT_FIRMWARE_TYPE_MASK);
        write_entry(
            pt,
            pt_index,
            (zero_page_physical_address & EPT_ADDRESS_MASK) | memory_type | EPT_READ,
        );
        Ok(())
    }

    fn ensure_4k_leaf(&mut self, physical_address: u64) -> Result<(TablePage, usize), EptError> {
        let pml4_index = ((physical_address / EPT_512GB_PAGE_SIZE) & 0x1ff) as usize;
        let pdpt_index = ((physical_address / EPT_1GB_PAGE_SIZE) & 0x1ff) as usize;
        let pd_index = ((physical_address / EPT_2MB_PAGE_SIZE) & 0x1ff) as usize;
        let pt_index = ((physical_address / PAGE_SIZE as u64) & 0x1ff) as usize;

        let pml4_entry = read_entry(self.root, pml4_index);
        let pdpt = if pml4_entry & EPT_PERMISSIONS == 0 {
            let pdpt = self.protection_pool.allocate_table()?;
            write_entry(self.root, pml4_index, table_entry(pdpt.physical_address));
            pdpt
        } else {
            table_from_entry(pml4_entry)?
        };
        let pdpt_entry = read_entry(pdpt, pdpt_index);
        if pdpt_entry & EPT_LARGE_PAGE != 0 {
            return Err(EptError::InvalidPageTable);
        }
        let pd = if pdpt_entry & EPT_PERMISSIONS == 0 {
            let pd = self.protection_pool.allocate_table()?;
            write_entry(pdpt, pdpt_index, table_entry(pd.physical_address));
            pd
        } else {
            table_from_entry(pdpt_entry)?
        };
        let pd_entry = read_entry(pd, pd_index);
        let pt = if pd_entry & EPT_PERMISSIONS == 0 {
            let pt = self.protection_pool.allocate_table()?;
            write_entry(pd, pd_index, table_entry(pt.physical_address));
            pt
        } else if pd_entry & EPT_LARGE_PAGE != 0 {
            let pt = self.protection_pool.allocate_table()?;
            let base_address = (pd_entry & EPT_ADDRESS_MASK) & !(EPT_2MB_PAGE_SIZE - 1);
            let leaf_attributes = pd_entry
                & (EPT_PERMISSIONS | (0x7 << EPT_MEMORY_TYPE_SHIFT) | EPT_FIRMWARE_TYPE_MASK);
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
        Ok((pt, pt_index))
    }

    fn translate(&self, guest_physical_address: u64) -> Result<EptTranslation, EptError> {
        if guest_physical_address >= self.mapped_end {
            return Err(EptError::InvalidRemapAddress(guest_physical_address));
        }
        let pml4_index = ((guest_physical_address / EPT_512GB_PAGE_SIZE) & 0x1ff) as usize;
        let pdpt_index = ((guest_physical_address / EPT_1GB_PAGE_SIZE) & 0x1ff) as usize;
        let pd_index = ((guest_physical_address / EPT_2MB_PAGE_SIZE) & 0x1ff) as usize;
        let pt_index = ((guest_physical_address / PAGE_SIZE as u64) & 0x1ff) as usize;

        let pml4_entry = read_entry(self.root, pml4_index);
        let pdpt = table_from_entry(pml4_entry)?;
        let pdpt_entry = read_entry(pdpt, pdpt_index);
        if pdpt_entry & EPT_LARGE_PAGE != 0 {
            return translation_from_leaf(pdpt_entry, guest_physical_address, EPT_1GB_PAGE_SIZE);
        }
        let pd = table_from_entry(pdpt_entry)?;
        let pd_entry = read_entry(pd, pd_index);
        if pd_entry & EPT_LARGE_PAGE != 0 {
            return translation_from_leaf(pd_entry, guest_physical_address, EPT_2MB_PAGE_SIZE);
        }
        let pt = table_from_entry(pd_entry)?;
        translation_from_leaf(
            read_entry(pt, pt_index),
            guest_physical_address,
            PAGE_SIZE as u64,
        )
    }
}

fn read_pci_bar_range(resources: *const u8) -> Result<Option<(u64, u64)>, EptError> {
    if unsafe { resources.read() } != 0x8a {
        return Ok(None);
    }
    let descriptor = unsafe { core::slice::from_raw_parts(resources, PCI_BAR_DESCRIPTOR_SIZE) };
    if u16::from_le_bytes([descriptor[1], descriptor[2]]) != 0x2b || descriptor[3] != 0 {
        return Ok(None);
    }
    let start = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
    let length = u64::from_le_bytes(descriptor[38..46].try_into().unwrap());
    if length == 0 {
        return Ok(None);
    }
    let end = start.checked_add(length).ok_or(EptError::AddressOverflow)?;
    if end > EPT_GUEST_PHYSICAL_LIMIT {
        return Err(EptError::GuestPhysicalAddressTooWide(end));
    }
    Ok(Some((start, end)))
}

fn high_address_mapping_end(mapped_end: u64, physical_bits: u32) -> Result<u64, EptError> {
    let physical_limit = 1_u64 << physical_bits;
    align_up(
        mapped_end.max(EPT_512GB_PAGE_SIZE).min(physical_limit),
        EPT_1GB_PAGE_SIZE,
    )
}

fn translation_from_leaf(
    entry: u64,
    guest_physical_address: u64,
    page_size: u64,
) -> Result<EptTranslation, EptError> {
    let permissions = entry & EPT_PERMISSIONS;
    if permissions == 0 {
        return Err(EptError::InvalidPageTable);
    }
    let base = (entry & EPT_ADDRESS_MASK) & !(page_size - 1);
    let offset = guest_physical_address & (page_size - 1);
    Ok(EptTranslation {
        physical_address: base + offset,
        permissions,
        memory_type: (entry >> EPT_MEMORY_TYPE_SHIFT) & 0x7,
    })
}

fn allocate_table(pages: &mut Vec<ResidentPages>) -> Result<TablePage, EptError> {
    let page = ResidentPages::allocate(1, AddressConstraint::Any).map_err(EptError::Allocation)?;
    let physical_address = page.physical_address();
    let entries = page.pointer().cast::<u64>();
    unsafe {
        entries.as_ptr().write_bytes(0, EPT_ENTRY_COUNT);
    }
    pages.push(page);
    Ok(TablePage {
        physical_address,
        entries,
    })
}

fn clone_table_tree(
    source: TablePage,
    level: u8,
    pages: &ResidentPages,
    next_table_index: &mut usize,
) -> Result<TablePage, EptError> {
    if *next_table_index >= pages.pages() {
        return Err(EptError::InvalidPageTable);
    }
    let page_offset = *next_table_index * PAGE_SIZE;
    *next_table_index += 1;
    let physical_address = pages.physical_address() + page_offset as u64;
    let entries =
        unsafe { NonNull::new_unchecked(pages.pointer().as_ptr().add(page_offset).cast::<u64>()) };
    unsafe {
        core::ptr::copy_nonoverlapping(source.entries.as_ptr(), entries.as_ptr(), EPT_ENTRY_COUNT);
    }
    let cloned = TablePage {
        physical_address,
        entries,
    };
    if level > 1 {
        for index in 0..EPT_ENTRY_COUNT {
            let entry = read_entry(cloned, index);
            if entry & EPT_PERMISSIONS != 0 && entry & EPT_LARGE_PAGE == 0 {
                let child =
                    clone_table_tree(table_from_entry(entry)?, level - 1, pages, next_table_index)?;
                write_entry(
                    cloned,
                    index,
                    (entry & !EPT_ADDRESS_MASK) | child.physical_address,
                );
            }
        }
    }
    Ok(cloned)
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

fn leaf_entry(
    physical_address: u64,
    firmware_type: EptMemoryType,
    memory_type: EptMemoryType,
) -> u64 {
    (physical_address & EPT_ADDRESS_MASK)
        | EPT_PERMISSIONS
        | ((memory_type as u64) << EPT_MEMORY_TYPE_SHIFT)
        | ((firmware_type as u64) << EPT_FIRMWARE_TYPE_SHIFT)
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

fn next_mapped_chunk(
    descriptors: &[MemoryDescriptor],
    cursor: &mut usize,
    address: u64,
) -> Result<u64, EptError> {
    // Keep legacy MMIO below 4 GiB covered. Above it, map described ranges and
    // PCI BARs without allocating tables for potentially terabyte-sized holes.
    if address < EPT_MINIMUM_MAPPED_END {
        return Ok(address);
    }
    while let Some(descriptor) = descriptors.get(*cursor) {
        let end = descriptor
            .page_count
            .checked_mul(PAGE_SIZE as u64)
            .and_then(|length| descriptor.phys_start.checked_add(length))
            .ok_or(EptError::AddressOverflow)?;
        if address < end {
            return Ok(address.max(descriptor.phys_start & !(EPT_2MB_PAGE_SIZE - 1)));
        }
        *cursor += 1;
    }
    Ok(EPT_GUEST_PHYSICAL_LIMIT)
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
