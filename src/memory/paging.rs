use alloc::vec::Vec;

use crate::arch::x86_64::control_regs;

use super::resident::{AddressConstraint, PAGE_SIZE, ResidentPages};

const PAGE_TABLE_ENTRIES: usize = 512;
const INITIAL_HOST_PAGE_TABLE_PAGES: usize = 256;
const MAX_HOST_PAGE_TABLE_PAGES: usize = 32_768;
const PAGE_PRESENT: u64 = 1;
const PAGE_LARGE: u64 = 1 << 7;
const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const CR3_LOW_MASK: u64 = 0xfff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostPagingError {
    Allocation(uefi::Status),
    TableCapacityExceeded { capacity: usize },
    InvalidSourceRoot,
    UnsupportedLa57(u64),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostAddressSpaceReport {
    pub source_cr3: u64,
    pub host_cr3: u64,
    pub arena_physical_address: u64,
    pub arena_pages: usize,
    pub table_pages: usize,
}

pub struct HostAddressSpace {
    arena: ResidentPages,
    metadata: CloneMetadata,
    report: HostAddressSpaceReport,
}

impl HostAddressSpace {
    pub fn reserve() -> Result<Self, HostPagingError> {
        let arena = ResidentPages::allocate(INITIAL_HOST_PAGE_TABLE_PAGES, AddressConstraint::Any)
            .map_err(HostPagingError::Allocation)?;
        let metadata = CloneMetadata::new(arena.pages())?;
        Ok(Self {
            report: HostAddressSpaceReport {
                arena_physical_address: arena.physical_address(),
                arena_pages: arena.pages(),
                ..HostAddressSpaceReport::default()
            },
            arena,
            metadata,
        })
    }

    pub fn clone_current(&mut self) -> Result<HostAddressSpaceReport, HostPagingError> {
        let cr4 = control_regs::read_cr4();
        if cr4 & control_regs::CR4_LA57 != 0 {
            return Err(HostPagingError::UnsupportedLa57(cr4));
        }
        loop {
            let (clone_result, table_count, source_cr3) = {
                let mut state = CloneState::new(&mut self.arena, &mut self.metadata);
                let source_cr3 = control_regs::read_cr3();
                let source_root = source_cr3 & PHYSICAL_ADDRESS_MASK;
                if source_root == 0 {
                    return Err(HostPagingError::InvalidSourceRoot);
                }

                let clone_result = state.clone_table(source_root, 4);
                (clone_result, state.metadata.source_pages.len(), source_cr3)
            };

            match clone_result {
                Ok(host_root) => {
                    self.report.source_cr3 = source_cr3;
                    self.report.host_cr3 = host_root | (source_cr3 & CR3_LOW_MASK);
                    self.report.table_pages = table_count;
                    return Ok(self.report);
                }
                Err(HostPagingError::TableCapacityExceeded { .. }) => {
                    let capacity = self.arena.pages();
                    let next_capacity = capacity
                        .checked_mul(2)
                        .filter(|pages| *pages <= MAX_HOST_PAGE_TABLE_PAGES);
                    let Some(next_capacity) = next_capacity else {
                        return Err(HostPagingError::TableCapacityExceeded { capacity });
                    };
                    let next_arena = ResidentPages::allocate(next_capacity, AddressConstraint::Any)
                        .map_err(HostPagingError::Allocation)?;
                    let next_metadata = CloneMetadata::new(next_capacity)?;
                    self.arena = next_arena;
                    self.metadata = next_metadata;
                    self.report.arena_physical_address = self.arena.physical_address();
                    self.report.arena_pages = self.arena.pages();
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn report(&self) -> HostAddressSpaceReport {
        self.report
    }

    pub fn restore_source_cr3(&self) {
        if self.report.source_cr3 != 0 {
            unsafe {
                control_regs::write_cr3(self.report.source_cr3);
            }
        }
    }
}

struct CloneMetadata {
    source_pages: Vec<u64>,
    hash_slots: Vec<usize>,
}

impl CloneMetadata {
    fn new(capacity: usize) -> Result<Self, HostPagingError> {
        let mut source_pages = Vec::new();
        source_pages
            .try_reserve_exact(capacity)
            .map_err(|_| HostPagingError::Allocation(uefi::Status::OUT_OF_RESOURCES))?;
        let hash_capacity = capacity * 2;
        let mut hash_slots = Vec::new();
        hash_slots
            .try_reserve_exact(hash_capacity)
            .map_err(|_| HostPagingError::Allocation(uefi::Status::OUT_OF_RESOURCES))?;
        hash_slots.resize(hash_capacity, 0);

        Ok(Self {
            source_pages,
            hash_slots,
        })
    }
}

struct CloneState<'a> {
    arena: &'a mut ResidentPages,
    metadata: &'a mut CloneMetadata,
}

impl<'a> CloneState<'a> {
    fn new(arena: &'a mut ResidentPages, metadata: &'a mut CloneMetadata) -> Self {
        metadata.source_pages.clear();
        metadata.hash_slots.fill(0);
        Self { arena, metadata }
    }

    fn clone_table(&mut self, source_pa: u64, level: u8) -> Result<u64, HostPagingError> {
        let mut slot = ((source_pa >> 12).wrapping_mul(0x9e37_79b9_7f4a_7c15) as usize)
            & (self.metadata.hash_slots.len() - 1);
        loop {
            let entry = self.metadata.hash_slots[slot];
            if entry == 0 {
                break;
            }
            let index = entry - 1;
            if self.metadata.source_pages[index] == source_pa {
                return Ok(self.arena.physical_address() + (index * PAGE_SIZE) as u64);
            }
            slot = (slot + 1) & (self.metadata.hash_slots.len() - 1);
        }
        if self.metadata.source_pages.len() >= self.arena.pages() {
            return Err(HostPagingError::TableCapacityExceeded {
                capacity: self.arena.pages(),
            });
        }

        let index = self.metadata.source_pages.len();
        let cloned_pa = self.arena.physical_address() + (index * PAGE_SIZE) as u64;
        self.metadata.source_pages.push(source_pa);
        self.metadata.hash_slots[slot] = index + 1;

        unsafe {
            core::ptr::copy_nonoverlapping(
                source_pa as *const u64,
                cloned_pa as *mut u64,
                PAGE_TABLE_ENTRIES,
            );
        }

        if level == 1 {
            return Ok(cloned_pa);
        }

        for entry_index in 0..PAGE_TABLE_ENTRIES {
            let entry_pointer = (cloned_pa as *mut u64).wrapping_add(entry_index);
            let entry = unsafe { entry_pointer.read() };
            if entry & PAGE_PRESENT == 0 {
                continue;
            }
            if level <= 3 && entry & PAGE_LARGE != 0 {
                continue;
            }

            let child_source_pa = entry & PHYSICAL_ADDRESS_MASK;
            if child_source_pa == 0 {
                continue;
            }
            let child_cloned_pa = self.clone_table(child_source_pa, level - 1)?;
            let cloned_entry = (entry & !PHYSICAL_ADDRESS_MASK) | child_cloned_pa;
            unsafe {
                entry_pointer.write(cloned_entry);
            }
        }

        Ok(cloned_pa)
    }
}
