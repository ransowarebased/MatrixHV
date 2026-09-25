use crate::arch::x86_64::control_regs;

use super::resident::{AddressConstraint, PAGE_SIZE, ResidentPages};

const PAGE_TABLE_ENTRIES: usize = 512;
const HOST_PAGE_TABLE_CAPACITY: usize = 256;
const PAGE_PRESENT: u64 = 1;
const PAGE_LARGE: u64 = 1 << 7;
const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const CR3_LOW_MASK: u64 = 0xfff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostPagingError {
    Allocation(uefi::Status),
    TableCapacityExceeded,
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
    report: HostAddressSpaceReport,
}

impl HostAddressSpace {
    pub fn reserve() -> Result<Self, HostPagingError> {
        let arena = ResidentPages::allocate(HOST_PAGE_TABLE_CAPACITY, AddressConstraint::Any)
            .map_err(HostPagingError::Allocation)?;
        Ok(Self {
            report: HostAddressSpaceReport {
                arena_physical_address: arena.physical_address(),
                arena_pages: arena.pages(),
                ..HostAddressSpaceReport::default()
            },
            arena,
        })
    }

    pub fn clone_current(&mut self) -> Result<HostAddressSpaceReport, HostPagingError> {
        let cr4 = control_regs::read_cr4();
        if cr4 & control_regs::CR4_LA57 != 0 {
            return Err(HostPagingError::UnsupportedLa57(cr4));
        }
        let source_cr3 = control_regs::read_cr3();
        let source_root = source_cr3 & PHYSICAL_ADDRESS_MASK;
        if source_root == 0 {
            return Err(HostPagingError::InvalidSourceRoot);
        }

        let mut state = CloneState::new(&mut self.arena);
        let host_root = state.clone_table(source_root, 4)?;
        let host_cr3 = host_root | (source_cr3 & CR3_LOW_MASK);
        self.report.source_cr3 = source_cr3;
        self.report.host_cr3 = host_cr3;
        self.report.table_pages = state.table_count;
        Ok(self.report)
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

struct CloneState<'a> {
    arena: &'a mut ResidentPages,
    source_pages: [u64; HOST_PAGE_TABLE_CAPACITY],
    cloned_pages: [u64; HOST_PAGE_TABLE_CAPACITY],
    table_count: usize,
}

impl<'a> CloneState<'a> {
    fn new(arena: &'a mut ResidentPages) -> Self {
        Self {
            arena,
            source_pages: [0; HOST_PAGE_TABLE_CAPACITY],
            cloned_pages: [0; HOST_PAGE_TABLE_CAPACITY],
            table_count: 0,
        }
    }

    fn clone_table(&mut self, source_pa: u64, level: u8) -> Result<u64, HostPagingError> {
        if let Some(existing) = self.find_clone(source_pa) {
            return Ok(existing);
        }
        if self.table_count >= HOST_PAGE_TABLE_CAPACITY {
            return Err(HostPagingError::TableCapacityExceeded);
        }

        let index = self.table_count;
        let cloned_pa = self.arena.physical_address() + (index * PAGE_SIZE) as u64;
        self.source_pages[index] = source_pa;
        self.cloned_pages[index] = cloned_pa;
        self.table_count += 1;

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

    fn find_clone(&self, source_pa: u64) -> Option<u64> {
        self.source_pages[..self.table_count]
            .iter()
            .position(|address| *address == source_pa)
            .map(|index| self.cloned_pages[index])
    }
}
