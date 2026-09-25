use uefi::Status;
use uefi::boot;
use uefi::mem::memory_map::{MemoryMap, MemoryType};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryMapSummary {
    pub descriptor_count: usize,
    pub conventional_pages: u64,
}

pub fn snapshot() -> Result<MemoryMapSummary, Status> {
    let memory_map = boot::memory_map(MemoryType::LOADER_DATA).map_err(|error| error.status())?;
    let descriptor_count = memory_map.entries().count();
    let conventional_pages = memory_map
        .entries()
        .filter(|descriptor| descriptor.ty == MemoryType::CONVENTIONAL)
        .map(|descriptor| descriptor.page_count)
        .sum();

    Ok(MemoryMapSummary {
        descriptor_count,
        conventional_pages,
    })
}
