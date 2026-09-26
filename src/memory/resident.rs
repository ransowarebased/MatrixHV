use core::ptr::NonNull;

use uefi::Status;
use uefi::boot::{self, AllocateType};
use uefi::mem::memory_map::MemoryType;
use uefi::proto::loaded_image::LoadedImage;

pub const PAGE_SIZE: usize = 4096;
pub const RESIDENT_MEMORY_TYPE: MemoryType = MemoryType::RESERVED;
pub const RESIDENT_EVENT_MEMORY_TYPE: MemoryType = MemoryType::RUNTIME_SERVICES_DATA;
pub const RESIDENT_CODE_MEMORY_TYPE: MemoryType = MemoryType::RUNTIME_SERVICES_CODE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressConstraint {
    Any,
    Max(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageResidencyReport {
    pub code_type: MemoryType,
    pub data_type: MemoryType,
}

pub struct ResidentPages {
    pointer: NonNull<u8>,
    pages: usize,
    release_on_drop: bool,
}

impl ResidentPages {
    pub fn allocate(pages: usize, constraint: AddressConstraint) -> Result<Self, Status> {
        Self::allocate_typed(pages, constraint, RESIDENT_MEMORY_TYPE)
    }

    pub fn allocate_typed(
        pages: usize,
        constraint: AddressConstraint,
        memory_type: MemoryType,
    ) -> Result<Self, Status> {
        if crate::hv_core::vt_resident::boot_services_exited() {
            return Err(Status::UNSUPPORTED);
        }
        let allocate_type = match constraint {
            AddressConstraint::Any => AllocateType::AnyPages,
            AddressConstraint::Max(address) => AllocateType::MaxAddress(address),
        };
        let pointer = boot::allocate_pages(allocate_type, memory_type, pages)
            .map_err(|error| error.status())?;
        unsafe {
            pointer.as_ptr().write_bytes(0, PAGE_SIZE * pages);
        }
        Ok(Self {
            pointer,
            pages,
            release_on_drop: true,
        })
    }

    pub fn pointer(&self) -> NonNull<u8> {
        self.pointer
    }

    pub fn physical_address(&self) -> u64 {
        self.pointer.as_ptr() as u64
    }

    pub fn pages(&self) -> usize {
        self.pages
    }

    pub fn byte_len(&self) -> usize {
        PAGE_SIZE * self.pages
    }

    pub fn preserve(&mut self) {
        self.release_on_drop = false;
    }
}

impl Drop for ResidentPages {
    fn drop(&mut self) {
        if self.release_on_drop && !crate::hv_core::vt_resident::boot_services_exited() {
            unsafe {
                let _ = boot::free_pages(self.pointer, self.pages);
            }
        }
    }
}

pub fn image_residency() -> Result<ImageResidencyReport, Status> {
    let image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
        .map_err(|error| error.status())?;
    Ok(ImageResidencyReport {
        code_type: image.code_type(),
        data_type: image.data_type(),
    })
}
