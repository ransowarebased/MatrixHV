use uefi::mem::memory_map::MemoryMapOwned;

pub unsafe fn exit_for_hypervisor() -> MemoryMapOwned {
    unsafe { uefi::boot::exit_boot_services(None) }
}
