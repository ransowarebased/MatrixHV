pub mod loaders;
pub mod memory_map;
pub mod services;
pub mod uefi;

use crate::arch::x86_64::cpu::{self, Vendor};
use crate::runtime::serial;
use ::uefi::Status;

pub fn run() -> Result<(), Status> {
    uefi::initialize_boot_environment()?;

    let capabilities = cpu::capabilities();
    if capabilities.vendor != Vendor::Intel {
        log::error!("MatrixHV requires an Intel x86-64 processor");
        return Err(Status::UNSUPPORTED);
    }
    if !capabilities.vmx {
        log::error!("Intel VT-x is not exposed by CPUID");
        return Err(Status::UNSUPPORTED);
    }
    if !capabilities.feature_control_locked || !capabilities.vmx_outside_smx {
        log::error!("Firmware does not permit VMX operation outside SMX");
        return Err(Status::UNSUPPORTED);
    }

    log::info!("Intel VT-x is available and enabled by IA32_FEATURE_CONTROL");
    serial::write_line("MATRIXHV:VMX_CAPABILITY_OK");

    let memory = memory_map::snapshot()?;
    log::info!(
        "UEFI memory map ready: {} descriptors, {} conventional pages",
        memory.descriptor_count,
        memory.conventional_pages
    );
    serial::write_line("MATRIXHV:MEMORY_MAP_OK");

    loaders::veracrypt::start()
}
