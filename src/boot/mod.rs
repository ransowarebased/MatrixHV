pub mod config;
pub mod loaders;
pub mod logger;
pub mod matrix_config;
pub mod memory_map;
pub mod services;
pub mod uefi;

use crate::arch::x86_64::cpu::{self, Vendor};
use crate::hv_core;
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
    logger::phase("vmx.capability.ok");

    let memory = memory_map::snapshot()?;
    log::info!(
        "UEFI memory map ready: {} descriptors, {} conventional pages",
        memory.descriptor_count,
        memory.conventional_pages
    );
    logger::info(format_args!(
        "memory_map descriptors={} conventional_pages={}",
        memory.descriptor_count, memory.conventional_pages
    ));
    logger::phase("uefi.memory_map.ok");

    logger::phase("vmx.vmxon.start");
    match hv_core::vt_init::probe_vmxon() {
        Ok(report) => {
            log::info!(
                "VMXON probe succeeded: revision={:#x}, region_size={}, region_pa={:#x}, cr0={:#x}->{:#x}, cr4={:#x}->{:#x}",
                report.revision_id,
                report.region_size,
                report.region_physical_address,
                report.original_cr0,
                report.vmx_cr0,
                report.original_cr4,
                report.vmx_cr4
            );
            logger::info(format_args!(
                "vmxon revision={:#x} region_size={} region_pa={:#x} cr0={:#x}->{:#x} cr4={:#x}->{:#x}",
                report.revision_id,
                report.region_size,
                report.region_physical_address,
                report.original_cr0,
                report.vmx_cr0,
                report.original_cr4,
                report.vmx_cr4
            ));
            logger::phase("vmx.vmxon.ok");
        }
        Err(error) => {
            log::error!("VMXON probe failed: {error:?}");
            logger::error(format_args!("vmxon error={error:?}"));
            logger::phase("vmx.vmxon.failed");
            return Err(Status::DEVICE_ERROR);
        }
    }

    logger::phase("vmx.vmcs.start");
    match hv_core::vt_init::probe_vmcs() {
        Ok(report) => {
            logger::info(format_args!(
                "vmcs revision={:#x} region_pa={:#x} current_pa={:#x} instruction_error={} vmxon_pa={:#x}",
                report.revision_id,
                report.region_physical_address,
                report.current_vmcs_physical_address,
                report.instruction_error,
                report.vmxon.region_physical_address
            ));
            logger::phase("vmx.vmcs.ok");
        }
        Err(error) => {
            log::error!("VMCS probe failed: {error:?}");
            logger::error(format_args!("vmcs error={error:?}"));
            logger::phase("vmx.vmcs.failed");
            return Err(Status::DEVICE_ERROR);
        }
    }

    loaders::veracrypt::start()
}
