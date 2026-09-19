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

    logger::phase("vmx.vmlaunch_probe.start");
    match hv_core::vt_init::probe_vmlaunch() {
        Ok(report) => {
            logger::info(format_args!(
                "vmlaunch proof vmcs_pa={:#x} exit_reason={:#x} qualification={:#x} instruction_len={} guest_rip_after_exit={:#x}",
                report.vmcs_physical_address,
                report.exit_reason,
                report.exit_qualification,
                report.exit_instruction_length,
                report.guest_rip_after_exit
            ));
            logger::info(format_args!(
                "vmlaunch proof vmxon_pa={:#x} host_cs={:#x} host_tr={:#x} guest_cs={:#x} guest_tr={:#x} controls primary={:#x} exit={:#x} entry={:#x}",
                report.vmxon.region_physical_address,
                report.host.cs_selector,
                report.host.tr_selector,
                report.guest.cs_selector,
                report.guest.tr_selector,
                report.controls.primary_processor_based,
                report.controls.vm_exit,
                report.controls.vm_entry
            ));
            logger::phase("vmx.vmlaunch_probe.ok");
        }
        Err(error) => {
            log::error!("VMLAUNCH probe failed: {error:?}");
            logger::error(format_args!("vmlaunch error={error:?}"));
            logger::phase("vmx.vmlaunch_probe.failed");
            return Err(Status::DEVICE_ERROR);
        }
    }

    loaders::veracrypt::start()
}
