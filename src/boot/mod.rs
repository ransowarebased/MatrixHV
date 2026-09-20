pub mod config;
pub use crate::runtime::logger;
pub mod memory_map;
pub mod services;

use crate::arch::x86_64::cpu::{self, Vendor};
use crate::guest::{firmware, vcpu};
use crate::hv_core;
use crate::memory::resident;
use crate::smp::{startup, topology};
use ::uefi::Status;

pub fn run() -> Result<(), Status> {
    services::initialize_boot_environment()?;
    let image_residency = resident::image_residency()?;
    logger::info(format_args!(
        "residency image code_type={} data_type={}",
        image_residency.code_type.0, image_residency.data_type.0
    ));
    logger::phase("vmx.residency.image_type.observed");

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

    logger::phase("smp.topology.start");
    let topology_report = match topology::enumerate() {
        Ok(report) => {
            logger::info(format_args!(
                "smp topology total={} enabled={} current={} bsp={} first_enabled_ap={:?}",
                report.total_processors,
                report.enabled_processors,
                report.current_processor,
                report.bsp_processor,
                report.first_enabled_ap
            ));
            logger::phase("smp.topology.ok");
            Some(report)
        }
        Err(status) => {
            logger::error(format_args!("smp topology status={status:?}"));
            logger::phase("smp.topology.unavailable");
            None
        }
    };

    if let Some(processor_number) = topology_report.and_then(|report| report.first_enabled_ap) {
        logger::phase("smp.cpu1_vmx.start");
        match startup::prove_application_processor_vmx(processor_number) {
            Ok(report) => {
                logger::info(format_args!(
                    "smp cpu1 vmx proof processor={} id={:#x} apic_id={:#x} vmxon={:#x} vmcs={:#x} guest_stack={:#x} bsp_vmxon={:#x} bsp_vmcs={:#x} bsp_guest_stack={:#x}",
                    report.processor_number,
                    report.processor_id,
                    report.initial_state.apic_id,
                    report.ap_resources.vmxon,
                    report.ap_resources.vmcs,
                    report.ap_resources.guest_stack,
                    report.bsp_resources.vmxon,
                    report.bsp_resources.vmcs,
                    report.bsp_resources.guest_stack
                ));
                logger::info(format_args!(
                    "smp cpu1 vmx state cr0={:#x}->{:#x} cr3={:#x}->{:#x} cr4={:#x}->{:#x} rflags={:#x}->{:#x} exit_reason={:#x} vmxon_report_pa={:#x} vmcs_report_pa={:#x}",
                    report.initial_state.cr0,
                    report.final_state.cr0,
                    report.initial_state.cr3,
                    report.final_state.cr3,
                    report.initial_state.cr4,
                    report.final_state.cr4,
                    report.initial_state.rflags,
                    report.final_state.rflags,
                    report.vmlaunch.exit_reason,
                    report.vmlaunch.vmxon.region_physical_address,
                    report.vmlaunch.vmcs_physical_address
                ));
                logger::phase("smp.cpu1_vmx.ok");
            }
            Err(error) => {
                logger::error(format_args!("smp cpu1 vmx error={error:?}"));
                logger::phase("smp.cpu1_vmx.failed");
                return Err(Status::DEVICE_ERROR);
            }
        }
    } else {
        logger::phase("smp.cpu1_vmx.skipped");
    }

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
    match hv_core::vt_vmxon::probe_vmxon() {
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
    match hv_core::vt_vmcs::probe_vmcs() {
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
    match hv_core::vt_entry::probe_vmlaunch() {
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

    logger::phase("vmx.dispatch_probe.start");
    match hv_core::vt_entry::probe_vmexit_dispatcher() {
        Ok(report) => {
            let diagnostics = report.diagnostics;
            logger::info(format_args!(
                "dispatcher proof vmcs_pa={:#x} exits={} cpuid={} vmcall={} resumes={} failure={} cpuid_input={:#x}/{:#x} cpuid_rip={:#x}/{:#x} vmcall_rip={:#x}/{:#x}",
                report.vmcs_physical_address,
                diagnostics.exit_count,
                diagnostics.cpuid_count,
                diagnostics.vmcall_count,
                diagnostics.resume_count,
                diagnostics.failure_code,
                diagnostics.cpuid_leaf,
                diagnostics.cpuid_subleaf,
                diagnostics.cpuid_rip,
                report.cpuid_rip_expected,
                diagnostics.vmcall_rip,
                report.vmcall_rip_expected
            ));
            logger::info(format_args!(
                "dispatcher guest-state cpuid eax={:#x} ebx={:#x} ecx={:#x} edx={:#x} final eax={:#x} ebx={:#x} ecx={:#x} edx={:#x} rsp={:#x}/{:#x}",
                diagnostics.cpuid_eax,
                diagnostics.cpuid_ebx,
                diagnostics.cpuid_ecx,
                diagnostics.cpuid_edx,
                diagnostics.final_eax,
                diagnostics.final_ebx,
                diagnostics.final_ecx,
                diagnostics.final_edx,
                diagnostics.final_rsp,
                report.guest.rsp
            ));
            logger::info(format_args!(
                "dispatcher host/guest vmxon_pa={:#x} host_tr={:#x} guest_rip={:#x} primary={:#x} secondary={:#x}",
                report.vmxon.region_physical_address,
                report.host.tr_selector,
                report.guest.rip,
                report.controls.primary_processor_based,
                report.controls.secondary_processor_based
            ));
            logger::phase("vmx.dispatch_probe.ok");
        }
        Err(error) => {
            log::error!("VM-exit dispatcher probe failed: {error:?}");
            logger::error(format_args!("dispatcher error={error:?}"));
            logger::phase("vmx.dispatch_probe.failed");
            return Err(Status::DEVICE_ERROR);
        }
    }

    logger::phase("vmx.resident_host_probe.start");
    match hv_core::vt_resident::probe() {
        Ok(report) => {
            logger::info(format_args!(
                "resident_host code_pa={:#x}/{} code_type={} data_type={} host_cr3={:#x} guest_cr3={:#x} observed_host_cr3={:#x} observed_guest_cr3={:#x}",
                report.code_physical_address,
                report.code_pages,
                report.code_memory_type,
                report.data_memory_type,
                report.host_cr3,
                report.guest_cr3,
                report.observed_host_cr3,
                report.observed_guest_cr3
            ));
            logger::info(format_args!(
                "resident_host exit_reason={:#x} guest_rip={:#x} gdt={:#x} idt={:#x} tss={:#x} host_stack={:#x}",
                report.exit_reason,
                report.guest_rip,
                report.host_gdt,
                report.host_idt,
                report.host_tss,
                report.host_stack
            ));
            logger::phase("vmx.resident_host_probe.ok");
        }
        Err(error) => {
            logger::error(format_args!("resident_host error={error:?}"));
            logger::phase("vmx.resident_host_probe.failed");
            return Err(hv_core::vt_resident::status_from_error(&error));
        }
    }

    firmware::reset_report();
    logger::phase("vmx.real_boot_vcpu.start");
    let vcpu_report = match vcpu::run(firmware::entry_address()) {
        Ok(report) => report,
        Err(error) => {
            log::error!("Persistent boot vCPU failed: {error:?}");
            logger::error(format_args!("real_boot_vcpu error={error:?}"));
            logger::phase("vmx.real_boot_vcpu.failed");
            return Err(vcpu::status_from_error(&error));
        }
    };
    let vcpu_diagnostics = vcpu_report.diagnostics;
    let boot_stage = firmware::report();
    logger::info(format_args!(
        "real_boot_vcpu result={:#x} result_name={} exits={} cpuid={} rdmsr={} wrmsr={} vmcall={} resumes={} failure={} guest_rsp={:#x}/{:#x} guest_rflags={:#x} initial_rflags={:#x}",
        vcpu_report.result,
        firmware::result_name(vcpu_report.result),
        vcpu_diagnostics.exit_count,
        vcpu_diagnostics.cpuid_count,
        vcpu_diagnostics.rdmsr_count,
        vcpu_diagnostics.wrmsr_count,
        vcpu_diagnostics.vmcall_count,
        vcpu_diagnostics.resume_count,
        vcpu_diagnostics.failure_code,
        vcpu_diagnostics.final_rsp,
        vcpu_report.guest.rsp,
        vcpu_report.guest.rflags,
        vcpu_report.initial_rflags
    ));
    logger::info(format_args!(
        "real_boot_vcpu firmware_report magic={:#x} version={} flags={:#x} status={:#x} handles={} required={}",
        boot_stage.magic,
        boot_stage.version,
        boot_stage.flags,
        boot_stage.status,
        boot_stage.handle_count,
        boot_stage.required_count
    ));
    logger::info(format_args!(
        "real_boot_vcpu vmcs_pa={:#x} vmxon_pa={:#x} host_tr={:#x} primary={:#x} secondary={:#x}",
        vcpu_report.vmcs_physical_address,
        vcpu_report.vmxon.region_physical_address,
        vcpu_report.host.tr_selector,
        vcpu_report.controls.primary_processor_based,
        vcpu_report.controls.secondary_processor_based
    ));
    logger::info(format_args!(
        "real_boot_vcpu address_space source_cr3={:#x} guest_initial_cr3={:#x} host_cr3={:#x} observed_host_cr3={:#x}/{:#x} last_guest_cr3={:#x} host_pt_arena={:#x}/{} host_pt_used={}",
        vcpu_report.host_address_space.source_cr3,
        vcpu_report.guest.cr3,
        vcpu_report.host.cr3,
        vcpu_diagnostics.first_host_cr3,
        vcpu_diagnostics.last_host_cr3,
        vcpu_diagnostics.last_guest_cr3,
        vcpu_report.host_address_space.arena_physical_address,
        vcpu_report.host_address_space.arena_pages,
        vcpu_report.host_address_space.table_pages
    ));
    logger::phase("vmx.host_address_space.ok");

    let root_handle_count = services::simple_file_system_count()?;
    let root_windows_present = services::windows_boot_present()?;
    logger::info(format_args!(
        "real_boot_vcpu crosscheck guest_handles={} root_handles={} root_windows_present={}",
        boot_stage.handle_count, root_handle_count, root_windows_present
    ));
    if vcpu_report.result != firmware::BOOT_STAGE_WINDOWS_IMAGE_LOAD_OK
        || !firmware::proof_complete(boot_stage)
        || usize::try_from(boot_stage.handle_count).ok() != Some(root_handle_count)
        || !root_windows_present
    {
        logger::phase("vmx.real_boot_vcpu.crosscheck_failed");
        return Err(Status::DEVICE_ERROR);
    }
    logger::phase("vmx.real_boot_vcpu.ok");

    logger::phase("vmx.residency_events.arm.start");
    let residency_events = match hv_core::vt_resident::arm_residency_events() {
        Ok(report) => {
            logger::info(format_args!(
                "residency_events code_pa={:#x} context_pa={:#x} code_type={} data_type={} ebs_event={:#x} va_event={:#x}",
                report.code_physical_address,
                report.context_physical_address,
                report.code_memory_type,
                report.data_memory_type,
                report.exit_boot_services_event,
                report.virtual_address_change_event
            ));
            logger::phase("vmx.residency_events.armed");
            report
        }
        Err(error) => {
            logger::error(format_args!("residency_events error={error:?}"));
            logger::phase("vmx.residency_events.failed");
            return Err(hv_core::vt_resident::status_from_error(&error));
        }
    };

    firmware::reset_report();
    logger::phase("vmx.windows_start_vcpu.start");
    logger::info(format_args!(
        "windows_start_vcpu entry={:#x} residency_context={:#x}",
        firmware::start_entry_address(),
        residency_events.context_physical_address
    ));
    match hv_core::vt_resident::run_windows_boot(
        firmware::start_entry_address(),
        residency_events.context_physical_address,
        firmware::ept_probe_fault_address(),
        firmware::ept_probe_resume_address(),
    ) {
        Ok(report) => {
            logger::error(format_args!(
                "windows_start_vcpu returned unexpectedly raw_path={} vm_instruction_error={:#x} host_cr3={:#x} guest_cr3={:#x} exits={} cpuid={} rdmsr={} wrmsr={} xsetbv={} vmcall={} checkpoint={} post_start={} post_ebs={} post_va={} ept_test={} last_reason={:#x} len={} qual={:#x} gpa={:#x} rip={:#x} last_guest_cr3={:#x} last_host_cr3={:#x} stop_result={:#x}",
                report.raw_path,
                report.vm_instruction_error,
                report.host_cr3,
                report.initial_guest_cr3,
                report.exit_count,
                report.cpuid_count,
                report.rdmsr_count,
                report.wrmsr_count,
                report.xsetbv_count,
                report.vmcall_count,
                report.start_checkpoint_seen,
                report.post_start_exit_count,
                report.post_ebs_exit_count,
                report.post_va_exit_count,
                report.ept_test_violation_seen,
                report.last_reason,
                report.last_instruction_len,
                report.last_qualification,
                report.last_guest_physical_address,
                report.last_guest_rip,
                report.last_guest_cr3,
                report.last_host_cr3,
                report.stop_result
            ));
            logger::phase("vmx.windows_start_vcpu.unexpected_return");
            Err(Status::DEVICE_ERROR)
        }
        Err(error) => {
            logger::error(format_args!("windows_start_vcpu error={error:?}"));
            logger::phase("vmx.windows_start_vcpu.failed");
            logger::phase("boot.native_fallback.after_vmlaunch_failure");
            services::start_loader()
        }
    }
}
