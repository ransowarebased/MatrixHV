pub mod config;
pub mod firmware;
pub mod guest;
pub mod smp;

use crate::arch::{self, Vendor};
use crate::boot::guest::BootTargetKind;
use crate::diagnostics;
use crate::logging;
use crate::vmx;
use uefi::Status;

pub fn run(options: config::MatrixConfig) -> Result<(), Status> {
    diagnostics::stage("UEFI boot services");
    firmware::initialize_boot_environment()?;
    diagnostics::stage("image residency");
    let image_residency = firmware::image_residency()?;
    logging::info(format_args!(
        "residency image code_type={} data_type={}",
        image_residency.code_type.0, image_residency.data_type.0
    ));
    logging::phase("vmx.residency.image_type.observed");

    diagnostics::stage("Intel VMX capability");
    let capabilities = arch::capabilities();
    if capabilities.vendor != Vendor::Intel {
        log::error!("MatrixHV requires an Intel x86-64 processor");
        diagnostics::error(format_args!("Intel processor required"));
        return Err(Status::UNSUPPORTED);
    }
    if !capabilities.vmx {
        log::error!("Intel VT-x is not exposed by CPUID");
        diagnostics::error(format_args!("VMX not exposed by CPUID"));
        return Err(Status::UNSUPPORTED);
    }
    if !capabilities.feature_control_locked || !capabilities.vmx_outside_smx {
        log::error!("Firmware does not permit VMX operation outside SMX");
        diagnostics::error(format_args!("firmware blocks VMX outside SMX"));
        return Err(Status::UNSUPPORTED);
    }

    log::info!("Intel VT-x is available and enabled by IA32_FEATURE_CONTROL");
    logging::phase("vmx.capability.ok");

    diagnostics::stage("processor topology");
    logging::phase("smp.topology.start");
    let topology_report = match smp::enumerate() {
        Ok(report) => {
            logging::info(format_args!(
                "smp topology total={} enabled={} current={} bsp={} first_enabled_ap={:?}",
                report.total_processors,
                report.enabled_processors,
                report.current_processor,
                report.bsp_processor,
                report.first_enabled_ap
            ));
            logging::phase("smp.topology.ok");
            Some(report)
        }
        Err(status) => {
            logging::error(format_args!("smp topology status={status:?}"));
            logging::phase("smp.topology.unavailable");
            diagnostics::message(format_args!("topology unavailable: {status:?}"));
            None
        }
    };

    if let Some(processor_number) = topology_report.and_then(|report| report.first_enabled_ap) {
        diagnostics::stage("AP VMX proof");
        logging::phase("smp.cpu1_vmx.start");
        match smp::prove_application_processor_vmx(processor_number) {
            Ok(report) => {
                logging::info(format_args!(
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
                logging::info(format_args!(
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
                logging::phase("smp.cpu1_vmx.ok");
            }
            Err(error) => {
                logging::error(format_args!("smp cpu1 vmx error={error:?}"));
                logging::phase("smp.cpu1_vmx.failed");
                diagnostics::error(format_args!("AP VMX proof: {error:?}"));
                return Err(Status::DEVICE_ERROR);
            }
        }
    } else {
        diagnostics::message(format_args!("AP VMX proof skipped"));
        logging::phase("smp.cpu1_vmx.skipped");
    }

    diagnostics::stage("UEFI memory map");
    let memory = firmware::memory_map::snapshot()?;
    log::info!(
        "UEFI memory map ready: {} descriptors, {} conventional pages",
        memory.descriptor_count,
        memory.conventional_pages
    );
    logging::info(format_args!(
        "memory_map descriptors={} conventional_pages={}",
        memory.descriptor_count, memory.conventional_pages
    ));
    logging::phase("uefi.memory_map.ok");

    if options.vmx_test {
        diagnostics::stage("VMXON proof");
        logging::phase("vmx.vmxon.start");
        match vmx::vmxon::probe_vmxon() {
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
                logging::info(format_args!(
                    "vmxon revision={:#x} region_size={} region_pa={:#x} cr0={:#x}->{:#x} cr4={:#x}->{:#x}",
                    report.revision_id,
                    report.region_size,
                    report.region_physical_address,
                    report.original_cr0,
                    report.vmx_cr0,
                    report.original_cr4,
                    report.vmx_cr4
                ));
                logging::phase("vmx.vmxon.ok");
            }
            Err(error) => {
                log::error!("VMXON probe failed: {error:?}");
                logging::error(format_args!("vmxon error={error:?}"));
                logging::phase("vmx.vmxon.failed");
                diagnostics::error(format_args!("VMXON proof: {error:?}"));
                return Err(Status::DEVICE_ERROR);
            }
        }

        diagnostics::stage("VMCS proof");
        logging::phase("vmx.vmcs.start");
        match vmx::vmcs::probe_vmcs() {
            Ok(report) => {
                logging::info(format_args!(
                    "vmcs revision={:#x} region_pa={:#x} current_pa={:#x} instruction_error={} vmxon_pa={:#x}",
                    report.revision_id,
                    report.region_physical_address,
                    report.current_vmcs_physical_address,
                    report.instruction_error,
                    report.vmxon.region_physical_address
                ));
                logging::phase("vmx.vmcs.ok");
            }
            Err(error) => {
                log::error!("VMCS probe failed: {error:?}");
                logging::error(format_args!("vmcs error={error:?}"));
                logging::phase("vmx.vmcs.failed");
                diagnostics::error(format_args!("VMCS proof: {error:?}"));
                return Err(Status::DEVICE_ERROR);
            }
        }

        diagnostics::stage("VMLAUNCH proof");
        logging::phase("vmx.vmlaunch_probe.start");
        match vmx::entry::probe_vmlaunch() {
            Ok(report) => {
                logging::info(format_args!(
                    "vmlaunch proof vmcs_pa={:#x} exit_reason={:#x} qualification={:#x} instruction_len={} guest_rip_after_exit={:#x}",
                    report.vmcs_physical_address,
                    report.exit_reason,
                    report.exit_qualification,
                    report.exit_instruction_length,
                    report.guest_rip_after_exit
                ));
                logging::info(format_args!(
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
                logging::phase("vmx.vmlaunch_probe.ok");
            }
            Err(error) => {
                log::error!("VMLAUNCH probe failed: {error:?}");
                logging::error(format_args!("vmlaunch error={error:?}"));
                logging::phase("vmx.vmlaunch_probe.failed");
                diagnostics::error(format_args!("VMLAUNCH proof: {error:?}"));
                return Err(Status::DEVICE_ERROR);
            }
        }

        diagnostics::stage("VM-exit dispatcher proof");
        logging::phase("vmx.dispatch_probe.start");
        match vmx::entry::probe_vmexit_dispatcher() {
            Ok(report) => {
                let diagnostics = report.diagnostics;
                logging::info(format_args!(
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
                logging::info(format_args!(
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
                logging::info(format_args!(
                    "dispatcher host/guest vmxon_pa={:#x} host_tr={:#x} guest_rip={:#x} primary={:#x} secondary={:#x}",
                    report.vmxon.region_physical_address,
                    report.host.tr_selector,
                    report.guest.rip,
                    report.controls.primary_processor_based,
                    report.controls.secondary_processor_based
                ));
                logging::phase("vmx.dispatch_probe.ok");
            }
            Err(error) => {
                log::error!("VM-exit dispatcher probe failed: {error:?}");
                logging::error(format_args!("dispatcher error={error:?}"));
                logging::phase("vmx.dispatch_probe.failed");
                diagnostics::error(format_args!("VM-exit dispatcher: {error:?}"));
                return Err(Status::DEVICE_ERROR);
            }
        }
    } else {
        logging::phase("vmx.preboot_probes.skipped");
    }

    diagnostics::stage("resident host proof");
    logging::phase("vmx.resident_host_probe.start");
    match vmx::entry::probe_residency() {
        Ok(report) => {
            diagnostics::message(format_args!(
                "resident host tables={}/{}",
                report.host_table_pages, report.host_table_capacity
            ));
            logging::info(format_args!(
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
            logging::info(format_args!(
                "resident_host exit_reason={:#x} guest_rip={:#x} gdt={:#x} idt={:#x} tss={:#x} host_stack={:#x}",
                report.exit_reason,
                report.guest_rip,
                report.host_gdt,
                report.host_idt,
                report.host_tss,
                report.host_stack
            ));
            logging::phase("vmx.resident_host_probe.ok");
        }
        Err(error) => {
            logging::error(format_args!("resident_host error={error:?}"));
            logging::phase("vmx.resident_host_probe.failed");
            diagnostics::error(format_args!("resident host: {error:?}"));
            return Err(vmx::resident::status_from_error(&error));
        }
    }

    let vcpu_proof = if options.vmx_test {
        diagnostics::stage("guest UEFI loader proof");
        guest::reset_report();
        logging::phase("vmx.real_boot_vcpu.start");
        let vcpu_report = match vmx::vcpu::run(guest::entry_address()) {
            Ok(report) => report,
            Err(error) => {
                log::error!("Persistent boot vCPU failed: {error:?}");
                logging::error(format_args!("real_boot_vcpu error={error:?}"));
                logging::phase("vmx.real_boot_vcpu.failed");
                diagnostics::error(format_args!("guest UEFI loader: {error:?}"));
                return Err(vmx::vcpu::status_from_error(&error));
            }
        };
        let vcpu_diagnostics = vcpu_report.diagnostics;
        let boot_stage = guest::report();
        diagnostics::message(format_args!(
            "guest result={} flags={:#x} status={:#x} handles={}",
            guest::result_name(vcpu_report.result),
            boot_stage.flags,
            boot_stage.status,
            boot_stage.handle_count
        ));
        logging::info(format_args!(
            "real_boot_vcpu result={:#x} result_name={} exits={} cpuid={} rdmsr={} wrmsr={} vmcall={} resumes={} failure={} guest_rsp={:#x}/{:#x} guest_rflags={:#x} initial_rflags={:#x}",
            vcpu_report.result,
            guest::result_name(vcpu_report.result),
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
        logging::info(format_args!(
            "real_boot_vcpu firmware_report magic={:#x} version={} flags={:#x} status={:#x} handles={} required={}",
            boot_stage.magic,
            boot_stage.version,
            boot_stage.flags,
            boot_stage.status,
            boot_stage.handle_count,
            boot_stage.required_count
        ));
        logging::info(format_args!(
            "real_boot_vcpu vmcs_pa={:#x} vmxon_pa={:#x} host_tr={:#x} primary={:#x} secondary={:#x}",
            vcpu_report.vmcs_physical_address,
            vcpu_report.vmxon.region_physical_address,
            vcpu_report.host.tr_selector,
            vcpu_report.controls.primary_processor_based,
            vcpu_report.controls.secondary_processor_based
        ));
        logging::info(format_args!(
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
        logging::phase("vmx.host_address_space.ok");
        Some((vcpu_report, boot_stage))
    } else {
        logging::phase("vmx.real_boot_vcpu.skipped");
        None
    };

    diagnostics::stage("root UEFI target lookup");
    let root_handle_count = firmware::simple_file_system_count()?;
    let root_boot_target = guest::find_boot_target(options.vmx_test)?;
    let root_boot_target_present = root_boot_target.is_some();
    if let Some(target) = root_boot_target {
        diagnostics::message(format_args!(
            "target={} path={}",
            target.kind.name(),
            target.path
        ));
        logging::info(format_args!(
            "boot target verified kind={} path={}",
            target.kind.name(),
            target.path
        ));
    }
    if root_boot_target.is_none() {
        diagnostics::error(format_args!(
            "no VeraCrypt, Ubuntu, or Windows loader found"
        ));
    }
    diagnostics::stage("NVRAM BootOrder scan");
    let nvram_boot_option = if options.vmx_test {
        None
    } else {
        match firmware::find_veracrypt_boot_option() {
            Ok(option) => option,
            Err(status) => {
                logging::error(format_args!("NVRAM scan unavailable: {status:?}"));
                None
            }
        }
    };
    if let Some((vcpu_report, boot_stage)) = vcpu_proof {
        logging::info(format_args!(
            "real_boot_vcpu crosscheck guest_handles={} root_handles={} root_boot_target_present={}",
            boot_stage.handle_count, root_handle_count, root_boot_target_present
        ));
        if vcpu_report.result != guest::BOOT_STAGE_TARGET_IMAGE_LOAD_OK
            || !guest::proof_complete(boot_stage)
            || usize::try_from(boot_stage.handle_count).ok() != Some(root_handle_count)
            || !root_boot_target_present
        {
            logging::phase("vmx.real_boot_vcpu.crosscheck_failed");
            diagnostics::error(format_args!(
                "guest crosscheck result={} flags={:#x} guest_handles={} root_handles={} target={}",
                guest::result_name(vcpu_report.result),
                boot_stage.flags,
                boot_stage.handle_count,
                root_handle_count,
                root_boot_target_present
            ));
            return Err(Status::DEVICE_ERROR);
        }
        logging::phase("vmx.real_boot_vcpu.ok");
    }

    diagnostics::stage("resident event setup");
    logging::phase("vmx.residency_events.arm.start");
    let residency_events = match vmx::resident::arm_residency_events() {
        Ok(report) => {
            logging::info(format_args!(
                "residency_events code_pa={:#x} context_pa={:#x} code_type={} data_type={} ebs_event={:#x} va_event={:#x}",
                report.code_physical_address,
                report.context_physical_address,
                report.code_memory_type,
                report.data_memory_type,
                report.exit_boot_services_event,
                report.virtual_address_change_event
            ));
            logging::phase("vmx.residency_events.armed");
            report
        }
        Err(error) => {
            logging::error(format_args!("residency_events error={error:?}"));
            logging::phase("vmx.residency_events.failed");
            diagnostics::error(format_args!("resident events: {error:?}"));
            return Err(vmx::resident::status_from_error(&error));
        }
    };

    diagnostics::stage("preload boot target");
    let target = root_boot_target.ok_or(Status::NOT_FOUND)?;
    let original_veracrypt_path =
        target.kind == BootTargetKind::VeraCrypt && nvram_boot_option.is_some();
    let child_handle = if original_veracrypt_path {
        let option = nvram_boot_option.as_ref().ok_or(Status::NOT_FOUND)?;
        logging::info(format_args!(
            "LoadImage Boot{:04X} original path bytes={}",
            option.number,
            option.image_path_size()
        ));
        match firmware::load_veracrypt_boot_option(option) {
            Ok(handle) => handle,
            Err(status) => {
                diagnostics::error(format_args!(
                    "LoadImage Boot{:04X}: {status:?}",
                    option.number
                ));
                return Err(status);
            }
        }
    } else {
        diagnostics::message(format_args!("LoadImage fallback path={}", target.path));
        let target_volume = firmware::find_image_volume(target.path)?.ok_or(Status::NOT_FOUND)?;
        firmware::load_image_on_volume(target_volume, target.path)?
    };
    diagnostics::message(format_args!(
        "LoadImage handle={:#x}",
        child_handle.as_ptr() as usize
    ));
    let nvram_options = if original_veracrypt_path {
        nvram_boot_option
            .as_ref()
            .map(|option| option.optional_data())
    } else {
        None
    };
    diagnostics::message(format_args!(
        "boot load options bytes={}",
        nvram_options.map_or(0, <[u8]>::len)
    ));
    if let Err(status) = firmware::configure_image_load_options(
        child_handle,
        guest::image_load_options(options.vmx_test, nvram_options),
    ) {
        let _ = ::uefi::boot::unload_image(child_handle);
        diagnostics::error(format_args!("boot target load options: {status:?}"));
        return Err(status);
    }
    diagnostics::message(format_args!(
        "preloaded boot target={} original_nvram_path={}",
        target.kind.name(),
        original_veracrypt_path
    ));

    diagnostics::stage("start target under MatrixHV");
    guest::reset_report();
    guest::set_start_image_handle(child_handle);
    diagnostics::message(format_args!(
        "resident entry={:#x} context={:#x} EPT probe={:#x}",
        guest::start_entry_address(),
        residency_events.context_physical_address,
        guest::ept_probe_fault_address()
    ));
    logging::phase("vmx.boot_loader_start_vcpu.start");
    if let Some(target) = root_boot_target {
        diagnostics::message(format_args!("chainload target={}", target.kind.name()));
        logging::info(format_args!(
            "boot target chainload kind={} path={}",
            target.kind.name(),
            target.path
        ));
    }
    logging::info(format_args!(
        "boot_loader_start_vcpu entry={:#x} residency_context={:#x}",
        guest::start_entry_address(),
        residency_events.context_physical_address
    ));
    match vmx::resident::boot::run_boot_loader(
        options,
        guest::start_entry_address(),
        residency_events.context_physical_address,
        guest::ept_probe_fault_address(),
        guest::ept_probe_resume_address(),
    ) {
        Ok(report) => {
            let guest_report = guest::report();
            diagnostics::error(format_args!(
                "boot vCPU returned: reason={:#x} rip={:#x} result={:#x}",
                report.last_reason, report.last_guest_rip, report.stop_result
            ));
            diagnostics::message(format_args!(
                "guest flags={:#x} status={:#x} exits={} vmcalls={} EPT={}",
                guest_report.flags,
                guest_report.status,
                report.exit_count,
                report.vmcall_count,
                report.ept_test_violation_seen
            ));
            diagnostics::message(format_args!(
                "post start={} post EBS={} post VA={} last GPA={:#x}",
                report.post_start_exit_count,
                report.post_ebs_exit_count,
                report.post_va_exit_count,
                report.last_guest_physical_address
            ));
            logging::error(format_args!(
                "boot_loader_start_vcpu returned unexpectedly raw_path={} vm_instruction_error={:#x} host_cr3={:#x} guest_cr3={:#x} exits={} cpuid={} rdmsr={} wrmsr={} xsetbv={} vmcall={} checkpoint={} post_start={} post_ebs={} post_va={} ept_test={} last_reason={:#x} len={} qual={:#x} gpa={:#x} rip={:#x} last_guest_cr3={:#x} last_host_cr3={:#x} stop_result={:#x}",
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
            logging::phase("vmx.boot_loader_start_vcpu.unexpected_return");
            Err(Status::DEVICE_ERROR)
        }
        Err(error) => {
            logging::error(format_args!("boot_loader_start_vcpu error={error:?}"));
            logging::phase("vmx.boot_loader_start_vcpu.failed");
            diagnostics::error(format_args!("boot vCPU failed: {error:?}"));
            Err(vmx::resident::status_from_error(&error))
        }
    }
}
