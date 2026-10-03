use super::abi::{BOOT_CONTEXT_CANARY_END, BOOT_CONTEXT_CANARY_START};
use super::abi::{ResidentBootContext, ResidentEventContext};
use super::{
    ResidentCode, ResidentProbeError, matrixhv_resident_boot_run_asm,
    matrixhv_resident_startup_halt_asm,
};
use crate::vmx::controls;
use crate::vmx::ept::{self, EptError};
use crate::vmx::exits::VMCALL_EXIT_REASON;
use crate::vmx::exits::{ResidentBootReport, validate_resident_run_path};
use crate::vmx::msr::configure_resident_msr_switch;
use crate::vmx::nested::{
    NestedVmcs02Configuration, configure_nested_vmcs02, configure_resident_vmcs_shadowing,
};
use crate::vmx::state::{self, configure_resident_host};
use crate::vmx::vcpu::{ResidentApLaunch, ResidentCpuResources};
use crate::vmx::vmcs::VM_INSTRUCTION_ERROR;
use crate::vmx::vmcs::{self, VmcsError};
use crate::vmx::vmxon::{self, VmxInstructionResult};
use crate::memory::host::{AddressConstraint, HostAddressSpace, ResidentPages};
use crate::vmx::nested::{VMX_SECONDARY_ENABLE_EPT, VMX_SECONDARY_ENABLE_VPID};
use crate::vmx::vmcs12::{VMCS12_LAUNCH_STATE_LAUNCHED};
use crate::arch;
use crate::vmx::hyperv;
use core::sync::atomic::Ordering;
pub fn run_boot_loader(
    options: crate::boot::config::MatrixConfig,
    entry_rip: u64,
    event_context: u64,
    ept_probe_fault_rip: u64,
    ept_probe_resume_rip: u64,
) -> Result<ResidentBootReport, ResidentProbeError> {
    crate::diagnostics::stage("resident resource allocation");
    let initial_rflags = arch::read_rflags();
    let code = ResidentCode::allocate(event_context)?;
    let root_segments = arch::capture();
    let msr_bitmap =
        crate::vmx::msr::allocate_bitmap().map_err(ResidentProbeError::Allocation)?;
    let ept_test_page = ResidentPages::allocate_initialized(1, AddressConstraint::Any, |bytes| {
        bytes[..8].copy_from_slice(&0x4550_5454_4553_5431_u64.to_ne_bytes());
    })
    .map_err(ResidentProbeError::Allocation)?;
    let zero_page = ResidentPages::allocate(1, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let mut host_address_space = HostAddressSpace::reserve().map_err(ResidentProbeError::Paging)?;
    let vmx_basic = vmxon::vmx_basic();
    let mut cpu_resources = ResidentCpuResources::allocate(
        vmx_basic,
        code.fatal,
        code.gp_handler,
        code.exception_stubs,
    )?;
    let mut ap_resources = crate::boot::smp::enabled_application_processors()
        .map_err(ResidentProbeError::Allocation)?
        .into_iter()
        .map(|processor_number| {
            ResidentCpuResources::allocate(
                vmx_basic,
                code.fatal,
                code.gp_handler,
                code.exception_stubs,
            )
            .map(|resources| (processor_number, resources))
        })
        .collect::<Result<alloc::vec::Vec<_>, _>>()?;
    let update = unsafe {
        &mut *((*(event_context as *const ResidentEventContext)).update_context_physical
            as *mut crate::update::RuntimeContext)
    };
    update.banks[0] = code.pages.physical_address();
    update.bank_idts[0][0] = cpu_resources.host_tables.idt;
    for (processor_number, resources) in &ap_resources {
        update.bank_idts[0][*processor_number] = resources.host_tables.idt;
    }
    update.transaction.current_version = super::core_version();
    update.transaction.current_identity = code.identity;
    update.transaction.status.previous_version = super::core_version();
    update.transaction.status.previous_identity = code.identity;
    update.transaction.status.retained_banks = 1;
    unsafe {
        core::ptr::copy_nonoverlapping(
            &update.transaction.status,
            core::ptr::addr_of_mut!((*(event_context as *mut ResidentEventContext)).update_status)
                .cast::<crate::update::Status>(),
            1,
        );
    }

    crate::diagnostics::stage("resident host paging");
    let host_space = host_address_space
        .clone_current()
        .map_err(ResidentProbeError::Paging)?;
    crate::diagnostics::stage("resident EPT setup");
    let mut ept = ept::IdentityEpt::build(
        crate::boot::firmware::memory_descriptors().map_err(ResidentProbeError::Allocation)?,
    )?;
    let pci_bar_ranges = crate::boot::firmware::pci_bar_ranges()?;
    ept.map_pci_bars(&pci_bar_ranges)?;
    let high_address_end = ept.map_high_address_gaps()?;
    crate::diagnostics::message(format_args!(
        "resident high address EPT coverage to={high_address_end:#x} UC gaps"
    ));
    for &(start, end) in &pci_bar_ranges {
        if end > (1_u64 << 32) {
            crate::diagnostics::message(format_args!(
                "resident high PCI BAR EPT range={start:#x}..{end:#x} UC"
            ));
        }
    }
    let zero_page_physical_address = zero_page.physical_address();
    protect_update_memory(
        &mut host_address_space,
        &mut ept,
        &code,
        event_context,
        zero_page_physical_address,
    )?;
    ept.conceal_guest_access(
        zero_page_physical_address,
        zero_page.pages(),
        zero_page_physical_address,
    )?;
    ept.conceal_guest_access(
        code.pages.physical_address(),
        code.pages.pages(),
        zero_page_physical_address,
    )?;
    ept.conceal_guest_access(
        msr_bitmap.physical_address(),
        msr_bitmap.pages(),
        zero_page_physical_address,
    )?;
    ept.conceal_guest_access(
        host_space.arena_physical_address,
        host_space.arena_pages,
        zero_page_physical_address,
    )?;
    ept.deny_guest_access(ept_test_page.physical_address(), ept_test_page.pages())?;
    cpu_resources.conceal_guest_access(&mut ept, zero_page_physical_address)?;
    for (_, resources) in &ap_resources {
        resources.conceal_guest_access(&mut ept, zero_page_physical_address)?;
    }
    ept.conceal_guest_access_to_tables(zero_page_physical_address)?;
    crate::diagnostics::stage("resident nested EPT setup");
    let mut ept12_template = ept::IdentityEpt::build(
        crate::boot::firmware::memory_descriptors().map_err(ResidentProbeError::Allocation)?,
    )?;
    ept12_template.map_high_address_gaps()?;
    cpu_resources.prepare_nested_ept(&ept, &ept12_template)?;
    for (_, resources) in &mut ap_resources {
        resources.prepare_nested_ept(&ept, &ept12_template)?;
    }
    drop(ept12_template);
    let mut nested_ept02_regions = cpu_resources.nested_ept02_table_regions();
    for (_, resources) in &ap_resources {
        nested_ept02_regions.extend(resources.nested_ept02_table_regions());
    }
    ept.conceal_guest_access_to_regions(&nested_ept02_regions, zero_page_physical_address)?;
    // Each CPU's sparse EPT02 is seeded with its probe mapping; later L2
    // compositions consult EPT01 after all nested table regions are concealed.

    let nested_ept02_pointer = cpu_resources
        .nested_ept02_pointer()
        .ok_or(EptError::InvalidPageTable)?;

    let vmcs_physical_address = cpu_resources.vmcs_region.physical_address();
    let nested_vmcs02_physical_address = cpu_resources.nested_vmcs02_region.physical_address();
    let shadow_resources = cpu_resources.vmcs_shadow_resources();
    // Calibration can call Stall; finish all diagnostic protocol work before VMXON.
    let (diagnostic_interval_tsc, diagnostic_timer_rate) =
        controls::resident_boot_timer_parameters();
    let watchdog_tsc_hz = if diagnostic_interval_tsc != 0 {
        diagnostic_interval_tsc
    } else {
        controls::resident_tsc_hz()
    };
    if crate::logging::framebuffer_enabled()
        && crate::diagnostics::prepare_resident_visuals()
        && let Some((visual_base, visual_stride_bytes)) =
            crate::diagnostics::resident_marker_layout()
    {
        let event_context = event_context as *mut ResidentEventContext;
        unsafe {
            (*event_context).visual_base = visual_base;
            (*event_context).visual_stride_bytes = visual_stride_bytes;
        }
    }
    crate::logging::info(format_args!(
        "nested VMCS shadowing resources={}",
        shadow_resources.is_some()
    ));
    crate::diagnostics::stage("resident BSP VMCS setup");
    let nested_configuration = crate::vmx::vcpu::nested_cpu_configuration(&cpu_resources)?;
    let session =
        vmxon::enter_vmx_root_with_borrowed_region(vmx_basic, &mut cpu_resources.vmxon_region)
            .map_err(ResidentProbeError::Vmxon)?;
    let l1_cr4 = session.report().original_cr4;
    super::EPT_TEST_PAGE_GPA.store(ept_test_page.physical_address(), Ordering::Release);
    let clear_result = unsafe { vmcs::vmclear(vmcs_physical_address) };
    if clear_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(ResidentProbeError::Vmclear(clear_result));
    }
    let load_result = unsafe { vmcs::vmptrld(vmcs_physical_address) };
    if load_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(ResidentProbeError::Vmcs(VmcsError::Vmptrld(load_result)));
    }

    let mut controls =
        controls::configure_resident_boot(msr_bitmap.physical_address(), ept.ept_pointer())?;
    controls::enable_resident_vpid(&mut controls, 1)?;
    controls::enable_resident_boot_timer(
        &mut controls,
        diagnostic_interval_tsc,
        diagnostic_timer_rate,
    )?;
    configure_resident_msr_switch(&cpu_resources.resident_msr_state)?;
    configure_resident_host(
        host_space.host_cr3,
        &cpu_resources.host_tables,
        root_segments,
    )?;
    let guest_rsp =
        cpu_resources.guest_stack.physical_address() + cpu_resources.guest_stack.byte_len() as u64;
    let guest = state::configure_guest_with_rflags(entry_rip, guest_rsp & !0xf, initial_rflags)?;
    controls::virtualize_resident_cr4_vmxe(l1_cr4)?;
    let vmcs_shadow = configure_resident_vmcs_shadowing(&mut controls, shadow_resources)?;
    let nested_state = crate::vmx::nested::prepare_cpu_state(
        nested_configuration,
        options,
        vmx_basic,
        l1_cr4,
        root_segments,
        vmcs_shadow,
        msr_bitmap.physical_address(),
    )?;

    let context = cpu_resources
        .context_pages
        .pointer()
        .as_ptr()
        .cast::<ResidentBootContext>();
    unsafe {
        context.write(ResidentBootContext::new(
            host_space.host_cr3,
            guest.cr3,
            event_context,
            ept_test_page.physical_address(),
            (ept_probe_fault_rip, ept_probe_resume_rip),
            nested_state,
            options.cpuid_presence,
        ));
        (*context).diagnostic_interval_tsc = diagnostic_interval_tsc;
        (*context).telemetry_probe_active = u64::from(options.vmx_test);
        (*context).watchdog_tsc_hz = watchdog_tsc_hz;
        let shared = event_context as *mut ResidentEventContext;
        (*context).hyperv_timing_supported = u64::from(hyperv::timing_supported(
            (*context).cpuid_presence != 0,
            (*shared).hyperv_tsc_scale,
        ));
        (*shared).watchdog_tsc_hz = watchdog_tsc_hz;
        (*shared).cpu_contexts[0] = context as u64;
        (*shared).control_apic_ids[0] = arch::apic_id();
        (*shared).control_cpu_states[0].vmxon_region = session.report().region_physical_address;
        (*shared).control_cpu_states[0].vmcs_region = vmcs_physical_address;
        (*context).cache_ept_pointer = ept.ept_pointer();
        (*context).diagnostic_timer_rate = diagnostic_timer_rate;
        (*context).diagnostic_deadline_tsc =
            core::arch::x86_64::_rdtsc().wrapping_add(diagnostic_interval_tsc);
    }
    let host_rsp = (cpu_resources.host_stack.physical_address()
        + cpu_resources.host_stack.byte_len() as u64
        - 8)
        & !0xf;
    unsafe {
        cpu_resources
            .host_tables
            .bind_context(host_rsp, context as u64);
    }
    configure_nested_vmcs02(NestedVmcs02Configuration {
        vmcs01_region: vmcs_physical_address,
        vmcs02_region: nested_vmcs02_physical_address,
        msr_bitmap: msr_bitmap.physical_address(),
        ept_pointer: nested_ept02_pointer,
        msr_state: &cpu_resources.resident_msr_state,
        host_cr3: host_space.host_cr3,
        host_tables: &cpu_resources.host_tables,
        segments: root_segments,
        host_rsp,
        host_rip: code.dispatch_entry,
        guest_rip: entry_rip,
        guest_rsp: guest_rsp & !0xf,
        guest_rflags: initial_rflags,
        l1_cr4,
    })?;

    // Firmware MP services run with the BSP's original CRs, tables, and IF.
    // Both VMCS regions must be inactive before this temporary VMXOFF.
    let clear = unsafe { vmcs::vmclear(vmcs_physical_address) };
    drop(session);
    if clear != VmxInstructionResult::Succeeded {
        return Err(ResidentProbeError::Vmclear(clear));
    }
    crate::diagnostics::stage("resident AP launch");
    let mut launches = ap_resources
        .iter_mut()
        .map(|(processor_number, resources)| ResidentApLaunch {
            options,
            resources,
            host_cr3: host_space.host_cr3,
            event_context,
            ept_pointer: ept.ept_pointer(),
            msr_bitmap: msr_bitmap.physical_address(),
            dispatch_entry: code.dispatch_entry,
            processor_number: *processor_number,
        })
        .collect::<alloc::vec::Vec<_>>();
    crate::diagnostics::message(format_args!("resident APs starting={}", launches.len()));
    if let Err(error) = crate::boot::smp::launch_all(&mut launches) {
        crate::diagnostics::error(format_args!("resident AP batch failed: {error:?}"));
        resident_startup_halt();
    }
    drop(launches);
    for (processor_number, resources) in &mut ap_resources {
        let ap_context = resources
            .context_pages
            .pointer()
            .as_ptr()
            .cast::<ResidentBootContext>();
        let started = unsafe { core::ptr::addr_of!((*ap_context).ap_started).read_volatile() };
        let nested = unsafe { core::ptr::addr_of!((*ap_context).nested).read_volatile() };
        crate::logging::info(format_args!(
            "smp resident processor={} started={} vmxon={:#x} vmcs={:#x} host_stack={:#x} context={:#x} host_cr3={:#x} ept={:#x}",
            processor_number,
            started,
            resources.vmxon_region.physical_address(),
            resources.vmcs_region.physical_address(),
            resources.host_stack.physical_address(),
            ap_context as u64,
            host_space.host_cr3,
            ept.ept_pointer()
        ));
        crate::logging::info(format_args!(
            "nested AP processor={} operand={:#x} region={:#x} vmxon={} vmxoff={} active={} failures={} complete={} cpuid_leaf1_ecx={:#x} cpuid_hypervisor_eax={:#x}",
            processor_number,
            nested.vmxon_operand,
            nested.vmxon_region,
            nested.vmxon_count,
            nested.vmxoff_count,
            nested.active,
            nested.failure_count,
            nested.probe_complete,
            unsafe { core::ptr::addr_of!((*ap_context).cpuid_leaf1_ecx).read_volatile() },
            unsafe { core::ptr::addr_of!((*ap_context).cpuid_hypervisor_eax).read_volatile() }
        ));
        crate::logging::info(format_args!(
            "nested AP VMCS12 processor={} region={:#x} stored={:#x} guest_rip={:#x} vmclear={} vmptrld={} vmptrst={} vmwrite={} vmread={} vmlaunch={} vmresume={} complete={} entry_rejections={}",
            processor_number,
            nested.vmcs12.region,
            nested.vmcs12.last_stored_pointer,
            nested.vmcs12.guest_rip,
            nested.vmcs12.vmclear_count,
            nested.vmcs12.vmptrld_count,
            nested.vmcs12.vmptrst_count,
            nested.vmcs12.vmwrite_count,
            nested.vmcs12.vmread_count,
            nested.vmcs12.vmlaunch_count,
            nested.vmcs12.vmresume_count,
            nested.vmcs12.probe_complete,
            nested.vmcs12.entry_rejection_count
        ));
        crate::logging::info(format_args!(
            "nested AP L2 processor={} vmcs01={:#x} vmcs02={:#x} shadow_vmcs={:#x} entries={} exits={} reflections={} resumes={} resume_exits={} reason={:#x} rip={:#x} rsp={:#x}",
            processor_number,
            nested.vmcs01_region,
            nested.vmcs02_region,
            nested.shadow_vmcs_region,
            nested.l2_entry_count,
            nested.l2_exit_count,
            nested.l1_reflection_count,
            nested.l2_resume_count,
            nested.l2_resume_exit_count,
            nested.l2_last_exit_reason,
            nested.l2_last_exit_rip,
            nested.l2_last_exit_rsp
        ));
        if started != 1
            || nested.vmxon_count != 2
            || nested.vmxoff_count != 1
            || nested.active != 0
            || nested.failure_count != 7
            || nested.probe_complete != 1
            || nested.vmcs12.last_stored_pointer != nested.vmcs12.region
            || nested.vmcs12.guest_rip == 0
            || nested.vmcs12.guest_rip != nested.l2_last_exit_rip
            || nested.vmcs12.guest_rsp == 0
            || nested.vmcs12.guest_rsp != nested.l2_last_exit_rsp
            || nested.vmcs12.host_rip == 0
            || nested.vmcs12.host_rsp == 0
            || nested.vmcs12.exit_reason & 0xffff != VMCALL_EXIT_REASON
            || nested.vmcs12.exit_instruction_len != 3
            || nested.vmcs12.vmclear_count != 2
            || nested.vmcs12.vmptrld_count != 2
            || nested.vmcs12.vmptrst_count != 1
            || nested.vmcs12.vmwrite_count != 31
            || nested.vmcs12.vmread_count != 36
            || nested.vmcs12.probe_complete != 1
            || nested.vmcs12.vmlaunch_count != 2
            || nested.vmcs12.vmresume_count != 3
            || nested.vmcs12.entry_rejection_count != 2
            || nested.vmcs12.control_validation_count != 3
            || nested.vmcs12.launch_state != VMCS12_LAUNCH_STATE_LAUNCHED
            || nested.vmcs12.extended_fields[0] != 1
            || nested.vmcs12.extended_fields[3]
                != (VMX_SECONDARY_ENABLE_EPT | VMX_SECONDARY_ENABLE_VPID) as u64
            || nested.vmcs01_region == nested.vmcs02_region
            || nested.l2_active != 0
            || nested.l2_entry_count != 3
            || nested.l2_exit_count != 3
            || nested.l2_last_exit_reason & 0xffff != VMCALL_EXIT_REASON
            || nested.l2_last_exit_rip == 0
            || nested.l2_last_exit_rsp == 0
            || nested.l1_reflection_count != 3
            || nested.l2_resume_count != 2
            || nested.l2_resume_exit_count != 2
            || nested.ept12_pointer == 0
            || nested.ept02_pointer == 0
            || nested.ept12_pointer == nested.ept02_pointer
            || nested.ept02_initial_pointer == 0
            || nested.ept02_alternate_pointer == 0
            || nested.ept02_initial_pointer == nested.ept02_alternate_pointer
            || nested.ept02_pointer != nested.ept02_alternate_pointer
            || nested.ept_source_gpa == nested.ept_target_gpa
            || nested.ept_source_gpa == nested.ept_second_target_gpa
            || nested.ept_target_gpa == nested.ept_second_target_gpa
            || nested.ept_composed_hpa != nested.ept_target_gpa
            || nested.ept_alternate_composed_hpa != nested.ept_second_target_gpa
            || nested.ept_permissions != 7
            || nested.ept_alternate_permissions != 7
            || nested.ept_composition_count < 2
            || nested.ept_probe_count != 3
            || nested.ept_observed_value != crate::vmx::vcpu::NESTED_EPT_TARGET_MARKER
            || nested.ept_observed_value_before_invept
                != crate::vmx::vcpu::NESTED_EPT_TARGET_MARKER
            || nested.ept_observed_value_after_invept
                != crate::vmx::vcpu::NESTED_EPT_SECOND_TARGET_MARKER
            || nested.invept_count != 2
            || nested.invept_software_count != 2
            || nested.invvpid_count != 2
            || nested.invvpid_software_count != 2
            || nested.control_merge_count != 3
            || nested.guest_state_sync_count != 3
            || nested.l1_host_restore_count != 3
            || nested.vmcs12.extended_fields[4] != 0
            || nested.last_synced_guest_cr0 != nested.vmcs12.extended_fields[29]
            || nested.last_synced_guest_cr3 != nested.vmcs12.extended_fields[30]
            || nested.last_synced_guest_cr4 != nested.vmcs12.extended_fields[31]
            || nested.last_restored_host_cr0 != nested.vmcs12.extended_fields[32]
            || nested.last_restored_host_cr3 != nested.vmcs12.extended_fields[33]
            || nested.last_restored_host_cr4 != nested.vmcs12.extended_fields[34]
            || nested.last_synced_guest_sysenter_eip != nested.vmcs12.extended_fields[87]
            || nested.last_restored_host_sysenter_eip != nested.vmcs12.extended_fields[90]
            || nested.inherited_l1_pat != nested.l2_saved_pat
            || nested.inherited_l1_efer != nested.l2_saved_efer
            || nested.vmcs12.extended_fields[16] != nested.ept12_pointer
        {
            crate::diagnostics::error(format_args!(
                "resident AP {} failed: started={started} complete={} vmx_failures={}",
                processor_number, nested.probe_complete, nested.failure_count
            ));
            resident_startup_halt();
        }
        unsafe {
            core::ptr::addr_of_mut!((*ap_context).telemetry_probe_active).write_volatile(0);
            core::ptr::addr_of_mut!((*ap_context).telemetry_active).write_volatile(0);
            // Startup validation must not seed the Windows telemetry session.
            for counter in [
                core::ptr::addr_of_mut!((*ap_context).exit_count),
                core::ptr::addr_of_mut!((*ap_context).watchdog_sequence),
                core::ptr::addr_of_mut!((*ap_context).watchdog_exit_count),
                core::ptr::addr_of_mut!((*ap_context).watchdog_handler_returns),
                core::ptr::addr_of_mut!((*ap_context).watchdog_resume_failures),
                core::ptr::addr_of_mut!((*ap_context).watchdog_last_reason),
                core::ptr::addr_of_mut!((*ap_context).watchdog_last_rip),
                core::ptr::addr_of_mut!((*ap_context).ept_violation_read),
                core::ptr::addr_of_mut!((*ap_context).ept_violation_write),
                core::ptr::addr_of_mut!((*ap_context).ept_violation_execute),
                core::ptr::addr_of_mut!((*ap_context).cr3_exits),
                core::ptr::addr_of_mut!((*ap_context).eptp_switches),
                core::ptr::addr_of_mut!((*ap_context).mtf_exits),
                core::ptr::addr_of_mut!((*ap_context).invept_exits),
                core::ptr::addr_of_mut!((*ap_context).preemption_timer_exits),
                core::ptr::addr_of_mut!((*ap_context).nested.l2_entry_count),
                core::ptr::addr_of_mut!((*ap_context).nested.failure_count),
                core::ptr::addr_of_mut!((*ap_context).nested.vmcs12.entry_rejection_count),
                core::ptr::addr_of_mut!((*ap_context).nested.invept_count),
                core::ptr::addr_of_mut!((*ap_context).nested.ept_composition_count),
                core::ptr::addr_of_mut!((*ap_context).nested.ept02_invalidation_count),
                core::ptr::addr_of_mut!((*ap_context).nested.l2_exit_count),
                core::ptr::addr_of_mut!((*ap_context).nested.l2_resume_count),
                core::ptr::addr_of_mut!((*ap_context).nested.l2_last_exit_reason),
                core::ptr::addr_of_mut!((*ap_context).nested.l2_last_exit_rip),
                core::ptr::addr_of_mut!((*ap_context).nested.l2_last_exit_rsp),
            ] {
                counter.write_volatile(0);
            }
            core::ptr::addr_of_mut!((*ap_context).watchdog_phase).write_volatile(1);
        }
        crate::diagnostics::message(format_args!("resident AP {} ready", processor_number));
    }
    crate::logging::info(format_args!(
        "smp resident BSP context={:#x} vmcs={:#x} vmxon={:#x}",
        context as u64,
        vmcs_physical_address,
        cpu_resources.vmxon_region.physical_address()
    ));
    crate::diagnostics::page("resident BSP VMLAUNCH");
    crate::diagnostics::message(format_args!(
        "resident APs ready={} BSP VMCS={:#x} EPT={:#x}",
        ap_resources.len(),
        vmcs_physical_address,
        ept.ept_pointer()
    ));
    let first_high_bar = pci_bar_ranges
        .iter()
        .copied()
        .find(|&(_, end)| end > (1_u64 << 32))
        .unwrap_or((0, 0));
    crate::diagnostics::message(format_args!(
        "PCI BARs={} first high={:#x}..{:#x}",
        pci_bar_ranges.len(),
        first_high_bar.0,
        first_high_bar.1
    ));
    crate::logging::describe_resident_diagnostics();
    let mut expected_mask = 1_u64;
    for (processor_number, _) in &ap_resources {
        expected_mask |= 1_u64 << processor_number;
    }
    let control_context = unsafe { &*(event_context as *const ResidentEventContext) };
    control_context
        .control_expected_mask
        .store(expected_mask, Ordering::Release);
    control_context
        .control_active_mask
        .store(expected_mask, Ordering::Release);
    unsafe {
        (*(event_context as *mut ResidentEventContext)).control_processor_count =
            u64::from(expected_mask.count_ones());
    }
    crate::diagnostics::message(format_args!(
        "BSP boot timer available={} interval TSC={:#x} rate={} display sampling={}",
        diagnostic_interval_tsc != 0,
        diagnostic_interval_tsc,
        diagnostic_timer_rate,
        if diagnostic_interval_tsc == 0 {
            "VM exits"
        } else {
            "VMX timer"
        }
    ));
    crate::diagnostics::message(format_args!(
        "EPT halt hex at right: GPA / guest RIP / qualification"
    ));
    let session = match vmxon::enter_vmx_root_with_borrowed_region(
        vmx_basic,
        &mut cpu_resources.vmxon_region,
    ) {
        Ok(session) => session,
        Err(error) => {
            crate::diagnostics::error(format_args!("resident BSP VMXON failed: {error:?}"));
            resident_startup_halt();
        }
    };
    let load = unsafe { vmcs::vmptrld(vmcs_physical_address) };
    if load != VmxInstructionResult::Succeeded {
        drop(session);
        crate::diagnostics::error(format_args!("resident BSP VMPTRLD failed: {load:?}"));
        resident_startup_halt();
    }
    let raw_path =
        unsafe { matrixhv_resident_boot_run_asm(context, host_rsp, code.dispatch_entry) };
    if !ap_resources.is_empty() {
        let boot_context = unsafe { &*context };
        crate::diagnostics::error(format_args!(
            "BSP returned with resident APs: path={} stop={:#x} exit={:#x} rip={:#x}",
            raw_path,
            boot_context.stop_result,
            boot_context.last_reason,
            boot_context.last_guest_rip
        ));
        resident_startup_halt();
    }
    super::EPT_TEST_PAGE_GPA.store(0, Ordering::Release);
    if raw_path == 0 {
        cpu_resources.host_tables.pages.preserve();
    }
    let vm_instruction_error = vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
    let shadow_clear =
        shadow_resources.map(|(shadow_vmcs, _, _)| unsafe { vmcs::vmclear(shadow_vmcs) });
    let final_clear = unsafe { vmcs::vmclear(vmcs_physical_address) };
    host_address_space.restore_source_cr3();
    drop(session);
    let _ = &ept;
    if let Some(clear) = shadow_clear
        && clear != VmxInstructionResult::Succeeded
    {
        return Err(ResidentProbeError::Vmclear(clear));
    }
    if final_clear != VmxInstructionResult::Succeeded {
        return Err(ResidentProbeError::Vmclear(final_clear));
    }
    validate_resident_run_path(raw_path, vm_instruction_error)?;

    let result = unsafe { &*context };
    if result.canary_start != BOOT_CONTEXT_CANARY_START
        || result.canary_end != BOOT_CONTEXT_CANARY_END
    {
        return Err(ResidentProbeError::CanaryCorrupted);
    }
    if result.last_host_cr3 != 0 && result.last_host_cr3 != host_space.host_cr3 {
        return Err(ResidentProbeError::HostCr3Mismatch {
            expected: host_space.host_cr3,
            observed: result.last_host_cr3,
        });
    }

    let report = ResidentBootReport {
        raw_path,
        vm_instruction_error,
        host_cr3: host_space.host_cr3,
        initial_guest_cr3: guest.cr3,
        exit_count: result.exit_count,
        cpuid_count: result.cpuid_count,
        rdmsr_count: result.rdmsr_count,
        wrmsr_count: result.wrmsr_count,
        xsetbv_count: result.xsetbv_count,
        vmcall_count: result.vmcall_count,
        start_checkpoint_seen: result.start_checkpoint_seen,
        post_start_exit_count: result.post_start_exit_count,
        post_ebs_exit_count: result.post_ebs_exit_count,
        post_va_exit_count: result.post_va_exit_count,
        ept_test_violation_seen: result.ept_test_violation_seen,
        last_reason: result.last_reason,
        last_instruction_len: result.last_instruction_len,
        last_qualification: result.last_qualification,
        last_guest_physical_address: result.last_guest_physical_address,
        last_guest_rax: result.last_guest_rax,
        last_guest_rcx: result.last_guest_rcx,
        last_guest_rdx: result.last_guest_rdx,
        last_guest_rip: result.last_guest_rip,
        last_guest_cr3: result.last_guest_cr3,
        last_host_cr3: result.last_host_cr3,
        stop_result: result.stop_result,
        cpuid_presence: result.cpuid_presence,
        cpuid_leaf1_count: result.cpuid_leaf1_count,
        cpuid_hypervisor_count: result.cpuid_hypervisor_count,
        cpuid_leaf1_ecx: result.cpuid_leaf1_ecx,
        cpuid_hypervisor_eax: result.cpuid_hypervisor_eax,
        nested: result.nested,
    };
    let _ = &cpu_resources;
    let _ = &zero_page;
    Ok(report)
}

fn resident_startup_halt() -> ! {
    crate::logging::error(format_args!(
        "smp resident startup failed; retaining active CPU resources"
    ));
    unsafe { matrixhv_resident_startup_halt_asm() }
}

fn protect_update_memory(
    host: &mut HostAddressSpace,
    ept: &mut ept::IdentityEpt,
    code: &ResidentCode,
    event_context: u64,
    zero_page: u64,
) -> Result<(), ResidentProbeError> {
    use crate::memory::host::PAGE_SIZE;
    use crate::update::{BANK_PAGES, EmbeddedImage, MAX_PACKAGE_BYTES, RuntimeContext};
    let event = unsafe { &*(event_context as *const ResidentEventContext) };
    let update = unsafe { &mut *(event.update_context_physical as *mut RuntimeContext) };
    for bank in 0..2 {
        for page in 0..BANK_PAGES {
            let flags = if bank == 0 && page * PAGE_SIZE < code.code_bytes {
                1
            } else {
                3 | (1 << 63)
            };
            update.bank_ptes[bank][page] = host
                .protect_page(update.banks[bank] + (page * PAGE_SIZE) as u64, flags)
                .map_err(ResidentProbeError::Paging)?;
        }
        ept.conceal_guest_access(update.banks[bank], BANK_PAGES, zero_page)?;
    }
    let root_image_base =
        event.update_loader_physical - (event.update_loader_runtime - event.update_image_physical);
    for base in [root_image_base, event.update_image_physical] {
        let image = EmbeddedImage::parse(unsafe {
            core::slice::from_raw_parts(base as *const u8, event.update_image_bytes as usize)
        })
        .map_err(|_| ResidentProbeError::InvalidCodeLayout)?;
        for page in 0..image.bytes.len().div_ceil(PAGE_SIZE) {
            host.protect_page(base + (page * PAGE_SIZE) as u64, image.page_flags(page))
                .map_err(ResidentProbeError::Paging)?;
        }
    }
    ept.conceal_guest_access(
        root_image_base,
        (event.update_image_bytes as usize).div_ceil(PAGE_SIZE),
        zero_page,
    )?;
    for (base, pages) in [
        (update.staging, MAX_PACKAGE_BYTES.div_ceil(PAGE_SIZE)),
        (
            event.update_context_physical,
            core::mem::size_of::<RuntimeContext>().div_ceil(PAGE_SIZE),
        ),
        (update.bank_idts[1][0], 64),
        (
            event.tracking_context_physical,
            core::mem::size_of::<crate::memory::tracking::Session>().div_ceil(PAGE_SIZE),
        ),
        (
            unsafe { (*(event.tracking_context_physical as *const crate::memory::tracking::Session)).pool.base },
            crate::protocol::memory::TRACK_TABLE_PAGES,
        ),
    ] {
        for page in 0..pages {
            host.protect_page(base + (page * PAGE_SIZE) as u64, 3 | (1 << 63))
                .map_err(ResidentProbeError::Paging)?;
        }
        ept.conceal_guest_access(base, pages, zero_page)?;
    }
    Ok(())
}
