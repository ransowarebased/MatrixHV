use crate::hv_core::vcpu::{VmlaunchProbeResourceAddresses, VmlaunchProbeResources};
use alloc::vec::Vec;

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use uefi::Status;
use uefi::boot;
use uefi::proto::pi::mp::MpServices;

use crate::arch;
use crate::hv_core::entry::{VmlaunchError, VmlaunchReport, run_vmlaunch_probe};
use crate::hv_core::resident::ResidentProbeError;
use crate::hv_core::vcpu::ResidentApLaunch;
use crate::hv_core::vcpu::matrixhv_ap_launch_asm;
use crate::runtime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TopologyReport {
    pub(crate) total_processors: usize,
    pub(crate) enabled_processors: usize,
    pub(crate) current_processor: usize,
    pub(crate) bsp_processor: usize,
    pub(crate) first_enabled_ap: Option<usize>,
}

fn open_mp_services() -> Result<boot::ScopedProtocol<MpServices>, Status> {
    let handle = boot::get_handle_for_protocol::<MpServices>().map_err(|error| error.status())?;
    // SAFETY: MP Services is a firmware-owned boot-time interface. Callers use
    // shared methods and neither unload/disconnect its provider nor exit boot
    // services while this borrow (including blocking AP callbacks) is live.
    unsafe {
        boot::open_protocol::<MpServices>(
            boot::OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            boot::OpenProtocolAttributes::GetProtocol,
        )
    }
    .map_err(|error| error.status())
}

pub(crate) fn enumerate() -> Result<TopologyReport, Status> {
    let mp = open_mp_services()?;
    let count = mp
        .get_number_of_processors()
        .map_err(|error| error.status())?;
    let current_processor = mp.who_am_i().map_err(|error| error.status())?;

    let mut bsp_processor = None;
    let mut first_enabled_ap = None;

    for processor_number in 0..count.total {
        let info = mp
            .get_processor_info(processor_number)
            .map_err(|error| error.status())?;
        runtime::info(format_args!(
            "smp processor={} id={:#x} bsp={} enabled={} healthy={} package={} core={} thread={}",
            processor_number,
            info.processor_id,
            info.is_bsp(),
            info.is_enabled(),
            info.is_healthy(),
            info.location.package,
            info.location.core,
            info.location.thread
        ));

        if info.is_bsp() {
            if bsp_processor.replace(processor_number).is_some() {
                return Err(Status::DEVICE_ERROR);
            }
        } else if info.is_enabled() && first_enabled_ap.is_none() {
            first_enabled_ap = Some(processor_number);
        }
    }

    let bsp_processor = bsp_processor.ok_or(Status::DEVICE_ERROR)?;
    Ok(TopologyReport {
        total_processors: count.total,
        enabled_processors: count.enabled,
        current_processor,
        bsp_processor,
        first_enabled_ap,
    })
}

pub(crate) fn enabled_application_processors() -> Result<Vec<usize>, Status> {
    let topology = enumerate()?;
    if topology.total_processors > 64 || topology.bsp_processor != 0 {
        return Err(Status::UNSUPPORTED);
    }
    let mut ap_resources = Vec::new();
    let mp = open_mp_services()?;
    for processor_number in 0..topology.total_processors {
        let info = mp
            .get_processor_info(processor_number)
            .map_err(|error| error.status())?;
        if info.is_enabled() && !info.is_bsp() {
            ap_resources.push(processor_number);
        }
    }
    Ok(ap_resources)
}

const INTERRUPT_FLAG: u64 = 1 << 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuLocalState {
    pub(crate) apic_id: u32,
    pub(crate) cr0: u64,
    pub(crate) cr3: u64,
    pub(crate) cr4: u64,
    pub(crate) rflags: u64,
    pub(crate) dr7: u64,
    pub(crate) debugctl: u64,
    pub(crate) fs_base: u64,
    pub(crate) gs_base: u64,
    pub(crate) gdtr_base: u64,
    pub(crate) gdtr_limit: u16,
    pub(crate) idtr_base: u64,
    pub(crate) idtr_limit: u16,
}

impl CpuLocalState {
    fn capture() -> Self {
        let gdtr = arch::read_gdtr();
        let idtr = arch::read_idtr();
        Self {
            apic_id: arch::apic_id(),
            cr0: arch::read_cr0(),
            cr3: arch::read_cr3(),
            cr4: arch::read_cr4(),
            rflags: arch::read_rflags(),
            dr7: arch::read_dr7(),
            debugctl: unsafe { arch::read_msr(arch::IA32_DEBUGCTL) },
            fs_base: arch::ArchitecturalMsr::FsBase.read(),
            gs_base: arch::ArchitecturalMsr::GsBase.read(),
            gdtr_base: gdtr.base,
            gdtr_limit: gdtr.limit,
            idtr_base: idtr.base,
            idtr_limit: idtr.limit,
        }
    }

    fn vmx_state_restored(self, after: Self) -> bool {
        self.apic_id == after.apic_id
            && self.cr0 == after.cr0
            && self.cr3 == after.cr3
            && self.cr4 == after.cr4
            && (self.rflags ^ after.rflags) & INTERRUPT_FLAG == 0
            && self.dr7 == after.dr7
            && self.debugctl == after.debugctl
            && self.fs_base == after.fs_base
            && self.gs_base == after.gs_base
            && self.gdtr_base == after.gdtr_base
            && self.gdtr_limit == after.gdtr_limit
            && self.idtr_base == after.idtr_base
            && self.idtr_limit == after.idtr_limit
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ApplicationProcessorVmxProofReport {
    pub(crate) processor_number: usize,
    pub(crate) processor_id: u64,
    pub(crate) bsp_resources: VmlaunchProbeResourceAddresses,
    pub(crate) ap_resources: VmlaunchProbeResourceAddresses,
    pub(crate) initial_state: CpuLocalState,
    pub(crate) final_state: CpuLocalState,
    pub(crate) vmlaunch: VmlaunchReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplicationProcessorVmxProofError {
    Uefi(Status),
    ProcessorIsBsp,
    ProcessorDisabled,
    ResourceAllocation(VmlaunchError),
    ResourceAlias,
    BspProbe(VmlaunchError),
    BspStateNotRestored,
    CallbackDidNotRun,
    ApProbe(VmlaunchError),
    ApStateNotRestored,
}

struct ApProbeContext {
    resources: *mut VmlaunchProbeResources,
    initial_state: Option<CpuLocalState>,
    final_state: Option<CpuLocalState>,
    result: Option<Result<VmlaunchReport, VmlaunchError>>,
}

pub(crate) fn prove_application_processor_vmx(
    processor_number: usize,
) -> Result<ApplicationProcessorVmxProofReport, ApplicationProcessorVmxProofError> {
    let mp = open_mp_services().map_err(ApplicationProcessorVmxProofError::Uefi)?;
    let processor_info = mp
        .get_processor_info(processor_number)
        .map_err(|error| ApplicationProcessorVmxProofError::Uefi(error.status()))?;
    if processor_info.is_bsp() {
        return Err(ApplicationProcessorVmxProofError::ProcessorIsBsp);
    }
    if !processor_info.is_enabled() {
        return Err(ApplicationProcessorVmxProofError::ProcessorDisabled);
    }

    let mut bsp_resources = VmlaunchProbeResources::allocate()
        .map_err(ApplicationProcessorVmxProofError::ResourceAllocation)?;
    let mut ap_resources = VmlaunchProbeResources::allocate()
        .map_err(ApplicationProcessorVmxProofError::ResourceAllocation)?;
    let bsp_addresses = bsp_resources.addresses();
    let ap_addresses = ap_resources.addresses();
    if resources_alias(bsp_addresses, ap_addresses) {
        return Err(ApplicationProcessorVmxProofError::ResourceAlias);
    }

    runtime::info(format_args!(
        "smp vmx proof resources bsp vmxon={:#x} vmcs={:#x} guest_stack={:#x} ap vmxon={:#x} vmcs={:#x} guest_stack={:#x}",
        bsp_addresses.vmxon,
        bsp_addresses.vmcs,
        bsp_addresses.guest_stack,
        ap_addresses.vmxon,
        ap_addresses.vmcs,
        ap_addresses.guest_stack
    ));

    let bsp_initial = CpuLocalState::capture();
    run_vmlaunch_probe(&mut bsp_resources).map_err(ApplicationProcessorVmxProofError::BspProbe)?;
    let bsp_final = CpuLocalState::capture();
    if !bsp_initial.vmx_state_restored(bsp_final) {
        log_state_mismatch("bsp", bsp_initial, bsp_final);
        return Err(ApplicationProcessorVmxProofError::BspStateNotRestored);
    }

    let mut context = ApProbeContext {
        resources: &mut ap_resources,
        initial_state: None,
        final_state: None,
        result: None,
    };
    runtime::phase("smp.cpu1_vmx.startup_this_ap.start");
    mp.startup_this_ap(
        processor_number,
        application_processor_vmx_callback,
        (&mut context as *mut ApProbeContext).cast::<c_void>(),
        None,
        Some(Duration::from_secs(5)),
    )
    .map_err(|error| ApplicationProcessorVmxProofError::Uefi(error.status()))?;
    runtime::phase("smp.cpu1_vmx.startup_this_ap.returned");

    let initial_state = context
        .initial_state
        .ok_or(ApplicationProcessorVmxProofError::CallbackDidNotRun)?;
    let final_state = context
        .final_state
        .ok_or(ApplicationProcessorVmxProofError::CallbackDidNotRun)?;
    let vmlaunch = context
        .result
        .ok_or(ApplicationProcessorVmxProofError::CallbackDidNotRun)?
        .map_err(ApplicationProcessorVmxProofError::ApProbe)?;
    if !initial_state.vmx_state_restored(final_state) {
        log_state_mismatch("ap", initial_state, final_state);
        return Err(ApplicationProcessorVmxProofError::ApStateNotRestored);
    }
    runtime::info(format_args!(
        "smp cpu={processor_number} restored gdtr={:#x}/{} idtr={:#x}/{}",
        final_state.gdtr_base,
        final_state.gdtr_limit,
        final_state.idtr_base,
        final_state.idtr_limit
    ));

    Ok(ApplicationProcessorVmxProofReport {
        processor_number,
        processor_id: processor_info.processor_id,
        bsp_resources: bsp_addresses,
        ap_resources: ap_addresses,
        initial_state,
        final_state,
        vmlaunch,
    })
}

fn log_state_mismatch(processor: &str, before: CpuLocalState, after: CpuLocalState) {
    runtime::error(format_args!("smp {processor} state before={before:?}"));
    runtime::error(format_args!("smp {processor} state after={after:?}"));
}

extern "efiapi" fn application_processor_vmx_callback(argument: *mut c_void) {
    let context = unsafe { &mut *argument.cast::<ApProbeContext>() };
    let initial_state = CpuLocalState::capture();
    context.initial_state = Some(initial_state);
    runtime::info(format_args!(
        "smp cpu1 callback apic_id={:#x} cr0={:#x} cr3={:#x} cr4={:#x} rflags={:#x}",
        initial_state.apic_id,
        initial_state.cr0,
        initial_state.cr3,
        initial_state.cr4,
        initial_state.rflags
    ));
    runtime::phase("smp.cpu1_vmx.vmlaunch.start");
    let resources = unsafe { &mut *context.resources };
    context.result = Some(run_vmlaunch_probe(resources));
    context.final_state = Some(CpuLocalState::capture());
    runtime::phase("smp.cpu1_vmx.vmlaunch.returned");
}

fn resources_alias(
    left: VmlaunchProbeResourceAddresses,
    right: VmlaunchProbeResourceAddresses,
) -> bool {
    let left_addresses = [left.vmxon, left.vmcs, left.guest_stack];
    let right_addresses = [right.vmxon, right.vmcs, right.guest_stack];
    left_addresses
        .iter()
        .any(|left_address| right_addresses.contains(left_address))
}

struct ApBatchEntry {
    processor_number: usize,
    launch: *mut c_void,
    invoked: AtomicBool,
}

struct ApBatchContext {
    mp: *const MpServices,
    entries: *const ApBatchEntry,
    entry_count: usize,
    callback_failed: AtomicBool,
}

pub(crate) fn launch_all(launches: &mut [ResidentApLaunch<'_>]) -> Result<(), ResidentProbeError> {
    let mp = open_mp_services().map_err(ResidentProbeError::Allocation)?;
    let count = mp
        .get_number_of_processors()
        .map_err(|error| ResidentProbeError::Allocation(error.status()))?;
    let mut enabled_ap_count = 0;
    // Reject mismatched batches before any AP can acquire resident resources.
    for processor_number in 0..count.total {
        let info = mp
            .get_processor_info(processor_number)
            .map_err(|error| ResidentProbeError::Allocation(error.status()))?;
        let expected = usize::from(info.is_enabled() && !info.is_bsp());
        let supplied = launches
            .iter()
            .filter(|launch| launch.processor_number == processor_number)
            .count();
        if supplied != expected {
            return Err(ResidentProbeError::Allocation(Status::INVALID_PARAMETER));
        }
        enabled_ap_count += expected;
    }
    if launches.len() != enabled_ap_count {
        return Err(ResidentProbeError::Allocation(Status::INVALID_PARAMETER));
    }
    if launches.is_empty() {
        return Ok(());
    }
    let entries: Vec<_> = launches
        .iter_mut()
        .map(|launch| ApBatchEntry {
            processor_number: launch.processor_number,
            launch: (launch as *mut ResidentApLaunch<'_>).cast(),
            invoked: AtomicBool::new(false),
        })
        .collect();
    let context = ApBatchContext {
        mp: &*mp,
        entries: entries.as_ptr(),
        entry_count: entries.len(),
        callback_failed: AtomicBool::new(false),
    };
    // The blocking call keeps each AP's distinct launch resources alive until all callbacks end.
    mp.startup_all_aps(
        false,
        callback,
        (&context as *const ApBatchContext).cast_mut().cast(),
        None,
        Some(Duration::from_secs(10)),
    )
    .map_err(|error| ResidentProbeError::Allocation(error.status()))?;
    if context.callback_failed.load(Ordering::Acquire)
        || entries
            .iter()
            .any(|entry| !entry.invoked.load(Ordering::Acquire))
    {
        return Err(ResidentProbeError::Allocation(Status::DEVICE_ERROR));
    }
    Ok(())
}

extern "efiapi" fn callback(argument: *mut c_void) {
    let context = unsafe { &*argument.cast::<ApBatchContext>() };
    let mp = unsafe { &*context.mp };
    let Ok(processor_number) = mp.who_am_i() else {
        context.callback_failed.store(true, Ordering::Release);
        return;
    };
    let entries = unsafe { core::slice::from_raw_parts(context.entries, context.entry_count) };
    let Some(entry) = entries
        .iter()
        .find(|entry| entry.processor_number == processor_number)
    else {
        context.callback_failed.store(true, Ordering::Release);
        return;
    };
    // Each launch contains a unique mutable resource borrow, so even an
    // unexpected duplicate firmware callback must not enter it twice.
    if entry.invoked.swap(true, Ordering::AcqRel) {
        context.callback_failed.store(true, Ordering::Release);
        return;
    }
    if unsafe { matrixhv_ap_launch_asm(entry.launch) } != 1 {
        context.callback_failed.store(true, Ordering::Release);
    }
}
