use core::ffi::c_void;
use core::time::Duration;

use uefi::Status;
use uefi::boot;
use uefi::proto::pi::mp::MpServices;

use crate::arch::x86_64::{control_regs, cpuid, registers};
use crate::hv_core::vt_entry::{
    VmlaunchError, VmlaunchProbeResourceAddresses, VmlaunchProbeResources, VmlaunchReport,
};
use crate::runtime::logger;

const INTERRUPT_FLAG: u64 = 1 << 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuLocalState {
    pub(crate) apic_id: u32,
    pub(crate) cr0: u64,
    pub(crate) cr3: u64,
    pub(crate) cr4: u64,
    pub(crate) rflags: u64,
}

impl CpuLocalState {
    fn capture() -> Self {
        let max_basic_leaf = cpuid::leaf(0).eax;
        let apic_id = if max_basic_leaf >= 0xb {
            cpuid::leaf_with_subleaf(0xb, 0).edx
        } else {
            cpuid::leaf(1).ebx >> 24
        };
        Self {
            apic_id,
            cr0: control_regs::read_cr0(),
            cr3: control_regs::read_cr3(),
            cr4: control_regs::read_cr4(),
            rflags: registers::read_rflags(),
        }
    }

    fn vmx_state_restored(self, after: Self) -> bool {
        self.apic_id == after.apic_id
            && self.cr0 == after.cr0
            && self.cr3 == after.cr3
            && self.cr4 == after.cr4
            && (self.rflags ^ after.rflags) & INTERRUPT_FLAG == 0
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
    let handle = boot::get_handle_for_protocol::<MpServices>()
        .map_err(|error| ApplicationProcessorVmxProofError::Uefi(error.status()))?;
    let mp = boot::open_protocol_exclusive::<MpServices>(handle)
        .map_err(|error| ApplicationProcessorVmxProofError::Uefi(error.status()))?;
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

    logger::info(format_args!(
        "smp vmx proof resources bsp vmxon={:#x} vmcs={:#x} guest_stack={:#x} ap vmxon={:#x} vmcs={:#x} guest_stack={:#x}",
        bsp_addresses.vmxon,
        bsp_addresses.vmcs,
        bsp_addresses.guest_stack,
        ap_addresses.vmxon,
        ap_addresses.vmcs,
        ap_addresses.guest_stack
    ));

    let bsp_initial = CpuLocalState::capture();
    bsp_resources
        .run()
        .map_err(ApplicationProcessorVmxProofError::BspProbe)?;
    let bsp_final = CpuLocalState::capture();
    if !bsp_initial.vmx_state_restored(bsp_final) {
        return Err(ApplicationProcessorVmxProofError::BspStateNotRestored);
    }

    let mut context = ApProbeContext {
        resources: &mut ap_resources,
        initial_state: None,
        final_state: None,
        result: None,
    };
    logger::phase("smp.cpu1_vmx.startup_this_ap.start");
    mp.startup_this_ap(
        processor_number,
        application_processor_vmx_callback,
        (&mut context as *mut ApProbeContext).cast::<c_void>(),
        None,
        Some(Duration::from_secs(5)),
    )
    .map_err(|error| ApplicationProcessorVmxProofError::Uefi(error.status()))?;
    logger::phase("smp.cpu1_vmx.startup_this_ap.returned");

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
        return Err(ApplicationProcessorVmxProofError::ApStateNotRestored);
    }

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

extern "efiapi" fn application_processor_vmx_callback(argument: *mut c_void) {
    let context = unsafe { &mut *argument.cast::<ApProbeContext>() };
    let initial_state = CpuLocalState::capture();
    context.initial_state = Some(initial_state);
    logger::info(format_args!(
        "smp cpu1 callback apic_id={:#x} cr0={:#x} cr3={:#x} cr4={:#x} rflags={:#x}",
        initial_state.apic_id,
        initial_state.cr0,
        initial_state.cr3,
        initial_state.cr4,
        initial_state.rflags
    ));
    logger::phase("smp.cpu1_vmx.vmlaunch.start");
    let resources = unsafe { &mut *context.resources };
    context.result = Some(resources.run());
    context.final_state = Some(CpuLocalState::capture());
    logger::phase("smp.cpu1_vmx.vmlaunch.returned");
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
