use uefi::Status;

use crate::arch::x86_64::registers;
use crate::boot::logger;
use crate::hv_core::vt_controls::{self, VmxControls, VmxControlsError};
use crate::hv_core::vt_entry;
use crate::hv_core::vt_exits::{self, DispatchDiagnostics, VmRunContext};
use crate::hv_core::vt_state::{self, GuestStateReport, HostStateReport};
use crate::hv_core::vt_vmcs::{self, VmcsError, VmcsRegion};
use crate::hv_core::vt_vmcs_fields::VM_INSTRUCTION_ERROR;
use crate::hv_core::vt_vmxon::{
    self, VmxInstructionResult, VmxRootSession, VmxonError, VmxonReport,
};
use crate::memory::paging::{HostAddressSpace, HostAddressSpaceReport, HostPagingError};
use crate::memory::resident::{AddressConstraint, RESIDENT_MEMORY_TYPE, ResidentPages};

const PAGE_SIZE: usize = 4096;
const GUEST_STACK_PAGES: usize = 64;
const HOST_EXIT_STACK_PAGES: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentVcpuError {
    Vmxon(VmxonError),
    Vmcs(VmcsError),
    Controls(VmxControlsError),
    VmlaunchVmFailInvalid,
    VmlaunchVmFailValid(u64),
    VmresumeVmFailInvalid,
    VmresumeVmFailValid(u64),
    HostRspVmwrite,
    HostRipVmwrite,
    GuestRspVmread,
    GuestRspVmwrite,
    UnexpectedRunPath(u64),
    DispatcherFailure(u32),
    MissingStopVmcall,
    GuestRspMismatch {
        expected: u64,
        actual: u64,
    },
    ResidentAllocation(Status),
    HostPaging(HostPagingError),
    HostCr3NotIndependent {
        guest: u64,
        host: u64,
    },
    HostCr3Mismatch {
        expected: u64,
        first_seen: u64,
        last_seen: u64,
    },
    CleanupVmclear(VmxInstructionResult),
}

impl From<VmcsError> for PersistentVcpuError {
    fn from(value: VmcsError) -> Self {
        Self::Vmcs(value)
    }
}

impl From<VmxControlsError> for PersistentVcpuError {
    fn from(value: VmxControlsError) -> Self {
        Self::Controls(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistentVcpuReport {
    pub vmxon: VmxonReport,
    pub vmcs_physical_address: u64,
    pub controls: VmxControls,
    pub host: HostStateReport,
    pub guest: GuestStateReport,
    pub diagnostics: DispatchDiagnostics,
    pub host_address_space: HostAddressSpaceReport,
    pub result: u64,
    pub initial_rflags: u64,
}

struct StackRegion {
    pages: ResidentPages,
}

impl StackRegion {
    fn allocate(pages: usize) -> Result<Self, PersistentVcpuError> {
        let pages = ResidentPages::allocate(pages, AddressConstraint::Any)
            .map_err(PersistentVcpuError::ResidentAllocation)?;
        Ok(Self { pages })
    }

    fn top(&self) -> u64 {
        (self.pages.physical_address() + self.pages.byte_len() as u64) & !0xf
    }

    fn prepare_host_exit(&mut self, context: *mut VmRunContext) -> u64 {
        let host_rsp = (self.top() - 16) & !0xf;
        unsafe {
            (host_rsp as *mut u64).write(context as u64);
        }
        host_rsp
    }
}

struct RunContextRegion {
    pages: ResidentPages,
}

impl RunContextRegion {
    fn allocate() -> Result<Self, PersistentVcpuError> {
        if core::mem::size_of::<VmRunContext>() > PAGE_SIZE {
            return Err(PersistentVcpuError::ResidentAllocation(
                Status::OUT_OF_RESOURCES,
            ));
        }
        let pages = ResidentPages::allocate(1, AddressConstraint::Any)
            .map_err(PersistentVcpuError::ResidentAllocation)?;
        unsafe {
            pages
                .pointer()
                .as_ptr()
                .cast::<VmRunContext>()
                .write(VmRunContext::default());
        }
        Ok(Self { pages })
    }

    fn as_mut_ptr(&mut self) -> *mut VmRunContext {
        self.pages.pointer().as_ptr().cast::<VmRunContext>()
    }

    fn physical_address(&self) -> u64 {
        self.pages.physical_address()
    }
}

pub struct Vcpu {
    session: Option<VmxRootSession>,
    vmcs_region: VmcsRegion,
    guest_stack: StackRegion,
    host_exit_stack: StackRegion,
    run_context: RunContextRegion,
    host_address_space: HostAddressSpace,
    vmxon: VmxonReport,
    vmcs_physical_address: u64,
    controls: VmxControls,
    host: HostStateReport,
    guest: GuestStateReport,
    initial_rflags: u64,
}

impl Vcpu {
    pub fn new(entry_rip: u64) -> Result<Self, PersistentVcpuError> {
        let initial_rflags = registers::read_rflags();
        let vmx_basic = vt_vmxon::vmx_basic();
        let revision_id = vt_vmxon::revision_id(vmx_basic);
        let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
        vmcs_region.write_revision_id(revision_id);
        let vmcs_physical_address = vmcs_region.physical_address();
        let guest_stack = StackRegion::allocate(GUEST_STACK_PAGES)?;
        let host_exit_stack = StackRegion::allocate(HOST_EXIT_STACK_PAGES)?;
        let run_context = RunContextRegion::allocate()?;
        let mut host_address_space =
            HostAddressSpace::reserve().map_err(PersistentVcpuError::HostPaging)?;

        let session = vt_vmxon::enter_vmx_root().map_err(PersistentVcpuError::Vmxon)?;
        let vmxon = session.report();
        let host_address_space_report = host_address_space
            .clone_current()
            .map_err(PersistentVcpuError::HostPaging)?;

        logger::phase("vmx.vcpu.vmclear.start");
        let clear_result = unsafe { vt_vmcs::vmclear(vmcs_physical_address) };
        if clear_result != VmxInstructionResult::Succeeded {
            drop(session);
            return Err(PersistentVcpuError::Vmcs(VmcsError::Vmclear(clear_result)));
        }
        logger::phase("vmx.vcpu.vmclear.ok");

        logger::phase("vmx.vcpu.vmptrld.start");
        let load_result = unsafe { vt_vmcs::vmptrld(vmcs_physical_address) };
        if load_result != VmxInstructionResult::Succeeded {
            drop(session);
            return Err(PersistentVcpuError::Vmcs(VmcsError::Vmptrld(load_result)));
        }
        logger::phase("vmx.vcpu.vmptrld.ok");

        let controls = vt_controls::configure()?;
        let host = vt_state::configure_host_with_cr3(host_address_space_report.host_cr3)?;
        let guest =
            vt_state::configure_guest_with_rflags(entry_rip, guest_stack.top(), initial_rflags)?;
        if host.cr3 == guest.cr3 {
            drop(session);
            return Err(PersistentVcpuError::HostCr3NotIndependent {
                guest: guest.cr3,
                host: host.cr3,
            });
        }
        logger::info(format_args!(
            "vcpu state vmcs_pa={:#x} entry={:#x} guest_rsp={:#x} guest_rflags={:#x} guest_cr3={:#x} host_cr3={:#x} host_tr={:#x} primary={:#x} secondary={:#x}",
            vmcs_physical_address,
            entry_rip,
            guest.rsp,
            guest.rflags,
            guest.cr3,
            host.cr3,
            host.tr_selector,
            controls.primary_processor_based,
            controls.secondary_processor_based
        ));
        logger::info(format_args!(
            "vcpu resident memory_type={} vmxon_pa={:#x} vmcs_pa={:#x} guest_stack={:#x}/{} host_stack={:#x}/{} context={:#x} host_pt_arena={:#x}/{} host_pt_used={}",
            RESIDENT_MEMORY_TYPE.0,
            vmxon.region_physical_address,
            vmcs_physical_address,
            guest_stack.pages.physical_address(),
            guest_stack.pages.pages(),
            host_exit_stack.pages.physical_address(),
            host_exit_stack.pages.pages(),
            run_context.physical_address(),
            host_address_space_report.arena_physical_address,
            host_address_space_report.arena_pages,
            host_address_space_report.table_pages
        ));
        logger::phase("vmx.vcpu.state.ok");

        Ok(Self {
            session: Some(session),
            vmcs_region,
            guest_stack,
            host_exit_stack,
            run_context,
            host_address_space,
            vmxon,
            vmcs_physical_address,
            controls,
            host,
            guest,
            initial_rflags,
        })
    }

    pub fn run(mut self) -> Result<PersistentVcpuReport, PersistentVcpuError> {
        let context = self.run_context.as_mut_ptr();
        let host_exit_rsp = self.host_exit_stack.prepare_host_exit(context);
        vt_exits::reset_diagnostics();
        logger::phase("vmx.vcpu.launch.start");
        let raw_path = unsafe { vt_entry::run_persistent_loop(context, host_exit_rsp) };
        logger::phase("vmx.vcpu.returned_to_host");

        let vm_instruction_error = vt_vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
        let diagnostics = vt_exits::diagnostics();
        let validation = validate_run(
            raw_path,
            vm_instruction_error,
            self.guest,
            self.host,
            diagnostics,
        );

        logger::phase("vmx.vcpu.final_vmclear.start");
        let final_clear = unsafe { vt_vmcs::vmclear(self.vmcs_physical_address) };
        if final_clear == VmxInstructionResult::Succeeded {
            logger::phase("vmx.vcpu.final_vmclear.ok");
        }
        self.host_address_space.restore_source_cr3();
        logger::phase("vmx.vcpu.host_cr3_restored");
        if let Some(session) = self.session.take() {
            drop(session);
        }
        logger::phase("vmx.vcpu.vmxoff_restored");

        if final_clear != VmxInstructionResult::Succeeded {
            return Err(PersistentVcpuError::CleanupVmclear(final_clear));
        }
        validation?;

        Ok(PersistentVcpuReport {
            vmxon: self.vmxon,
            vmcs_physical_address: self.vmcs_physical_address,
            controls: self.controls,
            host: self.host,
            guest: self.guest,
            diagnostics,
            host_address_space: self.host_address_space.report(),
            result: diagnostics.final_eax,
            initial_rflags: self.initial_rflags,
        })
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            let _ = unsafe { vt_vmcs::vmclear(self.vmcs_physical_address) };
            self.host_address_space.restore_source_cr3();
            drop(session);
        }
        let _ = &self.vmcs_region;
        let _ = &self.guest_stack;
    }
}

pub fn run(entry_rip: u64) -> Result<PersistentVcpuReport, PersistentVcpuError> {
    Vcpu::new(entry_rip)?.run()
}

fn validate_run(
    raw_path: u64,
    vm_instruction_error: u64,
    guest: GuestStateReport,
    host: HostStateReport,
    diagnostics: DispatchDiagnostics,
) -> Result<(), PersistentVcpuError> {
    match raw_path {
        0 => {}
        1 => return Err(PersistentVcpuError::VmlaunchVmFailInvalid),
        2 => {
            return Err(PersistentVcpuError::VmlaunchVmFailValid(
                vm_instruction_error,
            ));
        }
        3 => return Err(PersistentVcpuError::HostRspVmwrite),
        4 => return Err(PersistentVcpuError::HostRipVmwrite),
        5 => return Err(PersistentVcpuError::VmresumeVmFailInvalid),
        6 => {
            return Err(PersistentVcpuError::VmresumeVmFailValid(
                vm_instruction_error,
            ));
        }
        7 => return Err(PersistentVcpuError::GuestRspVmread),
        8 => return Err(PersistentVcpuError::GuestRspVmwrite),
        other => return Err(PersistentVcpuError::UnexpectedRunPath(other)),
    }

    if diagnostics.failure_code != 0 {
        return Err(PersistentVcpuError::DispatcherFailure(
            diagnostics.failure_code,
        ));
    }
    if diagnostics.vmcall_count != 1 {
        return Err(PersistentVcpuError::MissingStopVmcall);
    }
    if diagnostics.final_rsp != guest.rsp {
        return Err(PersistentVcpuError::GuestRspMismatch {
            expected: guest.rsp,
            actual: diagnostics.final_rsp,
        });
    }
    if diagnostics.first_host_cr3 != host.cr3 || diagnostics.last_host_cr3 != host.cr3 {
        return Err(PersistentVcpuError::HostCr3Mismatch {
            expected: host.cr3,
            first_seen: diagnostics.first_host_cr3,
            last_seen: diagnostics.last_host_cr3,
        });
    }
    Ok(())
}

pub fn status_from_error(error: &PersistentVcpuError) -> Status {
    match error {
        PersistentVcpuError::Vmxon(VmxonError::Allocation(status))
        | PersistentVcpuError::Vmcs(VmcsError::Allocation(status))
        | PersistentVcpuError::ResidentAllocation(status)
        | PersistentVcpuError::HostPaging(HostPagingError::Allocation(status)) => *status,
        _ => Status::DEVICE_ERROR,
    }
}
