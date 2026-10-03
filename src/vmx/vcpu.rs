use super::entry::VmlaunchError;
use crate::arch;
use crate::vmx::controls::{self, VmxControls, VmxControlsError};
use crate::vmx::entry;
use crate::vmx::exits::{self, DispatchDiagnostics, VmRunContext};
use crate::vmx::state::{
    self, GuestStateReport, HostStateReport, ResidentHostSelectors, ResidentHostTables,
};
use crate::vmx::vmcs::{self, VM_INSTRUCTION_ERROR, VmcsError, VmcsRegion};
use crate::vmx::vmxon::{
    self, VmxInstructionResult, VmxRootSession, VmxonError, VmxonRegion, VmxonReport,
};
use crate::memory::host::{
    AddressConstraint, HostAddressSpace, HostAddressSpaceReport, HostPagingError,
    RESIDENT_MEMORY_TYPE, ResidentPages,
};
use crate::logging;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::ffi::c_void;
use core::ptr::NonNull;
use uefi::Status;
use uefi::boot::{self, AllocateType};
use uefi::mem::memory_map::MemoryType;

use super::ept::{EptComposition, EptError, IdentityEpt};
use super::msr::configure_resident_msr_switch;
use super::nested::{
    NestedVmcs02Configuration, configure_nested_vmcs02, configure_resident_vmcs_shadowing,
};
use super::resident::abi::{
    RESIDENT_BOOT_CONTEXT_PAGES, ResidentBootContext, ResidentContext, ResidentEventContext,
};
use super::resident::{ResidentCode, ResidentProbeError};
use super::state::configure_resident_host;
use super::vmcs::{HOST_RIP, HOST_RSP, vmwrite};
use crate::vmx::hyperv;
pub(crate) const BOOT_GUEST_STACK_PAGES: usize = 64;
pub(crate) const HOST_STACK_PAGES: usize = 4;
use crate::vmx::nested::{NestedVmxCapabilities, native_vmcs_shadowing_available};

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
                .write(VmRunContext::for_boot_target());
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
        let initial_rflags = arch::read_rflags();
        let vmx_basic = vmxon::vmx_basic();
        let revision_id = vmxon::revision_id(vmx_basic);
        let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
        vmcs_region.write_revision_id(revision_id);
        let vmcs_physical_address = vmcs_region.physical_address();
        let guest_stack = StackRegion::allocate(GUEST_STACK_PAGES)?;
        let host_exit_stack = StackRegion::allocate(HOST_EXIT_STACK_PAGES)?;
        let run_context = RunContextRegion::allocate()?;
        let mut host_address_space =
            HostAddressSpace::reserve().map_err(PersistentVcpuError::HostPaging)?;

        let host_address_space_report = host_address_space
            .clone_current()
            .map_err(PersistentVcpuError::HostPaging)?;
        let session = vmxon::enter_vmx_root().map_err(PersistentVcpuError::Vmxon)?;
        let vmxon = session.report();

        logging::phase("vmx.vcpu.vmclear.start");
        let clear_result = unsafe { vmcs::vmclear(vmcs_physical_address) };
        if clear_result != VmxInstructionResult::Succeeded {
            drop(session);
            return Err(PersistentVcpuError::Vmcs(VmcsError::Vmclear(clear_result)));
        }
        logging::phase("vmx.vcpu.vmclear.ok");

        logging::phase("vmx.vcpu.vmptrld.start");
        let load_result = unsafe { vmcs::vmptrld(vmcs_physical_address) };
        if load_result != VmxInstructionResult::Succeeded {
            drop(session);
            return Err(PersistentVcpuError::Vmcs(VmcsError::Vmptrld(load_result)));
        }
        logging::phase("vmx.vcpu.vmptrld.ok");

        let controls = controls::configure()?;
        let host = state::configure_host_with_cr3(host_address_space_report.host_cr3)?;
        let guest =
            state::configure_guest_with_rflags(entry_rip, guest_stack.top(), initial_rflags)?;
        if host.cr3 == guest.cr3 {
            drop(session);
            return Err(PersistentVcpuError::HostCr3NotIndependent {
                guest: guest.cr3,
                host: host.cr3,
            });
        }
        logging::info(format_args!(
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
        logging::info(format_args!(
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
        logging::phase("vmx.vcpu.state.ok");

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
        exits::reset_diagnostics();
        logging::phase("vmx.vcpu.launch.start");
        let raw_path = unsafe { entry::run_persistent_loop(context, host_exit_rsp) };
        logging::phase("vmx.vcpu.returned_to_host");

        let vm_instruction_error = vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
        let diagnostics = exits::diagnostics();
        let validation = validate_run(
            raw_path,
            vm_instruction_error,
            self.guest,
            self.host,
            diagnostics,
        );

        logging::phase("vmx.vcpu.final_vmclear.start");
        let final_clear = unsafe { vmcs::vmclear(self.vmcs_physical_address) };
        if final_clear == VmxInstructionResult::Succeeded {
            logging::phase("vmx.vcpu.final_vmclear.ok");
        }
        self.host_address_space.restore_source_cr3();
        logging::phase("vmx.vcpu.host_cr3_restored");
        if let Some(session) = self.session.take() {
            drop(session);
        }
        logging::phase("vmx.vcpu.vmxoff_restored");

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
            let _ = unsafe { vmcs::vmclear(self.vmcs_physical_address) };
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

const NESTED_VMXON_OPERAND_OFFSET: u64 = 8;
const NESTED_VMCS12_OPERAND_POINTER_OFFSET: usize = 16;
const NESTED_VMPTRST_DESTINATION_POINTER_OFFSET: usize = 24;
const NESTED_VMCS12_OPERAND_PAGE_OFFSET: u64 = PAGE_SIZE as u64;
const NESTED_VMPTRST_DESTINATION_OFFSET: u64 = NESTED_VMCS12_OPERAND_PAGE_OFFSET + 8;
const NESTED_EPT12_POINTER_OFFSET: usize = 32;
const NESTED_EPT_SOURCE_POINTER_OFFSET: usize = 40;
const NESTED_EPT_TARGET_POINTER_OFFSET: usize = 48;
pub(crate) const NESTED_EPT_SECOND_TARGET_POINTER_OFFSET: usize = 56;
pub(crate) const NESTED_EPT12_SOURCE_LEAF_POINTER_OFFSET: usize = 64;
pub(crate) const NESTED_INVEPT_DESCRIPTOR_OFFSET: usize = 72;
pub(crate) const NESTED_INVEPT_RIP_OFFSET: usize = 88;
pub(crate) const NESTED_INVEPT_AFTER_RIP_OFFSET: usize = 96;
pub(crate) const NESTED_INVVPID_DESCRIPTOR_OFFSET: usize = 104;
pub(crate) const NESTED_INVVPID_RIP_OFFSET: usize = 120;
pub(crate) const NESTED_INVVPID_AFTER_RIP_OFFSET: usize = 128;
pub(crate) const NESTED_EPT_SOURCE_MARKER: u64 = 0x4e45_5054_5352_4331;
pub(crate) const NESTED_EPT_TARGET_MARKER: u64 = 0x4e45_5054_5447_5431;
pub(crate) const NESTED_EPT_SECOND_TARGET_MARKER: u64 = 0x4e45_5054_5447_5432;
const NESTED_MSR_STATE_PAGES: usize = 10;

struct ResidentVmcsShadow {
    vmcs_region: VmcsRegion,
    vmread_bitmap: ResidentPages,
    vmwrite_bitmap: ResidentPages,
}

pub(crate) struct ResidentCpuResources {
    pub(crate) vmxon_region: VmxonRegion,
    pub(crate) vmcs_region: VmcsRegion,
    pub(crate) nested_vmcs02_region: VmcsRegion,
    vmcs_shadow: Option<ResidentVmcsShadow>,
    pub(crate) host_tables: ResidentHostTables,
    pub(crate) context_pages: ResidentPages,
    pub(crate) guest_stack: ResidentPages,
    pub(crate) host_stack: ResidentPages,
    pub(crate) resident_msr_state: ResidentPages,
    pub(crate) nested_msr_state: ResidentPages,
    pub(crate) nested_eptp_list: ResidentPages,
    pub(crate) nested_eptp_tables: ResidentPages,
    pub(crate) nested_vmxon_page: ResidentPages,
    pub(crate) nested_vmcs12_pages: ResidentPages,
    nested_ept_source_page: ResidentPages,
    nested_ept_target_page: ResidentPages,
    nested_ept_second_target_page: ResidentPages,
    nested_ept12: Option<IdentityEpt>,
    nested_ept02: Option<IdentityEpt>,
    nested_ept02_alternate: Option<IdentityEpt>,
    nested_ept_composition: Option<EptComposition>,
    nested_ept_alternate_composition: Option<EptComposition>,
    nested_ept12_source_leaf: u64,
    nested_ept12_source_leaf_attributes: u64,
}

impl ResidentCpuResources {
    pub(crate) fn allocate(
        vmx_basic: u64,
        fatal_handler: u64,
        gp_handler: u64,
        exception_stubs: u64,
    ) -> Result<Self, ResidentProbeError> {
        let vmxon_region = VmxonRegion::allocate(vmx_basic).map_err(ResidentProbeError::Vmxon)?;
        let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
        vmcs_region.write_revision_id(vmxon::revision_id(vmx_basic));
        let mut nested_vmcs02_region = VmcsRegion::allocate(vmx_basic)?;
        nested_vmcs02_region.write_revision_id(vmxon::revision_id(vmx_basic));
        let vmcs_shadow = if native_vmcs_shadowing_available(unsafe {
            arch::read_msr(arch::IA32_VMX_PROCBASED_CTLS2)
        }) {
            let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
            vmcs_region.write_revision_id(vmxon::revision_id(vmx_basic) | (1 << 31));
            let bitmap_constraint = if vmxon::region_uses_32_bit_physical_addresses(vmx_basic) {
                AddressConstraint::Max(u32::MAX as u64)
            } else {
                AddressConstraint::Any
            };
            let vmread_bitmap =
                ResidentPages::allocate_initialized(1, bitmap_constraint, |bytes| {
                    bytes.fill(0xff);
                })
                .map_err(ResidentProbeError::Allocation)?;
            let vmwrite_bitmap =
                ResidentPages::allocate_initialized(1, bitmap_constraint, |bytes| {
                    bytes.fill(0xff);
                })
                .map_err(ResidentProbeError::Allocation)?;
            Some(ResidentVmcsShadow {
                vmcs_region,
                vmread_bitmap,
                vmwrite_bitmap,
            })
        } else {
            None
        };
        let host_tables = ResidentHostTables::allocate(
            fatal_handler,
            gp_handler,
            exception_stubs,
            ResidentHostSelectors::fixed(),
        )?;
        let context_pages =
            ResidentPages::allocate(RESIDENT_BOOT_CONTEXT_PAGES, AddressConstraint::Any)
                .map_err(ResidentProbeError::Allocation)?;
        // The OS loader accesses the firmware caller's stack before restoring firmware CR3.
        // Reserved pages can be absent from the loader's identity mapping.
        let guest_stack = ResidentPages::allocate_typed(
            BOOT_GUEST_STACK_PAGES,
            AddressConstraint::Any,
            MemoryType::LOADER_DATA,
        )
        .map_err(ResidentProbeError::Allocation)?;
        let host_stack = ResidentPages::allocate(HOST_STACK_PAGES, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let resident_msr_state = ResidentPages::allocate(1, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let nested_msr_state =
            ResidentPages::allocate(NESTED_MSR_STATE_PAGES, AddressConstraint::Any)
                .map_err(ResidentProbeError::Allocation)?;
        let nested_eptp_list = ResidentPages::allocate(1, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let nested_eptp_tables = ResidentPages::allocate(64, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let nested_vmxon_page = ResidentPages::allocate(1, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let nested_vmcs12_pages = ResidentPages::allocate(2, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let nested_ept_source_page = ResidentPages::allocate(1, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let nested_ept_target_page = ResidentPages::allocate(1, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let nested_ept_second_target_page = ResidentPages::allocate(1, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let capabilities = NestedVmxCapabilities::vmxon_vmxoff(vmx_basic);
        let nested_vmcs12_region = nested_vmcs12_pages.physical_address();
        let nested_vmcs12_operand = nested_vmcs12_region + NESTED_VMCS12_OPERAND_PAGE_OFFSET;
        let nested_vmptrst_destination = nested_vmcs12_region + NESTED_VMPTRST_DESTINATION_OFFSET;
        unsafe {
            let page = nested_vmxon_page.pointer().as_ptr();
            page.write_bytes(0, nested_vmxon_page.byte_len());
            page.cast::<u32>().write(capabilities.revision_id);
            page.add(NESTED_VMXON_OPERAND_OFFSET as usize)
                .cast::<u64>()
                .write(nested_vmxon_page.physical_address());
            page.add(NESTED_VMCS12_OPERAND_POINTER_OFFSET)
                .cast::<u64>()
                .write(nested_vmcs12_operand);
            page.add(NESTED_VMPTRST_DESTINATION_POINTER_OFFSET)
                .cast::<u64>()
                .write(nested_vmptrst_destination);

            let vmcs12 = nested_vmcs12_pages.pointer().as_ptr();
            vmcs12.write_bytes(0, nested_vmcs12_pages.byte_len());
            vmcs12.cast::<u32>().write(capabilities.revision_id);
            vmcs12
                .add(NESTED_VMCS12_OPERAND_PAGE_OFFSET as usize)
                .cast::<u64>()
                .write(nested_vmcs12_region);
            vmcs12
                .add(NESTED_VMPTRST_DESTINATION_OFFSET as usize)
                .cast::<u64>()
                .write(u64::MAX);
            nested_ept_source_page
                .pointer()
                .as_ptr()
                .cast::<u64>()
                .write(NESTED_EPT_SOURCE_MARKER);
            nested_ept_target_page
                .pointer()
                .as_ptr()
                .cast::<u64>()
                .write(NESTED_EPT_TARGET_MARKER);
            nested_ept_second_target_page
                .pointer()
                .as_ptr()
                .cast::<u64>()
                .write(NESTED_EPT_SECOND_TARGET_MARKER);
        }

        Ok(Self {
            vmxon_region,
            vmcs_region,
            nested_vmcs02_region,
            vmcs_shadow,
            host_tables,
            context_pages,
            guest_stack,
            host_stack,
            resident_msr_state,
            nested_msr_state,
            nested_eptp_list,
            nested_eptp_tables,
            nested_vmxon_page,
            nested_vmcs12_pages,
            nested_ept_source_page,
            nested_ept_target_page,
            nested_ept_second_target_page,
            nested_ept12: None,
            nested_ept02: None,
            nested_ept02_alternate: None,
            nested_ept_composition: None,
            nested_ept_alternate_composition: None,
            nested_ept12_source_leaf: 0,
            nested_ept12_source_leaf_attributes: 0,
        })
    }

    pub(crate) fn prepare_nested_ept(
        &mut self,
        ept01: &IdentityEpt,
        ept12_template: &IdentityEpt,
    ) -> Result<EptComposition, EptError> {
        let source_gpa = self.nested_ept_source_page.physical_address();
        let target_gpa = self.nested_ept_target_page.physical_address();
        let second_target_gpa = self.nested_ept_second_target_page.physical_address();
        let mut ept12 = ept12_template.clone_identity_tables()?;
        ept12.remap_page(source_gpa, target_gpa)?;
        let source_leaf = ept12.leaf_entry_physical_address(source_gpa)?;
        let source_leaf_attributes = ept12.leaf_entry_value(source_gpa)? & 0xfff;
        let mut ept02 = ept01.sparse_shadow()?;
        let composition = ept02.compose_page(&ept12, ept01, source_gpa)?;
        ept12.remap_page(source_gpa, second_target_gpa)?;
        let mut ept02_alternate = ept01.sparse_shadow()?;
        let alternate_composition = ept02_alternate.compose_page(&ept12, ept01, source_gpa)?;
        ept12.remap_page(source_gpa, target_gpa)?;
        unsafe {
            let metadata = self.nested_vmxon_page.pointer().as_ptr();
            metadata
                .add(NESTED_EPT12_POINTER_OFFSET)
                .cast::<u64>()
                .write(ept12.ept_pointer());
            metadata
                .add(NESTED_EPT_SOURCE_POINTER_OFFSET)
                .cast::<u64>()
                .write(source_gpa);
            metadata
                .add(NESTED_EPT_TARGET_POINTER_OFFSET)
                .cast::<u64>()
                .write(target_gpa);
            metadata
                .add(NESTED_EPT_SECOND_TARGET_POINTER_OFFSET)
                .cast::<u64>()
                .write(second_target_gpa);
            metadata
                .add(NESTED_EPT12_SOURCE_LEAF_POINTER_OFFSET)
                .cast::<u64>()
                .write(source_leaf);
            metadata
                .add(NESTED_INVEPT_DESCRIPTOR_OFFSET)
                .cast::<u64>()
                .write(ept12.ept_pointer());
            metadata
                .add(NESTED_INVEPT_DESCRIPTOR_OFFSET + size_of::<u64>())
                .cast::<u64>()
                .write(0);
            metadata
                .add(NESTED_INVVPID_DESCRIPTOR_OFFSET)
                .cast::<u64>()
                .write(1);
            metadata
                .add(NESTED_INVVPID_DESCRIPTOR_OFFSET + size_of::<u64>())
                .cast::<u64>()
                .write(0);
        }
        self.nested_ept12 = Some(ept12);
        self.nested_ept02 = Some(ept02);
        self.nested_ept02_alternate = Some(ept02_alternate);
        self.nested_ept_composition = Some(composition);
        self.nested_ept_alternate_composition = Some(alternate_composition);
        self.nested_ept12_source_leaf = source_leaf;
        self.nested_ept12_source_leaf_attributes = source_leaf_attributes;
        Ok(composition)
    }

    pub(crate) fn nested_vmxon_operand(&self) -> u64 {
        self.nested_vmxon_page.physical_address() + NESTED_VMXON_OPERAND_OFFSET
    }

    pub(crate) fn nested_vmxon_region(&self) -> u64 {
        self.nested_vmxon_page.physical_address()
    }

    pub(crate) fn nested_vmcs12_operand(&self) -> u64 {
        self.nested_vmcs12_pages.physical_address() + NESTED_VMCS12_OPERAND_PAGE_OFFSET
    }

    pub(crate) fn nested_vmcs12_region(&self) -> u64 {
        self.nested_vmcs12_pages.physical_address()
    }

    pub(crate) fn nested_vmptrst_destination(&self) -> u64 {
        self.nested_vmcs12_pages.physical_address() + NESTED_VMPTRST_DESTINATION_OFFSET
    }

    pub(crate) fn nested_vmcs02_region(&self) -> u64 {
        self.nested_vmcs02_region.physical_address()
    }

    pub(crate) fn vmcs_shadow_resources(&self) -> Option<(u64, u64, u64)> {
        self.vmcs_shadow.as_ref().map(|shadow| {
            (
                shadow.vmcs_region.physical_address(),
                shadow.vmread_bitmap.physical_address(),
                shadow.vmwrite_bitmap.physical_address(),
            )
        })
    }

    pub(crate) fn nested_ept12_pointer(&self) -> Option<u64> {
        self.nested_ept12.as_ref().map(IdentityEpt::ept_pointer)
    }

    pub(crate) fn nested_ept02_pointer(&self) -> Option<u64> {
        self.nested_ept02.as_ref().map(IdentityEpt::ept_pointer)
    }

    pub(crate) fn nested_ept02_alternate_pointer(&self) -> Option<u64> {
        self.nested_ept02_alternate
            .as_ref()
            .map(IdentityEpt::ept_pointer)
    }

    pub(crate) fn nested_ept02_table_pools(&self) -> Option<[(u64, usize, usize); 2]> {
        Some([
            self.nested_ept02.as_ref()?.protection_table_pool(),
            self.nested_ept02_alternate
                .as_ref()?
                .protection_table_pool(),
        ])
    }

    pub(crate) fn nested_ept_source_gpa(&self) -> u64 {
        self.nested_ept_source_page.physical_address()
    }

    pub(crate) fn nested_ept_target_gpa(&self) -> u64 {
        self.nested_ept_target_page.physical_address()
    }

    pub(crate) fn nested_ept_second_target_gpa(&self) -> u64 {
        self.nested_ept_second_target_page.physical_address()
    }

    pub(crate) fn nested_ept12_source_leaf(&self) -> u64 {
        self.nested_ept12_source_leaf
    }

    pub(crate) fn nested_ept12_source_leaf_attributes(&self) -> u64 {
        self.nested_ept12_source_leaf_attributes
    }

    pub(crate) fn nested_ept_composition(&self) -> Option<EptComposition> {
        self.nested_ept_composition
    }

    pub(crate) fn nested_ept_alternate_composition(&self) -> Option<EptComposition> {
        self.nested_ept_alternate_composition
    }

    pub(crate) fn nested_ept02_table_regions(&self) -> Vec<(u64, usize)> {
        let mut regions = self
            .nested_ept02
            .as_ref()
            .map(IdentityEpt::table_regions)
            .unwrap_or_default();
        if let Some(ept02) = &self.nested_ept02_alternate {
            regions.extend(ept02.table_regions());
        }
        regions
    }

    pub(crate) fn conceal_guest_access(
        &self,
        ept: &mut IdentityEpt,
        zero_page_physical_address: u64,
    ) -> Result<(), EptError> {
        ept.conceal_guest_access(
            self.nested_eptp_list.physical_address(),
            self.nested_eptp_list.pages(),
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.nested_eptp_tables.physical_address(),
            self.nested_eptp_tables.pages(),
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.vmxon_region.physical_address(),
            1,
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.vmcs_region.physical_address(),
            1,
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.nested_vmcs02_region.physical_address(),
            1,
            zero_page_physical_address,
        )?;
        if let Some(shadow) = &self.vmcs_shadow {
            ept.conceal_guest_access(
                shadow.vmcs_region.physical_address(),
                1,
                zero_page_physical_address,
            )?;
            ept.conceal_guest_access(
                shadow.vmread_bitmap.physical_address(),
                shadow.vmread_bitmap.pages(),
                zero_page_physical_address,
            )?;
            ept.conceal_guest_access(
                shadow.vmwrite_bitmap.physical_address(),
                shadow.vmwrite_bitmap.pages(),
                zero_page_physical_address,
            )?;
        }
        ept.conceal_guest_access(
            self.host_tables.pages.physical_address(),
            self.host_tables.pages.pages(),
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.context_pages.physical_address(),
            self.context_pages.pages(),
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.host_stack.physical_address(),
            self.host_stack.pages(),
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.resident_msr_state.physical_address(),
            self.resident_msr_state.pages(),
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.nested_msr_state.physical_address(),
            self.nested_msr_state.pages(),
            zero_page_physical_address,
        )?;
        Ok(())
    }
}

#[unsafe(no_mangle)]
unsafe extern "efiapi" fn matrixhv_ap_prepare(
    argument: *mut ResidentApLaunch<'_>,
    guest_rsp: u64,
    guest_rip: u64,
) -> u64 {
    let launch = unsafe { &mut *argument };
    match launch.prepare(guest_rsp, guest_rip) {
        Ok(nested_vmxon_operand) => nested_vmxon_operand,
        Err(error) => {
            crate::logging::error(format_args!("smp resident AP prepare error={error:?}"));
            0
        }
    }
}

unsafe extern "efiapi" {
    // Returns one after the resident guest probe, or zero if preparation failed.
    pub(crate) fn matrixhv_ap_launch_asm(argument: *mut c_void) -> u64;
}

#[unsafe(no_mangle)]
extern "efiapi" fn matrixhv_ap_launch_failed(flags: u64) -> ! {
    let error = crate::vmx::vmcs::vmread(crate::vmx::vmcs::VM_INSTRUCTION_ERROR);
    crate::logging::error(format_args!(
        "smp resident AP VMLAUNCH failed flags={flags:#x} instruction_error={error:?}"
    ));
    loop {
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

// The guest resumes on the firmware stack and returns through the original MP callback.
// Per-CPU VMX, paging, and context allocations remain retained for subsequent exits.
global_asm!(
    include_str!("../asm/guest_boot.S"),
    include_str!("asm/ap_launch.S"),
    ".purgem matrixhv_boot_guest_flow",
    ".purgem matrixhv_ap_guest_probe",
    checkpoint_magic = const crate::vmx::resident::RESIDENT_VMCALL_START_CHECKPOINT,
    stop_magic = const crate::vmx::resident::RESIDENT_VMCALL_STOP,
    nested_probe_failed = const crate::vmx::resident::RESIDENT_VMCALL_NESTED_PROBE_FAILED,
    guest_rip_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_RIP,
    guest_rsp_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_RSP,
    guest_rflags_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_RFLAGS,
    host_rip_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_RIP,
    host_rsp_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_RSP,
    exception_bitmap_field = const crate::vmx::vmcs12::VMCS_FIELD_EXCEPTION_BITMAP,
    cr3_target_count_field = const crate::vmx::vmcs12::VMCS_FIELD_CR3_TARGET_COUNT,
    guest_cr0_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_CR0,
    guest_cr3_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_CR3,
    guest_cr4_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_CR4,
    host_cr0_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_CR0,
    host_cr3_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_CR3,
    host_cr4_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_CR4,
    guest_sysenter_cs_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_SYSENTER_CS,
    guest_sysenter_esp_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_SYSENTER_ESP,
    guest_sysenter_eip_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_SYSENTER_EIP,
    host_sysenter_cs_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_SYSENTER_CS,
    host_sysenter_esp_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_SYSENTER_ESP,
    host_sysenter_eip_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_SYSENTER_EIP,
    pin_based_control_field = const crate::vmx::vmcs12::VMCS_FIELD_PIN_BASED_VM_EXEC_CONTROL,
    primary_control_field = const crate::vmx::vmcs12::VMCS_FIELD_CPU_BASED_VM_EXEC_CONTROL,
    secondary_control_field = const crate::vmx::vmcs12::VMCS_FIELD_SECONDARY_VM_EXEC_CONTROL,
    vpid_field = const crate::vmx::vmcs12::VMCS_FIELD_VPID,
    ept_pointer_field = const crate::vmx::vmcs12::VMCS_FIELD_EPT_POINTER,
    vm_exit_controls_field = const crate::vmx::vmcs12::VMCS_FIELD_VM_EXIT_CONTROLS,
    vm_entry_controls_field = const crate::vmx::vmcs12::VMCS_FIELD_VM_ENTRY_CONTROLS,
    primary_activate_secondary_controls = const crate::vmx::nested::VMX_PRIMARY_ACTIVATE_SECONDARY_CONTROLS,
    secondary_enable_ept = const crate::vmx::nested::VMX_SECONDARY_ENABLE_EPT,
    secondary_enable_vpid = const crate::vmx::nested::VMX_SECONDARY_ENABLE_VPID,
    vm_exit_host_address_space_size = const crate::vmx::nested::VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
    vm_entry_ia32e_mode_guest = const crate::vmx::nested::VM_ENTRY_IA32E_MODE_GUEST,
    ept_source_marker = const crate::vmx::vcpu::NESTED_EPT_SOURCE_MARKER,
    ept_target_marker = const crate::vmx::vcpu::NESTED_EPT_TARGET_MARKER,
    ept_second_target_marker = const crate::vmx::vcpu::NESTED_EPT_SECOND_TARGET_MARKER,
    exit_reason_field = const crate::vmx::vmcs12::VMCS_FIELD_VM_EXIT_REASON,
    exit_instruction_len_field = const crate::vmx::vmcs12::VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN,
    instruction_error_field = const crate::vmx::vmcs12::VMCS_FIELD_VM_INSTRUCTION_ERROR,
    vmxon_active_error = const crate::vmx::nested::VMXON_IN_VMX_ROOT_ERROR,
    invalid_control_error = const crate::vmx::nested::VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR,
    non_launched_error = const crate::vmx::nested::VMRESUME_NON_LAUNCHED_VMCS_ERROR,
    invalid_invalidation_operand_error = const crate::vmx::nested::INVALID_OPERAND_TO_INVEPT_INVVPID_ERROR,
    vmcs12_test_value = const crate::vmx::resident::NESTED_VMCS12_TEST_VALUE,
    l2_vmcall_magic = const crate::vmx::resident::NESTED_L2_VMCALL_MAGIC,
    l2_vmresume_magic = const crate::vmx::resident::NESTED_L2_VMRESUME_MAGIC,
    l2_post_invept_magic = const crate::vmx::resident::NESTED_L2_POST_INVEPT_MAGIC,
    sysenter_cs_msr = const crate::arch::IA32_SYSENTER_CS,
    sysenter_esp_msr = const crate::arch::IA32_SYSENTER_ESP,
    sysenter_eip_msr = const crate::arch::IA32_SYSENTER_EIP,
);

pub(crate) struct ResidentApLaunch<'a> {
    pub(crate) options: crate::boot::config::MatrixConfig,
    pub(crate) resources: &'a mut ResidentCpuResources,
    pub(crate) host_cr3: u64,
    pub(crate) event_context: u64,
    pub(crate) ept_pointer: u64,
    pub(crate) msr_bitmap: u64,
    pub(crate) dispatch_entry: u64,
    pub(crate) processor_number: usize,
}

impl ResidentApLaunch<'_> {
    pub(crate) fn prepare(
        &mut self,
        guest_rsp: u64,
        guest_rip: u64,
    ) -> Result<u64, ResidentProbeError> {
        let segments = arch::capture();
        let nested_vmxon_operand = self.resources.nested_vmxon_operand();
        let nested_vmcs02_region = self.resources.nested_vmcs02_region();
        let shadow_resources = self.resources.vmcs_shadow_resources();
        let nested_ept02_pointer = self
            .resources
            .nested_ept02_pointer()
            .ok_or(EptError::InvalidPageTable)?;
        let vmx_basic = vmxon::vmx_basic();
        let nested_configuration = nested_cpu_configuration(self.resources)?;
        let session =
            vmxon::enter_vmx_root_with_borrowed_region(vmx_basic, &mut self.resources.vmxon_region)
                .map_err(ResidentProbeError::Vmxon)?;
        let l1_cr4 = session.report().original_cr4;
        let vmcs = self.resources.vmcs_region.physical_address();
        let clear = unsafe { vmcs::vmclear(vmcs) };
        if clear != VmxInstructionResult::Succeeded {
            return Err(ResidentProbeError::Vmclear(clear));
        }
        let load = unsafe { vmcs::vmptrld(vmcs) };
        if load != VmxInstructionResult::Succeeded {
            return Err(ResidentProbeError::Vmcs(VmcsError::Vmptrld(load)));
        }
        let mut controls = controls::configure_resident_ap(self.msr_bitmap, self.ept_pointer)?;
        controls::enable_resident_vpid(&mut controls, 1)?;
        configure_resident_msr_switch(&self.resources.resident_msr_state)?;
        configure_resident_host(self.host_cr3, &self.resources.host_tables, segments)?;
        let guest = state::configure_guest(guest_rip, guest_rsp)?;
        controls::virtualize_resident_cr4_vmxe(l1_cr4)?;
        let vmcs_shadow = configure_resident_vmcs_shadowing(&mut controls, shadow_resources)?;
        let nested_state = super::nested::prepare_cpu_state(
            nested_configuration,
            self.options,
            vmx_basic,
            l1_cr4,
            segments,
            vmcs_shadow,
            self.msr_bitmap,
        )?;
        let context = self
            .resources
            .context_pages
            .pointer()
            .as_ptr()
            .cast::<ResidentBootContext>();
        let mut state = ResidentBootContext::new(
            self.host_cr3,
            guest.cr3,
            self.event_context,
            0,
            (0, 0),
            nested_state,
            self.options.cpuid_presence,
        );
        state.processor_number = self.processor_number as u64;
        // The AP startup probe explicitly collects diagnostics for its validation.
        state.telemetry_probe_active = 1;
        state.watchdog_tsc_hz =
            unsafe { (*(self.event_context as *const ResidentEventContext)).watchdog_tsc_hz };
        state.hyperv_timing_supported = u64::from(hyperv::timing_supported(
            state.cpuid_presence != 0,
            unsafe { (*(self.event_context as *const ResidentEventContext)).hyperv_tsc_scale },
        ));
        state.cache_ept_pointer = self.ept_pointer;
        let host_rsp = (self.resources.host_stack.physical_address()
            + self.resources.host_stack.byte_len() as u64
            - 8)
            & !0xf;
        unsafe {
            context.write(state);
            if self.processor_number < 64 {
                (*(self.event_context as *mut ResidentEventContext)).cpu_contexts
                    [self.processor_number] = context as u64;
                (*(self.event_context as *mut ResidentEventContext)).control_apic_ids
                    [self.processor_number] = arch::apic_id();
                (*(self.event_context as *mut ResidentEventContext)).control_cpu_states
                    [self.processor_number]
                    .vmxon_region = session.report().region_physical_address;
                (*(self.event_context as *mut ResidentEventContext)).control_cpu_states
                    [self.processor_number]
                    .vmcs_region = vmcs;
            }
            self.resources
                .host_tables
                .bind_context(host_rsp, context as u64);
        }
        configure_nested_vmcs02(NestedVmcs02Configuration {
            vmcs01_region: vmcs,
            vmcs02_region: nested_vmcs02_region,
            msr_bitmap: self.msr_bitmap,
            ept_pointer: nested_ept02_pointer,
            msr_state: &self.resources.resident_msr_state,
            host_cr3: self.host_cr3,
            host_tables: &self.resources.host_tables,
            segments,
            host_rsp,
            host_rip: self.dispatch_entry,
            guest_rip,
            guest_rsp,
            guest_rflags: 0x2,
            l1_cr4,
        })?;
        vmwrite(HOST_RSP, host_rsp)?;
        vmwrite(HOST_RIP, self.dispatch_entry)?;
        // The successful guest continuation returns to firmware without dropping this root session.
        core::mem::forget(session);
        Ok(nested_vmxon_operand)
    }
}

pub(crate) fn nested_cpu_configuration(
    resources: &ResidentCpuResources,
) -> Result<super::nested::CpuStateConfiguration, EptError> {
    Ok(super::nested::CpuStateConfiguration {
        vmxon_operand: resources.nested_vmxon_operand(),
        vmxon_region: resources.nested_vmxon_region(),
        vmcs12_operand: resources.nested_vmcs12_operand(),
        vmcs12_region: resources.nested_vmcs12_region(),
        vmptrst_destination: resources.nested_vmptrst_destination(),
        vmcs01_region: resources.vmcs_region.physical_address(),
        vmcs02_region: resources.nested_vmcs02_region(),
        msr_guest_list: resources.resident_msr_state.physical_address(),
        msr_state: resources.nested_msr_state.physical_address(),
        ept12_pointer: resources
            .nested_ept12_pointer()
            .ok_or(EptError::InvalidPageTable)?,
        ept02_pointer: resources
            .nested_ept02_pointer()
            .ok_or(EptError::InvalidPageTable)?,
        ept02_alternate_pointer: resources
            .nested_ept02_alternate_pointer()
            .ok_or(EptError::InvalidPageTable)?,
        ept02_table_pools: resources
            .nested_ept02_table_pools()
            .ok_or(EptError::InvalidPageTable)?,
        source_gpa: resources.nested_ept_source_gpa(),
        target_gpa: resources.nested_ept_target_gpa(),
        second_target_gpa: resources.nested_ept_second_target_gpa(),
        source_leaf: resources.nested_ept12_source_leaf(),
        source_leaf_attributes: resources.nested_ept12_source_leaf_attributes(),
        composition: resources
            .nested_ept_composition()
            .ok_or(EptError::InvalidPageTable)?,
        alternate: resources
            .nested_ept_alternate_composition()
            .ok_or(EptError::InvalidPageTable)?,
        eptp_list: resources.nested_eptp_list.physical_address(),
        eptp_tables: resources.nested_eptp_tables.physical_address(),
        eptp_pages: resources.nested_eptp_tables.pages() as u64,
        backing: resources.nested_vmcs12_pages.pointer().as_ptr(),
        backing_len: resources.nested_vmcs12_pages.byte_len(),
    })
}

const PROBE_GUEST_STACK_PAGES: usize = 4;
pub(crate) struct PreparedProbe {
    pub(crate) code_pages: ResidentPages,
    pub(crate) entry: u64,
    pub(crate) root_segments: arch::SegmentationState,
    pub(crate) tables: ResidentHostTables,
    pub(crate) context_pages: ResidentPages,
    pub(crate) guest_stack: ResidentPages,
    pub(crate) host_stack: ResidentPages,
    pub(crate) host_address_space: HostAddressSpace,
    pub(crate) vmcs_physical_address: u64,
    pub(crate) vmcs_region: VmcsRegion,
    pub(crate) host_space: crate::memory::host::HostAddressSpaceReport,
}

pub(crate) fn prepare_probe() -> Result<PreparedProbe, ResidentProbeError> {
    if size_of::<ResidentContext>() > PAGE_SIZE {
        return Err(ResidentProbeError::Allocation(Status::OUT_OF_RESOURCES));
    }

    let code = ResidentCode::allocate(0)?;
    let root_segments = arch::capture();
    let selectors = ResidentHostSelectors::inherited(root_segments)?;
    let tables =
        ResidentHostTables::allocate(code.fatal, code.gp_handler, code.exception_stubs, selectors)?;
    let context_pages = ResidentPages::allocate(1, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let guest_stack = ResidentPages::allocate(PROBE_GUEST_STACK_PAGES, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let host_stack = ResidentPages::allocate(HOST_STACK_PAGES, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let mut host_address_space = HostAddressSpace::reserve().map_err(ResidentProbeError::Paging)?;

    let vmx_basic = vmxon::vmx_basic();
    let revision_id = vmxon::revision_id(vmx_basic);
    let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
    vmcs_region.write_revision_id(revision_id);
    let vmcs_physical_address = vmcs_region.physical_address();
    let host_space = host_address_space
        .clone_current()
        .map_err(ResidentProbeError::Paging)?;
    Ok(PreparedProbe {
        code_pages: code.pages,
        entry: code.entry,
        root_segments,
        tables,
        context_pages,
        guest_stack,
        host_stack,
        host_address_space,
        vmcs_physical_address,
        vmcs_region,
        host_space,
    })
}

pub(crate) struct ProbeStack {
    pointer: NonNull<u8>,
}

impl ProbeStack {
    pub(crate) fn allocate() -> Result<Self, VmcsError> {
        let pointer = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .map_err(|error| VmcsError::Allocation(error.status()))?;
        unsafe {
            pointer.as_ptr().write_bytes(0, PAGE_SIZE);
        }
        Ok(Self { pointer })
    }

    pub(crate) fn top(&self) -> u64 {
        (self.pointer.as_ptr() as u64 + PAGE_SIZE as u64) & !0xf
    }

    fn physical_address(&self) -> u64 {
        self.pointer.as_ptr() as u64
    }
}

impl Drop for ProbeStack {
    fn drop(&mut self) {
        unsafe {
            let _ = boot::free_pages(self.pointer, 1);
        }
    }
}

pub(crate) struct HostExitStack {
    pointer: NonNull<u8>,
}

impl HostExitStack {
    pub(crate) fn allocate() -> Result<Self, VmcsError> {
        let pointer = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            HOST_EXIT_STACK_PAGES,
        )
        .map_err(|error| VmcsError::Allocation(error.status()))?;
        unsafe {
            pointer
                .as_ptr()
                .write_bytes(0, PAGE_SIZE * HOST_EXIT_STACK_PAGES);
        }
        Ok(Self { pointer })
    }

    pub(crate) fn prepare(&mut self, context: *mut VmRunContext) -> u64 {
        let end = self.pointer.as_ptr() as u64 + (PAGE_SIZE * HOST_EXIT_STACK_PAGES) as u64;
        let host_rsp = (end - 16) & !0xf;
        unsafe {
            (host_rsp as *mut u64).write(context as u64);
        }
        host_rsp
    }
}

impl Drop for HostExitStack {
    fn drop(&mut self) {
        unsafe {
            let _ = boot::free_pages(self.pointer, HOST_EXIT_STACK_PAGES);
        }
    }
}

pub(crate) struct VmlaunchProbeResources {
    pub(crate) vmxon_region: vmxon::VmxonRegion,
    pub(crate) vmcs_region: VmcsRegion,
    pub(crate) guest_stack: ProbeStack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VmlaunchProbeResourceAddresses {
    pub(crate) vmxon: u64,
    pub(crate) vmcs: u64,
    pub(crate) guest_stack: u64,
}

impl VmlaunchProbeResources {
    pub(crate) fn allocate() -> Result<Self, VmlaunchError> {
        let vmx_basic = vmxon::vmx_basic();
        let vmxon_region = vmxon::VmxonRegion::allocate(vmx_basic).map_err(VmlaunchError::Vmxon)?;
        let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
        vmcs_region.write_revision_id(vmxon::revision_id(vmx_basic));
        let guest_stack = ProbeStack::allocate()?;
        Ok(Self {
            vmxon_region,
            vmcs_region,
            guest_stack,
        })
    }

    pub(crate) fn addresses(&self) -> VmlaunchProbeResourceAddresses {
        VmlaunchProbeResourceAddresses {
            vmxon: self.vmxon_region.physical_address(),
            vmcs: self.vmcs_region.physical_address(),
            guest_stack: self.guest_stack.physical_address(),
        }
    }
}
