use core::arch::global_asm;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use uefi::boot::{self, SearchType};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{Handle, Status};

use crate::arch;
use crate::boot as boot_environment;
use crate::hv_core::vmcs::{self, VM_INSTRUCTION_ERROR, VmcsError, VmcsRegion};
use crate::hv_core::vt_controls::{self, VmxControls, VmxControlsError};
use crate::hv_core::vt_entry;
use crate::hv_core::vt_exits::{self, DispatchDiagnostics, VmRunContext};
use crate::hv_core::vt_resident;
use crate::hv_core::vt_state::{self, GuestStateReport, HostStateReport};
use crate::hv_core::vt_vmxon::{
    self, VmxInstructionResult, VmxRootSession, VmxonError, VmxonReport,
};
use crate::memory::{
    AddressConstraint, HostAddressSpace, HostAddressSpaceReport, HostPagingError,
    RESIDENT_MEMORY_TYPE, ResidentPages,
};
use crate::runtime;

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

        let host_address_space_report = host_address_space
            .clone_current()
            .map_err(PersistentVcpuError::HostPaging)?;
        let session = vt_vmxon::enter_vmx_root().map_err(PersistentVcpuError::Vmxon)?;
        let vmxon = session.report();

        runtime::phase("vmx.vcpu.vmclear.start");
        let clear_result = unsafe { vmcs::vmclear(vmcs_physical_address) };
        if clear_result != VmxInstructionResult::Succeeded {
            drop(session);
            return Err(PersistentVcpuError::Vmcs(VmcsError::Vmclear(clear_result)));
        }
        runtime::phase("vmx.vcpu.vmclear.ok");

        runtime::phase("vmx.vcpu.vmptrld.start");
        let load_result = unsafe { vmcs::vmptrld(vmcs_physical_address) };
        if load_result != VmxInstructionResult::Succeeded {
            drop(session);
            return Err(PersistentVcpuError::Vmcs(VmcsError::Vmptrld(load_result)));
        }
        runtime::phase("vmx.vcpu.vmptrld.ok");

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
        runtime::info(format_args!(
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
        runtime::info(format_args!(
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
        runtime::phase("vmx.vcpu.state.ok");

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
        runtime::phase("vmx.vcpu.launch.start");
        let raw_path = unsafe { vt_entry::run_persistent_loop(context, host_exit_rsp) };
        runtime::phase("vmx.vcpu.returned_to_host");

        let vm_instruction_error = vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
        let diagnostics = vt_exits::diagnostics();
        let validation = validate_run(
            raw_path,
            vm_instruction_error,
            self.guest,
            self.host,
            diagnostics,
        );

        runtime::phase("vmx.vcpu.final_vmclear.start");
        let final_clear = unsafe { vmcs::vmclear(self.vmcs_physical_address) };
        if final_clear == VmxInstructionResult::Succeeded {
            runtime::phase("vmx.vcpu.final_vmclear.ok");
        }
        self.host_address_space.restore_source_cr3();
        runtime::phase("vmx.vcpu.host_cr3_restored");
        if let Some(session) = self.session.take() {
            drop(session);
        }
        runtime::phase("vmx.vcpu.vmxoff_restored");

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

pub const BOOT_STAGE_MAGIC: u64 = 0x4d_48_56_42_4f_4f_54_31;
pub const BOOT_STAGE_VERSION: u32 = 1;
pub const BOOT_STAGE_LOCATE_OK: u64 = 0xb010;
pub const BOOT_STAGE_TARGET_PATH_OK: u64 = 0xb020;
pub const BOOT_STAGE_TARGET_IMAGE_LOAD_OK: u64 = 0xb030;
pub const BOOT_STAGE_START_IMAGE_RETURNED: u64 = 0xb040;
pub const BOOT_STAGE_START_IMAGE_ERROR: u64 = 0xb041;
pub const BOOT_STAGE_BUFFER_TOO_SMALL: u64 = 0xb011;
pub const BOOT_STAGE_NOT_FOUND: u64 = 0xb012;
pub const BOOT_STAGE_ERROR: u64 = 0xb0ee;

const FLAG_ENTERED: u32 = 1 << 0;
const FLAG_LOCATE_OK: u32 = 1 << 1;
const FLAG_TARGET_PATH_OK: u32 = 1 << 2;
const FLAG_TARGET_IMAGE_LOAD_OK: u32 = 1 << 3;
const FLAG_TERMINAL_READY: u32 = 1 << 4;
const FLAG_START_CHECKPOINT_COMPLETE: u32 = 1 << 5;
const FLAG_EPT_PROBE_COMPLETE: u32 = 1 << 6;
const FLAG_START_IMAGE_ENTERED: u32 = 1 << 7;
const FLAG_START_IMAGE_RETURNED: u32 = 1 << 8;
const HANDLE_CAPACITY: usize = 128;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BootStageReport {
    pub magic: u64,
    pub version: u32,
    pub flags: u32,
    pub status: u64,
    pub handle_count: u32,
    pub required_count: u32,
}

static REPORT_MAGIC: AtomicU64 = AtomicU64::new(0);
static REPORT_VERSION: AtomicU32 = AtomicU32::new(0);
static REPORT_FLAGS: AtomicU32 = AtomicU32::new(0);
static REPORT_STATUS: AtomicU64 = AtomicU64::new(0);
static REPORT_HANDLE_COUNT: AtomicU32 = AtomicU32::new(0);
static REPORT_REQUIRED_COUNT: AtomicU32 = AtomicU32::new(0);
static START_IMAGE_HANDLE: AtomicUsize = AtomicUsize::new(0);

pub fn reset_report() {
    REPORT_MAGIC.store(BOOT_STAGE_MAGIC, Ordering::Relaxed);
    REPORT_VERSION.store(BOOT_STAGE_VERSION, Ordering::Relaxed);
    REPORT_FLAGS.store(0, Ordering::Relaxed);
    REPORT_STATUS.store(0, Ordering::Relaxed);
    REPORT_HANDLE_COUNT.store(0, Ordering::Relaxed);
    REPORT_REQUIRED_COUNT.store(0, Ordering::Relaxed);
}

pub fn set_start_image_handle(handle: Handle) {
    START_IMAGE_HANDLE.store(handle.as_ptr() as usize, Ordering::Release);
}

pub fn report() -> BootStageReport {
    BootStageReport {
        magic: REPORT_MAGIC.load(Ordering::Acquire),
        version: REPORT_VERSION.load(Ordering::Acquire),
        flags: REPORT_FLAGS.load(Ordering::Acquire),
        status: REPORT_STATUS.load(Ordering::Acquire),
        handle_count: REPORT_HANDLE_COUNT.load(Ordering::Acquire),
        required_count: REPORT_REQUIRED_COUNT.load(Ordering::Acquire),
    }
}

pub fn start_image_entered() -> bool {
    REPORT_FLAGS.load(Ordering::Acquire) & FLAG_START_IMAGE_ENTERED != 0
}

pub fn proof_complete(report: BootStageReport) -> bool {
    report.magic == BOOT_STAGE_MAGIC
        && report.version == BOOT_STAGE_VERSION
        && report.flags & (FLAG_ENTERED | FLAG_LOCATE_OK | FLAG_TERMINAL_READY)
            == (FLAG_ENTERED | FLAG_LOCATE_OK | FLAG_TERMINAL_READY)
        && report.flags & FLAG_TARGET_PATH_OK != 0
        && report.flags & FLAG_TARGET_IMAGE_LOAD_OK != 0
        && report.status == Status::SUCCESS.0 as u64
        && report.handle_count > 0
}

pub fn entry_address() -> u64 {
    matrixhv_real_boot_guest_asm as *const () as usize as u64
}

pub fn start_entry_address() -> u64 {
    matrixhv_boot_loader_start_guest_asm as *const () as usize as u64
}

pub fn ept_probe_fault_address() -> u64 {
    core::ptr::addr_of!(matrixhv_boot_loader_ept_probe_fault) as u64
}

pub fn ept_probe_resume_address() -> u64 {
    core::ptr::addr_of!(matrixhv_boot_loader_ept_probe_resume) as u64
}

pub fn result_name(result: u64) -> &'static str {
    match result {
        BOOT_STAGE_LOCATE_OK => "locate_sfs_ok",
        BOOT_STAGE_TARGET_PATH_OK => "target_path_ok",
        BOOT_STAGE_TARGET_IMAGE_LOAD_OK => "target_image_load_ok",
        BOOT_STAGE_START_IMAGE_RETURNED => "start_image_returned",
        BOOT_STAGE_START_IMAGE_ERROR => "start_image_error",
        BOOT_STAGE_BUFFER_TOO_SMALL => "buffer_too_small",
        BOOT_STAGE_NOT_FOUND => "not_found",
        BOOT_STAGE_ERROR => "error",
        _ => "unknown",
    }
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn matrixhv_vt_nested_enabled() -> u64 {
    u64::from(crate::boot::current().vt_nested)
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn matrixhv_vmx_test_enabled() -> u64 {
    u64::from(crate::boot::current().vmx_test)
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn matrixhv_boot_loader_start_guest_stage() -> u64 {
    REPORT_FLAGS.fetch_or(FLAG_ENTERED, Ordering::Release);
    crate::boot::screen::message(format_args!("resident guest stage entered"));
    let handle_address = START_IMAGE_HANDLE.load(Ordering::Acquire);
    let Some(child_handle) = (unsafe { Handle::from_ptr(handle_address as *mut _) }) else {
        REPORT_STATUS.store(Status::NOT_FOUND.0 as u64, Ordering::Relaxed);
        REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
        return BOOT_STAGE_NOT_FOUND;
    };
    REPORT_FLAGS.fetch_or(FLAG_TARGET_IMAGE_LOAD_OK, Ordering::Release);
    unsafe {
        matrixhv_boot_loader_start_checkpoint_asm();
    }
    REPORT_FLAGS.fetch_or(FLAG_START_CHECKPOINT_COMPLETE, Ordering::Release);
    crate::boot::screen::message(format_args!("resident guest checkpoint complete"));
    let ept_test_page_gpa = vt_resident::ept_test_page_gpa();
    if ept_test_page_gpa != 0 {
        unsafe {
            matrixhv_boot_loader_ept_probe_asm(ept_test_page_gpa);
        }
        REPORT_FLAGS.fetch_or(FLAG_EPT_PROBE_COMPLETE, Ordering::Release);
        crate::boot::screen::message(format_args!("resident guest EPT probe complete"));
    }
    REPORT_FLAGS.fetch_or(FLAG_START_IMAGE_ENTERED, Ordering::Release);
    crate::boot::screen::message(format_args!("resident guest starting boot target"));
    match boot::start_image(child_handle) {
        Ok(()) => {
            REPORT_STATUS.store(Status::SUCCESS.0 as u64, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(
                FLAG_START_IMAGE_RETURNED | FLAG_TERMINAL_READY,
                Ordering::Release,
            );
            BOOT_STAGE_START_IMAGE_RETURNED
        }
        Err(error) => {
            REPORT_STATUS.store(error.status().0 as u64, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(
                FLAG_START_IMAGE_RETURNED | FLAG_TERMINAL_READY,
                Ordering::Release,
            );
            BOOT_STAGE_START_IMAGE_ERROR
        }
    }
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn matrixhv_real_boot_guest_stage() -> u64 {
    REPORT_FLAGS.fetch_or(FLAG_ENTERED, Ordering::Release);

    let mut handles: [MaybeUninit<Handle>; HANDLE_CAPACITY] =
        [const { MaybeUninit::uninit() }; HANDLE_CAPACITY];
    match boot::locate_handle(SearchType::from_proto::<SimpleFileSystem>(), &mut handles) {
        Ok(found) => {
            REPORT_STATUS.store(Status::SUCCESS.0 as u64, Ordering::Relaxed);
            REPORT_HANDLE_COUNT.store(found.len() as u32, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(FLAG_LOCATE_OK, Ordering::Release);

            for target in boot_environment::boot_target_candidates() {
                for handle in found.iter() {
                    if boot_environment::volume_contains(*handle, target.path) {
                        REPORT_FLAGS.fetch_or(FLAG_TARGET_PATH_OK, Ordering::Release);
                        match boot_environment::load_and_unload_image_on_volume(
                            *handle,
                            target.path,
                        ) {
                            Ok(()) => {
                                REPORT_STATUS.store(Status::SUCCESS.0 as u64, Ordering::Relaxed);
                                REPORT_FLAGS.fetch_or(
                                    FLAG_TARGET_IMAGE_LOAD_OK | FLAG_TERMINAL_READY,
                                    Ordering::Release,
                                );
                                return BOOT_STAGE_TARGET_IMAGE_LOAD_OK;
                            }
                            Err(status) => {
                                REPORT_STATUS.store(status.0 as u64, Ordering::Relaxed);
                                REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
                                return BOOT_STAGE_ERROR;
                            }
                        }
                    }
                }
            }

            REPORT_STATUS.store(Status::NOT_FOUND.0 as u64, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
            BOOT_STAGE_NOT_FOUND
        }
        Err(error) if error.status() == Status::BUFFER_TOO_SMALL => {
            REPORT_STATUS.store(error.status().0 as u64, Ordering::Relaxed);
            REPORT_REQUIRED_COUNT.store(error.data().unwrap_or(0) as u32, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
            BOOT_STAGE_BUFFER_TOO_SMALL
        }
        Err(error) if error.status() == Status::NOT_FOUND => {
            REPORT_STATUS.store(error.status().0 as u64, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
            BOOT_STAGE_NOT_FOUND
        }
        Err(error) => {
            REPORT_STATUS.store(error.status().0 as u64, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
            BOOT_STAGE_ERROR
        }
    }
}

unsafe extern "efiapi" {
    fn matrixhv_real_boot_guest_asm();
    fn matrixhv_boot_loader_start_guest_asm();
    fn matrixhv_boot_loader_start_checkpoint_asm();
    fn matrixhv_boot_loader_ept_probe_asm(physical_address: u64);
    static matrixhv_boot_loader_ept_probe_fault: u8;
    static matrixhv_boot_loader_ept_probe_resume: u8;
}

global_asm!(
    ".text",
    ".globl matrixhv_real_boot_guest_asm",
    "matrixhv_real_boot_guest_asm:",
    "sub rsp, 32",
    "call matrixhv_real_boot_guest_stage",
    "add rsp, 32",
    "vmcall",
    "ud2",
);

global_asm!(
    ".text",
    ".globl matrixhv_boot_loader_ept_probe_asm",
    ".globl matrixhv_boot_loader_ept_probe_fault",
    ".globl matrixhv_boot_loader_ept_probe_resume",
    "matrixhv_boot_loader_ept_probe_asm:",
    "matrixhv_boot_loader_ept_probe_fault:",
    "mov rax, qword ptr [rcx]",
    "matrixhv_boot_loader_ept_probe_resume:",
    "ret",
);

global_asm!(
    ".text",
    ".globl matrixhv_boot_loader_start_checkpoint_asm",
    "matrixhv_boot_loader_start_checkpoint_asm:",
    "mov rax, {checkpoint_magic}",
    "vmcall",
    "ret",
    ".globl matrixhv_boot_loader_start_guest_asm",
    "matrixhv_boot_loader_start_guest_asm:",
    "mov rbx, rax",
    "sub rsp, 32",
    "call matrixhv_vmx_test_enabled",
    "add rsp, 32",
    "test rax, rax",
    "jz .Lwindows_cpuid_done",
    "mov rax, rbx",
    "mov r8, qword ptr [rax + 8]",
    "mov r9, qword ptr [rax + 16]",
    "mov rbx, rax",
    "mov r10, cr4",
    "mov r12, r10",
    "or r10, 0x2000",
    "mov cr4, r10",
    "vmxon [rax]",
    "jna .Lwindows_nested_probe_failed",
    "vmclear [r8]",
    "jna .Lwindows_nested_probe_failed",
    "vmptrld [r8]",
    "jna .Lwindows_nested_probe_failed",
    "vmxon [rax]",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "cmp r10d, 0x40",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {instruction_error_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {vmxon_active_error}",
    "jne .Lwindows_nested_probe_failed",
    "vmptrst [r9]",
    "jna .Lwindows_nested_probe_failed",
    "mov r10, qword ptr [r8]",
    "cmp qword ptr [r9], r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rip_field}",
    "mov rdx, {vmcs12_test_value}",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "mov r10, {vmcs12_test_value}",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {exception_bitmap_field}",
    "mov edx, 0x40",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, 0x40",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {cr3_target_count_field}",
    "mov edx, 5",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, 5",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_cr3_field}",
    "mov rdx, cr3",
    "mov r10, rdx",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {host_cr3_field}",
    "mov rdx, cr3",
    "mov r10, rdx",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_cr0_field}",
    "mov rdx, cr0",
    "mov r10, rdx",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {host_cr0_field}",
    "mov rdx, r10",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_cr4_field}",
    "mov rdx, cr4",
    "mov r10, rdx",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {host_cr4_field}",
    "mov rdx, r10",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov ecx, {sysenter_cs_msr}",
    "rdmsr",
    "shl rdx, 32",
    "or rdx, rax",
    "mov r10, rdx",
    "mov rcx, {guest_sysenter_cs_field}",
    "vmwrite rcx, r10",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {host_sysenter_cs_field}",
    "vmwrite rcx, r10",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov ecx, {sysenter_esp_msr}",
    "rdmsr",
    "shl rdx, 32",
    "or rdx, rax",
    "mov r10, rdx",
    "mov rcx, {guest_sysenter_esp_field}",
    "vmwrite rcx, r10",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {host_sysenter_esp_field}",
    "vmwrite rcx, r10",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov ecx, {sysenter_eip_msr}",
    "rdmsr",
    "shl rdx, 32",
    "or rdx, rax",
    "mov r10, rdx",
    "mov rcx, {guest_sysenter_eip_field}",
    "vmwrite rcx, r10",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {host_sysenter_eip_field}",
    "vmwrite rcx, r10",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "vmlaunch",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "cmp r10d, 64",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {instruction_error_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {invalid_control_error}",
    "jne .Lwindows_nested_probe_failed",
    "vmresume",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "cmp r10d, 64",
    "jne .Lwindows_nested_probe_failed",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {non_launched_error}",
    "jne .Lwindows_nested_probe_failed",
    "vmclear [r8]",
    "jna .Lwindows_nested_probe_failed",
    "vmlaunch",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "cmp r10d, 1",
    "jne .Lwindows_nested_probe_failed",
    "vmresume",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "cmp r10d, 1",
    "jne .Lwindows_nested_probe_failed",
    "vmptrld [r8]",
    "jna .Lwindows_nested_probe_failed",
    "mov rcx, {exception_bitmap_field}",
    "xor edx, edx",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rcx, {cr3_target_count_field}",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rcx, {pin_based_control_field}",
    "xor edx, edx",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "test edx, edx",
    "jnz .Lwindows_nested_probe_failed",
    "mov rcx, {primary_control_field}",
    "mov edx, {primary_activate_secondary_controls}",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {primary_activate_secondary_controls}",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {secondary_control_field}",
    "mov edx, {secondary_enable_ept}",
    "or edx, {secondary_enable_vpid}",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "mov r10d, {secondary_enable_ept}",
    "or r10d, {secondary_enable_vpid}",
    "cmp edx, r10d",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {vpid_field}",
    "mov edx, 1",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, 1",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {ept_pointer_field}",
    "mov rdx, qword ptr [rbx + 24]",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, qword ptr [rbx + 24]",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {vm_exit_controls_field}",
    "mov edx, {vm_exit_host_address_space_size}",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {vm_exit_host_address_space_size}",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {vm_entry_controls_field}",
    "mov edx, {vm_entry_ia32e_mode_guest}",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {vm_entry_ia32e_mode_guest}",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rip_field}",
    "lea rdx, [rip + .Lwindows_nested_l2_entry]",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rsp_field}",
    "mov rdx, rsp",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rflags_field}",
    "mov rdx, 2",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rcx, {host_rip_field}",
    "lea rdx, [rip + .Lwindows_nested_l1_exit]",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rcx, {host_rsp_field}",
    "mov rdx, rsp",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov r14, qword ptr [rbx + 32]",
    "mov r15, qword ptr [rbx + 40]",
    "mov r10, qword ptr [r14]",
    "mov r11, {ept_source_marker}",
    "cmp r10, r11",
    "jne .Lwindows_nested_probe_failed",
    "mov r10, qword ptr [r15]",
    "mov r11, {ept_target_marker}",
    "cmp r10, r11",
    "jne .Lwindows_nested_probe_failed",
    "vmlaunch",
    "jmp .Lwindows_nested_probe_failed",
    ".Lwindows_nested_l2_entry:",
    "mov r13, qword ptr [r14]",
    "mov r11, {ept_target_marker}",
    "cmp r13, r11",
    "jne .Lwindows_nested_l2_bad_resume",
    "mov rax, {l2_vmcall_magic}",
    ".Lwindows_nested_l2_vmcall:",
    "vmcall",
    ".Lwindows_nested_l2_after_first:",
    "mov r13, qword ptr [r14]",
    "mov r11, {ept_target_marker}",
    "cmp r13, r11",
    "jne .Lwindows_nested_l2_bad_resume",
    "mov r10, {l2_vmresume_magic}",
    "cmp rax, r10",
    "jne .Lwindows_nested_l2_bad_resume",
    ".Lwindows_nested_l2_before_invept_vmcall:",
    "vmcall",
    ".Lwindows_nested_l2_after_invept:",
    "mov r13, qword ptr [r14]",
    "mov r11, {ept_second_target_marker}",
    "cmp r13, r11",
    "jne .Lwindows_nested_l2_bad_resume",
    "mov r10, {l2_post_invept_magic}",
    "cmp rax, r10",
    "jne .Lwindows_nested_l2_bad_resume",
    ".Lwindows_nested_l2_after_invept_vmcall:",
    "vmcall",
    ".Lwindows_nested_l2_bad_resume:",
    "ud2",
    ".Lwindows_nested_l1_exit:",
    "mov r10, {l2_vmcall_magic}",
    "cmp rax, r10",
    "je .Lwindows_nested_l1_first_exit",
    "mov r10, {l2_vmresume_magic}",
    "cmp rax, r10",
    "je .Lwindows_nested_l1_resume_exit",
    "mov r10, {l2_post_invept_magic}",
    "cmp rax, r10",
    "je .Lwindows_nested_l1_after_invept_exit",
    "jmp .Lwindows_nested_probe_failed",
    ".Lwindows_nested_l1_first_exit:",
    "mov rcx, {exit_reason_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "and edx, 0xffff",
    "cmp edx, 18",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rip_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "lea r10, [rip + .Lwindows_nested_l2_vmcall]",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {exit_instruction_len_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, 3",
    "jne .Lwindows_nested_probe_failed",
    "mov r11, {ept_target_marker}",
    "cmp r13, r11",
    "jne .Lwindows_nested_probe_failed",
    "mov r10, qword ptr [r14]",
    "mov r11, {ept_source_marker}",
    "cmp r10, r11",
    "jne .Lwindows_nested_probe_failed",
    "mov r10, qword ptr [rbx + 56]",
    "mov r11, qword ptr [r10]",
    "and r11, 0xfff",
    "mov rdx, qword ptr [rbx + 48]",
    "or r11, rdx",
    "mov qword ptr [r10], r11",
    "mov rcx, {guest_rip_field}",
    "lea rdx, [rip + .Lwindows_nested_l2_after_first]",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rax, {l2_vmresume_magic}",
    "vmresume",
    "jmp .Lwindows_nested_probe_failed",
    ".Lwindows_nested_l1_resume_exit:",
    "mov rcx, {exit_reason_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "and edx, 0xffff",
    "cmp edx, 18",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rip_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "lea r10, [rip + .Lwindows_nested_l2_before_invept_vmcall]",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {exit_instruction_len_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, 3",
    "jne .Lwindows_nested_probe_failed",
    "mov r11, {ept_target_marker}",
    "cmp r13, r11",
    "jne .Lwindows_nested_probe_failed",
    "lea r10, [rip + .Lwindows_nested_invept_invalid]",
    "mov qword ptr [rbx + 80], r10",
    "lea r10, [rip + .Lwindows_nested_invept_invalid_after]",
    "mov qword ptr [rbx + 88], r10",
    "mov rcx, 2",
    ".Lwindows_nested_invept_invalid:",
    "invept rcx, xmmword ptr [rbx + 64]",
    ".Lwindows_nested_invept_invalid_after:",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "cmp r10d, 0x40",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {instruction_error_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {invalid_invalidation_operand_error}",
    "jne .Lwindows_nested_probe_failed",
    "lea r10, [rip + .Lwindows_nested_invept_valid]",
    "mov qword ptr [rbx + 80], r10",
    "lea r10, [rip + .Lwindows_nested_invept_valid_after]",
    "mov qword ptr [rbx + 88], r10",
    "mov rcx, 1",
    ".Lwindows_nested_invept_valid:",
    "invept rcx, xmmword ptr [rbx + 64]",
    ".Lwindows_nested_invept_valid_after:",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "test r10d, r10d",
    "jnz .Lwindows_nested_probe_failed",
    "mov qword ptr [rbx + 96], 0",
    "lea r10, [rip + .Lwindows_nested_invvpid_invalid]",
    "mov qword ptr [rbx + 112], r10",
    "lea r10, [rip + .Lwindows_nested_invvpid_invalid_after]",
    "mov qword ptr [rbx + 120], r10",
    "mov rcx, 1",
    ".Lwindows_nested_invvpid_invalid:",
    "invvpid rcx, xmmword ptr [rbx + 96]",
    ".Lwindows_nested_invvpid_invalid_after:",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "cmp r10d, 0x40",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {instruction_error_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {invalid_invalidation_operand_error}",
    "jne .Lwindows_nested_probe_failed",
    "mov qword ptr [rbx + 96], 1",
    "lea r10, [rip + .Lwindows_nested_invvpid_valid]",
    "mov qword ptr [rbx + 112], r10",
    "lea r10, [rip + .Lwindows_nested_invvpid_valid_after]",
    "mov qword ptr [rbx + 120], r10",
    "mov rcx, 1",
    ".Lwindows_nested_invvpid_valid:",
    "invvpid rcx, xmmword ptr [rbx + 96]",
    ".Lwindows_nested_invvpid_valid_after:",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "test r10d, r10d",
    "jnz .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rip_field}",
    "lea rdx, [rip + .Lwindows_nested_l2_after_invept]",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rax, {l2_post_invept_magic}",
    "vmresume",
    "jmp .Lwindows_nested_probe_failed",
    ".Lwindows_nested_l1_after_invept_exit:",
    "mov rcx, {exit_reason_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "and edx, 0xffff",
    "cmp edx, 18",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rip_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "lea r10, [rip + .Lwindows_nested_l2_after_invept_vmcall]",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {exit_instruction_len_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, 3",
    "jne .Lwindows_nested_probe_failed",
    "mov r11, {ept_second_target_marker}",
    "cmp r13, r11",
    "jne .Lwindows_nested_probe_failed",
    "vmxoff",
    "jna .Lwindows_nested_probe_failed",
    "mov cr4, r12",
    "sub rsp, 32",
    "call matrixhv_vt_nested_enabled",
    "add rsp, 32",
    "test rax, rax",
    "jnz .Lwindows_cpuid_done",
    "mov eax, 1",
    "xor ecx, ecx",
    "cpuid",
    "test ecx, 0x20",
    "jnz .Lwindows_nested_probe_failed",
    "test ecx, 0x80000000",
    "jnz .Lwindows_cpuid_done",
    "mov eax, 0x40000000",
    "xor ecx, ecx",
    "cpuid",
    "or eax, ebx",
    "or eax, ecx",
    "or eax, edx",
    "jnz .Lwindows_nested_probe_failed",
    "mov eax, 0x40000003",
    "xor ecx, ecx",
    "cpuid",
    "or eax, ebx",
    "or eax, ecx",
    "or eax, edx",
    "jnz .Lwindows_nested_probe_failed",
    "mov eax, 0x40000010",
    "xor ecx, ecx",
    "cpuid",
    "or eax, ebx",
    "or eax, ecx",
    "or eax, edx",
    "jnz .Lwindows_nested_probe_failed",
    "mov eax, 0x40000100",
    "xor ecx, ecx",
    "cpuid",
    "or eax, ebx",
    "or eax, ecx",
    "or eax, edx",
    "jnz .Lwindows_nested_probe_failed",
    ".Lwindows_cpuid_done:",
    "sub rsp, 32",
    "call matrixhv_boot_loader_start_guest_stage",
    "add rsp, 32",
    "mov rdx, rax",
    "mov rax, {stop_magic}",
    "vmcall",
    "ud2",
    ".Lwindows_nested_probe_failed:",
    "mov rax, {nested_probe_failed}",
    "vmcall",
    "ud2",
    checkpoint_magic = const vt_resident::RESIDENT_VMCALL_START_CHECKPOINT,
    stop_magic = const vt_resident::RESIDENT_VMCALL_STOP,
    nested_probe_failed = const vt_resident::RESIDENT_VMCALL_NESTED_PROBE_FAILED,
    guest_rip_field = const crate::nested::VMCS_FIELD_GUEST_RIP,
    guest_rsp_field = const crate::nested::VMCS_FIELD_GUEST_RSP,
    guest_rflags_field = const crate::nested::VMCS_FIELD_GUEST_RFLAGS,
    host_rip_field = const crate::nested::VMCS_FIELD_HOST_RIP,
    host_rsp_field = const crate::nested::VMCS_FIELD_HOST_RSP,
    exception_bitmap_field = const crate::nested::VMCS_FIELD_EXCEPTION_BITMAP,
    cr3_target_count_field = const crate::nested::VMCS_FIELD_CR3_TARGET_COUNT,
    guest_cr0_field = const crate::nested::VMCS_FIELD_GUEST_CR0,
    guest_cr3_field = const crate::nested::VMCS_FIELD_GUEST_CR3,
    guest_cr4_field = const crate::nested::VMCS_FIELD_GUEST_CR4,
    host_cr0_field = const crate::nested::VMCS_FIELD_HOST_CR0,
    host_cr3_field = const crate::nested::VMCS_FIELD_HOST_CR3,
    host_cr4_field = const crate::nested::VMCS_FIELD_HOST_CR4,
    guest_sysenter_cs_field = const crate::nested::VMCS_FIELD_GUEST_SYSENTER_CS,
    guest_sysenter_esp_field = const crate::nested::VMCS_FIELD_GUEST_SYSENTER_ESP,
    guest_sysenter_eip_field = const crate::nested::VMCS_FIELD_GUEST_SYSENTER_EIP,
    host_sysenter_cs_field = const crate::nested::VMCS_FIELD_HOST_SYSENTER_CS,
    host_sysenter_esp_field = const crate::nested::VMCS_FIELD_HOST_SYSENTER_ESP,
    host_sysenter_eip_field = const crate::nested::VMCS_FIELD_HOST_SYSENTER_EIP,
    pin_based_control_field = const crate::nested::VMCS_FIELD_PIN_BASED_VM_EXEC_CONTROL,
    primary_control_field = const crate::nested::VMCS_FIELD_CPU_BASED_VM_EXEC_CONTROL,
    secondary_control_field = const crate::nested::VMCS_FIELD_SECONDARY_VM_EXEC_CONTROL,
    vpid_field = const crate::nested::VMCS_FIELD_VPID,
    ept_pointer_field = const crate::nested::VMCS_FIELD_EPT_POINTER,
    vm_exit_controls_field = const crate::nested::VMCS_FIELD_VM_EXIT_CONTROLS,
    vm_entry_controls_field = const crate::nested::VMCS_FIELD_VM_ENTRY_CONTROLS,
    primary_activate_secondary_controls = const crate::nested::VMX_PRIMARY_ACTIVATE_SECONDARY_CONTROLS,
    secondary_enable_ept = const crate::nested::VMX_SECONDARY_ENABLE_EPT,
    secondary_enable_vpid = const crate::nested::VMX_SECONDARY_ENABLE_VPID,
    vm_exit_host_address_space_size = const crate::nested::VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
    vm_entry_ia32e_mode_guest = const crate::nested::VM_ENTRY_IA32E_MODE_GUEST,
    ept_source_marker = const crate::smp::NESTED_EPT_SOURCE_MARKER,
    ept_target_marker = const crate::smp::NESTED_EPT_TARGET_MARKER,
    ept_second_target_marker = const crate::smp::NESTED_EPT_SECOND_TARGET_MARKER,
    exit_reason_field = const crate::nested::VMCS_FIELD_VM_EXIT_REASON,
    exit_instruction_len_field = const crate::nested::VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN,
    instruction_error_field = const crate::nested::VMCS_FIELD_VM_INSTRUCTION_ERROR,
    vmxon_active_error = const crate::nested::VMXON_IN_VMX_ROOT_ERROR,
    invalid_control_error = const crate::nested::VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR,
    non_launched_error = const crate::nested::VMRESUME_NON_LAUNCHED_VMCS_ERROR,
    invalid_invalidation_operand_error = const crate::nested::INVALID_OPERAND_TO_INVEPT_INVVPID_ERROR,
    vmcs12_test_value = const vt_resident::NESTED_VMCS12_TEST_VALUE,
    l2_vmcall_magic = const vt_resident::NESTED_L2_VMCALL_MAGIC,
    l2_vmresume_magic = const vt_resident::NESTED_L2_VMRESUME_MAGIC,
    l2_post_invept_magic = const vt_resident::NESTED_L2_POST_INVEPT_MAGIC,
    sysenter_cs_msr = const crate::arch::IA32_SYSENTER_CS,
    sysenter_esp_msr = const crate::arch::IA32_SYSENTER_ESP,
    sysenter_eip_msr = const crate::arch::IA32_SYSENTER_EIP,
);
