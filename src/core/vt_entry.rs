use core::arch::global_asm;
use core::ptr::NonNull;

use uefi::boot::{self, AllocateType};
use uefi::mem::memory_map::MemoryType;

use super::vmcs::{
    self, EXIT_QUALIFICATION, GUEST_RIP, GUEST_RSP, HOST_RIP, HOST_RSP, VM_EXIT_INSTRUCTION_LEN,
    VM_EXIT_REASON, VM_INSTRUCTION_ERROR, VmcsError, VmcsRegion,
};
use super::vt_controls::{self, VmxControls, VmxControlsError};
use super::vt_exits::{self, DispatchDiagnostics, VmRunContext};
use super::vt_state::{self, GuestStateReport, HostStateReport};
use super::vt_vmxon::{self, VmxInstructionResult, VmxonError, VmxonReport};
use crate::runtime;

const PAGE_SIZE: usize = 4096;
const HOST_EXIT_STACK_PAGES: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmlaunchError {
    Vmxon(VmxonError),
    Vmcs(VmcsError),
    Controls(VmxControlsError),
    HostRspVmwrite(u64),
    HostRipVmwrite(u64),
    VmFailInvalid,
    VmFailValid(u64),
    VmEntryFailure {
        exit_reason: u32,
        qualification: u64,
    },
    UnexpectedExit(u32),
    UnexpectedInstructionLength(u32),
    GuestRipMismatch {
        expected: u64,
        actual: u64,
    },
    CleanupVmclear(VmxInstructionResult),
}

impl From<VmcsError> for VmlaunchError {
    fn from(value: VmcsError) -> Self {
        Self::Vmcs(value)
    }
}

impl From<VmxControlsError> for VmlaunchError {
    fn from(value: VmxControlsError) -> Self {
        Self::Controls(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmlaunchReport {
    pub vmxon: VmxonReport,
    pub vmcs_physical_address: u64,
    pub controls: VmxControls,
    pub host: HostStateReport,
    pub guest: GuestStateReport,
    pub exit_reason: u32,
    pub exit_qualification: u64,
    pub exit_instruction_length: u32,
    pub guest_rip_after_exit: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmexitLoopError {
    Vmxon(VmxonError),
    Vmcs(VmcsError),
    Controls(VmxControlsError),
    VmlaunchVmFailInvalid,
    VmlaunchVmFailValid(u64),
    VmresumeVmFailInvalid,
    VmresumeVmFailValid(u64),
    HostRspVmwrite(u64),
    HostRipVmwrite(u64),
    TrampolineGuestRspVmread,
    TrampolineGuestRspVmwrite,
    DispatcherFailure(u32),
    UnexpectedExitCounts { exits: u32, cpuid: u32, vmcall: u32 },
    CpuidRipMismatch { expected: u64, actual: u64 },
    VmcallRipMismatch { expected: u64, actual: u64 },
    GuestRegisterMismatch,
    GuestRspMismatch { expected: u64, actual: u64 },
    CpuidInputMismatch { leaf: u32, subleaf: u32 },
    CleanupVmclear(VmxInstructionResult),
}

impl From<VmcsError> for VmexitLoopError {
    fn from(value: VmcsError) -> Self {
        Self::Vmcs(value)
    }
}

impl From<VmxControlsError> for VmexitLoopError {
    fn from(value: VmxControlsError) -> Self {
        Self::Controls(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmexitLoopReport {
    pub vmxon: VmxonReport,
    pub vmcs_physical_address: u64,
    pub controls: VmxControls,
    pub host: HostStateReport,
    pub guest: GuestStateReport,
    pub diagnostics: DispatchDiagnostics,
    pub cpuid_rip_expected: u64,
    pub vmcall_rip_expected: u64,
}

struct ProbeStack {
    pointer: NonNull<u8>,
}

impl ProbeStack {
    fn allocate() -> Result<Self, VmcsError> {
        let pointer = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .map_err(|error| VmcsError::Allocation(error.status()))?;
        unsafe {
            pointer.as_ptr().write_bytes(0, PAGE_SIZE);
        }
        Ok(Self { pointer })
    }

    fn top(&self) -> u64 {
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

struct HostExitStack {
    pointer: NonNull<u8>,
}

impl HostExitStack {
    fn allocate() -> Result<Self, VmcsError> {
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

    fn prepare(&mut self, context: *mut VmRunContext) -> u64 {
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
    vmxon_region: vt_vmxon::VmxonRegion,
    vmcs_region: VmcsRegion,
    guest_stack: ProbeStack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VmlaunchProbeResourceAddresses {
    pub(crate) vmxon: u64,
    pub(crate) vmcs: u64,
    pub(crate) guest_stack: u64,
}

impl VmlaunchProbeResources {
    pub(crate) fn allocate() -> Result<Self, VmlaunchError> {
        let vmx_basic = vt_vmxon::vmx_basic();
        let vmxon_region =
            vt_vmxon::VmxonRegion::allocate(vmx_basic).map_err(VmlaunchError::Vmxon)?;
        let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
        vmcs_region.write_revision_id(vt_vmxon::revision_id(vmx_basic));
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

    pub(crate) fn run(&mut self) -> Result<VmlaunchReport, VmlaunchError> {
        run_vmlaunch_probe(self)
    }
}

pub fn probe_vmlaunch() -> Result<VmlaunchReport, VmlaunchError> {
    let mut resources = VmlaunchProbeResources::allocate()?;
    run_vmlaunch_probe(&mut resources)
}

fn run_vmlaunch_probe(
    resources: &mut VmlaunchProbeResources,
) -> Result<VmlaunchReport, VmlaunchError> {
    let vmx_basic = vt_vmxon::vmx_basic();
    let revision_id = vt_vmxon::revision_id(vmx_basic);
    resources.vmcs_region.write_revision_id(revision_id);
    let vmcs_physical_address = resources.vmcs_region.physical_address();

    let session =
        vt_vmxon::enter_vmx_root_with_borrowed_region(vmx_basic, &mut resources.vmxon_region)
            .map_err(VmlaunchError::Vmxon)?;
    let vmxon_report = session.report();

    runtime::phase("vmx.vmlaunch.vmclear.start");
    let clear_result = unsafe { vmcs::vmclear(vmcs_physical_address) };
    if clear_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(VmlaunchError::Vmcs(VmcsError::Vmclear(clear_result)));
    }
    runtime::phase("vmx.vmlaunch.vmclear.ok");

    runtime::phase("vmx.vmlaunch.vmptrld.start");
    let load_result = unsafe { vmcs::vmptrld(vmcs_physical_address) };
    if load_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(VmlaunchError::Vmcs(VmcsError::Vmptrld(load_result)));
    }
    runtime::phase("vmx.vmlaunch.vmptrld.ok");

    let controls = vt_controls::configure()?;
    runtime::info(format_args!(
        "vmlaunch controls pin={:#x} primary={:#x} secondary={:#x} exit={:#x} entry={:#x}",
        controls.pin_based,
        controls.primary_processor_based,
        controls.secondary_processor_based,
        controls.vm_exit,
        controls.vm_entry
    ));
    runtime::phase("vmx.vmlaunch.controls.ok");

    let host = vt_state::configure_host()?;
    runtime::info(format_args!(
        "vmlaunch host cs={:#x} ss={:#x} tr={:#x} tr_base={:#x} gdtr={:#x} idtr={:#x}",
        host.cs_selector,
        host.ss_selector,
        host.tr_selector,
        host.tr_base,
        host.gdtr_base,
        host.idtr_base
    ));
    runtime::phase("vmx.vmlaunch.host_state.ok");

    let guest_rip = guest_probe_address();
    let guest = vt_state::configure_guest(guest_rip, resources.guest_stack.top())?;
    runtime::info(format_args!(
        "vmlaunch guest rip={:#x} rsp={:#x} rflags={:#x} cs={:#x} ss={:#x} tr={:#x}",
        guest.rip, guest.rsp, guest.rflags, guest.cs_selector, guest.ss_selector, guest.tr_selector
    ));
    runtime::phase("vmx.vmlaunch.guest_state.ok");

    runtime::phase("vmx.vmlaunch.start");
    let raw_path = unsafe { matrixhv_vmlaunch_probe_asm() };
    runtime::phase("vmx.vmlaunch.returned_to_host");

    let exit_reason = vmcs::vmread(VM_EXIT_REASON).unwrap_or(0) as u32;
    let basic_exit_reason = vt_exits::basic_reason(exit_reason);
    let exit_qualification = vmcs::vmread(EXIT_QUALIFICATION).unwrap_or(0);
    let instruction_length = vmcs::vmread(VM_EXIT_INSTRUCTION_LEN).unwrap_or(0);
    let vm_instruction_error = vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
    let guest_rip_after_exit = vmcs::vmread(GUEST_RIP).unwrap_or(0);

    runtime::info(format_args!(
        "vmlaunch raw_path={} exit_reason={:#x} exit_name={} basic_reason={} qualification={:#x} instruction_len={} vm_instruction_error={} vm_instruction_error_name={} guest_rip={:#x}",
        raw_path,
        exit_reason,
        vt_exits::reason_name(exit_reason),
        basic_exit_reason,
        exit_qualification,
        instruction_length,
        vm_instruction_error,
        vmcs::instruction_error_name(vm_instruction_error),
        guest_rip_after_exit
    ));

    let launch_result = match raw_path {
        0 if vt_exits::is_vm_entry_failure(exit_reason) => Err(VmlaunchError::VmEntryFailure {
            exit_reason,
            qualification: exit_qualification,
        }),
        0 if basic_exit_reason != vt_exits::VMCALL => {
            Err(VmlaunchError::UnexpectedExit(basic_exit_reason))
        }
        0 if instruction_length != 3 => Err(VmlaunchError::UnexpectedInstructionLength(
            instruction_length as u32,
        )),
        0 if guest_rip_after_exit != guest.rip => Err(VmlaunchError::GuestRipMismatch {
            expected: guest.rip,
            actual: guest_rip_after_exit,
        }),
        0 => Ok(VmlaunchReport {
            vmxon: vmxon_report,
            vmcs_physical_address,
            controls,
            host,
            guest,
            exit_reason,
            exit_qualification,
            exit_instruction_length: instruction_length as u32,
            guest_rip_after_exit,
        }),
        1 => Err(VmlaunchError::VmFailInvalid),
        2 => Err(VmlaunchError::VmFailValid(vm_instruction_error)),
        3 => Err(VmlaunchError::HostRspVmwrite(vm_instruction_error)),
        4 => Err(VmlaunchError::HostRipVmwrite(vm_instruction_error)),
        _ => Err(VmlaunchError::VmFailInvalid),
    };

    runtime::phase("vmx.vmlaunch.final_vmclear.start");
    let final_clear = unsafe { vmcs::vmclear(vmcs_physical_address) };
    if final_clear == VmxInstructionResult::Succeeded {
        runtime::phase("vmx.vmlaunch.final_vmclear.ok");
    }
    drop(session);
    runtime::phase("vmx.vmlaunch.vmxoff_restored");

    if final_clear != VmxInstructionResult::Succeeded {
        return Err(VmlaunchError::CleanupVmclear(final_clear));
    }

    launch_result
}

pub fn probe_vmexit_dispatcher() -> Result<VmexitLoopReport, VmexitLoopError> {
    let vmx_basic = vt_vmxon::vmx_basic();
    let revision_id = vt_vmxon::revision_id(vmx_basic);
    let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
    vmcs_region.write_revision_id(revision_id);
    let vmcs_physical_address = vmcs_region.physical_address();
    let guest_stack = ProbeStack::allocate()?;
    let mut host_exit_stack = HostExitStack::allocate()?;
    let mut run_context = VmRunContext::default();
    let host_exit_rsp = host_exit_stack.prepare(&mut run_context);

    let session = vt_vmxon::enter_vmx_root().map_err(VmexitLoopError::Vmxon)?;
    let vmxon_report = session.report();

    runtime::phase("vmx.dispatch_probe.vmclear.start");
    let clear_result = unsafe { vmcs::vmclear(vmcs_physical_address) };
    if clear_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(VmexitLoopError::Vmcs(VmcsError::Vmclear(clear_result)));
    }
    runtime::phase("vmx.dispatch_probe.vmclear.ok");

    runtime::phase("vmx.dispatch_probe.vmptrld.start");
    let load_result = unsafe { vmcs::vmptrld(vmcs_physical_address) };
    if load_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(VmexitLoopError::Vmcs(VmcsError::Vmptrld(load_result)));
    }
    runtime::phase("vmx.dispatch_probe.vmptrld.ok");

    let controls = vt_controls::configure()?;
    runtime::info(format_args!(
        "dispatch controls pin={:#x} primary={:#x} secondary={:#x} exit={:#x} entry={:#x}",
        controls.pin_based,
        controls.primary_processor_based,
        controls.secondary_processor_based,
        controls.vm_exit,
        controls.vm_entry
    ));
    runtime::phase("vmx.dispatch_probe.controls.ok");

    let host = vt_state::configure_host()?;
    runtime::phase("vmx.dispatch_probe.host_state.ok");

    let guest_rip = dispatch_guest_address();
    let guest = vt_state::configure_guest(guest_rip, guest_stack.top())?;
    runtime::info(format_args!(
        "dispatch guest rip={:#x} rsp={:#x} cpuid_rip={:#x} vmcall_rip={:#x}",
        guest.rip,
        guest.rsp,
        dispatch_guest_cpuid_address(),
        dispatch_guest_vmcall_address()
    ));
    runtime::phase("vmx.dispatch_probe.guest_state.ok");

    vt_exits::reset_diagnostics();
    runtime::phase("vmx.dispatch_probe.launch.start");
    let raw_path = unsafe { matrixhv_dispatch_run_asm(&mut run_context, host_exit_rsp) };
    runtime::phase("vmx.dispatch_probe.returned_to_host");

    let vm_instruction_error = vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
    let diagnostics = vt_exits::diagnostics();
    runtime::info(format_args!(
        "dispatch return path={} vm_instruction_error={} vm_instruction_error_name={} exits={} cpuid={} vmcall={} resumes={} failure={} failure_name={}",
        raw_path,
        vm_instruction_error,
        vmcs::instruction_error_name(vm_instruction_error),
        diagnostics.exit_count,
        diagnostics.cpuid_count,
        diagnostics.vmcall_count,
        diagnostics.resume_count,
        diagnostics.failure_code,
        vt_exits::failure_name(diagnostics.failure_code)
    ));

    let report = VmexitLoopReport {
        vmxon: vmxon_report,
        vmcs_physical_address,
        controls,
        host,
        guest,
        diagnostics,
        cpuid_rip_expected: dispatch_guest_cpuid_address(),
        vmcall_rip_expected: dispatch_guest_vmcall_address(),
    };
    let result = validate_dispatch_run(raw_path, vm_instruction_error, report);

    runtime::phase("vmx.dispatch_probe.final_vmclear.start");
    let final_clear = unsafe { vmcs::vmclear(vmcs_physical_address) };
    if final_clear == VmxInstructionResult::Succeeded {
        runtime::phase("vmx.dispatch_probe.final_vmclear.ok");
    }
    drop(session);
    runtime::phase("vmx.dispatch_probe.vmxoff_restored");

    if final_clear != VmxInstructionResult::Succeeded {
        return Err(VmexitLoopError::CleanupVmclear(final_clear));
    }

    result
}

fn validate_dispatch_run(
    raw_path: u64,
    vm_instruction_error: u64,
    report: VmexitLoopReport,
) -> Result<VmexitLoopReport, VmexitLoopError> {
    let diagnostics = report.diagnostics;
    match raw_path {
        0 => {}
        1 => return Err(VmexitLoopError::VmlaunchVmFailInvalid),
        2 => return Err(VmexitLoopError::VmlaunchVmFailValid(vm_instruction_error)),
        3 => return Err(VmexitLoopError::HostRspVmwrite(vm_instruction_error)),
        4 => return Err(VmexitLoopError::HostRipVmwrite(vm_instruction_error)),
        5 => return Err(VmexitLoopError::VmresumeVmFailInvalid),
        6 => return Err(VmexitLoopError::VmresumeVmFailValid(vm_instruction_error)),
        7 => return Err(VmexitLoopError::TrampolineGuestRspVmread),
        8 => return Err(VmexitLoopError::TrampolineGuestRspVmwrite),
        _ => return Err(VmexitLoopError::VmlaunchVmFailInvalid),
    }

    if diagnostics.failure_code != 0 {
        return Err(VmexitLoopError::DispatcherFailure(diagnostics.failure_code));
    }
    if diagnostics.exit_count != 2
        || diagnostics.cpuid_count != 1
        || diagnostics.vmcall_count != 1
        || diagnostics.resume_count != 1
    {
        return Err(VmexitLoopError::UnexpectedExitCounts {
            exits: diagnostics.exit_count,
            cpuid: diagnostics.cpuid_count,
            vmcall: diagnostics.vmcall_count,
        });
    }

    if diagnostics.cpuid_leaf != 1 || diagnostics.cpuid_subleaf != 0 {
        return Err(VmexitLoopError::CpuidInputMismatch {
            leaf: diagnostics.cpuid_leaf,
            subleaf: diagnostics.cpuid_subleaf,
        });
    }

    if diagnostics.cpuid_rip != report.cpuid_rip_expected {
        return Err(VmexitLoopError::CpuidRipMismatch {
            expected: report.cpuid_rip_expected,
            actual: diagnostics.cpuid_rip,
        });
    }
    if diagnostics.vmcall_rip != report.vmcall_rip_expected {
        return Err(VmexitLoopError::VmcallRipMismatch {
            expected: report.vmcall_rip_expected,
            actual: diagnostics.vmcall_rip,
        });
    }

    if diagnostics.final_eax != u64::from(diagnostics.cpuid_eax)
        || diagnostics.final_ebx != u64::from(diagnostics.cpuid_ebx)
        || diagnostics.final_ecx != u64::from(diagnostics.cpuid_ecx)
        || diagnostics.final_edx != u64::from(diagnostics.cpuid_edx)
    {
        return Err(VmexitLoopError::GuestRegisterMismatch);
    }
    if diagnostics.final_rsp != report.guest.rsp {
        return Err(VmexitLoopError::GuestRspMismatch {
            expected: report.guest.rsp,
            actual: diagnostics.final_rsp,
        });
    }

    Ok(report)
}

fn guest_probe_address() -> u64 {
    matrixhv_guest_probe_asm as *const () as usize as u64
}

fn dispatch_guest_address() -> u64 {
    matrixhv_dispatch_guest_asm as *const () as usize as u64
}

fn dispatch_guest_cpuid_address() -> u64 {
    matrixhv_dispatch_guest_cpuid_asm as *const () as usize as u64
}

fn dispatch_guest_vmcall_address() -> u64 {
    matrixhv_dispatch_guest_vmcall_asm as *const () as usize as u64
}

unsafe extern "efiapi" {
    fn matrixhv_vmlaunch_probe_asm() -> u64;
    fn matrixhv_guest_probe_asm();
    fn matrixhv_dispatch_run_asm(context: *mut VmRunContext, host_exit_rsp: u64) -> u64;
    fn matrixhv_dispatch_guest_asm();
    fn matrixhv_dispatch_guest_cpuid_asm();
    fn matrixhv_dispatch_guest_vmcall_asm();
}

pub(crate) unsafe fn run_persistent_loop(context: *mut VmRunContext, host_exit_rsp: u64) -> u64 {
    unsafe { matrixhv_dispatch_run_asm(context, host_exit_rsp) }
}

global_asm!(
    ".text",
    ".globl matrixhv_guest_probe_asm",
    "matrixhv_guest_probe_asm:",
    "vmcall",
    "ud2",
    ".globl matrixhv_vmlaunch_probe_asm",
    "matrixhv_vmlaunch_probe_asm:",
    "mov rax, {host_rsp}",
    "mov rdx, rsp",
    "vmwrite rax, rdx",
    "jc 3f",
    "jz 3f",
    "mov rax, {host_rip}",
    "lea rdx, [rip + 2f]",
    "vmwrite rax, rdx",
    "jc 4f",
    "jz 4f",
    "vmlaunch",
    "setc al",
    "setz dl",
    "movzx r8d, al",
    "movzx r9d, dl",
    "shl r9d, 1",
    "or r8d, r9d",
    "mov rax, r8",
    "ret",
    "2:",
    "xor eax, eax",
    "ret",
    "3:",
    "mov eax, 3",
    "ret",
    "4:",
    "mov eax, 4",
    "ret",
    ".globl matrixhv_dispatch_guest_asm",
    "matrixhv_dispatch_guest_asm:",
    "mov eax, 1",
    "xor ecx, ecx",
    ".globl matrixhv_dispatch_guest_cpuid_asm",
    "matrixhv_dispatch_guest_cpuid_asm:",
    "cpuid",
    ".globl matrixhv_dispatch_guest_vmcall_asm",
    "matrixhv_dispatch_guest_vmcall_asm:",
    "vmcall",
    "ud2",
    ".globl matrixhv_dispatch_run_asm",
    "matrixhv_dispatch_run_asm:",
    "push rbx",
    "push rbp",
    "push rdi",
    "push rsi",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov qword ptr [rcx], rsp",
    "fxsave64 [rcx + {root_fx_state}]",
    "mov rax, {host_rsp}",
    "vmwrite rax, rdx",
    "jc 13f",
    "jz 13f",
    "mov rax, {host_rip}",
    "lea rdx, [rip + matrixhv_vmexit_trampoline_asm]",
    "vmwrite rax, rdx",
    "jc 14f",
    "jz 14f",
    "vmlaunch",
    "jc 11f",
    "jz 12f",
    "mov eax, 7",
    "jmp 19f",
    "11:",
    "mov eax, 1",
    "jmp 15f",
    "12:",
    "mov eax, 2",
    "jmp 15f",
    "13:",
    "mov eax, 3",
    "jmp 15f",
    "14:",
    "mov eax, 4",
    "15:",
    "fxrstor64 [rcx + {root_fx_state}]",
    "jmp 19f",
    ".globl matrixhv_vmexit_trampoline_asm",
    "matrixhv_vmexit_trampoline_asm:",
    "sub rsp, 8",
    "push r15",
    "push r14",
    "push r13",
    "push r12",
    "push r11",
    "push r10",
    "push r9",
    "push r8",
    "push rdi",
    "push rsi",
    "push rbp",
    "push rdx",
    "push rcx",
    "push rbx",
    "push rax",
    "mov rax, {guest_rsp}",
    "vmread r11, rax",
    "jc 20f",
    "jz 20f",
    "mov qword ptr [rsp + 120], r11",
    "mov r10, qword ptr [rsp + 128]",
    "fxsave64 [r10 + {guest_fx_state}]",
    "mov rcx, rsp",
    "mov rdx, qword ptr [rsp + 128]",
    "sub rsp, 32",
    "cld",
    "call matrixhv_vmexit_dispatch",
    "add rsp, 32",
    "cmp eax, 1",
    "je 16f",
    "mov r10, qword ptr [rsp + 128]",
    "fxrstor64 [r10 + {root_fx_state}]",
    "mov rsp, qword ptr [r10]",
    "xor eax, eax",
    "jmp 19f",
    "16:",
    "mov r10, qword ptr [rsp + 128]",
    "fxrstor64 [r10 + {guest_fx_state}]",
    "mov r11, qword ptr [rsp + 120]",
    "mov rax, {guest_rsp}",
    "vmwrite rax, r11",
    "jc 21f",
    "jz 21f",
    "pop rax",
    "pop rbx",
    "pop rcx",
    "pop rdx",
    "pop rbp",
    "pop rsi",
    "pop rdi",
    "pop r8",
    "pop r9",
    "pop r10",
    "pop r11",
    "pop r12",
    "pop r13",
    "pop r14",
    "pop r15",
    "add rsp, 8",
    "vmresume",
    "jc 17f",
    "jz 18f",
    "mov eax, 7",
    "mov r10, qword ptr [rsp]",
    "fxrstor64 [r10 + {root_fx_state}]",
    "mov rsp, qword ptr [r10]",
    "jmp 19f",
    "17:",
    "mov eax, 5",
    "mov r10, qword ptr [rsp]",
    "fxrstor64 [r10 + {root_fx_state}]",
    "mov rsp, qword ptr [r10]",
    "jmp 19f",
    "18:",
    "mov eax, 6",
    "mov r10, qword ptr [rsp]",
    "fxrstor64 [r10 + {root_fx_state}]",
    "mov rsp, qword ptr [r10]",
    "jmp 19f",
    "20:",
    "mov r10, qword ptr [rsp + 128]",
    "fxrstor64 [r10 + {root_fx_state}]",
    "mov rsp, qword ptr [r10]",
    "mov eax, 7",
    "jmp 19f",
    "21:",
    "mov r10, qword ptr [rsp + 128]",
    "fxrstor64 [r10 + {root_fx_state}]",
    "mov rsp, qword ptr [r10]",
    "mov eax, 8",
    "19:",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rsi",
    "pop rdi",
    "pop rbp",
    "pop rbx",
    "ret",
    host_rsp = const HOST_RSP,
    host_rip = const HOST_RIP,
    guest_rsp = const GUEST_RSP,
    root_fx_state = const 16,
    guest_fx_state = const 528,
);
