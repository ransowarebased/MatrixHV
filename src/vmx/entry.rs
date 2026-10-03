use super::controls::{self, VmxControls, VmxControlsError};
use super::exits::{self, DispatchDiagnostics, VmRunContext};
use super::exits::{VMCALL_EXIT_REASON, validate_resident_run_path};
use super::resident::abi::{CONTEXT_CANARY_END, CONTEXT_CANARY_START, ResidentContext};
use super::resident::{CONTEXT_COMPLETE, ResidentProbeError};
use super::state::configure_resident_host;
use super::state::{self, GuestStateReport, HostStateReport};
use super::vcpu::PreparedProbe;
use super::vcpu::{HostExitStack, ProbeStack, VmlaunchProbeResources};
use super::vmcs::{
    self, EXIT_QUALIFICATION, GUEST_RIP, GUEST_RSP, HOST_RIP, HOST_RSP, VM_EXIT_INSTRUCTION_LEN,
    VM_EXIT_REASON, VM_INSTRUCTION_ERROR, VmcsError, VmcsRegion,
};
use super::vmxon::{self, VmxInstructionResult, VmxonError, VmxonReport};
use crate::memory::host::{RESIDENT_CODE_MEMORY_TYPE, RESIDENT_MEMORY_TYPE};
use crate::logging;
use core::arch::global_asm;

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

pub fn probe_vmlaunch() -> Result<VmlaunchReport, VmlaunchError> {
    let mut resources = VmlaunchProbeResources::allocate()?;
    run_vmlaunch_probe(&mut resources)
}

pub(crate) fn run_vmlaunch_probe(
    resources: &mut VmlaunchProbeResources,
) -> Result<VmlaunchReport, VmlaunchError> {
    let vmx_basic = vmxon::vmx_basic();
    let revision_id = vmxon::revision_id(vmx_basic);
    resources.vmcs_region.write_revision_id(revision_id);
    let vmcs_physical_address = resources.vmcs_region.physical_address();

    let session =
        vmxon::enter_vmx_root_with_borrowed_region(vmx_basic, &mut resources.vmxon_region)
            .map_err(VmlaunchError::Vmxon)?;
    let vmxon_report = session.report();

    logging::phase("vmx.vmlaunch.vmclear.start");
    let clear_result = unsafe { vmcs::vmclear(vmcs_physical_address) };
    if clear_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(VmlaunchError::Vmcs(VmcsError::Vmclear(clear_result)));
    }
    logging::phase("vmx.vmlaunch.vmclear.ok");

    logging::phase("vmx.vmlaunch.vmptrld.start");
    let load_result = unsafe { vmcs::vmptrld(vmcs_physical_address) };
    if load_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(VmlaunchError::Vmcs(VmcsError::Vmptrld(load_result)));
    }
    logging::phase("vmx.vmlaunch.vmptrld.ok");

    let controls = controls::configure()?;
    logging::info(format_args!(
        "vmlaunch controls pin={:#x} primary={:#x} secondary={:#x} exit={:#x} entry={:#x}",
        controls.pin_based,
        controls.primary_processor_based,
        controls.secondary_processor_based,
        controls.vm_exit,
        controls.vm_entry
    ));
    logging::phase("vmx.vmlaunch.controls.ok");

    let host = state::configure_host()?;
    logging::info(format_args!(
        "vmlaunch host cs={:#x} ss={:#x} tr={:#x} tr_base={:#x} gdtr={:#x} idtr={:#x}",
        host.cs_selector,
        host.ss_selector,
        host.tr_selector,
        host.tr_base,
        host.gdtr_base,
        host.idtr_base
    ));
    logging::phase("vmx.vmlaunch.host_state.ok");

    let guest_rip = guest_probe_address();
    let guest = state::configure_guest(guest_rip, resources.guest_stack.top())?;
    logging::info(format_args!(
        "vmlaunch guest rip={:#x} rsp={:#x} rflags={:#x} cs={:#x} ss={:#x} tr={:#x}",
        guest.rip, guest.rsp, guest.rflags, guest.cs_selector, guest.ss_selector, guest.tr_selector
    ));
    logging::phase("vmx.vmlaunch.guest_state.ok");

    logging::phase("vmx.vmlaunch.start");
    let raw_path = unsafe { matrixhv_vmlaunch_probe_asm() };
    logging::phase("vmx.vmlaunch.returned_to_host");

    let exit_reason = vmcs::vmread(VM_EXIT_REASON).unwrap_or(0) as u32;
    let basic_exit_reason = exits::basic_reason(exit_reason);
    let exit_qualification = vmcs::vmread(EXIT_QUALIFICATION).unwrap_or(0);
    let instruction_length = vmcs::vmread(VM_EXIT_INSTRUCTION_LEN).unwrap_or(0);
    let vm_instruction_error = vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
    let guest_rip_after_exit = vmcs::vmread(GUEST_RIP).unwrap_or(0);

    logging::info(format_args!(
        "vmlaunch raw_path={} exit_reason={:#x} exit_name={} basic_reason={} qualification={:#x} instruction_len={} vm_instruction_error={} vm_instruction_error_name={} guest_rip={:#x}",
        raw_path,
        exit_reason,
        exits::reason_name(exit_reason),
        basic_exit_reason,
        exit_qualification,
        instruction_length,
        vm_instruction_error,
        vmcs::instruction_error_name(vm_instruction_error),
        guest_rip_after_exit
    ));

    let launch_result = match raw_path {
        0 if exits::is_vm_entry_failure(exit_reason) => Err(VmlaunchError::VmEntryFailure {
            exit_reason,
            qualification: exit_qualification,
        }),
        0 if basic_exit_reason != exits::VMCALL => {
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

    logging::phase("vmx.vmlaunch.final_vmclear.start");
    let final_clear = unsafe { vmcs::vmclear(vmcs_physical_address) };
    if final_clear == VmxInstructionResult::Succeeded {
        logging::phase("vmx.vmlaunch.final_vmclear.ok");
    }
    drop(session);
    logging::phase("vmx.vmlaunch.vmxoff_restored");

    if final_clear != VmxInstructionResult::Succeeded {
        return Err(VmlaunchError::CleanupVmclear(final_clear));
    }

    launch_result
}

pub fn probe_vmexit_dispatcher() -> Result<VmexitLoopReport, VmexitLoopError> {
    let vmx_basic = vmxon::vmx_basic();
    let revision_id = vmxon::revision_id(vmx_basic);
    let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
    vmcs_region.write_revision_id(revision_id);
    let vmcs_physical_address = vmcs_region.physical_address();
    let guest_stack = ProbeStack::allocate()?;
    let mut host_exit_stack = HostExitStack::allocate()?;
    let mut run_context = VmRunContext::default();
    let host_exit_rsp = host_exit_stack.prepare(&mut run_context);

    let session = vmxon::enter_vmx_root().map_err(VmexitLoopError::Vmxon)?;
    let vmxon_report = session.report();

    logging::phase("vmx.dispatch_probe.vmclear.start");
    let clear_result = unsafe { vmcs::vmclear(vmcs_physical_address) };
    if clear_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(VmexitLoopError::Vmcs(VmcsError::Vmclear(clear_result)));
    }
    logging::phase("vmx.dispatch_probe.vmclear.ok");

    logging::phase("vmx.dispatch_probe.vmptrld.start");
    let load_result = unsafe { vmcs::vmptrld(vmcs_physical_address) };
    if load_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(VmexitLoopError::Vmcs(VmcsError::Vmptrld(load_result)));
    }
    logging::phase("vmx.dispatch_probe.vmptrld.ok");

    let controls = controls::configure()?;
    logging::info(format_args!(
        "dispatch controls pin={:#x} primary={:#x} secondary={:#x} exit={:#x} entry={:#x}",
        controls.pin_based,
        controls.primary_processor_based,
        controls.secondary_processor_based,
        controls.vm_exit,
        controls.vm_entry
    ));
    logging::phase("vmx.dispatch_probe.controls.ok");

    let host = state::configure_host()?;
    logging::phase("vmx.dispatch_probe.host_state.ok");

    let guest_rip = dispatch_guest_address();
    let guest = state::configure_guest(guest_rip, guest_stack.top())?;
    logging::info(format_args!(
        "dispatch guest rip={:#x} rsp={:#x} cpuid_rip={:#x} vmcall_rip={:#x}",
        guest.rip,
        guest.rsp,
        dispatch_guest_cpuid_address(),
        dispatch_guest_vmcall_address()
    ));
    logging::phase("vmx.dispatch_probe.guest_state.ok");

    exits::reset_diagnostics();
    logging::phase("vmx.dispatch_probe.launch.start");
    let raw_path = unsafe { matrixhv_dispatch_run_asm(&mut run_context, host_exit_rsp) };
    logging::phase("vmx.dispatch_probe.returned_to_host");

    let vm_instruction_error = vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
    let diagnostics = exits::diagnostics();
    logging::info(format_args!(
        "dispatch return path={} vm_instruction_error={} vm_instruction_error_name={} exits={} cpuid={} vmcall={} resumes={} failure={} failure_name={}",
        raw_path,
        vm_instruction_error,
        vmcs::instruction_error_name(vm_instruction_error),
        diagnostics.exit_count,
        diagnostics.cpuid_count,
        diagnostics.vmcall_count,
        diagnostics.resume_count,
        diagnostics.failure_code,
        exits::failure_name(diagnostics.failure_code)
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

    logging::phase("vmx.dispatch_probe.final_vmclear.start");
    let final_clear = unsafe { vmcs::vmclear(vmcs_physical_address) };
    if final_clear == VmxInstructionResult::Succeeded {
        logging::phase("vmx.dispatch_probe.final_vmclear.ok");
    }
    drop(session);
    logging::phase("vmx.dispatch_probe.vmxoff_restored");

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

pub fn probe_residency() -> Result<ResidentProbeReport, ResidentProbeError> {
    let PreparedProbe {
        code_pages,
        entry,
        root_segments,
        mut tables,
        context_pages,
        guest_stack,
        host_stack,
        host_address_space,
        vmcs_physical_address,
        vmcs_region,
        host_space,
    } = super::vcpu::prepare_probe()?;
    let _vmcs_region = vmcs_region;
    let session = vmxon::enter_vmx_root().map_err(ResidentProbeError::Vmxon)?;
    let source_cr3 = host_space.source_cr3;
    let context = context_pages.pointer().as_ptr().cast::<ResidentContext>();
    unsafe {
        context.write(ResidentContext::new(source_cr3, host_space.host_cr3));
    }

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

    let _controls = controls::configure()?;
    configure_resident_host(host_space.host_cr3, &tables, root_segments)?;
    let guest_rsp = guest_stack.physical_address() + guest_stack.byte_len() as u64;
    let guest = state::configure_guest(super::resident::guest_probe_address(), guest_rsp & !0xf)?;

    let host_rsp = (host_stack.physical_address() + host_stack.byte_len() as u64 - 8) & !0xf;
    unsafe {
        (host_rsp as *mut u64).write(context as u64);
    }

    let raw_path = unsafe { matrixhv_resident_probe_run_asm(context, host_rsp, entry) };
    if raw_path == 0 {
        tables.pages.preserve();
    }
    let vm_instruction_error = vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
    let final_clear = unsafe { vmcs::vmclear(vmcs_physical_address) };
    host_address_space.restore_source_cr3();
    drop(session);
    if final_clear != VmxInstructionResult::Succeeded {
        return Err(ResidentProbeError::Vmclear(final_clear));
    }
    validate_resident_run_path(raw_path, vm_instruction_error)?;

    let result = unsafe { &*context };
    if result.completed != CONTEXT_COMPLETE {
        return Err(ResidentProbeError::Incomplete(result.completed));
    }
    if result.canary_start != CONTEXT_CANARY_START || result.canary_end != CONTEXT_CANARY_END {
        return Err(ResidentProbeError::CanaryCorrupted);
    }
    if result.exit_reason & 0xffff != VMCALL_EXIT_REASON {
        return Err(ResidentProbeError::UnexpectedExitReason(result.exit_reason));
    }
    if result.observed_host_cr3 != host_space.host_cr3 {
        return Err(ResidentProbeError::HostCr3Mismatch {
            expected: host_space.host_cr3,
            observed: result.observed_host_cr3,
        });
    }
    if result.observed_guest_cr3 != guest.cr3 {
        return Err(ResidentProbeError::GuestCr3Mismatch {
            expected: guest.cr3,
            observed: result.observed_guest_cr3,
        });
    }

    let report = ResidentProbeReport {
        code_physical_address: code_pages.physical_address(),
        code_pages: code_pages.pages(),
        host_table_pages: host_space.table_pages,
        host_table_capacity: host_space.arena_pages,
        data_memory_type: RESIDENT_MEMORY_TYPE.0,
        code_memory_type: RESIDENT_CODE_MEMORY_TYPE.0,
        host_cr3: host_space.host_cr3,
        guest_cr3: guest.cr3,
        observed_host_cr3: result.observed_host_cr3,
        observed_guest_cr3: result.observed_guest_cr3,
        exit_reason: result.exit_reason,
        guest_rip: result.guest_rip,
        host_gdt: tables.gdt,
        host_idt: tables.idt,
        host_tss: tables.tss,
        host_stack: host_rsp,
    };

    let _ = &tables.pages;
    Ok(report)
}

unsafe extern "efiapi" {
    fn matrixhv_resident_probe_run_asm(
        context: *mut ResidentContext,
        host_rsp: u64,
        host_rip: u64,
    ) -> u64;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentProbeReport {
    pub code_physical_address: u64,
    pub code_pages: usize,
    pub host_table_pages: usize,
    pub host_table_capacity: usize,
    pub data_memory_type: u32,
    pub code_memory_type: u32,
    pub host_cr3: u64,
    pub guest_cr3: u64,
    pub observed_host_cr3: u64,
    pub observed_guest_cr3: u64,
    pub exit_reason: u64,
    pub guest_rip: u64,
    pub host_gdt: u64,
    pub host_idt: u64,
    pub host_tss: u64,
    pub host_stack: u64,
}
