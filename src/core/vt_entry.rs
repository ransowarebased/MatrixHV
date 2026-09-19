use core::arch::global_asm;
use core::ptr::NonNull;

use uefi::boot::{self, AllocateType};
use uefi::mem::memory_map::MemoryType;

use super::vt_controls::{self, VmxControls, VmxControlsError};
use super::vt_exit_reason;
use super::vt_guest::{self, GuestStateReport};
use super::vt_host::{self, HostStateReport};
use super::vt_vmcs::{self, VmcsError, VmcsRegion};
use super::vt_vmcs_fields::{
    EXIT_QUALIFICATION, GUEST_RIP, HOST_RIP, HOST_RSP, VM_EXIT_INSTRUCTION_LEN, VM_EXIT_REASON,
    VM_INSTRUCTION_ERROR,
};
use super::vt_vmxon::{self, VmxInstructionResult, VmxonError, VmxonReport};
use crate::boot::logger;

const PAGE_SIZE: usize = 4096;

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
}

impl Drop for ProbeStack {
    fn drop(&mut self) {
        unsafe {
            let _ = boot::free_pages(self.pointer, 1);
        }
    }
}

pub fn probe_vmlaunch() -> Result<VmlaunchReport, VmlaunchError> {
    let vmx_basic = vt_vmxon::vmx_basic();
    let revision_id = vt_vmxon::revision_id(vmx_basic);
    let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
    vmcs_region.write_revision_id(revision_id);
    let vmcs_physical_address = vmcs_region.physical_address();
    let guest_stack = ProbeStack::allocate()?;

    let session = vt_vmxon::enter_vmx_root().map_err(VmlaunchError::Vmxon)?;
    let vmxon_report = session.report();

    logger::phase("vmx.vmlaunch.vmclear.start");
    let clear_result = unsafe { vt_vmcs::vmclear(vmcs_physical_address) };
    if clear_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(VmlaunchError::Vmcs(VmcsError::Vmclear(clear_result)));
    }
    logger::phase("vmx.vmlaunch.vmclear.ok");

    logger::phase("vmx.vmlaunch.vmptrld.start");
    let load_result = unsafe { vt_vmcs::vmptrld(vmcs_physical_address) };
    if load_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(VmlaunchError::Vmcs(VmcsError::Vmptrld(load_result)));
    }
    logger::phase("vmx.vmlaunch.vmptrld.ok");

    let controls = vt_controls::configure()?;
    logger::info(format_args!(
        "vmlaunch controls pin={:#x} primary={:#x} secondary={:#x} exit={:#x} entry={:#x}",
        controls.pin_based,
        controls.primary_processor_based,
        controls.secondary_processor_based,
        controls.vm_exit,
        controls.vm_entry
    ));
    logger::phase("vmx.vmlaunch.controls.ok");

    let host = vt_host::configure()?;
    logger::info(format_args!(
        "vmlaunch host cs={:#x} ss={:#x} tr={:#x} tr_base={:#x} gdtr={:#x} idtr={:#x}",
        host.cs_selector,
        host.ss_selector,
        host.tr_selector,
        host.tr_base,
        host.gdtr_base,
        host.idtr_base
    ));
    logger::phase("vmx.vmlaunch.host_state.ok");

    let guest_rip = guest_probe_address();
    let guest = vt_guest::configure(guest_rip, guest_stack.top())?;
    logger::info(format_args!(
        "vmlaunch guest rip={:#x} rsp={:#x} rflags={:#x} cs={:#x} ss={:#x} tr={:#x}",
        guest.rip, guest.rsp, guest.rflags, guest.cs_selector, guest.ss_selector, guest.tr_selector
    ));
    logger::phase("vmx.vmlaunch.guest_state.ok");

    logger::phase("vmx.vmlaunch.start");
    let raw_path = unsafe { matrixhv_vmlaunch_probe_asm() };
    logger::phase("vmx.vmlaunch.returned_to_host");

    let exit_reason = vt_vmcs::vmread(VM_EXIT_REASON).unwrap_or(0) as u32;
    let basic_exit_reason = vt_exit_reason::basic(exit_reason);
    let exit_qualification = vt_vmcs::vmread(EXIT_QUALIFICATION).unwrap_or(0);
    let instruction_length = vt_vmcs::vmread(VM_EXIT_INSTRUCTION_LEN).unwrap_or(0);
    let vm_instruction_error = vt_vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
    let guest_rip_after_exit = vt_vmcs::vmread(GUEST_RIP).unwrap_or(0);

    logger::info(format_args!(
        "vmlaunch raw_path={} exit_reason={:#x} exit_name={} basic_reason={} qualification={:#x} instruction_len={} vm_instruction_error={} vm_instruction_error_name={} guest_rip={:#x}",
        raw_path,
        exit_reason,
        vt_exit_reason::name(exit_reason),
        basic_exit_reason,
        exit_qualification,
        instruction_length,
        vm_instruction_error,
        vt_vmcs::instruction_error_name(vm_instruction_error),
        guest_rip_after_exit
    ));

    let launch_result = match raw_path {
        0 if vt_exit_reason::is_vm_entry_failure(exit_reason) => {
            Err(VmlaunchError::VmEntryFailure {
                exit_reason,
                qualification: exit_qualification,
            })
        }
        0 if basic_exit_reason != vt_exit_reason::VMCALL => {
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

    logger::phase("vmx.vmlaunch.final_vmclear.start");
    let final_clear = unsafe { vt_vmcs::vmclear(vmcs_physical_address) };
    if final_clear == VmxInstructionResult::Succeeded {
        logger::phase("vmx.vmlaunch.final_vmclear.ok");
    }
    drop(session);
    logger::phase("vmx.vmlaunch.vmxoff_restored");

    if final_clear != VmxInstructionResult::Succeeded {
        return Err(VmlaunchError::CleanupVmclear(final_clear));
    }

    launch_result
}

fn guest_probe_address() -> u64 {
    matrixhv_guest_probe_asm as *const () as usize as u64
}

unsafe extern "efiapi" {
    fn matrixhv_vmlaunch_probe_asm() -> u64;
    fn matrixhv_guest_probe_asm();
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
    host_rsp = const HOST_RSP,
    host_rip = const HOST_RIP,
);
