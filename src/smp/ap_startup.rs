use core::arch::global_asm;
use core::ffi::c_void;

use uefi::boot;
use uefi::proto::pi::mp::MpServices;

use crate::hv_core::vt_resident::{ResidentApLaunch, ResidentProbeError};

pub(crate) fn launch(
    processor_number: usize,
    launch: &mut ResidentApLaunch<'_>,
) -> Result<(), ResidentProbeError> {
    let handle = boot::get_handle_for_protocol::<MpServices>()
        .map_err(|error| ResidentProbeError::Allocation(error.status()))?;
    let mp = boot::open_protocol_exclusive::<MpServices>(handle)
        .map_err(|error| ResidentProbeError::Allocation(error.status()))?;
    mp.startup_this_ap(
        processor_number,
        callback,
        (launch as *mut ResidentApLaunch<'_>).cast(),
        None,
        None,
    )
    .map_err(|error| ResidentProbeError::Allocation(error.status()))
}

extern "efiapi" fn callback(argument: *mut c_void) {
    unsafe {
        matrixhv_ap_launch_asm(argument);
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
            crate::runtime::logger::error(format_args!("smp resident AP prepare error={error:?}"));
            0
        }
    }
}

unsafe extern "efiapi" {
    fn matrixhv_ap_launch_asm(argument: *mut c_void);
}

#[unsafe(no_mangle)]
extern "efiapi" fn matrixhv_ap_launch_failed(flags: u64) -> ! {
    let error =
        crate::hv_core::vt_vmcs::vmread(crate::hv_core::vt_vmcs_fields::VM_INSTRUCTION_ERROR);
    crate::runtime::logger::error(format_args!(
        "smp resident AP VMLAUNCH failed flags={flags:#x} instruction_error={error:?}"
    ));
    loop {
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

// The guest resumes on the firmware stack and returns through the original MP callback.
// Only the persistent exit stack and VMCS remain owned by root after this point.
global_asm!(
    ".text",
    ".globl matrixhv_ap_launch_asm",
    "matrixhv_ap_launch_asm:",
    "pushfq",
    "cli",
    "push rbx",
    "push rbp",
    "push rsi",
    "push rdi",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "sub rsp, 544",
    "fxsave64 [rsp + 32]",
    "mov rdx, rsp",
    "lea r8, [rip + .Lap_guest_return]",
    "call matrixhv_ap_prepare",
    "test rax, rax",
    "jz .Lap_restore",
    "vmlaunch",
    // A failed launch cannot release resources while another CPU may be resident.
    "pushfq",
    "pop rcx",
    "call matrixhv_ap_launch_failed",
    ".Lap_guest_return:",
    "vmxon [rax]",
    "jna .Lap_nested_probe_failed",
    "vmxoff",
    "jna .Lap_nested_probe_failed",
    "mov eax, 1",
    "xor ecx, ecx",
    "cpuid",
    "mov eax, 0x40000000",
    "xor ecx, ecx",
    "cpuid",
    "mov rax, 0x4856415052454144",
    "vmcall",
    "jmp .Lap_restore",
    ".Lap_nested_probe_failed:",
    "mov rax, {nested_probe_failed}",
    "vmcall",
    ".Lap_restore:",
    "fxrstor64 [rsp + 32]",
    "add rsp, 544",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rdi",
    "pop rsi",
    "pop rbp",
    "pop rbx",
    "popfq",
    "ret",
    nested_probe_failed = const crate::hv_core::vt_resident::RESIDENT_VMCALL_NESTED_PROBE_FAILED,
);
