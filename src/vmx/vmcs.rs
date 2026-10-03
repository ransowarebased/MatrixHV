use core::arch::asm;

use uefi::Status;

use super::vmxon::{self, VmxInstructionResult, VmxonError, VmxonReport};

use crate::memory::host::{AddressConstraint, ResidentPages};
use crate::logging;

pub const VIRTUAL_PROCESSOR_ID: u64 = 0x0000;
pub const GUEST_ES_SELECTOR: u64 = 0x0800;
pub const GUEST_CS_SELECTOR: u64 = 0x0802;
pub const GUEST_SS_SELECTOR: u64 = 0x0804;
pub const GUEST_DS_SELECTOR: u64 = 0x0806;
pub const GUEST_FS_SELECTOR: u64 = 0x0808;
pub const GUEST_GS_SELECTOR: u64 = 0x080a;
pub const GUEST_LDTR_SELECTOR: u64 = 0x080c;
pub const GUEST_TR_SELECTOR: u64 = 0x080e;
pub const HOST_ES_SELECTOR: u64 = 0x0c00;
pub const HOST_CS_SELECTOR: u64 = 0x0c02;
pub const HOST_SS_SELECTOR: u64 = 0x0c04;
pub const HOST_DS_SELECTOR: u64 = 0x0c06;
pub const HOST_FS_SELECTOR: u64 = 0x0c08;
pub const HOST_GS_SELECTOR: u64 = 0x0c0a;
pub const HOST_TR_SELECTOR: u64 = 0x0c0c;

pub const VMCS_LINK_POINTER: u64 = 0x2800;
pub const GUEST_IA32_DEBUGCTL: u64 = 0x2802;
pub const GUEST_IA32_PAT: u64 = 0x2804;
pub const GUEST_IA32_EFER: u64 = 0x2806;
pub const VMX_PREEMPTION_TIMER_VALUE: u64 = 0x482e;
pub const GUEST_PDPTR0: u64 = 0x280a;
pub const GUEST_PDPTR1: u64 = 0x280c;
pub const GUEST_PDPTR2: u64 = 0x280e;
pub const GUEST_PDPTR3: u64 = 0x2810;
pub const HOST_IA32_PAT: u64 = 0x2c00;
pub const HOST_IA32_EFER: u64 = 0x2c02;
pub const IO_BITMAP_A: u64 = 0x2000;
pub const IO_BITMAP_B: u64 = 0x2002;
pub const MSR_BITMAP: u64 = 0x2004;
pub const VM_EXIT_MSR_STORE_ADDR: u64 = 0x2006;
pub const VM_EXIT_MSR_LOAD_ADDR: u64 = 0x2008;
pub const VM_ENTRY_MSR_LOAD_ADDR: u64 = 0x200a;
pub const TSC_OFFSET: u64 = 0x2010;
pub const VIRTUAL_APIC_PAGE_ADDR: u64 = 0x2012;
pub const EPT_POINTER: u64 = 0x201a;
pub const VM_FUNCTION_CONTROL: u64 = 0x2018;
pub const EPTP_LIST_ADDRESS: u64 = 0x2024;
pub const VMREAD_BITMAP: u64 = 0x2026;
pub const VMWRITE_BITMAP: u64 = 0x2028;
pub const XSS_EXITING_BITMAP: u64 = 0x202c;

pub const PIN_BASED_VM_EXEC_CONTROL: u64 = 0x4000;
pub const CPU_BASED_VM_EXEC_CONTROL: u64 = 0x4002;
pub const EXCEPTION_BITMAP: u64 = 0x4004;
pub const PAGE_FAULT_ERROR_CODE_MASK: u64 = 0x4006;
pub const PAGE_FAULT_ERROR_CODE_MATCH: u64 = 0x4008;
pub const CR3_TARGET_COUNT: u64 = 0x400a;
pub const VM_EXIT_CONTROLS: u64 = 0x400c;
pub const VM_EXIT_MSR_STORE_COUNT: u64 = 0x400e;
pub const VM_EXIT_MSR_LOAD_COUNT: u64 = 0x4010;
pub const VM_ENTRY_CONTROLS: u64 = 0x4012;
pub const VM_ENTRY_MSR_LOAD_COUNT: u64 = 0x4014;
pub const VM_ENTRY_INTR_INFO_FIELD: u64 = 0x4016;
pub const VM_ENTRY_EXCEPTION_ERROR_CODE: u64 = 0x4018;
pub const VM_ENTRY_INSTRUCTION_LEN: u64 = 0x401a;
pub const TPR_THRESHOLD: u64 = 0x401c;
pub const SECONDARY_VM_EXEC_CONTROL: u64 = 0x401e;

pub const VM_INSTRUCTION_ERROR: u64 = 0x4400;
pub const VM_EXIT_REASON: u64 = 0x4402;
pub const VM_EXIT_INTR_INFO: u64 = 0x4404;
pub const VM_EXIT_INTR_ERROR_CODE: u64 = 0x4406;
pub const IDT_VECTORING_INFO_FIELD: u64 = 0x4408;
pub const IDT_VECTORING_ERROR_CODE: u64 = 0x440a;
pub const VM_EXIT_INSTRUCTION_LEN: u64 = 0x440c;
pub const VM_EXIT_INSTRUCTION_INFO: u64 = 0x440e;

pub const GUEST_ES_LIMIT: u64 = 0x4800;
pub const GUEST_CS_LIMIT: u64 = 0x4802;
pub const GUEST_SS_LIMIT: u64 = 0x4804;
pub const GUEST_DS_LIMIT: u64 = 0x4806;
pub const GUEST_FS_LIMIT: u64 = 0x4808;
pub const GUEST_GS_LIMIT: u64 = 0x480a;
pub const GUEST_LDTR_LIMIT: u64 = 0x480c;
pub const GUEST_TR_LIMIT: u64 = 0x480e;
pub const GUEST_GDTR_LIMIT: u64 = 0x4810;
pub const GUEST_IDTR_LIMIT: u64 = 0x4812;
pub const GUEST_ES_AR_BYTES: u64 = 0x4814;
pub const GUEST_CS_AR_BYTES: u64 = 0x4816;
pub const GUEST_SS_AR_BYTES: u64 = 0x4818;
pub const GUEST_DS_AR_BYTES: u64 = 0x481a;
pub const GUEST_FS_AR_BYTES: u64 = 0x481c;
pub const GUEST_GS_AR_BYTES: u64 = 0x481e;
pub const GUEST_LDTR_AR_BYTES: u64 = 0x4820;
pub const GUEST_TR_AR_BYTES: u64 = 0x4822;
pub const GUEST_INTERRUPTIBILITY_INFO: u64 = 0x4824;
pub const GUEST_ACTIVITY_STATE: u64 = 0x4826;
pub const GUEST_SYSENTER_CS: u64 = 0x482a;

pub const HOST_SYSENTER_CS: u64 = 0x4c00;

pub const CR0_GUEST_HOST_MASK: u64 = 0x6000;
pub const CR4_GUEST_HOST_MASK: u64 = 0x6002;
pub const CR0_READ_SHADOW: u64 = 0x6004;
pub const CR4_READ_SHADOW: u64 = 0x6006;

pub const EXIT_QUALIFICATION: u64 = 0x6400;
pub const GUEST_LINEAR_ADDRESS: u64 = 0x640a;
pub const GUEST_PHYSICAL_ADDRESS: u64 = 0x2400;

pub const GUEST_CR0: u64 = 0x6800;
pub const GUEST_CR3: u64 = 0x6802;
pub const GUEST_CR4: u64 = 0x6804;
pub const GUEST_ES_BASE: u64 = 0x6806;
pub const GUEST_CS_BASE: u64 = 0x6808;
pub const GUEST_SS_BASE: u64 = 0x680a;
pub const GUEST_DS_BASE: u64 = 0x680c;
pub const GUEST_FS_BASE: u64 = 0x680e;
pub const GUEST_GS_BASE: u64 = 0x6810;
pub const GUEST_LDTR_BASE: u64 = 0x6812;
pub const GUEST_TR_BASE: u64 = 0x6814;
pub const GUEST_GDTR_BASE: u64 = 0x6816;
pub const GUEST_IDTR_BASE: u64 = 0x6818;
pub const GUEST_DR7: u64 = 0x681a;
pub const GUEST_RSP: u64 = 0x681c;
pub const GUEST_RIP: u64 = 0x681e;
pub const GUEST_RFLAGS: u64 = 0x6820;
pub const GUEST_PENDING_DBG_EXCEPTIONS: u64 = 0x6822;
pub const GUEST_SYSENTER_ESP: u64 = 0x6824;
pub const GUEST_SYSENTER_EIP: u64 = 0x6826;

pub const HOST_CR0: u64 = 0x6c00;
pub const HOST_CR3: u64 = 0x6c02;
pub const HOST_CR4: u64 = 0x6c04;
pub const HOST_FS_BASE: u64 = 0x6c06;
pub const HOST_GS_BASE: u64 = 0x6c08;
pub const HOST_TR_BASE: u64 = 0x6c0a;
pub const HOST_GDTR_BASE: u64 = 0x6c0c;
pub const HOST_IDTR_BASE: u64 = 0x6c0e;
pub const HOST_SYSENTER_ESP: u64 = 0x6c10;
pub const HOST_SYSENTER_EIP: u64 = 0x6c12;
pub const HOST_RSP: u64 = 0x6c14;
pub const HOST_RIP: u64 = 0x6c16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmcsError {
    Vmxon(VmxonError),
    Allocation(Status),
    Vmclear(VmxInstructionResult),
    Vmptrld(VmxInstructionResult),
    CurrentPointerMismatch { expected: u64, actual: u64 },
    Vmread(VmxInstructionResult),
    Vmwrite(VmxInstructionResult),
    FinalVmclear(VmxInstructionResult),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmcsReport {
    pub vmxon: VmxonReport,
    pub revision_id: u32,
    pub region_physical_address: u64,
    pub current_vmcs_physical_address: u64,
    pub instruction_error: u64,
}

pub(crate) struct VmcsRegion {
    pages: ResidentPages,
}

impl VmcsRegion {
    pub(crate) fn allocate(vmx_basic: u64) -> Result<Self, VmcsError> {
        let constraint = if vmxon::region_uses_32_bit_physical_addresses(vmx_basic) {
            AddressConstraint::Max(u32::MAX as u64)
        } else {
            AddressConstraint::Any
        };
        let pages = ResidentPages::allocate(1, constraint).map_err(VmcsError::Allocation)?;
        Ok(Self { pages })
    }

    pub(crate) fn physical_address(&self) -> u64 {
        self.pages.physical_address()
    }

    pub(crate) fn write_revision_id(&mut self, revision_id: u32) {
        unsafe {
            self.pages
                .pointer()
                .as_ptr()
                .cast::<u32>()
                .write(revision_id);
        }
    }
}

pub fn probe_vmcs() -> Result<VmcsReport, VmcsError> {
    let vmx_basic = vmxon::vmx_basic();
    let revision_id = vmxon::revision_id(vmx_basic);
    let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
    vmcs_region.write_revision_id(revision_id);
    let region_physical_address = vmcs_region.physical_address();
    let session = vmxon::enter_vmx_root().map_err(VmcsError::Vmxon)?;
    let vmxon_report = session.report();

    logging::phase("vmx.vmcs.vmclear.start");
    let clear_result = unsafe { vmclear(region_physical_address) };
    if clear_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(VmcsError::Vmclear(clear_result));
    }
    logging::phase("vmx.vmcs.vmclear.ok");

    logging::phase("vmx.vmcs.vmptrld.start");
    let load_result = unsafe { vmptrld(region_physical_address) };
    if load_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(VmcsError::Vmptrld(load_result));
    }
    logging::phase("vmx.vmcs.vmptrld.ok");

    logging::phase("vmx.vmcs.vmptrst.start");
    let current_vmcs_physical_address = unsafe { vmptrst() };
    logging::phase("vmx.vmcs.vmptrst.ok");
    logging::phase("vmx.vmcs.vmread_error.start");
    let (instruction_error, read_result) = unsafe { vmread_raw(VM_INSTRUCTION_ERROR) };
    if read_result == VmxInstructionResult::Succeeded {
        logging::phase("vmx.vmcs.vmread_error.ok");
    }
    logging::phase("vmx.vmcs.final_vmclear.start");
    let final_clear_result = unsafe { vmclear(region_physical_address) };
    if final_clear_result == VmxInstructionResult::Succeeded {
        logging::phase("vmx.vmcs.final_vmclear.ok");
    }

    drop(session);

    if current_vmcs_physical_address != region_physical_address {
        return Err(VmcsError::CurrentPointerMismatch {
            expected: region_physical_address,
            actual: current_vmcs_physical_address,
        });
    }
    if read_result != VmxInstructionResult::Succeeded {
        return Err(VmcsError::Vmread(read_result));
    }
    if final_clear_result != VmxInstructionResult::Succeeded {
        return Err(VmcsError::FinalVmclear(final_clear_result));
    }

    Ok(VmcsReport {
        vmxon: vmxon_report,
        revision_id,
        region_physical_address,
        current_vmcs_physical_address,
        instruction_error,
    })
}

pub(crate) unsafe fn vmclear(physical_address: u64) -> VmxInstructionResult {
    let carry: u8;
    let zero: u8;
    unsafe {
        asm!(
            "vmclear [{address}]",
            "setc {carry}",
            "setz {zero}",
            address = in(reg) &physical_address,
            carry = lateout(reg_byte) carry,
            zero = lateout(reg_byte) zero,
            options(nostack)
        );
    }
    vmxon::decode_flags(carry, zero)
}

pub(crate) unsafe fn vmptrld(physical_address: u64) -> VmxInstructionResult {
    let carry: u8;
    let zero: u8;
    unsafe {
        asm!(
            "vmptrld [{address}]",
            "setc {carry}",
            "setz {zero}",
            address = in(reg) &physical_address,
            carry = lateout(reg_byte) carry,
            zero = lateout(reg_byte) zero,
            options(nostack)
        );
    }
    vmxon::decode_flags(carry, zero)
}

unsafe fn vmptrst() -> u64 {
    let mut physical_address = u64::MAX;
    unsafe {
        asm!(
            "vmptrst [{address}]",
            address = in(reg) &mut physical_address,
            options(nostack)
        );
    }
    physical_address
}

pub(crate) unsafe fn vmread_raw(field: u64) -> (u64, VmxInstructionResult) {
    let value: u64;
    let carry: u8;
    let zero: u8;
    unsafe {
        asm!(
            "vmread {value}, {field}",
            "setc {carry}",
            "setz {zero}",
            value = lateout(reg) value,
            field = in(reg) field,
            carry = lateout(reg_byte) carry,
            zero = lateout(reg_byte) zero,
            options(nostack)
        );
    }
    (value, vmxon::decode_flags(carry, zero))
}

pub(crate) fn vmread(field: u64) -> Result<u64, VmcsError> {
    let (value, result) = unsafe { vmread_raw(field) };
    if result == VmxInstructionResult::Succeeded {
        Ok(value)
    } else {
        Err(VmcsError::Vmread(result))
    }
}

pub(crate) fn vmwrite(field: u64, value: u64) -> Result<(), VmcsError> {
    let carry: u8;
    let zero: u8;
    unsafe {
        asm!(
            "vmwrite {field}, {value}",
            "setc {carry}",
            "setz {zero}",
            field = in(reg) field,
            value = in(reg) value,
            carry = lateout(reg_byte) carry,
            zero = lateout(reg_byte) zero,
            options(nostack)
        );
    }
    let result = vmxon::decode_flags(carry, zero);
    if result == VmxInstructionResult::Succeeded {
        Ok(())
    } else {
        Err(VmcsError::Vmwrite(result))
    }
}

pub(crate) fn instruction_error_name(error: u64) -> &'static str {
    match error {
        0 => "none",
        4 => "vmlaunch_non_clear_vmcs",
        7 => "vm_entry_invalid_control_fields",
        8 => "vm_entry_invalid_host_state",
        26 => "vm_entry_blocked_by_mov_ss",
        _ => "other",
    }
}
