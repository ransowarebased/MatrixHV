use core::arch::asm;
use uefi::Status;

use super::vt_vmcs_fields::VM_INSTRUCTION_ERROR;
use super::vt_vmxon::{self, VmxInstructionResult, VmxonError, VmxonReport};
use crate::memory::resident::{AddressConstraint, ResidentPages};
use crate::runtime::logger;

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
        let constraint = if vt_vmxon::region_uses_32_bit_physical_addresses(vmx_basic) {
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
    let vmx_basic = vt_vmxon::vmx_basic();
    let revision_id = vt_vmxon::revision_id(vmx_basic);
    let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
    vmcs_region.write_revision_id(revision_id);
    let region_physical_address = vmcs_region.physical_address();
    let session = vt_vmxon::enter_vmx_root().map_err(VmcsError::Vmxon)?;
    let vmxon_report = session.report();

    logger::phase("vmx.vmcs.vmclear.start");
    let clear_result = unsafe { vmclear(region_physical_address) };
    if clear_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(VmcsError::Vmclear(clear_result));
    }
    logger::phase("vmx.vmcs.vmclear.ok");

    logger::phase("vmx.vmcs.vmptrld.start");
    let load_result = unsafe { vmptrld(region_physical_address) };
    if load_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(VmcsError::Vmptrld(load_result));
    }
    logger::phase("vmx.vmcs.vmptrld.ok");

    logger::phase("vmx.vmcs.vmptrst.start");
    let current_vmcs_physical_address = unsafe { vmptrst() };
    logger::phase("vmx.vmcs.vmptrst.ok");
    logger::phase("vmx.vmcs.vmread_error.start");
    let (instruction_error, read_result) = unsafe { vmread_raw(VM_INSTRUCTION_ERROR) };
    if read_result == VmxInstructionResult::Succeeded {
        logger::phase("vmx.vmcs.vmread_error.ok");
    }
    logger::phase("vmx.vmcs.final_vmclear.start");
    let final_clear_result = unsafe { vmclear(region_physical_address) };
    if final_clear_result == VmxInstructionResult::Succeeded {
        logger::phase("vmx.vmcs.final_vmclear.ok");
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
    vt_vmxon::decode_flags(carry, zero)
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
    vt_vmxon::decode_flags(carry, zero)
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
    (value, vt_vmxon::decode_flags(carry, zero))
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
    let result = vt_vmxon::decode_flags(carry, zero);
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
