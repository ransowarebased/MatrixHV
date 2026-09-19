use crate::arch::x86_64::msr;

use super::vt_vmcs::{VmcsError, vmwrite};
use super::vt_vmcs_fields::*;

const IA32_VMX_BASIC_TRUE_CTLS: u64 = 1 << 55;
const PIN_BASED_NMI_EXITING: u32 = 1 << 3;
const CPU_BASED_ACTIVATE_SECONDARY_CONTROLS: u32 = 1 << 31;
const SECONDARY_ENABLE_EPT: u32 = 1 << 1;
const VM_EXIT_HOST_ADDRESS_SPACE_SIZE: u32 = 1 << 9;
const VM_ENTRY_IA32E_MODE_GUEST: u32 = 1 << 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmxControls {
    pub pin_based: u32,
    pub primary_processor_based: u32,
    pub secondary_processor_based: u32,
    pub vm_exit: u32,
    pub vm_entry: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmxControlsError {
    Vmcs(VmcsError),
    HostAddressSpaceSizeUnavailable,
    Ia32eGuestModeUnavailable,
    EptUnexpectedlyRequired,
}

impl From<VmcsError> for VmxControlsError {
    fn from(value: VmcsError) -> Self {
        Self::Vmcs(value)
    }
}

pub fn configure() -> Result<VmxControls, VmxControlsError> {
    let basic = unsafe { msr::read(msr::IA32_VMX_BASIC) };
    let use_true_controls = basic & IA32_VMX_BASIC_TRUE_CTLS != 0;

    let pin_msr = if use_true_controls {
        msr::IA32_VMX_TRUE_PINBASED_CTLS
    } else {
        msr::IA32_VMX_PINBASED_CTLS
    };
    let proc_msr = if use_true_controls {
        msr::IA32_VMX_TRUE_PROCBASED_CTLS
    } else {
        msr::IA32_VMX_PROCBASED_CTLS
    };
    let exit_msr = if use_true_controls {
        msr::IA32_VMX_TRUE_EXIT_CTLS
    } else {
        msr::IA32_VMX_EXIT_CTLS
    };
    let entry_msr = if use_true_controls {
        msr::IA32_VMX_TRUE_ENTRY_CTLS
    } else {
        msr::IA32_VMX_ENTRY_CTLS
    };

    let pin_based = adjust_control(PIN_BASED_NMI_EXITING, pin_msr);
    let primary_processor_based = adjust_control(0, proc_msr);
    let secondary_processor_based =
        if primary_processor_based & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS != 0 {
            adjust_control(0, msr::IA32_VMX_PROCBASED_CTLS2)
        } else {
            0
        };
    let vm_exit = adjust_control(VM_EXIT_HOST_ADDRESS_SPACE_SIZE, exit_msr);
    let vm_entry = adjust_control(VM_ENTRY_IA32E_MODE_GUEST, entry_msr);

    if vm_exit & VM_EXIT_HOST_ADDRESS_SPACE_SIZE == 0 {
        return Err(VmxControlsError::HostAddressSpaceSizeUnavailable);
    }
    if vm_entry & VM_ENTRY_IA32E_MODE_GUEST == 0 {
        return Err(VmxControlsError::Ia32eGuestModeUnavailable);
    }
    if secondary_processor_based & SECONDARY_ENABLE_EPT != 0 {
        return Err(VmxControlsError::EptUnexpectedlyRequired);
    }

    vmwrite(PIN_BASED_VM_EXEC_CONTROL, u64::from(pin_based))?;
    vmwrite(
        CPU_BASED_VM_EXEC_CONTROL,
        u64::from(primary_processor_based),
    )?;
    if primary_processor_based & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS != 0 {
        vmwrite(
            SECONDARY_VM_EXEC_CONTROL,
            u64::from(secondary_processor_based),
        )?;
    }
    vmwrite(VM_EXIT_CONTROLS, u64::from(vm_exit))?;
    vmwrite(VM_ENTRY_CONTROLS, u64::from(vm_entry))?;

    vmwrite(EXCEPTION_BITMAP, 1 << 6)?;
    vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0)?;
    vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0)?;
    vmwrite(CR3_TARGET_COUNT, 0)?;
    vmwrite(VM_EXIT_MSR_STORE_COUNT, 0)?;
    vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0)?;
    vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0)?;
    vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0)?;
    vmwrite(CR0_GUEST_HOST_MASK, 0)?;
    vmwrite(CR4_GUEST_HOST_MASK, 0)?;
    vmwrite(CR0_READ_SHADOW, 0)?;
    vmwrite(CR4_READ_SHADOW, 0)?;

    Ok(VmxControls {
        pin_based,
        primary_processor_based,
        secondary_processor_based,
        vm_exit,
        vm_entry,
    })
}

fn adjust_control(desired: u32, capability_msr: u32) -> u32 {
    let capabilities = unsafe { msr::read(capability_msr) };
    let must_be_one = capabilities as u32;
    let may_be_one = (capabilities >> 32) as u32;
    (desired | must_be_one) & may_be_one
}
