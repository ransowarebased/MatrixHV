use crate::arch::x86_64::msr;

use super::vt_vmcs::{VmcsError, vmwrite};
use super::vt_vmcs_fields::*;

const IA32_VMX_BASIC_TRUE_CTLS: u64 = 1 << 55;
const PIN_BASED_NMI_EXITING: u32 = 1 << 3;
const CPU_BASED_USE_TSC_OFFSETTING: u32 = 1 << 3;
const CPU_BASED_USE_MSR_BITMAPS: u32 = 1 << 28;
const CPU_BASED_ACTIVATE_SECONDARY_CONTROLS: u32 = 1 << 31;
const SECONDARY_ENABLE_EPT: u32 = 1 << 1;
const SECONDARY_ENABLE_RDTSCP: u32 = 1 << 3;
const SECONDARY_UNRESTRICTED_GUEST: u32 = 1 << 7;
const SECONDARY_ENABLE_XSAVES: u32 = 1 << 20;
const VM_EXIT_HOST_ADDRESS_SPACE_SIZE: u32 = 1 << 9;
const VM_EXIT_SAVE_IA32_PAT: u32 = 1 << 18;
const VM_EXIT_LOAD_IA32_PAT: u32 = 1 << 19;
const VM_EXIT_SAVE_IA32_EFER: u32 = 1 << 20;
const VM_EXIT_LOAD_IA32_EFER: u32 = 1 << 21;
const VM_ENTRY_IA32E_MODE_GUEST: u32 = 1 << 9;
const VM_ENTRY_LOAD_IA32_PAT: u32 = 1 << 14;
const VM_ENTRY_LOAD_IA32_EFER: u32 = 1 << 15;

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
    EptUnavailable,
    UnrestrictedGuestUnavailable,
    EptUnexpectedlyRequired,
    MsrBitmapsUnavailable,
    TscOffsettingUnavailable,
    RdtscpUnavailable,
    XsavesUnavailable,
    PatControlsUnavailable,
    EferControlsUnavailable,
}

impl From<VmcsError> for VmxControlsError {
    fn from(value: VmcsError) -> Self {
        Self::Vmcs(value)
    }
}

pub fn configure() -> Result<VmxControls, VmxControlsError> {
    configure_internal(PIN_BASED_NMI_EXITING, 0, 0, 0, 0, 1 << 6, None, None)
}

pub fn configure_resident_boot(
    msr_bitmap: u64,
    ept_pointer: u64,
) -> Result<VmxControls, VmxControlsError> {
    configure_internal(
        0,
        CPU_BASED_USE_TSC_OFFSETTING
            | CPU_BASED_USE_MSR_BITMAPS
            | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
        SECONDARY_ENABLE_EPT | SECONDARY_ENABLE_RDTSCP | SECONDARY_ENABLE_XSAVES,
        VM_EXIT_SAVE_IA32_PAT
            | VM_EXIT_LOAD_IA32_PAT
            | VM_EXIT_SAVE_IA32_EFER
            | VM_EXIT_LOAD_IA32_EFER,
        VM_ENTRY_LOAD_IA32_PAT | VM_ENTRY_LOAD_IA32_EFER,
        0,
        Some(msr_bitmap),
        Some(ept_pointer),
    )
}

pub(crate) fn configure_resident_ap(
    msr_bitmap: u64,
    ept_pointer: u64,
) -> Result<VmxControls, VmxControlsError> {
    let mut controls = configure_resident_boot(msr_bitmap, ept_pointer)?;
    controls.secondary_processor_based = adjust_control(
        controls.secondary_processor_based | SECONDARY_UNRESTRICTED_GUEST,
        msr::IA32_VMX_PROCBASED_CTLS2,
    );
    if controls.secondary_processor_based & SECONDARY_UNRESTRICTED_GUEST == 0 {
        return Err(VmxControlsError::UnrestrictedGuestUnavailable);
    }
    vmwrite(
        SECONDARY_VM_EXEC_CONTROL,
        u64::from(controls.secondary_processor_based),
    )?;
    Ok(controls)
}

fn configure_internal(
    desired_pin: u32,
    desired_primary: u32,
    desired_secondary: u32,
    desired_exit: u32,
    desired_entry: u32,
    exception_bitmap: u64,
    msr_bitmap: Option<u64>,
    ept_pointer: Option<u64>,
) -> Result<VmxControls, VmxControlsError> {
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

    let pin_based = adjust_control(desired_pin, pin_msr);
    let primary_processor_based = adjust_control(desired_primary, proc_msr);
    let secondary_processor_based =
        if primary_processor_based & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS != 0 {
            adjust_control(desired_secondary, msr::IA32_VMX_PROCBASED_CTLS2)
        } else {
            0
        };
    let vm_exit = adjust_control(VM_EXIT_HOST_ADDRESS_SPACE_SIZE | desired_exit, exit_msr);
    let vm_entry = adjust_control(VM_ENTRY_IA32E_MODE_GUEST | desired_entry, entry_msr);

    if vm_exit & VM_EXIT_HOST_ADDRESS_SPACE_SIZE == 0 {
        return Err(VmxControlsError::HostAddressSpaceSizeUnavailable);
    }
    if vm_entry & VM_ENTRY_IA32E_MODE_GUEST == 0 {
        return Err(VmxControlsError::Ia32eGuestModeUnavailable);
    }
    if desired_secondary & SECONDARY_ENABLE_EPT != 0
        && secondary_processor_based & SECONDARY_ENABLE_EPT == 0
    {
        return Err(VmxControlsError::EptUnavailable);
    }
    if secondary_processor_based & SECONDARY_ENABLE_EPT != 0 && ept_pointer.is_none() {
        return Err(VmxControlsError::EptUnexpectedlyRequired);
    }
    if desired_secondary & SECONDARY_ENABLE_RDTSCP != 0
        && secondary_processor_based & SECONDARY_ENABLE_RDTSCP == 0
    {
        return Err(VmxControlsError::RdtscpUnavailable);
    }
    if desired_primary & CPU_BASED_USE_MSR_BITMAPS != 0
        && primary_processor_based & CPU_BASED_USE_MSR_BITMAPS == 0
    {
        return Err(VmxControlsError::MsrBitmapsUnavailable);
    }
    if desired_primary & CPU_BASED_USE_TSC_OFFSETTING != 0
        && primary_processor_based & CPU_BASED_USE_TSC_OFFSETTING == 0
    {
        return Err(VmxControlsError::TscOffsettingUnavailable);
    }
    if desired_secondary & SECONDARY_ENABLE_XSAVES != 0
        && secondary_processor_based & SECONDARY_ENABLE_XSAVES == 0
    {
        return Err(VmxControlsError::XsavesUnavailable);
    }
    let desired_pat_exit = desired_exit & (VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT);
    let desired_pat_entry = desired_entry & VM_ENTRY_LOAD_IA32_PAT;
    if vm_exit & desired_pat_exit != desired_pat_exit
        || vm_entry & desired_pat_entry != desired_pat_entry
    {
        return Err(VmxControlsError::PatControlsUnavailable);
    }
    let desired_efer_exit = desired_exit & (VM_EXIT_SAVE_IA32_EFER | VM_EXIT_LOAD_IA32_EFER);
    let desired_efer_entry = desired_entry & VM_ENTRY_LOAD_IA32_EFER;
    if vm_exit & desired_efer_exit != desired_efer_exit
        || vm_entry & desired_efer_entry != desired_efer_entry
    {
        return Err(VmxControlsError::EferControlsUnavailable);
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

    if let Some(bitmap) = msr_bitmap {
        vmwrite(MSR_BITMAP, bitmap)?;
    }
    if secondary_processor_based & SECONDARY_ENABLE_EPT != 0 {
        vmwrite(EPT_POINTER, ept_pointer.unwrap())?;
    }
    vmwrite(EXCEPTION_BITMAP, exception_bitmap)?;
    vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0)?;
    vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0)?;
    vmwrite(CR3_TARGET_COUNT, 0)?;
    vmwrite(VM_EXIT_MSR_STORE_COUNT, 0)?;
    vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0)?;
    vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0)?;
    vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0)?;
    if secondary_processor_based & SECONDARY_ENABLE_XSAVES != 0 {
        vmwrite(XSS_EXITING_BITMAP, 0)?;
    }
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
