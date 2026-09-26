use core::arch::asm;

use crate::arch::x86_64::{msr, registers::CR4_VMXE};
use crate::nested::capabilities::IA32_VMX_MISC_MSR;

use super::vt_vmcs::{VmcsError, vmwrite};
use super::vt_vmcs_fields::*;

const IA32_VMX_BASIC_TRUE_CTLS: u64 = 1 << 55;
const PIN_BASED_NMI_EXITING: u32 = 1 << 3;
const PIN_BASED_VIRTUAL_NMIS: u32 = 1 << 5;
const PIN_BASED_VMX_PREEMPTION_TIMER: u32 = 1 << 6;
const CPU_BASED_USE_TSC_OFFSETTING: u32 = 1 << 3;
const CPU_BASED_USE_MSR_BITMAPS: u32 = 1 << 28;
const CPU_BASED_ACTIVATE_SECONDARY_CONTROLS: u32 = 1 << 31;
const SECONDARY_ENABLE_EPT: u32 = 1 << 1;
const SECONDARY_ENABLE_RDTSCP: u32 = 1 << 3;
const SECONDARY_ENABLE_VPID: u32 = 1 << 5;
const SECONDARY_UNRESTRICTED_GUEST: u32 = 1 << 7;
const SECONDARY_ENABLE_INVPCID: u32 = 1 << 12;
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
    InvpcidUnavailable,
    XsavesUnavailable,
    PatControlsUnavailable,
    EferControlsUnavailable,
    VpidInvalidationFailed,
    VirtualNmisUnavailable,
}

struct RequestedControls {
    pin_based: u32,
    primary_processor_based: u32,
    secondary_processor_based: u32,
    vm_exit: u32,
    vm_entry: u32,
    exception_bitmap: u64,
    msr_bitmap: Option<u64>,
    ept_pointer: Option<u64>,
}

impl From<VmcsError> for VmxControlsError {
    fn from(value: VmcsError) -> Self {
        Self::Vmcs(value)
    }
}

pub fn configure() -> Result<VmxControls, VmxControlsError> {
    configure_internal(RequestedControls {
        pin_based: PIN_BASED_NMI_EXITING,
        primary_processor_based: 0,
        secondary_processor_based: 0,
        vm_exit: 0,
        vm_entry: 0,
        exception_bitmap: 1 << 6,
        msr_bitmap: None,
        ept_pointer: None,
    })
}

pub fn configure_resident_boot(
    msr_bitmap: u64,
    ept_pointer: u64,
) -> Result<VmxControls, VmxControlsError> {
    let cpuid = crate::arch::x86_64::cpuid::leaf;
    let mut secondary = SECONDARY_ENABLE_EPT;
    if cpuid(0x8000_0001).edx & (1 << 27) != 0 {
        secondary |= SECONDARY_ENABLE_RDTSCP;
    }
    if cpuid(7).ebx & (1 << 10) != 0 {
        secondary |= SECONDARY_ENABLE_INVPCID;
    }
    if crate::arch::x86_64::cpuid::leaf_with_subleaf(0xd, 1).eax & (1 << 3) != 0 {
        secondary |= SECONDARY_ENABLE_XSAVES;
    }
    let controls = configure_internal(RequestedControls {
        pin_based: PIN_BASED_NMI_EXITING | PIN_BASED_VIRTUAL_NMIS,
        primary_processor_based: CPU_BASED_USE_TSC_OFFSETTING
            | CPU_BASED_USE_MSR_BITMAPS
            | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
        secondary_processor_based: secondary,
        vm_exit: VM_EXIT_SAVE_IA32_PAT
            | VM_EXIT_LOAD_IA32_PAT
            | VM_EXIT_SAVE_IA32_EFER
            | VM_EXIT_LOAD_IA32_EFER,
        vm_entry: VM_ENTRY_LOAD_IA32_PAT | VM_ENTRY_LOAD_IA32_EFER,
        exception_bitmap: 1 << 6,
        msr_bitmap: Some(msr_bitmap),
        ept_pointer: Some(ept_pointer),
    })?;
    vmwrite(CR0_GUEST_HOST_MASK, (1 << 30) | (1 << 29))?;
    vmwrite(
        CR0_READ_SHADOW,
        crate::arch::x86_64::control_regs::read_cr0(),
    )?;
    Ok(controls)
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

pub(crate) fn resident_boot_timer_parameters() -> (u64, u64) {
    if !crate::runtime::logger::enabled() {
        return (0, 0);
    }
    let basic = unsafe { msr::read(msr::IA32_VMX_BASIC) };
    let pin_msr = if basic & IA32_VMX_BASIC_TRUE_CTLS != 0 {
        msr::IA32_VMX_TRUE_PINBASED_CTLS
    } else {
        msr::IA32_VMX_PINBASED_CTLS
    };
    let capability = unsafe { msr::read(pin_msr) };
    if capability >> 32 & u64::from(PIN_BASED_VMX_PREEMPTION_TIMER) == 0 {
        return (0, 0);
    }
    let timer_rate = unsafe { msr::read(IA32_VMX_MISC_MSR) } & 31;
    let start_tsc = unsafe { core::arch::x86_64::_rdtsc() };
    uefi::boot::stall(core::time::Duration::from_millis(10));
    let interval_tsc = unsafe { core::arch::x86_64::_rdtsc() }
        .wrapping_sub(start_tsc)
        .saturating_mul(100)
        .max(1);
    (interval_tsc, timer_rate)
}

pub(crate) fn enable_resident_boot_timer(
    controls: &mut VmxControls,
    interval_tsc: u64,
    timer_rate: u64,
) -> Result<(), VmxControlsError> {
    if interval_tsc == 0 {
        return Ok(());
    }
    // Avoid timer values 0 and 1, including the value-1 erratum on recent Intel CPUs.
    let timer_ticks = (interval_tsc >> timer_rate).clamp(2, u64::from(u32::MAX));
    vmwrite(VMX_PREEMPTION_TIMER_VALUE, timer_ticks)?;
    controls.pin_based |= PIN_BASED_VMX_PREEMPTION_TIMER;
    vmwrite(PIN_BASED_VM_EXEC_CONTROL, u64::from(controls.pin_based))?;
    Ok(())
}

pub(crate) fn virtualize_resident_cr4_vmxe(guest_cr4: u64) -> Result<(), VmxControlsError> {
    vmwrite(CR4_GUEST_HOST_MASK, CR4_VMXE)?;
    vmwrite(CR4_READ_SHADOW, guest_cr4)?;
    Ok(())
}

pub(crate) fn enable_resident_vpid(
    controls: &mut VmxControls,
    virtual_processor_id: u16,
) -> Result<(), VmxControlsError> {
    let secondary = unsafe { msr::read(msr::IA32_VMX_PROCBASED_CTLS2) };
    let invalidation = unsafe { msr::read(msr::IA32_VMX_EPT_VPID_CAP) };
    let required = (1_u64 << 32) | (1_u64 << 41);
    if secondary & (u64::from(SECONDARY_ENABLE_VPID) << 32) == 0
        || invalidation & required != required
    {
        return Ok(());
    }

    // Retire translations from an earlier VMX session before reusing this tag.
    let descriptor = [u64::from(virtual_processor_id), 0];
    let failed: u8;
    unsafe {
        asm!(
            "invvpid {kind}, xmmword ptr [{descriptor}]",
            "setna {failed}",
            kind = in(reg) 1_u64,
            descriptor = in(reg) descriptor.as_ptr(),
            failed = lateout(reg_byte) failed,
            options(nostack),
        );
    }
    if failed != 0 {
        return Err(VmxControlsError::VpidInvalidationFailed);
    }
    vmwrite(VIRTUAL_PROCESSOR_ID, u64::from(virtual_processor_id))?;
    controls.secondary_processor_based |= SECONDARY_ENABLE_VPID;
    vmwrite(
        SECONDARY_VM_EXEC_CONTROL,
        u64::from(controls.secondary_processor_based),
    )?;
    Ok(())
}

fn configure_internal(requested: RequestedControls) -> Result<VmxControls, VmxControlsError> {
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

    let pin_based = adjust_control(requested.pin_based, pin_msr);
    if requested.pin_based & PIN_BASED_VIRTUAL_NMIS != 0
        && (pin_based & (PIN_BASED_NMI_EXITING | PIN_BASED_VIRTUAL_NMIS)
            != (PIN_BASED_NMI_EXITING | PIN_BASED_VIRTUAL_NMIS)
            || unsafe { msr::read(proc_msr) } & (1_u64 << (32 + 22)) == 0)
    {
        return Err(VmxControlsError::VirtualNmisUnavailable);
    }
    let primary_processor_based = adjust_control(requested.primary_processor_based, proc_msr);
    let secondary_processor_based =
        if primary_processor_based & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS != 0 {
            adjust_control(
                requested.secondary_processor_based,
                msr::IA32_VMX_PROCBASED_CTLS2,
            )
        } else {
            0
        };
    let vm_exit = adjust_control(
        VM_EXIT_HOST_ADDRESS_SPACE_SIZE | requested.vm_exit,
        exit_msr,
    );
    let vm_entry = adjust_control(VM_ENTRY_IA32E_MODE_GUEST | requested.vm_entry, entry_msr);

    if vm_exit & VM_EXIT_HOST_ADDRESS_SPACE_SIZE == 0 {
        return Err(VmxControlsError::HostAddressSpaceSizeUnavailable);
    }
    if vm_entry & VM_ENTRY_IA32E_MODE_GUEST == 0 {
        return Err(VmxControlsError::Ia32eGuestModeUnavailable);
    }
    if requested.secondary_processor_based & SECONDARY_ENABLE_EPT != 0
        && secondary_processor_based & SECONDARY_ENABLE_EPT == 0
    {
        return Err(VmxControlsError::EptUnavailable);
    }
    if secondary_processor_based & SECONDARY_ENABLE_EPT != 0 && requested.ept_pointer.is_none() {
        return Err(VmxControlsError::EptUnexpectedlyRequired);
    }
    if requested.secondary_processor_based & SECONDARY_ENABLE_RDTSCP != 0
        && secondary_processor_based & SECONDARY_ENABLE_RDTSCP == 0
    {
        return Err(VmxControlsError::RdtscpUnavailable);
    }
    if requested.primary_processor_based & CPU_BASED_USE_MSR_BITMAPS != 0
        && primary_processor_based & CPU_BASED_USE_MSR_BITMAPS == 0
    {
        return Err(VmxControlsError::MsrBitmapsUnavailable);
    }
    if requested.primary_processor_based & CPU_BASED_USE_TSC_OFFSETTING != 0
        && primary_processor_based & CPU_BASED_USE_TSC_OFFSETTING == 0
    {
        return Err(VmxControlsError::TscOffsettingUnavailable);
    }
    if requested.secondary_processor_based & SECONDARY_ENABLE_INVPCID != 0
        && secondary_processor_based & SECONDARY_ENABLE_INVPCID == 0
    {
        return Err(VmxControlsError::InvpcidUnavailable);
    }
    if requested.secondary_processor_based & SECONDARY_ENABLE_XSAVES != 0
        && secondary_processor_based & SECONDARY_ENABLE_XSAVES == 0
    {
        return Err(VmxControlsError::XsavesUnavailable);
    }
    let desired_pat_exit = requested.vm_exit & (VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT);
    let desired_pat_entry = requested.vm_entry & VM_ENTRY_LOAD_IA32_PAT;
    if vm_exit & desired_pat_exit != desired_pat_exit
        || vm_entry & desired_pat_entry != desired_pat_entry
    {
        return Err(VmxControlsError::PatControlsUnavailable);
    }
    let desired_efer_exit = requested.vm_exit & (VM_EXIT_SAVE_IA32_EFER | VM_EXIT_LOAD_IA32_EFER);
    let desired_efer_entry = requested.vm_entry & VM_ENTRY_LOAD_IA32_EFER;
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

    if let Some(bitmap) = requested.msr_bitmap {
        vmwrite(MSR_BITMAP, bitmap)?;
    }
    if secondary_processor_based & SECONDARY_ENABLE_EPT != 0 {
        vmwrite(
            EPT_POINTER,
            requested
                .ept_pointer
                .ok_or(VmxControlsError::EptUnexpectedlyRequired)?,
        )?;
    }
    vmwrite(EXCEPTION_BITMAP, requested.exception_bitmap)?;
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
