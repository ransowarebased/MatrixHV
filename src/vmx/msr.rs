use super::vmcs::*;
use crate::arch;
use crate::memory::host::{AddressConstraint, ResidentPages};
use core::mem::size_of;
use uefi::Status;

const MSR_BITMAP_PAGES: usize = 1;
const MSR_BITMAP_READ_HIGH_OFFSET: usize = 1024;
pub(crate) const MSR_BITMAP_WRITE_LOW_OFFSET: usize = 2048;
const MSR_BITMAP_WRITE_HIGH_OFFSET: usize = 3072;
pub(crate) const IA32_TSC_MSR: u32 = 0x10;
const IA32_TSC_ADJUST_MSR: u32 = 0x3b;
pub(crate) const IA32_PLATFORM_ID_MSR: u32 = 0x17;
pub(crate) const IA32_APIC_BASE_MSR: u32 = 0x1b;
pub(crate) const IA32_FEATURE_CONTROL_MSR: u32 = 0x3a;
pub(crate) const IA32_SPEC_CTRL_MSR: u32 = 0x48;
const IA32_PRED_CMD_MSR: u32 = 0x49;
pub(crate) const IA32_BIOS_SIGN_ID_MSR: u32 = 0x8b;
pub(crate) const IA32_MTRRCAP_MSR: u32 = 0xfe;
const IA32_ARCH_CAPABILITIES_MSR: u32 = 0x10a;
const IA32_MCG_CAP_MSR: u32 = 0x179;
const IA32_MCG_STATUS_MSR: u32 = 0x17a;
const IA32_MCG_CTL_MSR: u32 = 0x17b;
pub(crate) const IA32_SYSENTER_CS_MSR: u32 = 0x174;
pub(crate) const IA32_SYSENTER_ESP_MSR: u32 = 0x175;
pub(crate) const IA32_SYSENTER_EIP_MSR: u32 = 0x176;
const IA32_MISC_ENABLE_MSR: u32 = 0x1a0;
pub(crate) const IA32_MTRR_PHYSBASE0_MSR: u32 = 0x200;
pub(crate) const IA32_MTRR_FIX64K_00000_MSR: u32 = 0x250;
pub(crate) const IA32_MTRR_FIX16K_80000_MSR: u32 = 0x258;
pub(crate) const IA32_MTRR_FIX16K_A0000_MSR: u32 = 0x259;
pub(crate) const IA32_MTRR_FIX4K_C0000_MSR: u32 = 0x268;
pub(crate) const IA32_MTRR_FIX4K_F8000_MSR: u32 = 0x26f;
const IA32_MC0_CTL2_MSR: u32 = 0x280;
pub(crate) const IA32_MTRR_DEF_TYPE_MSR: u32 = 0x2ff;
const IA32_MC0_CTL_MSR: u32 = 0x400;
const IA32_MC0_STATUS_MSR: u32 = 0x401;
pub(crate) const IA32_X2APIC_MSR_BASE: u32 = 0x800;
pub(crate) const IA32_X2APIC_MSR_END: u32 = 0x8ff;
pub(crate) const MSR_PKG_ENERGY_STATUS: u32 = 0x611;
pub(crate) const MSR_RAPL_POWER_UNIT: u32 = 0x606;
pub(crate) const MSR_DRAM_ENERGY_STATUS: u32 = 0x619;
pub(crate) const MSR_PP0_ENERGY_STATUS: u32 = 0x639;
pub(crate) const MSR_PP1_ENERGY_STATUS: u32 = 0x641;
const IA32_TSC_DEADLINE_MSR: u32 = 0x6e0;
pub(crate) const IA32_HWP_REQUEST_MSR: u32 = 0x774;
pub(crate) const IA32_XSS_MSR: u32 = 0xda0;
pub(crate) const AMD_SEV_STATUS_MSR: u32 = 0xc001_0131;
const MACHINE_CHECK_BANK_MSR_STRIDE: u32 = 4;
pub(crate) const IA32_EFER_MSR: u32 = 0xc000_0080;
pub(crate) const IA32_STAR_MSR: u32 = 0xc000_0081;
pub(crate) const IA32_LSTAR_MSR: u32 = 0xc000_0082;
pub(crate) const IA32_CSTAR_MSR: u32 = 0xc000_0083;
pub(crate) const IA32_FMASK_MSR: u32 = 0xc000_0084;
pub(crate) const IA32_FS_BASE_MSR: u32 = 0xc000_0100;
pub(crate) const IA32_GS_BASE_MSR: u32 = 0xc000_0101;
pub(crate) const IA32_KERNEL_GS_BASE_MSR: u32 = 0xc000_0102;
pub(crate) const IA32_TSC_AUX_MSR: u32 = 0xc000_0103;
pub(crate) const RESIDENT_MSR_SWITCH_CAPACITY: usize = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VmxMsrEntry {
    index: u32,
    reserved: u32,
    value: u64,
}
fn allow_low_msr_passthrough(bitmap: &mut [u8], index: u32) {
    assert!(index <= 0x1fff);
    let byte_index = (index >> 3) as usize;
    let bit_mask = !(1_u8 << (index & 7));
    bitmap[byte_index] &= bit_mask;
    bitmap[MSR_BITMAP_WRITE_LOW_OFFSET + byte_index] &= bit_mask;
}

fn allow_low_msr_read_passthrough(bitmap: &mut [u8], index: u32) {
    assert!(index <= 0x1fff);
    let byte_index = (index >> 3) as usize;
    let bit_mask = !(1_u8 << (index & 7));
    bitmap[byte_index] &= bit_mask;
}

fn allow_low_msr_write_passthrough(bitmap: &mut [u8], index: u32) {
    assert!(index <= 0x1fff);
    let byte_index = (index >> 3) as usize;
    let bit_mask = !(1_u8 << (index & 7));
    bitmap[MSR_BITMAP_WRITE_LOW_OFFSET + byte_index] &= bit_mask;
}

fn allow_high_msr_passthrough(bitmap: &mut [u8], index: u32) {
    assert!((0xc000_0000..=0xc000_1fff).contains(&index));
    let relative_index = index - 0xc000_0000;
    let byte_index = (relative_index >> 3) as usize;
    let bit_mask = !(1_u8 << (relative_index & 7));
    bitmap[MSR_BITMAP_READ_HIGH_OFFSET + byte_index] &= bit_mask;
    bitmap[MSR_BITMAP_WRITE_HIGH_OFFSET + byte_index] &= bit_mask;
}

fn allow_native_msr_reads(bitmap: &mut [u8]) {
    // Unmodified reads already reach guarded RDMSR in the resident handler.
    // Avoid that round trip; L1's read intercepts are still ORed into VMCS02.
    // Feature control, VMX capabilities and EFER retain the virtualized view.
    bitmap[..MSR_BITMAP_WRITE_LOW_OFFSET].fill(0);
    bitmap[(IA32_FEATURE_CONTROL_MSR >> 3) as usize] |= 1 << (IA32_FEATURE_CONTROL_MSR & 7);
    bitmap[0x480 / 8..0x4a0 / 8].fill(0xff);
    let efer_byte = MSR_BITMAP_READ_HIGH_OFFSET + ((IA32_EFER_MSR & 0x1fff) >> 3) as usize;
    bitmap[efer_byte] |= 1 << (IA32_EFER_MSR & 7);
}

fn spec_ctrl_available(leaf7_edx: u32) -> bool {
    leaf7_edx & ((1 << 26) | (1 << 27) | (1 << 31)) != 0
}

pub(crate) fn resident_msr_switch_count() -> u64 {
    let cpuid = crate::arch::leaf;
    u64::from(cpuid(0).eax >= 7 && spec_ctrl_available(cpuid(7).edx))
}

pub(crate) fn configure_resident_msr_switch(msr_state: &ResidentPages) -> Result<(), VmcsError> {
    let entries = msr_state.pointer().as_ptr().cast::<VmxMsrEntry>();
    // The resident assembly never executes SYSCALL, SWAPGS, or RDTSCP. Preserve
    // those MSRs naturally across exits; only root speculation policy needs a switch.
    let count = resident_msr_switch_count();
    if count != 0 {
        let entry = VmxMsrEntry {
            index: IA32_SPEC_CTRL_MSR,
            reserved: 0,
            value: unsafe { arch::read_msr(IA32_SPEC_CTRL_MSR) },
        };
        unsafe {
            entries.write(entry);
            entries.add(RESIDENT_MSR_SWITCH_CAPACITY).write(entry);
        }
    }
    let guest_entry = msr_state.physical_address();
    let host_entry = guest_entry + (RESIDENT_MSR_SWITCH_CAPACITY * size_of::<VmxMsrEntry>()) as u64;
    vmwrite(VM_EXIT_MSR_STORE_ADDR, guest_entry)?;
    vmwrite(VM_EXIT_MSR_LOAD_ADDR, host_entry)?;
    vmwrite(VM_ENTRY_MSR_LOAD_ADDR, guest_entry)?;
    vmwrite(VM_EXIT_MSR_STORE_COUNT, count)?;
    vmwrite(VM_EXIT_MSR_LOAD_COUNT, count)?;
    vmwrite(VM_ENTRY_MSR_LOAD_COUNT, count)?;
    Ok(())
}

pub(crate) fn allocate_bitmap() -> Result<ResidentPages, Status> {
    let machine_check_bank_count = unsafe { arch::read_msr(IA32_MCG_CAP_MSR) } as u32 & 0xff;
    let msr_bitmap =
        ResidentPages::allocate_initialized(MSR_BITMAP_PAGES, AddressConstraint::Any, |bitmap| {
            bitmap.fill(0xff);
            allow_native_msr_reads(bitmap);
            allow_low_msr_passthrough(bitmap, IA32_ARCH_CAPABILITIES_MSR);
            allow_low_msr_passthrough(bitmap, IA32_SPEC_CTRL_MSR);
            allow_low_msr_write_passthrough(bitmap, IA32_PRED_CMD_MSR);
            // HWP requests already pass unchanged to the physical processor in the handler.
            allow_low_msr_write_passthrough(bitmap, IA32_HWP_REQUEST_MSR);
            allow_low_msr_read_passthrough(bitmap, IA32_MCG_CAP_MSR);
            allow_low_msr_passthrough(bitmap, IA32_MCG_STATUS_MSR);
            allow_low_msr_passthrough(bitmap, IA32_MCG_CTL_MSR);
            // VMCS guest state saves and restores SYSENTER MSRs. Intercepting them
            // here would reflect exits that L1's MSR bitmap explicitly disabled.
            allow_low_msr_passthrough(bitmap, IA32_SYSENTER_CS_MSR);
            allow_low_msr_passthrough(bitmap, IA32_SYSENTER_ESP_MSR);
            allow_low_msr_passthrough(bitmap, IA32_SYSENTER_EIP_MSR);
            // Resident CPUs own their physical APIC. Keep TSC synchronization and its
            // deadline timer in the same clock domain; L1 bitmap intercepts still apply to L2.
            for index in [IA32_TSC_MSR, IA32_TSC_ADJUST_MSR, IA32_TSC_DEADLINE_MSR] {
                allow_low_msr_passthrough(bitmap, index);
            }
            // L1 owns the local APIC; trapping its accesses only repeats the same MSR
            // instruction in root mode. VMCS02 still includes every L1 bitmap intercept.
            for index in IA32_X2APIC_MSR_BASE..=IA32_X2APIC_MSR_END {
                allow_low_msr_passthrough(bitmap, index);
            }
            allow_low_msr_passthrough(bitmap, IA32_XSS_MSR);
            for bank in 0..machine_check_bank_count {
                allow_low_msr_passthrough(bitmap, IA32_MC0_CTL2_MSR + bank);
                allow_low_msr_passthrough(
                    bitmap,
                    IA32_MC0_CTL_MSR + bank * MACHINE_CHECK_BANK_MSR_STRIDE,
                );
                allow_low_msr_passthrough(
                    bitmap,
                    IA32_MC0_STATUS_MSR + bank * MACHINE_CHECK_BANK_MSR_STRIDE,
                );
            }
            allow_low_msr_passthrough(bitmap, IA32_MISC_ENABLE_MSR);
            allow_low_msr_passthrough(bitmap, arch::IA32_PAT);
            allow_high_msr_passthrough(bitmap, IA32_STAR_MSR);
            allow_high_msr_passthrough(bitmap, IA32_LSTAR_MSR);
            allow_high_msr_passthrough(bitmap, IA32_CSTAR_MSR);
            allow_high_msr_passthrough(bitmap, IA32_FMASK_MSR);
            // VM exits save FS/GS bases and VM entries restore them from the guest state.
            // Let hardware update those fields without introducing an L1-unrequested exit.
            allow_high_msr_passthrough(bitmap, IA32_FS_BASE_MSR);
            allow_high_msr_passthrough(bitmap, IA32_GS_BASE_MSR);
            allow_high_msr_passthrough(bitmap, IA32_KERNEL_GS_BASE_MSR);
            allow_high_msr_passthrough(bitmap, IA32_TSC_AUX_MSR);
        })?;
    Ok(msr_bitmap)
}
