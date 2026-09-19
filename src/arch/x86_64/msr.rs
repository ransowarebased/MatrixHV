use core::arch::asm;

pub const IA32_FEATURE_CONTROL: u32 = 0x3a;
pub const IA32_DEBUGCTL: u32 = 0x1d9;
pub const IA32_PAT: u32 = 0x277;
pub const IA32_SYSENTER_CS: u32 = 0x174;
pub const IA32_SYSENTER_ESP: u32 = 0x175;
pub const IA32_SYSENTER_EIP: u32 = 0x176;
pub const IA32_VMX_BASIC: u32 = 0x480;
pub const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
pub const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
pub const IA32_VMX_EXIT_CTLS: u32 = 0x483;
pub const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
pub const IA32_VMX_CR0_FIXED0: u32 = 0x486;
pub const IA32_VMX_CR0_FIXED1: u32 = 0x487;
pub const IA32_VMX_CR4_FIXED0: u32 = 0x488;
pub const IA32_VMX_CR4_FIXED1: u32 = 0x489;
pub const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48b;
pub const IA32_VMX_EPT_VPID_CAP: u32 = 0x48c;
pub const IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x48d;
pub const IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x48e;
pub const IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x48f;
pub const IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x490;
pub const IA32_FS_BASE: u32 = 0xc000_0100;
pub const IA32_GS_BASE: u32 = 0xc000_0101;
pub const IA32_EFER: u32 = 0xc000_0080;

#[inline]
pub unsafe fn read(index: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") index,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

#[inline]
pub unsafe fn write(index: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") index,
            in("eax") low,
            in("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
}
