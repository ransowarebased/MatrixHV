use core::arch::asm;
use core::arch::x86_64::{__cpuid, __cpuid_count};

// Control registers
pub const CR4_VMXE: u64 = 1 << 13;
pub const CR4_LA57: u64 = 1 << 12;

#[inline]
pub fn read_cr0() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, cr0", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

#[inline]
pub fn read_cr3() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

#[inline]
pub unsafe fn write_cr3(value: u64) {
    unsafe {
        asm!("mov cr3, {}", in(reg) value, options(nostack, preserves_flags));
    }
}

#[inline]
pub unsafe fn write_cr0(value: u64) {
    unsafe {
        asm!("mov cr0, {}", in(reg) value, options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn read_cr4() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

#[inline]
pub unsafe fn write_cr4(value: u64) {
    unsafe {
        asm!("mov cr4, {}", in(reg) value, options(nomem, nostack, preserves_flags));
    }
}

// Flags and debug registers
#[inline]
pub fn read_rflags() -> u64 {
    let value: u64;
    unsafe {
        asm!("pushfq", "pop {}", out(reg) value, options(nomem));
    }
    value
}

#[inline]
pub fn read_dr7() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, dr7", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

// MSRs
pub const IA32_FEATURE_CONTROL: u32 = 0x3a;
pub const IA32_DEBUGCTL: u32 = 0x1d9;
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
pub const IA32_PAT: u32 = 0x277;
pub const IA32_EFER: u32 = 0xc000_0080;
pub const IA32_FS_BASE: u32 = 0xc000_0100;
pub const IA32_GS_BASE: u32 = 0xc000_0101;

#[inline]
pub unsafe fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

#[inline]
pub unsafe fn write_msr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
}

// CPUID
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuIdLeaf {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

#[inline]
pub fn leaf(function: u32) -> CpuIdLeaf {
    let result = __cpuid(function);
    CpuIdLeaf {
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}

#[inline]
pub fn leaf_with_subleaf(function: u32, subleaf: u32) -> CpuIdLeaf {
    let result = __cpuid_count(function, subleaf);
    CpuIdLeaf {
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}

// CPU Vendor & Capabilities
const CPUID_FEATURE_INFORMATION: u32 = 1;
const CPUID_VMX_BIT: u32 = 1 << 5;
const FEATURE_CONTROL_LOCK: u64 = 1 << 0;
const FEATURE_CONTROL_VMX_OUTSIDE_SMX: u64 = 1 << 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Vendor {
    Intel,
    Other([u8; 12]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub vendor: Vendor,
    pub vmx: bool,
    pub feature_control_locked: bool,
    pub vmx_outside_smx: bool,
}

pub fn capabilities() -> Capabilities {
    let basic = leaf(0);
    let mut vendor = [0_u8; 12];
    vendor[0..4].copy_from_slice(&basic.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&basic.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&basic.ecx.to_le_bytes());

    let vendor = if &vendor == b"GenuineIntel" {
        Vendor::Intel
    } else {
        Vendor::Other(vendor)
    };

    let features = leaf(CPUID_FEATURE_INFORMATION);
    let vmx = features.ecx & CPUID_VMX_BIT != 0;
    let feature_control = if matches!(vendor, Vendor::Intel) && vmx {
        unsafe { read_msr(IA32_FEATURE_CONTROL) }
    } else {
        0
    };

    Capabilities {
        vendor,
        vmx,
        feature_control_locked: feature_control & FEATURE_CONTROL_LOCK != 0,
        vmx_outside_smx: feature_control & FEATURE_CONTROL_VMX_OUTSIDE_SMX != 0,
    }
}
