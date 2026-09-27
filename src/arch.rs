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

// This module runs in the hypervisor's CPL0 environment. Restrict safe reads
// to architectural state with baseline x86-64 support or a checked CPUID bit.
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum ArchitecturalMsr {
    Pat = IA32_PAT,
    Efer = IA32_EFER,
    FsBase = IA32_FS_BASE,
    GsBase = IA32_GS_BASE,
    SysenterCs = IA32_SYSENTER_CS,
    SysenterEsp = IA32_SYSENTER_ESP,
    SysenterEip = IA32_SYSENTER_EIP,
}

impl ArchitecturalMsr {
    pub fn read(self) -> u64 {
        let required_feature = match self {
            Self::Pat => 1 << 16,
            Self::SysenterCs | Self::SysenterEsp | Self::SysenterEip => 1 << 11,
            Self::Efer | Self::FsBase | Self::GsBase => 0,
        };
        if required_feature != 0 {
            assert!(
                leaf(1).edx & required_feature != 0,
                "architectural MSR is not supported by this processor"
            );
        }
        // All enum values name read-only accesses to supported architectural state.
        unsafe { read_msr(self as u32) }
    }
}

/// # Safety
/// The caller must run at CPL0 and verify that this MSR is implemented and
/// readable on the current processor, including model-specific side effects.
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

pub fn apic_id() -> u32 {
    if leaf(0).eax >= 0xb {
        let topology = leaf_with_subleaf(0xb, 0);
        if topology.ebx != 0 {
            return topology.edx;
        }
    }
    leaf(1).ebx >> 24
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

const SYNTHETIC_TR_SELECTOR: u16 = 0x40;
const SYNTHETIC_TR_LIMIT: u32 = 0x67;
const SYNTHETIC_TR_ACCESS_RIGHTS: u32 = 0x008b;

#[repr(C, align(16))]
struct SyntheticTss {
    bytes: [u8; 104],
}

static SYNTHETIC_TSS: SyntheticTss = SyntheticTss { bytes: [0; 104] };

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DescriptorTablePointer {
    pub limit: u16,
    pub base: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SegmentState {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub access_rights: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SegmentationState {
    pub es: SegmentState,
    pub cs: SegmentState,
    pub ss: SegmentState,
    pub ds: SegmentState,
    pub fs: SegmentState,
    pub gs: SegmentState,
    pub ldtr: SegmentState,
    pub tr: SegmentState,
    pub gdtr: DescriptorTablePointer,
    pub idtr: DescriptorTablePointer,
}

pub fn capture() -> SegmentationState {
    let gdtr = read_gdtr();
    let idtr = read_idtr();
    let mut state = SegmentationState {
        es: segment_from_gdt(read_es(), gdtr),
        cs: segment_from_gdt(read_cs(), gdtr),
        ss: segment_from_gdt(read_ss(), gdtr),
        ds: segment_from_gdt(read_ds(), gdtr),
        fs: segment_from_gdt(read_fs(), gdtr),
        gs: segment_from_gdt(read_gs(), gdtr),
        ldtr: segment_from_gdt(read_ldtr(), gdtr),
        tr: segment_from_gdt(read_tr(), gdtr),
        gdtr,
        idtr,
    };

    state.fs.base = ArchitecturalMsr::FsBase.read();
    state.gs.base = ArchitecturalMsr::GsBase.read();
    state
}

pub fn vmx_usable_tr(current: SegmentState) -> SegmentState {
    let access = current.access_rights;
    let valid_busy_tss = current.selector != 0
        && current.selector & 0x4 == 0
        && access & (1 << 16) == 0
        && access & 0xf == 0xb
        && access & 0x10 == 0
        && access & 0x80 != 0
        && current.base != 0;
    if valid_busy_tss {
        return current;
    }

    SegmentState {
        selector: SYNTHETIC_TR_SELECTOR,
        base: core::ptr::addr_of!(SYNTHETIC_TSS) as u64,
        limit: SYNTHETIC_TR_LIMIT,
        access_rights: SYNTHETIC_TR_ACCESS_RIGHTS,
    }
}

pub fn read_gdtr() -> DescriptorTablePointer {
    let mut pointer = DescriptorTablePointer::default();
    unsafe {
        asm!("sgdt [{}]", in(reg) &mut pointer, options(nostack, preserves_flags));
    }
    pointer
}

pub fn read_idtr() -> DescriptorTablePointer {
    let mut pointer = DescriptorTablePointer::default();
    unsafe {
        asm!("sidt [{}]", in(reg) &mut pointer, options(nostack, preserves_flags));
    }
    pointer
}

fn segment_from_gdt(selector: u16, gdtr: DescriptorTablePointer) -> SegmentState {
    if selector & !0x7 == 0 || selector & 0x4 != 0 {
        return SegmentState {
            selector,
            base: 0,
            limit: 0,
            access_rights: 1 << 16,
        };
    }

    let table_offset = usize::from(selector & !0x7);
    if table_offset + 7 > usize::from(gdtr.limit) {
        return SegmentState {
            selector,
            base: 0,
            limit: 0,
            access_rights: 1 << 16,
        };
    }

    let descriptor_address = gdtr.base.wrapping_add(table_offset as u64) as *const u64;
    let descriptor = unsafe { descriptor_address.read_unaligned() };
    let access = ((descriptor >> 40) & 0xff) as u32;
    if access & 0x10 == 0 && table_offset + 15 > usize::from(gdtr.limit) {
        return SegmentState {
            selector,
            base: 0,
            limit: 0,
            access_rights: 1 << 16,
        };
    }
    let flags = ((descriptor >> 52) & 0xf) as u32;
    let mut limit = ((descriptor & 0xffff) | (((descriptor >> 48) & 0xf) << 16)) as u32;
    if flags & 0x8 != 0 {
        limit = (limit << 12) | 0xfff;
    }

    let mut base = ((descriptor >> 16) & 0xffff)
        | (((descriptor >> 32) & 0xff) << 16)
        | (((descriptor >> 56) & 0xff) << 24);
    if access & 0x10 == 0 {
        let high = unsafe { descriptor_address.add(1).read_unaligned() } & 0xffff_ffff;
        base |= high << 32;
    }

    SegmentState {
        selector,
        base,
        limit,
        access_rights: access | (flags << 12),
    }
}

macro_rules! selector_reader {
    ($name:ident, $segment:literal) => {
        fn $name() -> u16 {
            let selector: u16;
            unsafe {
                asm!(concat!("mov {0:x}, ", $segment), out(reg) selector, options(nomem, nostack, preserves_flags));
            }
            selector
        }
    };
}

selector_reader!(read_es, "es");
selector_reader!(read_cs, "cs");
selector_reader!(read_ss, "ss");
selector_reader!(read_ds, "ds");
selector_reader!(read_fs, "fs");
selector_reader!(read_gs, "gs");

fn read_ldtr() -> u16 {
    let selector: u16;
    unsafe {
        asm!("sldt {0:x}", out(reg) selector, options(nomem, nostack, preserves_flags));
    }
    selector
}

fn read_tr() -> u16 {
    let selector: u16;
    unsafe {
        asm!("str {0:x}", out(reg) selector, options(nomem, nostack, preserves_flags));
    }
    selector
}
