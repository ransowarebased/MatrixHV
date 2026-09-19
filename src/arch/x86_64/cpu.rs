use super::{cpuid, msr};

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
    let basic = cpuid::leaf(0);
    let mut vendor = [0_u8; 12];
    vendor[0..4].copy_from_slice(&basic.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&basic.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&basic.ecx.to_le_bytes());

    let vendor = if &vendor == b"GenuineIntel" {
        Vendor::Intel
    } else {
        Vendor::Other(vendor)
    };

    let features = cpuid::leaf(CPUID_FEATURE_INFORMATION);
    let vmx = features.ecx & CPUID_VMX_BIT != 0;
    let feature_control = if matches!(vendor, Vendor::Intel) && vmx {
        unsafe { msr::read(msr::IA32_FEATURE_CONTROL) }
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
