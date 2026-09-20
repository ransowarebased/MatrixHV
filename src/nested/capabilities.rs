pub const IA32_FEATURE_CONTROL_LOCKED: u64 = 1 << 0;
pub const IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX: u64 = 1 << 2;
pub const VMX_MEMORY_TYPE_WRITE_BACK: u64 = 6;
pub const VMX_REGION_SIZE: u64 = 4096;

pub const CPUID_VMX_BIT: u32 = 1 << 5;
pub const CPUID_OSXSAVE_BIT: u32 = 1 << 27;
pub const CPUID_HYPERVISOR_PRESENT_BIT: u32 = 1 << 31;
pub const HYPERVISOR_LEAF_START: u32 = 0x4000_0000;
pub const HYPERVISOR_LEAF_END: u32 = 0x4fff_ffff;
pub const HYPERV_FEATURES_LEAF: u32 = 0x4000_0003;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedVmxCapabilities {
    pub revision_id: u32,
    pub feature_control: u64,
    pub vmx_basic: u64,
    pub expose_vmx: bool,
}

impl NestedVmxCapabilities {
    pub fn vmxon_vmxoff(host_vmx_basic: u64) -> Self {
        let revision_id = host_vmx_basic as u32 & 0x7fff_ffff;
        Self {
            revision_id,
            feature_control: IA32_FEATURE_CONTROL_LOCKED | IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX,
            vmx_basic: u64::from(revision_id)
                | (VMX_REGION_SIZE << 32)
                | (VMX_MEMORY_TYPE_WRITE_BACK << 50),
            expose_vmx: false,
        }
    }
}
