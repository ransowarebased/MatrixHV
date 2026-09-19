pub const CPUID_VMX_BIT: u32 = 1 << 5;
pub const CPUID_OSXSAVE_BIT: u32 = 1 << 27;
pub const CPUID_HYPERVISOR_PRESENT_BIT: u32 = 1 << 31;
pub const HYPERVISOR_LEAF_START: u32 = 0x4000_0000;
pub const HYPERVISOR_LEAF_END: u32 = 0x4fff_ffff;
pub const HYPERV_FEATURES_LEAF: u32 = 0x4000_0003;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuidRegisters {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub fn filter(
    leaf: u32,
    mut registers: CpuidRegisters,
    cpuid_presence: bool,
    expose_vmx: bool,
    guest_osxsave: bool,
) -> CpuidRegisters {
    if !cpuid_presence && (HYPERVISOR_LEAF_START..=HYPERVISOR_LEAF_END).contains(&leaf) {
        return CpuidRegisters {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        };
    }

    if leaf == 1 {
        registers.ecx &= !(CPUID_VMX_BIT | CPUID_OSXSAVE_BIT);
        if expose_vmx {
            registers.ecx |= CPUID_VMX_BIT;
        }
        if guest_osxsave {
            registers.ecx |= CPUID_OSXSAVE_BIT;
        }
        if cpuid_presence {
            registers.ecx |= CPUID_HYPERVISOR_PRESENT_BIT;
        } else {
            registers.ecx &= !CPUID_HYPERVISOR_PRESENT_BIT;
        }
    } else if leaf == HYPERV_FEATURES_LEAF {
        registers.eax &= !(1 << 10);
        registers.edx &= !(1 << 5);
    }

    registers
}
