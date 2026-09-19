use core::arch::x86_64::{__cpuid, __cpuid_count};

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
