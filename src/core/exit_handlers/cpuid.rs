use crate::arch::x86_64::cpuid;

use super::super::vt_exits::GuestRegisters;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuidResult {
    pub leaf: u32,
    pub subleaf: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub fn handle(registers: &mut GuestRegisters) -> CpuidResult {
    let leaf = registers.rax as u32;
    let subleaf = registers.rcx as u32;
    let result = cpuid::leaf_with_subleaf(leaf, subleaf);

    registers.rax = u64::from(result.eax);
    registers.rbx = u64::from(result.ebx);
    registers.rcx = u64::from(result.ecx);
    registers.rdx = u64::from(result.edx);

    CpuidResult {
        leaf,
        subleaf,
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}
