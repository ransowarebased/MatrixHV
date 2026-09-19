use crate::arch::x86_64::msr;

use super::super::vt_exits::GuestRegisters;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MsrReadResult {
    pub index: u32,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MsrWriteResult {
    pub index: u32,
    pub value: u64,
}

pub fn handle_read(registers: &mut GuestRegisters) -> MsrReadResult {
    let index = registers.rcx as u32;
    let value = unsafe { msr::read(index) };
    registers.rax = u64::from(value as u32);
    registers.rdx = u64::from((value >> 32) as u32);
    MsrReadResult { index, value }
}

pub fn handle_write(registers: &GuestRegisters) -> MsrWriteResult {
    let index = registers.rcx as u32;
    let value = ((registers.rdx as u32 as u64) << 32) | u64::from(registers.rax as u32);
    unsafe {
        msr::write(index, value);
    }
    MsrWriteResult { index, value }
}
