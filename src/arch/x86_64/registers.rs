use core::arch::asm;

#[inline]
pub fn read_dr7() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, dr7", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}
