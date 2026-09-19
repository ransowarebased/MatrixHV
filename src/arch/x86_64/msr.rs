use core::arch::asm;

pub const IA32_FEATURE_CONTROL: u32 = 0x3a;

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
