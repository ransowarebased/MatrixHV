use std::arch::x86_64::{__cpuid_count, __rdtscp, _rdtsc, _xgetbv};
use std::hint::black_box;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentThread() -> *mut core::ffi::c_void;
    fn SetThreadAffinityMask(thread: *mut core::ffi::c_void, affinity_mask: usize) -> usize;
}

const ITERATIONS: u32 = 20_000;
const ROUNDS: usize = 9;

#[inline(never)]
fn sample(mut operation: impl FnMut(u32) -> u64) -> f64 {
    let mut auxiliary = 0;
    let start = unsafe { __rdtscp(&mut auxiliary) };
    let mut checksum = 0_u64;
    for index in 0..ITERATIONS {
        checksum = checksum.wrapping_add(operation(index));
    }
    let end = unsafe { __rdtscp(&mut auxiliary) };
    black_box(checksum);
    f64::from((end - start) as u32) / f64::from(ITERATIONS)
}

fn measure(name: &str, tsc_hz: f64, operation: impl FnMut(u32) -> u64 + Copy) {
    let mut samples = [0.0; ROUNDS];
    for value in &mut samples {
        *value = sample(operation);
    }
    samples.sort_by(f64::total_cmp);
    let median = samples[ROUNDS / 2];
    let p90 = samples[ROUNDS - 2];
    println!(
        "{name}: median={median:.1} cycles/op ({:.1} ns/op), p90={p90:.1} cycles/op",
        median * 1e9 / tsc_hz
    );
}

fn main() {
    let previous_mask = unsafe { SetThreadAffinityMask(GetCurrentThread(), 1) };
    assert_ne!(previous_mask, 0, "Unable to pin timing thread to CPU 0");

    let frequency = __cpuid_count(0x15, 0);
    assert_ne!(frequency.eax, 0, "TSC ratio unavailable");
    assert_ne!(frequency.ecx, 0, "TSC crystal frequency unavailable");
    let tsc_hz = f64::from(frequency.ecx) * f64::from(frequency.ebx) / f64::from(frequency.eax);

    println!("tsc_hz={tsc_hz:.0}, iterations={ITERATIONS}, rounds={ROUNDS}");
    measure("loop", tsc_hz, |index| u64::from(black_box(index)));
    measure("RDTSC", tsc_hz, |_| unsafe { _rdtsc() });
    measure("RDTSCP", tsc_hz, |_| {
        let mut auxiliary = 0;
        unsafe { __rdtscp(&mut auxiliary) }
    });
    measure("XGETBV", tsc_hz, |_| unsafe { _xgetbv(0) });
    measure("CPUID leaf 0", tsc_hz, |_| {
        u64::from(__cpuid_count(0, 0).eax)
    });
    measure("CPUID leaf 1", tsc_hz, |_| {
        u64::from(__cpuid_count(1, 0).ecx)
    });
    measure("CPUID status", tsc_hz, |_| {
        u64::from(__cpuid_count(0x4d48_5652, 0).eax)
    });

    unsafe { SetThreadAffinityMask(GetCurrentThread(), previous_mask) };
}
