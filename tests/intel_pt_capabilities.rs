use std::arch::x86_64::__cpuid_count;
use std::ffi::c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn GetCurrentThread() -> *mut c_void;
    fn GetProcessAffinityMask(
        process: *mut c_void,
        process_mask: *mut usize,
        system_mask: *mut usize,
    ) -> i32;
    fn SetThreadAffinityMask(thread: *mut c_void, mask: usize) -> usize;
}

struct Affinity {
    thread: *mut c_void,
    original: usize,
}

impl Drop for Affinity {
    fn drop(&mut self) {
        unsafe { SetThreadAffinityMask(self.thread, self.original) };
    }
}

fn main() {
    let mut process_mask = 0;
    let mut system_mask = 0;
    assert_ne!(
        unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut process_mask, &mut system_mask) },
        0
    );
    let thread = unsafe { GetCurrentThread() };
    let original = unsafe { SetThreadAffinityMask(thread, 1 << process_mask.trailing_zeros()) };
    assert_ne!(original, 0);
    let affinity = Affinity { thread, original };
    println!(
        "{{\"scope\":\"Read-only per-CPU PT capabilities and resident VMX_MISC snapshot\",\"cpus\":["
    );
    let mut separator = "";
    for cpu in 0..usize::BITS {
        if process_mask & (1_usize << cpu) == 0 {
            continue;
        }
        assert_ne!(
            unsafe { SetThreadAffinityMask(affinity.thread, 1_usize << cpu) },
            0
        );
        let basic = __cpuid_count(0, 0);
        let features = __cpuid_count(7, 0);
        let pt = __cpuid_count(0x14, 0);
        let misc = __cpuid_count(0x4d48_5652, 48);
        let host_misc = u64::from(misc.eax) | (u64::from(misc.ebx) << 32);
        let state = __cpuid_count(0x4d48_5652, 0x600);
        let supported = basic.eax >= 0x14
            && features.ebx & (1 << 25) != 0
            && pt.ecx & 1 != 0
            && host_misc & (1 << 14) != 0;
        println!(
            "{separator}{{\"cpu\":{cpu},\"max_leaf\":{},\"leaf7_ebx\":{},\"pt_eax\":{},\"pt_ebx\":{},\"pt_ecx\":{},\"pt_edx\":{},\"host_vmx_misc\":{host_misc},\"pt_present\":{},\"topa\":{},\"pt_in_vmx\":{},\"supported\":{supported},\"resident_state\":{},\"armed\":{},\"bytes\":{}}}",
            basic.eax,
            features.ebx,
            pt.eax,
            pt.ebx,
            pt.ecx,
            pt.edx,
            features.ebx & (1 << 25) != 0,
            pt.ecx & 1 != 0,
            host_misc & (1 << 14) != 0,
            state.eax,
            state.ebx,
            state.ecx
        );
        separator = ",";
    }
    println!("]}}");
}
