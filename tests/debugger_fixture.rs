use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualAlloc(
        address: *mut core::ffi::c_void,
        size: usize,
        kind: u32,
        protection: u32,
    ) -> *mut core::ffi::c_void;
    fn VirtualProtect(
        address: *mut core::ffi::c_void,
        size: usize,
        protection: u32,
        previous: *mut u32,
    ) -> i32;
    fn VirtualFree(address: *mut core::ffi::c_void, size: usize, kind: u32) -> i32;
}

struct GuardedPages(*mut core::ffi::c_void);

impl GuardedPages {
    fn new() -> Self {
        let address = unsafe { VirtualAlloc(core::ptr::null_mut(), 3 * 4096, 0x3000, 4) };
        assert!(!address.is_null());
        unsafe { address.cast::<u8>().write_bytes(0xa5, 3 * 4096) };
        let mut previous = 0;
        assert_ne!(
            unsafe { VirtualProtect(address.byte_add(4096), 4096, 1, &mut previous) },
            0
        );
        Self(address)
    }
}

impl Drop for GuardedPages {
    fn drop(&mut self) {
        assert_ne!(unsafe { VirtualFree(self.0, 0, 0x8000) }, 0);
    }
}

#[repr(C)]
struct Fixture {
    vtable: *const usize,
    calls: AtomicU64,
    last_scalar: AtomicU64,
    last_stack: AtomicU64,
    data: [u8; 32],
}

#[unsafe(no_mangle)]
extern "win64" fn matrix_fixture_target(
    state: *mut Fixture,
    scalar: u64,
    data: *const u8,
    count: u64,
    stack: u64,
) -> u64 {
    let state = unsafe { &*state };
    assert_eq!(data, state.data.as_ptr());
    assert_eq!(count, 7);
    state.calls.fetch_add(1, Ordering::SeqCst);
    state.last_scalar.store(scalar, Ordering::SeqCst);
    state.last_stack.store(stack, Ordering::SeqCst);
    scalar ^ stack
}

core::arch::global_asm!(
    r#"
.text
.globl matrix_fixture_direct
matrix_fixture_direct:
    sub rsp, 40
    mov qword ptr [rsp + 32], 85
.globl matrix_fixture_direct_probe
matrix_fixture_direct_probe:
    call matrix_fixture_target
    add rsp, 40
    ret
.globl matrix_fixture_virtual
matrix_fixture_virtual:
    sub rsp, 40
    mov qword ptr [rsp + 32], 85
    mov rax, qword ptr [rcx]
.globl matrix_fixture_virtual_probe
matrix_fixture_virtual_probe:
    call qword ptr [rax]
    add rsp, 40
    ret
"#
);

unsafe extern "win64" {
    fn matrix_fixture_direct(state: *mut Fixture, scalar: u64, data: *const u8, count: u64) -> u64;
    fn matrix_fixture_virtual(state: *mut Fixture, scalar: u64, data: *const u8, count: u64)
        -> u64;
    static matrix_fixture_direct_probe: u8;
    static matrix_fixture_virtual_probe: u8;
}

fn main() {
    let guarded_pages = GuardedPages::new();
    let vtable = [matrix_fixture_target as *const () as usize];
    let mut state = Box::new(Fixture {
        vtable: vtable.as_ptr(),
        calls: AtomicU64::new(0),
        last_scalar: AtomicU64::new(0),
        last_stack: AtomicU64::new(0),
        data: [0x5a; 32],
    });
    println!(
        "{{\"type\":\"ready\",\"pid\":{},\"direct_probe\":\"{:#x}\",\"virtual_probe\":\"{:#x}\",\"target\":\"{:#x}\",\"state\":\"{:#x}\",\"data\":\"{:#x}\",\"vtable\":\"{:#x}\",\"partial_region\":\"{:#x}\",\"sparse_region\":\"{:#x}\",\"scalar\":\"0x11223344\",\"stack_offset\":32,\"stack_value\":85}}",
        std::process::id(),
        core::ptr::addr_of!(matrix_fixture_direct_probe) as usize,
        core::ptr::addr_of!(matrix_fixture_virtual_probe) as usize,
        matrix_fixture_target as *const () as usize,
        &*state as *const Fixture as usize,
        state.data.as_ptr() as usize,
        vtable.as_ptr() as usize,
        guarded_pages.0 as usize + 4088,
        guarded_pages.0 as usize + 8184
    );
    io::stdout().flush().unwrap();
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let result = if line == "concurrent" {
            let barrier = Arc::new(Barrier::new(5));
            let mut workers = Vec::new();
            for _ in 0..4 {
                let barrier = barrier.clone();
                let address = &*state as *const Fixture as usize;
                workers.push(std::thread::spawn(move || {
                    let state = address as *mut Fixture;
                    let data = unsafe { (*state).data.as_ptr() };
                    barrier.wait();
                    unsafe { matrix_fixture_direct(state, 0x11223344, data, 7) }
                }));
            }
            barrier.wait();
            for worker in workers {
                assert_eq!(worker.join().unwrap(), 0x11223344 ^ 85);
            }
            0x11223344 ^ 85
        } else {
            let function = match line.as_str() {
                "direct" => matrix_fixture_direct,
                "virtual" => matrix_fixture_virtual,
                "exit" => break,
                _ => continue,
            };
            let data = state.data.as_ptr();
            unsafe { function(&mut *state, 0x11223344, data, 7) }
        };
        println!(
            "{{\"type\":\"done\",\"operation\":\"{line}\",\"calls\":{},\"scalar\":{},\"stack\":{},\"result\":{result}}}",
            state.calls.load(Ordering::SeqCst),
            state.last_scalar.load(Ordering::SeqCst),
            state.last_stack.load(Ordering::SeqCst)
        );
        io::stdout().flush().unwrap();
    }
}
