use core::arch::asm;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};

const COM1: u16 = 0x3f8;
const TRANSMIT_EMPTY: u8 = 1 << 5;
const TX_WAIT_LIMIT: usize = 100_000;
const RUST_LOCK_OWNER: u64 = 1;

static FALLBACK_LOCK: AtomicU64 = AtomicU64::new(0);
static SHARED_LOCK_ADDRESS: AtomicU64 = AtomicU64::new(0);

struct SerialWriter;

impl Write for SerialWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for byte in value.bytes() {
            if byte == b'\n' {
                write_byte(b'\r');
            }
            write_byte(byte);
        }
        Ok(())
    }
}

pub fn initialize() {
    unsafe {
        out8(COM1 + 1, 0x00);
        out8(COM1 + 3, 0x80);
        out8(COM1, 0x01);
        out8(COM1 + 1, 0x00);
        out8(COM1 + 3, 0x03);
        out8(COM1 + 2, 0xc7);
        out8(COM1 + 4, 0x0b);
    }
}

pub fn install_shared_lock(address: u64) {
    SHARED_LOCK_ADDRESS.store(address, Ordering::Release);
}

pub fn write_line(message: &str) {
    let _guard = SerialLockGuard::acquire();
    let mut writer = SerialWriter;
    let _ = writeln!(writer, "{message}");
}

struct SerialLockGuard {
    lock: &'static AtomicU64,
}

impl SerialLockGuard {
    fn acquire() -> Self {
        let address = SHARED_LOCK_ADDRESS.load(Ordering::Acquire);
        let lock = if address == 0 {
            &FALLBACK_LOCK
        } else {
            unsafe { &*(address as *const AtomicU64) }
        };
        while lock
            .compare_exchange_weak(0, RUST_LOCK_OWNER, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self { lock }
    }
}

impl Drop for SerialLockGuard {
    fn drop(&mut self) {
        self.lock.store(0, Ordering::Release);
    }
}

fn write_byte(byte: u8) {
    for _ in 0..TX_WAIT_LIMIT {
        let ready = unsafe { in8(COM1 + 5) } & TRANSMIT_EMPTY != 0;
        if ready {
            unsafe { out8(COM1, byte) };
            return;
        }
        core::hint::spin_loop();
    }
}

#[inline]
unsafe fn out8(port: u16, value: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline]
unsafe fn in8(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}
