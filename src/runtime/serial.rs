use core::arch::asm;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) const COM1: u16 = 0x3f8;
pub(crate) const TRANSMIT_EMPTY: u8 = 1 << 5;
pub(crate) const TX_WAIT_LIMIT: usize = 100_000;
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

pub fn initialize() -> bool {
    probe_com1(
        |port| unsafe { in8(port) },
        |port, value| unsafe { out8(port, value) },
    )
}

fn probe_com1(mut read: impl FnMut(u16) -> u8, mut write: impl FnMut(u16, u8)) -> bool {
    if read(COM1 + 5) == 0xff {
        return false;
    }
    let scratch = read(COM1 + 7);
    for pattern in [0x5a, 0xa5] {
        write(COM1 + 7, pattern);
        if read(COM1 + 7) != pattern {
            write(COM1 + 7, scratch);
            return false;
        }
    }
    write(COM1 + 7, scratch);

    let line_control = read(COM1 + 3);
    let modem_control = read(COM1 + 4);
    write(COM1 + 3, line_control & !0x80);
    let interrupt_enable = read(COM1 + 1);
    write(COM1 + 1, 0);
    write(COM1 + 3, 0x80);
    let divisor_low = read(COM1);
    let divisor_high = read(COM1 + 1);
    write(COM1, 1);
    write(COM1 + 1, 0);
    write(COM1 + 3, 0x03);
    // Internal loopback verifies a UART without transmitting probe bytes to the cable.
    write(COM1 + 4, 0x10);
    for _ in 0..64 {
        if read(COM1 + 5) & 1 == 0 {
            break;
        }
        let _ = read(COM1);
    }
    write(COM1, 0xae);
    let mut present = false;
    for _ in 0..TX_WAIT_LIMIT {
        let status = read(COM1 + 5);
        if status == 0xff {
            break;
        }
        if status & 1 != 0 {
            present = read(COM1) == 0xae;
            break;
        }
        core::hint::spin_loop();
    }
    if present {
        write(COM1 + 2, 0xc7);
        write(COM1 + 4, 0x0b);
    } else {
        write(COM1 + 4, modem_control);
        write(COM1 + 3, 0x80);
        write(COM1, divisor_low);
        write(COM1 + 1, divisor_high);
        write(COM1 + 3, line_control & !0x80);
        write(COM1 + 1, interrupt_enable);
        write(COM1 + 3, line_control);
    }
    present
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
