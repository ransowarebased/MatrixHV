use core::arch::asm;
use core::fmt::{self, Write};

const COM1: u16 = 0x3f8;
const TRANSMIT_EMPTY: u8 = 1 << 5;
const TX_WAIT_LIMIT: usize = 100_000;

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

pub fn write_line(message: &str) {
    let mut writer = SerialWriter;
    let _ = writeln!(writer, "{message}");
}

pub fn write_status(prefix: &str, status: uefi::Status) {
    let mut writer = SerialWriter;
    let _ = writeln!(writer, "{prefix}:{status:?}");
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
