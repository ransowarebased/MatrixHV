use core::arch::asm;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

const LOG_BUFFER_CAPACITY: usize = 512;
pub(crate) const SERIAL_SINK: u8 = 1;
pub(crate) const FRAMEBUFFER_SINK: u8 = 2;
static BACKEND: AtomicU8 = AtomicU8::new(LogBackend::Disabled as u8);
static SERIAL_PRESENT: AtomicBool = AtomicBool::new(false);
static LOG_ADAPTER: LogAdapter = LogAdapter;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LogBackend {
    Disabled = 0,
    Framebuffer = 2,
    SerialAndFramebuffer = 3,
}

fn select_backend(enabled: bool, serial_probe: impl FnOnce() -> bool) -> LogBackend {
    if !enabled {
        LogBackend::Disabled
    } else if serial_probe() {
        LogBackend::SerialAndFramebuffer
    } else {
        LogBackend::Framebuffer
    }
}

struct LogAdapter;

impl log::Log for LogAdapter {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        enabled()
    }

    fn log(&self, record: &log::Record<'_>) {
        write_record(record.level().as_str(), *record.args());
    }

    fn flush(&self) {}
}

struct LogBuffer {
    bytes: [u8; LOG_BUFFER_CAPACITY],
    length: usize,
}

impl LogBuffer {
    const fn new() -> Self {
        Self {
            bytes: [0; LOG_BUFFER_CAPACITY],
            length: 0,
        }
    }

    fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.bytes[..self.length]).ok()
    }
}

impl Write for LogBuffer {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let remaining = self.bytes.len().saturating_sub(self.length);
        if value.len() > remaining {
            return Err(fmt::Error);
        }

        let end = self.length + value.len();
        self.bytes[self.length..end].copy_from_slice(value.as_bytes());
        self.length = end;
        Ok(())
    }
}

pub fn initialize() {
    let selected = select_backend(enabled(), initialize_serial);
    SERIAL_PRESENT.store(
        selected == LogBackend::SerialAndFramebuffer,
        Ordering::Release,
    );
    BACKEND.store(selected as u8, Ordering::Release);
    let _ = log::set_logger(&LOG_ADAPTER);
    log::set_max_level(if selected == LogBackend::Disabled {
        log::LevelFilter::Off
    } else {
        log::LevelFilter::Info
    });
}

pub fn enabled() -> bool {
    backend() != LogBackend::Disabled
}

pub fn set_enabled(enabled: bool) {
    let selected = select_backend(enabled, || SERIAL_PRESENT.load(Ordering::Acquire));
    BACKEND.store(selected as u8, Ordering::Release);
}

pub(crate) fn backend() -> LogBackend {
    match BACKEND.load(Ordering::Acquire) {
        2 => LogBackend::Framebuffer,
        3 => LogBackend::SerialAndFramebuffer,
        _ => LogBackend::Disabled,
    }
}

pub(crate) fn framebuffer_enabled() -> bool {
    backend() as u8 & FRAMEBUFFER_SINK != 0
}

pub fn phase(name: &str) {
    write_record("PHASE", format_args!("{name}"));
}

pub fn info(arguments: fmt::Arguments<'_>) {
    write_record("INFO", arguments);
}

pub fn error(arguments: fmt::Arguments<'_>) {
    write_record("ERROR", arguments);
}

pub fn error_status(phase: &str, status: uefi::Status) {
    error(format_args!("phase={phase} status={status:?}"));
}

fn write_record(level: &str, arguments: fmt::Arguments<'_>) {
    if !enabled() {
        return;
    }

    let mut buffer = LogBuffer::new();
    let _ = write!(buffer, "[MATRIXHV][{level}] {arguments}");
    if let Some(message) = buffer.as_str() {
        let sinks = backend() as u8;
        if sinks & FRAMEBUFFER_SINK != 0 {
            crate::diagnostics::write_record(message);
        }
        if sinks & SERIAL_SINK != 0 {
            write_line(message);
        }
    }
}

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

fn initialize_serial() -> bool {
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

pub(crate) fn describe_resident_diagnostics() {
    crate::diagnostics::message(format_args!(
        "runtime framebuffer diagnostics stop 40 seconds after ExitBootServices"
    ));
    crate::diagnostics::message(format_args!(
        "mark rows: first reason bits, VMRESUME error bits, first eight exits"
    ));
    crate::diagnostics::message(format_args!(
        "hex rows: 0 exits 1 reason 2 RIP 3 RCX 4 MSR GP count 5 last GP MSR"
    ));
    crate::diagnostics::message(format_args!(
        "hex rows: 6 GPA 7 qualification 8 CPU mask 9 CPU A host fault B host RIP"
    ));
    crate::diagnostics::message(format_args!("hex rows: C host error code D host CR2"));
    crate::diagnostics::message(format_args!(
        "hex left E timer samples F last normal reason; right 0 CR0 1 CR3 2 CR4 3 EFER"
    ));
    crate::diagnostics::message(format_args!(
        "hex right 4 flags 5 activity 6 normal RIP 7 EFER write 8 RSP 9 interruptibility"
    ));
    crate::diagnostics::message(format_args!(
        "hex right A RDMSR B WRMSR C L2 entries D nested failures E nested error F expired"
    ));
}
