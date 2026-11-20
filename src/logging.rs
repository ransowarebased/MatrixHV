use alloc::vec::Vec;
use core::arch::asm;
use core::cell::UnsafeCell;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

const LOG_BUFFER_CAPACITY: usize = 512;
const PRE_EBS_LOG_CAPACITY: usize = 131072;
pub(crate) const SERIAL_SINK: u8 = 1;
pub(crate) const FRAMEBUFFER_SINK: u8 = 2;
static BACKEND: AtomicU8 = AtomicU8::new(LogBackend::Disabled as u8);
static LOG_ADAPTER: LogAdapter = LogAdapter;
static PRE_EBS_LOG_LOCK: AtomicU64 = AtomicU64::new(0);
static PRE_EBS_LOG: PreEbsLogStorage = PreEbsLogStorage::new();

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
        let length = value.floor_char_boundary(value.len().min(remaining));

        let end = self.length + length;
        self.bytes[self.length..end].copy_from_slice(&value.as_bytes()[..length]);
        self.length = end;
        if length == value.len() {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

pub fn initialize(enabled: bool) {
    let selected = select_backend(enabled, initialize_serial);
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
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    write_record("PHASE", format_args!("{name} tsc={tsc:#x}"));
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
        if !crate::boot::firmware::boot_services_exited() {
            append_pre_ebs_log(message);
        }
        let sinks = backend() as u8;
        if sinks & FRAMEBUFFER_SINK != 0 {
            crate::diagnostics::write_record(message);
        }
        if sinks & SERIAL_SINK != 0 {
            write_line(message);
        }
    }
}

struct PreEbsLogStorage {
    bytes: UnsafeCell<[u8; PRE_EBS_LOG_CAPACITY]>,
    length: UnsafeCell<usize>,
    truncated: UnsafeCell<bool>,
}

unsafe impl Sync for PreEbsLogStorage {}

impl PreEbsLogStorage {
    const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new([0; PRE_EBS_LOG_CAPACITY]),
            length: UnsafeCell::new(0),
            truncated: UnsafeCell::new(false),
        }
    }
}

fn acquire_pre_ebs_log_lock() -> bool {
    for _ in 0..TX_WAIT_LIMIT {
        if PRE_EBS_LOG_LOCK
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn append_pre_ebs_log(message: &str) {
    if !acquire_pre_ebs_log_lock() {
        return;
    }
    unsafe {
        let length = &mut *PRE_EBS_LOG.length.get();
        let bytes = &mut *PRE_EBS_LOG.bytes.get();
        let needed = message.len().saturating_add(2);
        if *length + needed <= bytes.len() {
            let start = *length;
            bytes[start..start + message.len()].copy_from_slice(message.as_bytes());
            bytes[start + message.len()] = b'\r';
            bytes[start + message.len() + 1] = b'\n';
            *length = start + needed;
        } else {
            *PRE_EBS_LOG.truncated.get() = true;
        }
    }
    PRE_EBS_LOG_LOCK.store(0, Ordering::Release);
}

pub fn flush_pre_ebs_file() {
    if !enabled() || crate::boot::firmware::boot_services_exited() {
        return;
    }
    if !acquire_pre_ebs_log_lock() {
        return;
    }
    let (mut snapshot, truncated) = unsafe {
        let length = *PRE_EBS_LOG.length.get();
        let bytes = core::slice::from_raw_parts(PRE_EBS_LOG.bytes.get().cast::<u8>(), length);
        let mut copy = Vec::with_capacity(length + 48);
        copy.extend_from_slice(bytes);
        (copy, *PRE_EBS_LOG.truncated.get())
    };
    PRE_EBS_LOG_LOCK.store(0, Ordering::Release);

    if snapshot.is_empty() {
        return;
    }
    if truncated {
        snapshot.extend_from_slice(b"[MATRIXHV][INFO] pre-ebs log truncated\r\n");
    }
    if let Err(status) = crate::boot::firmware::write_boot_log(&snapshot) {
        let mut buffer = LogBuffer::new();
        let _ = write!(buffer, "[MATRIXHV][ERROR] write \\MatrixHV.log failed: {status:?}");
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
    let Some(_guard) = SerialLockGuard::acquire() else {
        return;
    };
    let mut writer = SerialWriter;
    let _ = writeln!(writer, "{message}");
}

struct SerialLockGuard {
    lock: &'static AtomicU64,
}

impl SerialLockGuard {
    fn acquire() -> Option<Self> {
        let address = SHARED_LOCK_ADDRESS.load(Ordering::Acquire);
        let lock = if address == 0 {
            &FALLBACK_LOCK
        } else {
            unsafe { &*(address as *const AtomicU64) }
        };
        for _ in 0..TX_WAIT_LIMIT {
            if lock
                .compare_exchange_weak(0, RUST_LOCK_OWNER, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Some(Self { lock });
            }
            core::hint::spin_loop();
        }
        None
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
        "runtime framebuffer diagnostics v2: four columns 00-3F; stop 20 seconds after ExitBootServices"
    ));
    crate::diagnostics::message(format_args!(
        "mark rows: first reason bits, VMRESUME error bits, first eight exits"
    ));
    crate::diagnostics::message(format_args!(
        "hex 00-0F: exits reason RIP RCX GP-count GP-MSR GPA qualification CPU-mask CPU host-vector host-RIP error CR2 samples previous-reason"
    ));
    crate::diagnostics::message(format_args!(
        "hex 10-1F: CR0 CR3 CR4 EFER flags activity cache-state PAT RSP interruptibility previous-RIP previous-MSR perf-state previous-flags nested-error expired (telemetry off)"
    ));
    crate::diagnostics::message(format_args!(
        "hex 20-2F: version+validity root-CR0 root-PAT previous-render-TSC RAX RCX RDX RBX RBP RSI RDI R8 R9 R10 R11 code[0]"
    ));
    crate::diagnostics::message(format_args!(
        "hex 30-3F: code[1] stack[0..7] selected-CPU CPU-exits CPU-RIP CPU-reason INIT-mask SIPI-mask halted-mask"
    ));
    crate::diagnostics::message(format_args!(
        "hex right 4 flags 5 activity 6 normal RIP 7 EFER write 8 RSP 9 interruptibility"
    ));
    crate::diagnostics::message(format_args!(
        "code bytes are little-endian qwords at exact RIP; invalid reads are FFFFFFFFFFFFFFFF; validity bits 0-1=code, 2-9=stack; L2 memory capture is skipped"
    ));
}
