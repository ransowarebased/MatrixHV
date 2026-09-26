use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU8, Ordering};

use super::serial;

const LOG_BUFFER_CAPACITY: usize = 512;
pub(crate) const SERIAL_SINK: u8 = 1;
pub(crate) const FRAMEBUFFER_SINK: u8 = 2;
static BACKEND: AtomicU8 = AtomicU8::new(LogBackend::Disabled as u8);
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
    let selected = select_backend(enabled(), serial::initialize);
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
    BACKEND.store(
        if enabled {
            LogBackend::Framebuffer
        } else {
            LogBackend::Disabled
        } as u8,
        Ordering::Release,
    );
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
            crate::boot::screen::write_record(message);
        }
        if sinks & SERIAL_SINK != 0 {
            serial::write_line(message);
        }
    }
}
