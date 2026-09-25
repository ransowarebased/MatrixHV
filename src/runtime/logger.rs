use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};

use super::serial;

const LOG_BUFFER_CAPACITY: usize = 512;
static ENABLED: AtomicBool = AtomicBool::new(true);

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
    if enabled() {
        serial::initialize();
    }
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
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
        serial::write_line(message);
    }
}
