use core::fmt;

use crate::runtime::logger as runtime_logger;

pub fn phase(name: &str) {
    runtime_logger::phase(name);
}

pub fn info(arguments: fmt::Arguments<'_>) {
    runtime_logger::info(arguments);
}

pub fn error(arguments: fmt::Arguments<'_>) {
    runtime_logger::error(arguments);
}
