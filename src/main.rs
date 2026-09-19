#![no_main]
#![no_std]

extern crate alloc;

mod arch;
mod boot;
mod config;
mod guest;
#[path = "core/mod.rs"]
mod hv_core;
mod memory;
mod runtime;
mod smp;

use uefi::{Status, entry};

#[entry]
fn main() -> Status {
    let config = crate::boot::config::load_embedded().unwrap_or_default();
    crate::boot::config::apply(config);
    let active_config = crate::boot::config::current();
    crate::runtime::logger::set_enabled(active_config.logger);
    crate::runtime::logger::initialize();
    crate::runtime::logger::phase("boot.entry");
    crate::runtime::logger::info(format_args!(
        "config cpuidpresence={} logger={}",
        active_config.cpuid_presence, active_config.logger
    ));

    if uefi::helpers::init().is_err() {
        crate::runtime::logger::error(format_args!("UEFI helper initialization failed"));
        return Status::ABORTED;
    }
    if !active_config.logger {
        log::set_max_level(log::LevelFilter::Off);
    }

    match boot::run() {
        Ok(()) => Status::SUCCESS,
        Err(status) => {
            log::error!("MatrixHV boot failed: {status:?}");
            crate::runtime::logger::error_status("boot.run", status);
            status
        }
    }
}
