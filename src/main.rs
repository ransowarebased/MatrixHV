#![no_main]
#![no_std]

extern crate alloc;

mod arch;
mod boot;
mod guest;
#[path = "core/mod.rs"]
mod hv_core;
mod memory;
mod nested;
mod runtime;
mod smp;

use uefi::{Status, entry};

#[entry]
fn main() -> Status {
    let config = crate::boot::load_embedded().unwrap_or_default();
    crate::boot::apply(config);
    let active_config = crate::boot::current();
    crate::runtime::set_enabled(active_config.logger);
    crate::boot::screen::begin();
    crate::runtime::phase("logger.detect_com1");
    crate::runtime::initialize();
    crate::runtime::phase("boot.entry");
    crate::runtime::info(format_args!(
        "config cpuidpresence={} logger={} vt_nested={} vmx_test={}",
        active_config.cpuid_presence,
        active_config.logger,
        active_config.vt_nested,
        active_config.vmx_test
    ));
    crate::runtime::info(format_args!(
        "logger backend={:?}",
        crate::runtime::backend()
    ));

    if uefi::helpers::init().is_err() {
        crate::runtime::error(format_args!("UEFI helper initialization failed"));
        crate::boot::screen::hold_on_failure();
        return Status::ABORTED;
    }

    match boot::run() {
        Ok(()) => Status::SUCCESS,
        Err(status) => {
            crate::runtime::error_status("boot.run", status);
            crate::boot::screen::hold_on_failure();
            status
        }
    }
}
