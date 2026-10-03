#![no_main]
#![no_std]

extern crate alloc;

mod access;
mod arch;
mod boot;
mod config;
mod diagnostics;
mod firmware;
mod guest;
#[path = "core/mod.rs"]
mod hv_core;
mod hyperv;
mod memory;
mod nested;
mod protocol;
mod runtime;
mod smp;
pub mod update;

use uefi::{Status, entry};

#[entry]
fn main() -> Status {
    crate::runtime::set_enabled(true);
    crate::diagnostics::begin();
    crate::runtime::phase("logger.detect_com1");
    crate::runtime::initialize();
    crate::runtime::phase("boot.entry");
    let active_config = match crate::firmware::load_from_boot_volume() {
        Ok(config) => config,
        Err(error) => {
            crate::runtime::error(format_args!("failed to load \\MatrixConfig.bin: {error:?}"));
            crate::diagnostics::hold_on_failure();
            return Status::ABORTED;
        }
    };
    crate::guest::configure(active_config);
    crate::runtime::set_enabled(active_config.logger);
    crate::runtime::info(format_args!(
        "config cpuidpresence={} logger={} vt_nested={} vt_evmcs={} vmx_test={}",
        active_config.cpuid_presence,
        active_config.logger,
        active_config.vt_nested,
        active_config.vt_evmcs,
        active_config.vmx_test
    ));
    crate::runtime::info(format_args!(
        "logger backend={:?}",
        crate::runtime::backend()
    ));

    if uefi::helpers::init().is_err() {
        crate::runtime::error(format_args!("UEFI helper initialization failed"));
        crate::diagnostics::hold_on_failure();
        return Status::ABORTED;
    }

    match boot::run(active_config) {
        Ok(()) => Status::SUCCESS,
        Err(status) => {
            crate::runtime::error_status("boot.run", status);
            crate::diagnostics::hold_on_failure();
            status
        }
    }
}
