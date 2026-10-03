#![no_main]
#![no_std]

extern crate alloc;

mod arch;
mod boot;
mod diagnostics;
mod logging;
mod memory;
mod protocol;
pub mod update;
mod vmx;

use uefi::{Status, entry};

#[entry]
fn main() -> Status {
    crate::logging::set_enabled(true);
    crate::diagnostics::begin();
    crate::logging::phase("logger.detect_com1");
    crate::logging::initialize();
    crate::logging::phase("boot.entry");
    let active_config = match crate::boot::firmware::load_from_boot_volume() {
        Ok(config) => config,
        Err(error) => {
            crate::logging::error(format_args!("failed to load \\MatrixConfig.bin: {error:?}"));
            crate::diagnostics::hold_on_failure();
            return Status::ABORTED;
        }
    };
    crate::boot::guest::configure(active_config);
    crate::logging::set_enabled(active_config.logger);
    crate::logging::info(format_args!(
        "config cpuidpresence={} logger={} vt_nested={} vt_evmcs={} vmx_test={}",
        active_config.cpuid_presence,
        active_config.logger,
        active_config.vt_nested,
        active_config.vt_evmcs,
        active_config.vmx_test
    ));
    crate::logging::info(format_args!(
        "logger backend={:?}",
        crate::logging::backend()
    ));

    if uefi::helpers::init().is_err() {
        crate::logging::error(format_args!("UEFI helper initialization failed"));
        crate::diagnostics::hold_on_failure();
        return Status::ABORTED;
    }

    match boot::run(active_config) {
        Ok(()) => Status::SUCCESS,
        Err(status) => {
            crate::logging::error_status("boot.run", status);
            crate::diagnostics::hold_on_failure();
            status
        }
    }
}
