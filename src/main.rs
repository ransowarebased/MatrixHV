#![no_main]
#![no_std]

mod arch;
mod boot;
mod runtime;

use uefi::{Status, entry};

#[entry]
fn main() -> Status {
    crate::runtime::serial::initialize();
    crate::runtime::serial::write_line("MATRIXHV:ENTRY");

    if uefi::helpers::init().is_err() {
        crate::runtime::serial::write_line("MATRIXHV:UEFI_HELPERS_FAILED");
        return Status::ABORTED;
    }

    match boot::run() {
        Ok(()) => Status::SUCCESS,
        Err(status) => {
            log::error!("MatrixHV boot failed: {status:?}");
            crate::runtime::serial::write_status("MATRIXHV:BOOT_FAILED", status);
            status
        }
    }
}
