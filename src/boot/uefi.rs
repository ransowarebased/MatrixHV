use uefi::{Status, boot};

pub fn initialize_boot_environment() -> Result<(), Status> {
    boot::set_watchdog_timer(0, 0x10000, None).map_err(|error| error.status())?;
    log::info!("MatrixHV UEFI bootstrap started");
    Ok(())
}
