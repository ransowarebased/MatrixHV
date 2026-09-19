use crate::boot::services;
use crate::runtime::serial;
use uefi::{Status, cstr16};

const VERACRYPT_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\VeraCrypt\DcsBoot.efi");
const WINDOWS_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\Microsoft\Boot\bootmgfw.efi");

pub fn start() -> Result<(), Status> {
    if let Some(device_handle) = services::find_image_volume(VERACRYPT_BOOT_PATH)? {
        log::info!("VeraCrypt EFI loader detected: {}", VERACRYPT_BOOT_PATH);
        serial::write_line("MATRIXHV:VERACRYPT_DETECTED");
        serial::write_line("MATRIXHV:VERACRYPT_START");
        let result = services::start_image_on_volume(device_handle, VERACRYPT_BOOT_PATH);
        if result.is_err() {
            serial::write_line("MATRIXHV:VERACRYPT_RETURNED_ERROR");
        }
        return result;
    }

    log::info!("VeraCrypt was not detected; starting the normal Windows boot manager");
    serial::write_line("MATRIXHV:VERACRYPT_ABSENT");

    let device_handle = services::find_image_volume(WINDOWS_BOOT_PATH)?.ok_or_else(|| {
        serial::write_line("MATRIXHV:WINDOWS_FALLBACK_NOT_FOUND");
        Status::NOT_FOUND
    })?;

    serial::write_line("MATRIXHV:WINDOWS_FALLBACK_START");
    services::start_image_on_volume(device_handle, WINDOWS_BOOT_PATH)
}
