use crate::boot::{logger, services};
use uefi::{Status, cstr16};

const VERACRYPT_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\VeraCrypt\DcsBoot.efi");
const WINDOWS_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\Microsoft\Boot\bootmgfw.efi");

pub fn start() -> Result<(), Status> {
    if let Some(device_handle) = services::find_image_volume(VERACRYPT_BOOT_PATH)? {
        log::info!("VeraCrypt EFI loader detected: {}", VERACRYPT_BOOT_PATH);
        logger::phase("boot.veracrypt.detected");
        logger::phase("boot.veracrypt.start");
        let result = services::start_image_on_volume(device_handle, VERACRYPT_BOOT_PATH);
        if result.is_err() {
            logger::phase("boot.veracrypt.returned_error");
        }
        return result;
    }

    log::info!("VeraCrypt was not detected; starting the normal Windows boot manager");
    logger::phase("boot.veracrypt.absent");

    let device_handle = services::find_image_volume(WINDOWS_BOOT_PATH)?.ok_or_else(|| {
        logger::phase("boot.windows_fallback.not_found");
        Status::NOT_FOUND
    })?;

    logger::phase("boot.windows_fallback.start");
    services::start_image_on_volume(device_handle, WINDOWS_BOOT_PATH)
}
