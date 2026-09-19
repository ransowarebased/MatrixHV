use alloc::vec::Vec;
use uefi::boot::{self, LoadImageSource};
use uefi::proto::BootPolicy;
use uefi::proto::device_path::{DevicePath, build};
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{CStr16, Status};

extern crate alloc;

pub fn find_image_volume(path: &CStr16) -> Result<Option<uefi::Handle>, Status> {
    let handles = boot::find_handles::<SimpleFileSystem>().map_err(|error| error.status())?;

    for handle in handles {
        if volume_contains(handle, path) {
            return Ok(Some(handle));
        }
    }

    Ok(None)
}

fn volume_contains(device_handle: uefi::Handle, path: &CStr16) -> bool {
    let Ok(mut file_system) = boot::open_protocol_exclusive::<SimpleFileSystem>(device_handle)
    else {
        return false;
    };
    let Ok(mut root) = file_system.open_volume() else {
        return false;
    };

    root.open(path, FileMode::Read, FileAttribute::empty())
        .is_ok()
}

pub fn start_image_on_volume(device_handle: uefi::Handle, path: &CStr16) -> Result<(), Status> {
    let device_path = boot::open_protocol_exclusive::<DevicePath>(device_handle)
        .map_err(|error| error.status())?;

    let mut file_path_storage = Vec::new();
    let file_path = build::DevicePathBuilder::with_vec(&mut file_path_storage)
        .push(&build::media::FilePath { path_name: path })
        .map_err(|_| Status::INVALID_PARAMETER)?
        .finalize()
        .map_err(|_| Status::INVALID_PARAMETER)?;

    let full_path = device_path
        .append_path(file_path)
        .map_err(|_| Status::NOT_FOUND)?;
    drop(device_path);

    let child_handle = boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromDevicePath {
            device_path: &full_path,
            boot_policy: BootPolicy::ExactMatch,
        },
    )
    .map_err(|error| error.status())?;

    let result = boot::start_image(child_handle).map_err(|error| error.status());
    let _ = boot::unload_image(child_handle);
    result
}
