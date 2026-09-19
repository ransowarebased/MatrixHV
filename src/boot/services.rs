use alloc::vec::Vec;
use core::mem::MaybeUninit;

use uefi::boot::{self, LoadImageSource, OpenProtocolAttributes, OpenProtocolParams, SearchType};
use uefi::proto::BootPolicy;
use uefi::proto::device_path::{DevicePath, build};
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{CStr16, Status};

extern crate alloc;

const HANDLE_COUNT_CAPACITY: usize = 128;

pub fn simple_file_system_count() -> Result<usize, Status> {
    let mut handles: [MaybeUninit<uefi::Handle>; HANDLE_COUNT_CAPACITY] =
        [const { MaybeUninit::uninit() }; HANDLE_COUNT_CAPACITY];
    boot::locate_handle(SearchType::from_proto::<SimpleFileSystem>(), &mut handles)
        .map(|found| found.len())
        .map_err(|error| error.status())
}

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
    let child_handle = load_image_on_volume(device_handle, path)?;

    let result = boot::start_image(child_handle).map_err(|error| error.status());
    let _ = boot::unload_image(child_handle);
    result
}

pub fn load_and_unload_image_on_volume(
    device_handle: uefi::Handle,
    path: &CStr16,
) -> Result<(), Status> {
    let child_handle = load_image_on_volume(device_handle, path)?;
    boot::unload_image(child_handle).map_err(|error| error.status())
}

pub(crate) fn load_image_on_volume(
    device_handle: uefi::Handle,
    path: &CStr16,
) -> Result<uefi::Handle, Status> {
    let device_path = unsafe {
        boot::open_protocol::<DevicePath>(
            OpenProtocolParams {
                handle: device_handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
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

    boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromDevicePath {
            device_path: &full_path,
            boot_policy: BootPolicy::ExactMatch,
        },
    )
    .map_err(|error| error.status())
}
