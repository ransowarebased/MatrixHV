use alloc::vec::Vec;
use core::mem::{MaybeUninit, size_of_val};

use uefi::boot::{self, LoadImageSource, OpenProtocolAttributes, OpenProtocolParams, SearchType};
use uefi::proto::BootPolicy;
use uefi::proto::device_path::{DevicePath, build};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{CStr16, Status, cstr16};

extern crate alloc;

const VERACRYPT_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\VeraCrypt\DcsBoot.efi");
const UBUNTU_SHIM_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\ubuntu\shimx64.efi");
const UBUNTU_GRUB_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\ubuntu\grubx64.efi");
const WINDOWS_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\Microsoft\Boot\bootmgfw.efi");
const VMX_FLAT_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\BOOT\VMXFLAT.EFI");
const VMX_FLAT_LOAD_OPTIONS: &uefi::CStr16 = cstr16!(
    "vmx.efi test_vmx_feature_control test_vmxon test_vmptrld test_vmclear test_vmptrst test_vmwrite_vmread test_vmx_caps vmenter"
);
const HANDLE_COUNT_CAPACITY: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootTargetKind {
    VmxFlat,
    VeraCrypt,
    UbuntuShim,
    UbuntuGrub,
    Windows,
}

impl BootTargetKind {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::VmxFlat => "vmx_flat",
            Self::VeraCrypt => "veracrypt",
            Self::UbuntuShim => "ubuntu_shim",
            Self::UbuntuGrub => "ubuntu_grub",
            Self::Windows => "windows",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct BootTargetSpec {
    pub kind: BootTargetKind,
    pub path: &'static CStr16,
}

#[derive(Clone, Copy)]
pub(crate) struct BootTarget {
    pub device_handle: uefi::Handle,
    pub spec: BootTargetSpec,
}

const VMX_TEST_BOOT_TARGETS: &[BootTargetSpec] = &[BootTargetSpec {
    kind: BootTargetKind::VmxFlat,
    path: VMX_FLAT_BOOT_PATH,
}];
const NORMAL_BOOT_TARGETS: &[BootTargetSpec] = &[
    BootTargetSpec {
        kind: BootTargetKind::VeraCrypt,
        path: VERACRYPT_BOOT_PATH,
    },
    BootTargetSpec {
        kind: BootTargetKind::UbuntuShim,
        path: UBUNTU_SHIM_BOOT_PATH,
    },
    BootTargetSpec {
        kind: BootTargetKind::UbuntuGrub,
        path: UBUNTU_GRUB_BOOT_PATH,
    },
    BootTargetSpec {
        kind: BootTargetKind::Windows,
        path: WINDOWS_BOOT_PATH,
    },
];

pub fn initialize_boot_environment() -> Result<(), Status> {
    boot::set_watchdog_timer(0, 0x10000, None).map_err(|error| error.status())?;
    log::info!("MatrixHV UEFI bootstrap started");
    Ok(())
}

pub fn start_loader() -> Result<(), Status> {
    let target = find_boot_target()?.ok_or_else(|| {
        crate::runtime::logger::phase("boot.target.not_found");
        Status::NOT_FOUND
    })?;
    log::info!(
        "EFI boot target detected: kind={} path={}",
        target.spec.kind.name(),
        target.spec.path
    );
    crate::runtime::logger::info(format_args!(
        "boot target kind={} path={}",
        target.spec.kind.name(),
        target.spec.path
    ));
    crate::runtime::logger::phase("boot.target.detected");
    crate::runtime::logger::phase("boot.target.start");

    let result = start_image_on_volume(target.device_handle, target.spec.path);
    if result.is_err() {
        crate::runtime::logger::phase("boot.target.returned_error");
    }
    result
}

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

pub(crate) fn volume_contains(device_handle: uefi::Handle, path: &CStr16) -> bool {
    let params = OpenProtocolParams {
        handle: device_handle,
        agent: boot::image_handle(),
        controller: None,
    };
    let Ok(mut file_system) = (unsafe {
        boot::open_protocol::<SimpleFileSystem>(params, OpenProtocolAttributes::GetProtocol)
    }) else {
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
    configure_image_load_options(child_handle)?;

    let result = boot::start_image(child_handle).map_err(|error| error.status());
    let _ = boot::unload_image(child_handle);
    result
}

pub(crate) fn boot_target_candidates() -> &'static [BootTargetSpec] {
    if crate::boot::config::current().vmx_test {
        VMX_TEST_BOOT_TARGETS
    } else {
        NORMAL_BOOT_TARGETS
    }
}

pub(crate) fn find_boot_target() -> Result<Option<BootTarget>, Status> {
    for spec in boot_target_candidates() {
        if let Some(device_handle) = find_image_volume(spec.path)? {
            return Ok(Some(BootTarget {
                device_handle,
                spec: *spec,
            }));
        }
    }

    Ok(None)
}

pub(crate) fn configure_image_load_options(child_handle: uefi::Handle) -> Result<(), Status> {
    if !crate::boot::config::current().vmx_test {
        return Ok(());
    }

    let params = OpenProtocolParams {
        handle: child_handle,
        agent: boot::image_handle(),
        controller: None,
    };
    let mut loaded_image =
        unsafe { boot::open_protocol::<LoadedImage>(params, OpenProtocolAttributes::GetProtocol) }
            .map_err(|error| error.status())?;
    let options = VMX_FLAT_LOAD_OPTIONS.as_slice_with_nul();
    unsafe {
        loaded_image.set_load_options(
            options.as_ptr().cast(),
            size_of_val(options)
                .try_into()
                .map_err(|_| Status::BAD_BUFFER_SIZE)?,
        );
    }
    Ok(())
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
