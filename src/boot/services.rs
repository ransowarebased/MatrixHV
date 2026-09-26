use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::{MaybeUninit, size_of_val};

use uefi::boot::{self, LoadImageSource, OpenProtocolAttributes, OpenProtocolParams, SearchType};
use uefi::proto::BootPolicy;
use uefi::proto::device_path::{DevicePath, DeviceSubType, DeviceType, build};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::runtime::{self, VariableVendor};
use uefi::{CStr16, Status, cstr16};

use super::{boot_order, logger, screen};

extern crate alloc;

const VERACRYPT_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\VeraCrypt\DcsBoot.efi");
const UBUNTU_SHIM_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\ubuntu\shimx64.efi");
const UBUNTU_GRUB_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\ubuntu\grubx64.efi");
const WINDOWS_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\Microsoft\Boot\bootmgfw.efi");
const VMX_FLAT_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\BOOT\VMXFLAT.EFI");
const VMX_FLAT_LOAD_OPTIONS: &uefi::CStr16 = cstr16!(
    "vmx.efi test_vmx_feature_control test_vmxon test_vmptrld test_vmclear test_vmptrst test_vmwrite_vmread test_vmcs_high test_vmcs_lifecycle test_vmx_caps vmenter vmx_controls_test vmx_host_state_area_test vmx_guest_state_area_test CR_shadowing I/O_bitmap MSR_switch instruction_intercept vmx_store_tsc_test vmx_intr_window_test vmx_nmi_window_test interrupt nmi_hlt ept_access_test_not_present ept_access_test_read_only ept_access_test_read_write ept_access_test_read_execute ept_access_test_read_write_execute"
);
const HANDLE_COUNT_CAPACITY: usize = 128;
const VERACRYPT_BOOT_PATH_TEXT: &str = r"\EFI\VeraCrypt\DcsBoot.efi";

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

pub(crate) struct VeraCryptBootOption {
    pub number: u16,
    data: Box<[u8]>,
}

impl VeraCryptBootOption {
    fn parsed(&self) -> boot_order::BootOption<'_> {
        boot_order::parse_boot_option(&self.data).expect("validated Boot#### option")
    }

    pub(crate) fn optional_data(&self) -> &[u8] {
        self.parsed().optional_data
    }

    pub(crate) fn image_path_size(&self) -> usize {
        self.parsed().image_path.len()
    }
}

pub(crate) fn find_veracrypt_boot_option() -> Result<Option<VeraCryptBootOption>, Status> {
    let (order, _) =
        runtime::get_variable_boxed(cstr16!("BootOrder"), &VariableVendor::GLOBAL_VARIABLE)
            .map_err(|error| error.status())?;
    let numbers = boot_order::parse_boot_order(&order).map_err(|_| Status::COMPROMISED_DATA)?;
    logger::info(format_args!("NVRAM BootOrder entries={}", numbers.len()));

    let mut selected = None;
    for number in numbers {
        let mut name = [0u16; 9];
        for (index, character) in b"Boot".iter().enumerate() {
            name[index] = u16::from(*character);
        }
        for digit in 0..4 {
            let shift = 12 - digit * 4;
            let nibble = ((number >> shift) & 0x0f) as usize;
            name[4 + digit] = u16::from(b"0123456789ABCDEF"[nibble]);
        }
        let name = CStr16::from_u16_with_nul(&name).map_err(|_| Status::INVALID_PARAMETER)?;
        let data = match runtime::get_variable_boxed(name, &VariableVendor::GLOBAL_VARIABLE) {
            Ok((data, _)) => data,
            Err(error) => {
                logger::error(format_args!("NVRAM {name}: {:?}", error.status()));
                continue;
            }
        };
        let option = match boot_order::parse_boot_option(&data) {
            Ok(option) => option,
            Err(error) => {
                logger::error(format_args!("NVRAM {name}: invalid {error:?}"));
                continue;
            }
        };
        let description = String::from_utf16_lossy(
            &option
                .description
                .as_chunks::<2>()
                .0
                .iter()
                .take(48)
                .map(|character| u16::from_le_bytes([character[0], character[1]]))
                .collect::<Vec<_>>(),
        );
        let file_path = option
            .image_file_path()
            .map(|path| String::from_utf16_lossy(&path))
            .unwrap_or_default();
        screen::message(format_args!(
            "NVRAM {name} active={} {description}",
            option.is_active()
        ));
        screen::message(format_args!("NVRAM {name} path={file_path}"));
        logger::info(format_args!(
            "NVRAM {name} attributes={:#x} description={description} path={file_path} path_bytes={} optional_bytes={}",
            option.attributes,
            option.image_path.len(),
            option.optional_data.len()
        ));
        if selected.is_none()
            && option.is_active()
            && option.image_file_path_matches(VERACRYPT_BOOT_PATH_TEXT)
        {
            screen::message(format_args!("NVRAM VeraCrypt target={name}"));
            selected = Some(VeraCryptBootOption { number, data });
        }
    }
    Ok(selected)
}

pub(crate) fn load_veracrypt_boot_option(
    option: &VeraCryptBootOption,
) -> Result<uefi::Handle, Status> {
    let parsed = option.parsed();
    let device_path =
        <&DevicePath>::try_from(parsed.image_path).map_err(|_| Status::COMPROMISED_DATA)?;
    let first_node = device_path
        .node_iter()
        .next()
        .ok_or(Status::COMPROMISED_DATA)?;
    screen::message(format_args!(
        "Boot{:04X} first node type={:#x} subtype={:#x}",
        option.number,
        first_node.device_type().0,
        first_node.sub_type().0
    ));
    if first_node.full_type() != (DeviceType::MEDIA, DeviceSubType::MEDIA_HARD_DRIVE) {
        screen::message(format_args!(
            "Boot{:04X} LoadImage original full path",
            option.number
        ));
        return boot::load_image(
            boot::image_handle(),
            LoadImageSource::FromDevicePath {
                device_path,
                boot_policy: BootPolicy::ExactMatch,
            },
        )
        .map_err(|error| error.status());
    }
    let suffix_offset = usize::from(first_node.length());
    let suffix = <&DevicePath>::try_from(&parsed.image_path[suffix_offset..])
        .map_err(|_| Status::COMPROMISED_DATA)?;
    screen::message(format_args!(
        "Boot{:04X} expanding original HD short path",
        option.number
    ));
    let handles = boot::find_handles::<SimpleFileSystem>().map_err(|error| error.status())?;
    let mut matched = false;
    let mut last_status = Status::NOT_FOUND;
    for handle in handles {
        let params = OpenProtocolParams {
            handle,
            agent: boot::image_handle(),
            controller: None,
        };
        let Ok(volume_path) = (unsafe {
            boot::open_protocol::<DevicePath>(params, OpenProtocolAttributes::GetProtocol)
        }) else {
            continue;
        };
        let Some(volume_hd_node) = volume_path
            .node_iter()
            .find(|node| node.full_type() == (DeviceType::MEDIA, DeviceSubType::MEDIA_HARD_DRIVE))
        else {
            continue;
        };
        if !same_hd_partition(first_node.data(), volume_hd_node.data()) {
            continue;
        }
        matched = true;
        screen::message(format_args!(
            "Boot{:04X} matched volume handle={:#x}",
            option.number,
            handle.as_ptr() as usize
        ));
        let full_path = volume_path
            .append_path(suffix)
            .map_err(|_| Status::OUT_OF_RESOURCES)?;
        drop(volume_path);
        match boot::load_image(
            boot::image_handle(),
            LoadImageSource::FromDevicePath {
                device_path: &full_path,
                boot_policy: BootPolicy::ExactMatch,
            },
        ) {
            Ok(child_handle) => {
                screen::message(format_args!(
                    "Boot{:04X} expanded LoadImage OK",
                    option.number
                ));
                return Ok(child_handle);
            }
            Err(error) => {
                last_status = error.status();
                screen::message(format_args!(
                    "Boot{:04X} expanded LoadImage: {last_status:?}",
                    option.number
                ));
            }
        }
    }
    if !matched {
        screen::error(format_args!(
            "Boot{:04X} HD partition not found",
            option.number
        ));
    }
    Err(last_status)
}

fn same_hd_partition(original: &[u8], candidate: &[u8]) -> bool {
    original.len() == 38
        && candidate.len() == 38
        && original[..4] == candidate[..4]
        && original[20..38] == candidate[20..38]
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

pub(crate) fn boot_target_candidates() -> &'static [BootTargetSpec] {
    if crate::boot::config::current().vmx_test {
        VMX_TEST_BOOT_TARGETS
    } else {
        NORMAL_BOOT_TARGETS
    }
}

pub(crate) fn find_boot_target() -> Result<Option<BootTargetSpec>, Status> {
    for spec in boot_target_candidates() {
        if find_image_volume(spec.path)?.is_some() {
            return Ok(Some(*spec));
        }
    }

    Ok(None)
}

pub(crate) fn configure_image_load_options(
    child_handle: uefi::Handle,
    nvram_options: Option<&[u8]>,
) -> Result<(), Status> {
    if !crate::boot::config::current().vmx_test && nvram_options.is_none_or(|data| data.is_empty())
    {
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
    let test_options = VMX_FLAT_LOAD_OPTIONS.as_slice_with_nul();
    let options = if crate::boot::config::current().vmx_test {
        unsafe {
            core::slice::from_raw_parts(test_options.as_ptr().cast(), size_of_val(test_options))
        }
    } else {
        nvram_options.unwrap_or_default()
    };
    unsafe {
        loaded_image.set_load_options(
            options.as_ptr().cast(),
            options
                .len()
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
