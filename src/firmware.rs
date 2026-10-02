use crate::hv_core::bridge::VariableBridge;
use crate::memory::PAGE_SIZE;
use crate::protocol::{CONTROL_MAGIC, CONTROL_VERSION, ControlStatus};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use core::ffi::c_void;
use core::mem::{MaybeUninit, size_of};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use uefi::proto::unsafe_protocol;

use uefi::boot::{
    self, EventNotifyFn, EventType, LoadImageSource, OpenProtocolAttributes, OpenProtocolParams,
    SearchType, Tpl,
};
use uefi::proto::BootPolicy;
use uefi::proto::device_path::{DevicePath, DeviceSubType, DeviceType, build};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::runtime::{self as uefi_runtime, VariableVendor};
use uefi::{CStr16, Event, Status, cstr16};

use crate::config::{self, MatrixConfig, ParseError};
use crate::runtime;

const CONFIG_FILE_PATH: &CStr16 = cstr16!(r"\MatrixConfig.bin");
const CONFIG_FILE_MAX_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigLoadError {
    Firmware(Status),
    MissingImageDevice,
    NotRegularFile,
    TooLarge,
    Parse(ParseError),
}

pub fn load_from_boot_volume() -> Result<MatrixConfig, ConfigLoadError> {
    let params = OpenProtocolParams {
        handle: boot::image_handle(),
        agent: boot::image_handle(),
        controller: None,
    };
    let loaded_image =
        unsafe { boot::open_protocol::<LoadedImage>(params, OpenProtocolAttributes::GetProtocol) }
            .map_err(|error| ConfigLoadError::Firmware(error.status()))?;
    let device_handle = loaded_image
        .device()
        .ok_or(ConfigLoadError::MissingImageDevice)?;
    drop(loaded_image);

    let params = OpenProtocolParams {
        handle: device_handle,
        agent: boot::image_handle(),
        controller: None,
    };
    let mut file_system = unsafe {
        boot::open_protocol::<SimpleFileSystem>(params, OpenProtocolAttributes::GetProtocol)
    }
    .map_err(|error| ConfigLoadError::Firmware(error.status()))?;
    let mut root = file_system
        .open_volume()
        .map_err(|error| ConfigLoadError::Firmware(error.status()))?;
    let file = root
        .open(CONFIG_FILE_PATH, FileMode::Read, FileAttribute::empty())
        .map_err(|error| ConfigLoadError::Firmware(error.status()))?;
    let mut file = file
        .into_regular_file()
        .ok_or(ConfigLoadError::NotRegularFile)?;

    let mut bytes = [0u8; CONFIG_FILE_MAX_BYTES + 1];
    let mut length = 0;
    loop {
        let read = file
            .read(&mut bytes[length..])
            .map_err(|error| ConfigLoadError::Firmware(error.status()))?;
        length += read;
        if read == 0 || length == bytes.len() {
            break;
        }
    }
    if length > CONFIG_FILE_MAX_BYTES {
        return Err(ConfigLoadError::TooLarge);
    }
    config::parse(&bytes[..length]).map_err(ConfigLoadError::Parse)
}

mod boot_order {
    use alloc::vec::Vec;

    extern crate alloc;

    const LOAD_OPTION_ACTIVE: u32 = 1;
    const DEVICE_PATH_HEADER_SIZE: usize = 4;
    const DEVICE_PATH_END_TYPE: u8 = 0x7f;
    const DEVICE_PATH_END_INSTANCE: u8 = 0x01;
    const DEVICE_PATH_END_ENTIRE: u8 = 0xff;
    const DEVICE_PATH_MEDIA_TYPE: u8 = 0x04;
    const DEVICE_PATH_FILE_SUBTYPE: u8 = 0x04;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ParseError {
        InvalidBootOrder,
        TruncatedLoadOption,
        UnterminatedDescription,
        InvalidDevicePath,
    }

    pub(crate) fn parse_boot_order(bytes: &[u8]) -> Result<Vec<u16>, ParseError> {
        if !bytes.len().is_multiple_of(2) {
            return Err(ParseError::InvalidBootOrder);
        }
        Ok(bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|number| u16::from_le_bytes([number[0], number[1]]))
            .collect())
    }

    pub(crate) struct BootOption<'a> {
        pub attributes: u32,
        pub description: &'a [u8],
        pub image_path: &'a [u8],
        pub optional_data: &'a [u8],
    }

    impl BootOption<'_> {
        pub(crate) fn is_active(&self) -> bool {
            self.attributes & LOAD_OPTION_ACTIVE != 0
        }

        pub(crate) fn image_file_path(&self) -> Option<Vec<u16>> {
            let mut offset = 0;
            let mut path = Vec::new();
            let separator = u16::from(b'\\');
            while offset < self.image_path.len() {
                let node_size =
                    u16::from_le_bytes([self.image_path[offset + 2], self.image_path[offset + 3]])
                        as usize;
                let node = &self.image_path[offset..offset + node_size];
                if node[0] == DEVICE_PATH_END_TYPE {
                    break;
                }
                if node[0] == DEVICE_PATH_MEDIA_TYPE && node[1] == DEVICE_PATH_FILE_SUBTYPE {
                    let mut characters = node[DEVICE_PATH_HEADER_SIZE..]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|character| u16::from_le_bytes([character[0], character[1]]))
                        .take_while(|character| *character != 0)
                        .peekable();
                    if let Some(first) = characters.peek().copied() {
                        if path.last() == Some(&separator) && first == separator {
                            characters.next();
                        } else if path.last() != Some(&separator) && first != separator {
                            path.push(separator);
                        }
                        path.extend(characters);
                    }
                }
                offset += node_size;
            }
            (!path.is_empty()).then_some(path)
        }

        pub(crate) fn image_file_path_matches(&self, expected: &str) -> bool {
            self.image_file_path().is_some_and(|path| {
                path.len() == expected.len()
                    && path.iter().zip(expected.bytes()).all(|(actual, wanted)| {
                        u8::try_from(*actual)
                            .is_ok_and(|actual| actual.eq_ignore_ascii_case(&wanted))
                    })
            })
        }
    }

    pub(crate) fn parse_boot_option(bytes: &[u8]) -> Result<BootOption<'_>, ParseError> {
        if bytes.len() < 8 {
            return Err(ParseError::TruncatedLoadOption);
        }
        let attributes = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let path_list_size = u16::from_le_bytes(bytes[4..6].try_into().unwrap()) as usize;
        let mut offset = 6;
        let description_start = offset;
        loop {
            if offset + 2 > bytes.len() {
                return Err(ParseError::UnterminatedDescription);
            }
            let character = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
            offset += 2;
            if character == 0 {
                break;
            }
        }
        let description = &bytes[description_start..offset - 2];
        let path_list_end = offset
            .checked_add(path_list_size)
            .filter(|end| *end <= bytes.len())
            .ok_or(ParseError::TruncatedLoadOption)?;
        let paths = &bytes[offset..path_list_end];
        let mut path_offset = 0;
        let mut first_path_end = None;
        while path_offset < paths.len() {
            if path_offset + DEVICE_PATH_HEADER_SIZE > paths.len() {
                return Err(ParseError::InvalidDevicePath);
            }
            let node_size =
                u16::from_le_bytes([paths[path_offset + 2], paths[path_offset + 3]]) as usize;
            if node_size < DEVICE_PATH_HEADER_SIZE || path_offset + node_size > paths.len() {
                return Err(ParseError::InvalidDevicePath);
            }
            let major = paths[path_offset];
            let minor = paths[path_offset + 1];
            if major == DEVICE_PATH_MEDIA_TYPE && minor == DEVICE_PATH_FILE_SUBTYPE {
                let file_path_size = node_size - DEVICE_PATH_HEADER_SIZE;
                if file_path_size < 2
                    || !file_path_size.is_multiple_of(2)
                    || paths[path_offset + node_size - 2..path_offset + node_size] != [0, 0]
                    || paths[path_offset + DEVICE_PATH_HEADER_SIZE..path_offset + node_size - 2]
                        .as_chunks::<2>()
                        .0
                        .contains(&[0, 0])
                {
                    return Err(ParseError::InvalidDevicePath);
                }
            }
            path_offset += node_size;
            if major == DEVICE_PATH_END_TYPE {
                if node_size != DEVICE_PATH_HEADER_SIZE
                    || (minor != DEVICE_PATH_END_INSTANCE && minor != DEVICE_PATH_END_ENTIRE)
                {
                    return Err(ParseError::InvalidDevicePath);
                }
                if minor == DEVICE_PATH_END_ENTIRE && first_path_end.is_none() {
                    first_path_end = Some(path_offset);
                }
            }
        }
        if path_offset != paths.len() || paths.len() < DEVICE_PATH_HEADER_SIZE {
            return Err(ParseError::InvalidDevicePath);
        }
        let first_path_end = first_path_end.ok_or(ParseError::InvalidDevicePath)?;
        if paths[paths.len() - DEVICE_PATH_HEADER_SIZE] != DEVICE_PATH_END_TYPE
            || paths[paths.len() - DEVICE_PATH_HEADER_SIZE + 1] != DEVICE_PATH_END_ENTIRE
        {
            return Err(ParseError::InvalidDevicePath);
        }
        Ok(BootOption {
            attributes,
            description,
            image_path: &paths[..first_path_end],
            optional_data: &bytes[path_list_end..],
        })
    }
}

pub(crate) mod memory_map {
    use uefi::Status;
    use uefi::boot;
    use uefi::mem::memory_map::{MemoryMap, MemoryType};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct MemoryMapSummary {
        pub descriptor_count: usize,
        pub conventional_pages: u64,
    }

    pub fn snapshot() -> Result<MemoryMapSummary, Status> {
        let memory_map =
            boot::memory_map(MemoryType::LOADER_DATA).map_err(|error| error.status())?;
        let descriptor_count = memory_map.entries().count();
        let conventional_pages = memory_map
            .entries()
            .filter(|descriptor| descriptor.ty == MemoryType::CONVENTIONAL)
            .map(|descriptor| descriptor.page_count)
            .sum();

        Ok(MemoryMapSummary {
            descriptor_count,
            conventional_pages,
        })
    }
}

const HANDLE_COUNT_CAPACITY: usize = 128;
const VERACRYPT_BOOT_PATH_TEXT: &str = r"\EFI\VeraCrypt\DcsBoot.efi";

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
        uefi_runtime::get_variable_boxed(cstr16!("BootOrder"), &VariableVendor::GLOBAL_VARIABLE)
            .map_err(|error| error.status())?;
    let numbers = boot_order::parse_boot_order(&order).map_err(|_| Status::COMPROMISED_DATA)?;
    runtime::info(format_args!("NVRAM BootOrder entries={}", numbers.len()));

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
        let data = match uefi_runtime::get_variable_boxed(name, &VariableVendor::GLOBAL_VARIABLE) {
            Ok((data, _)) => data,
            Err(error) => {
                runtime::error(format_args!("NVRAM {name}: {:?}", error.status()));
                continue;
            }
        };
        let option = match boot_order::parse_boot_option(&data) {
            Ok(option) => option,
            Err(error) => {
                runtime::error(format_args!("NVRAM {name}: invalid {error:?}"));
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
        crate::diagnostics::message(format_args!(
            "NVRAM {name} active={} {description}",
            option.is_active()
        ));
        crate::diagnostics::message(format_args!("NVRAM {name} path={file_path}"));
        runtime::info(format_args!(
            "NVRAM {name} attributes={:#x} description={description} path={file_path} path_bytes={} optional_bytes={}",
            option.attributes,
            option.image_path.len(),
            option.optional_data.len()
        ));
        if selected.is_none()
            && option.is_active()
            && option.image_file_path_matches(VERACRYPT_BOOT_PATH_TEXT)
        {
            crate::diagnostics::message(format_args!("NVRAM VeraCrypt target={name}"));
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
    crate::diagnostics::message(format_args!(
        "Boot{:04X} first node type={:#x} subtype={:#x}",
        option.number,
        first_node.device_type().0,
        first_node.sub_type().0
    ));
    if first_node.full_type() != (DeviceType::MEDIA, DeviceSubType::MEDIA_HARD_DRIVE) {
        crate::diagnostics::message(format_args!(
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
    crate::diagnostics::message(format_args!(
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
        crate::diagnostics::message(format_args!(
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
                crate::diagnostics::message(format_args!(
                    "Boot{:04X} expanded LoadImage OK",
                    option.number
                ));
                return Ok(child_handle);
            }
            Err(error) => {
                last_status = error.status();
                crate::diagnostics::message(format_args!(
                    "Boot{:04X} expanded LoadImage: {last_status:?}",
                    option.number
                ));
            }
        }
    }
    if !matched {
        crate::diagnostics::error(format_args!(
            "Boot{:04X} HD partition not found",
            option.number
        ));
    }
    Err(last_status)
}

fn same_hd_partition(original: &[u8], candidate: &[u8]) -> bool {
    if original.len() != 38
        || candidate.len() != 38
        || original[..4] != candidate[..4]
        || original[36..38] != candidate[36..38]
    {
        return false;
    }
    match original[37] {
        0 => original[4..20] == candidate[4..20],
        1 => original[20..24] == candidate[20..24],
        2 => original[20..36] == candidate[20..36],
        _ => false,
    }
}

pub fn initialize_boot_environment() -> Result<(), Status> {
    boot::set_watchdog_timer(0, 0x10000, None).map_err(|error| error.status())?;
    log::info!("MatrixHV UEFI bootstrap started");
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageResidencyReport {
    pub code_type: uefi::mem::memory_map::MemoryType,
    pub data_type: uefi::mem::memory_map::MemoryType,
}

pub fn image_residency() -> Result<ImageResidencyReport, Status> {
    let image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
        .map_err(|error| error.status())?;
    Ok(ImageResidencyReport {
        code_type: image.code_type(),
        data_type: image.data_type(),
    })
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

pub(crate) fn configure_image_load_options(
    child_handle: uefi::Handle,
    options: &[u8],
) -> Result<(), Status> {
    if options.is_empty() {
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

static EVENT_CONTEXT_ADDRESS: AtomicU64 = AtomicU64::new(0);
static EBS_SEEN_OFFSET: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn publish_events(context: u64, ebs_seen_offset: usize) {
    EBS_SEEN_OFFSET.store(ebs_seen_offset, Ordering::Relaxed);
    EVENT_CONTEXT_ADDRESS.store(context, Ordering::Release);
}

pub(crate) fn boot_services_exited() -> bool {
    let context = EVENT_CONTEXT_ADDRESS.load(Ordering::Acquire);
    if context == 0 {
        return false;
    }
    // Residency publishes retained runtime storage after event registration.
    let flag = context + EBS_SEEN_OFFSET.load(Ordering::Relaxed) as u64;
    unsafe { (*(flag as *const AtomicU64)).load(Ordering::Acquire) != 0 }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PciDiscoveryError {
    Allocation(Status),
    PciBar(Status),
    InvalidPciBar,
    AddressOverflow,
    GuestPhysicalAddressTooWide(u64),
}

const PCI_BAR_DESCRIPTOR_SIZE: usize = 46;
const FIRMWARE_PHYSICAL_LIMIT: u64 = 1 << 48;

pub(crate) fn memory_descriptors() -> Result<Vec<uefi::mem::memory_map::MemoryDescriptor>, Status> {
    use uefi::mem::memory_map::{MemoryMap, MemoryType};
    let map = boot::memory_map(MemoryType::LOADER_DATA).map_err(|error| error.status())?;
    Ok(map.entries().copied().collect())
}
#[repr(C)]
#[unsafe_protocol("4cf5b200-68b8-4ca5-9eec-b23e3f50029a")]
struct PciIoProtocol {
    // EFI_PCI_IO_PROTOCOL places GetBarAttributes after sixteen function slots.
    _preceding_functions: [usize; 16],
    get_bar_attributes:
        unsafe extern "efiapi" fn(*mut PciIoProtocol, u8, *mut u64, *mut *mut c_void) -> Status,
}
const _: () =
    assert!(core::mem::offset_of!(PciIoProtocol, get_bar_attributes) == 16 * size_of::<usize>());

pub(crate) fn pci_bar_ranges() -> Result<Vec<(u64, u64)>, PciDiscoveryError> {
    let handles = match boot::find_handles::<PciIoProtocol>() {
        Ok(handles) => handles,
        Err(error) if error.status() == Status::NOT_FOUND => return Ok(Vec::new()),
        Err(error) => return Err(PciDiscoveryError::Allocation(error.status())),
    };
    let mut ranges = Vec::new();
    for handle in handles {
        let params = OpenProtocolParams {
            handle,
            agent: boot::image_handle(),
            controller: None,
        };
        let pci_io = unsafe {
            boot::open_protocol::<PciIoProtocol>(params, OpenProtocolAttributes::GetProtocol)
        }
        .map_err(|error| PciDiscoveryError::PciBar(error.status()))?;
        let mut device_ranges = Vec::new();
        for bar_index in 0..6 {
            let mut resources = core::ptr::null_mut();
            let status = unsafe {
                (pci_io.get_bar_attributes)(
                    (&*pci_io as *const PciIoProtocol).cast_mut(),
                    bar_index,
                    core::ptr::null_mut(),
                    &mut resources,
                )
            };
            if status == Status::UNSUPPORTED {
                continue;
            }
            if status != Status::SUCCESS {
                return Err(PciDiscoveryError::PciBar(status));
            }
            let resource_pointer =
                NonNull::new(resources.cast::<u8>()).ok_or(PciDiscoveryError::InvalidPciBar)?;
            let range = read_pci_bar_range(resource_pointer.as_ptr());
            unsafe { boot::free_pool(resource_pointer) }
                .map_err(|error| PciDiscoveryError::PciBar(error.status()))?;
            if let Some(range) = range? {
                device_ranges.push(range);
            }
        }
        drop(pci_io);
        for (start, end) in device_ranges {
            ranges.push((start, end));
        }
    }
    Ok(ranges)
}

fn read_pci_bar_range(resources: *const u8) -> Result<Option<(u64, u64)>, PciDiscoveryError> {
    if unsafe { resources.read() } != 0x8a {
        return Ok(None);
    }
    let descriptor = unsafe { core::slice::from_raw_parts(resources, PCI_BAR_DESCRIPTOR_SIZE) };
    if u16::from_le_bytes([descriptor[1], descriptor[2]]) != 0x2b || descriptor[3] != 0 {
        return Ok(None);
    }
    let start = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
    let length = u64::from_le_bytes(descriptor[38..46].try_into().unwrap());
    if length == 0 {
        return Ok(None);
    }
    let end = start
        .checked_add(length)
        .ok_or(PciDiscoveryError::AddressOverflow)?;
    if end > FIRMWARE_PHYSICAL_LIMIT {
        return Err(PciDiscoveryError::GuestPhysicalAddressTooWide(end));
    }
    Ok(Some((start, end)))
}

// The caller must retain executable EFI callbacks, their context and bridge pages
// through both notifications. Registration rolls back before releasing those pages.
pub(crate) unsafe fn register_residency_events(
    exit_boot_services_callback: u64,
    virtual_address_change_callback: u64,
    bridge: &VariableBridge,
    context: u64,
) -> Result<(Event, Event), Status> {
    let notify_context = NonNull::new(context as *mut c_void).ok_or(Status::OUT_OF_RESOURCES)?;
    let ebs_callback = unsafe {
        core::mem::transmute::<usize, EventNotifyFn>(exit_boot_services_callback as usize)
    };
    let va_callback = unsafe {
        core::mem::transmute::<usize, EventNotifyFn>(virtual_address_change_callback as usize)
    };
    let ebs_event = unsafe {
        boot::create_event(
            EventType::SIGNAL_EXIT_BOOT_SERVICES,
            Tpl::NOTIFY,
            Some(ebs_callback),
            Some(notify_context),
        )
    }
    .map_err(|error| error.status())?;
    let va_event = match unsafe {
        boot::create_event(
            EventType::SIGNAL_VIRTUAL_ADDRESS_CHANGE,
            Tpl::NOTIFY,
            Some(va_callback),
            Some(notify_context),
        )
    } {
        Ok(event) => event,
        Err(error) => {
            let _ = boot::close_event(ebs_event);
            return Err(error.status());
        }
    };
    if let Err(status) = install_control_bridge(bridge, context) {
        let _ = boot::close_event(va_event);
        let _ = boot::close_event(ebs_event);
        return Err(status);
    }
    Ok((ebs_event, va_event))
}

fn install_control_bridge(code: &VariableBridge, context: u64) -> Result<(), Status> {
    let table = uefi::table::system_table_raw().ok_or(Status::NOT_READY)?;
    let system = unsafe { table.as_ref() };
    let runtime = unsafe { system.runtime_services.as_mut() }.ok_or(Status::NOT_READY)?;
    if (runtime.header.size as usize) < size_of::<uefi_raw::table::runtime::RuntimeServices>()
        || runtime.header.size as usize > PAGE_SIZE
    {
        return Err(Status::INCOMPATIBLE_VERSION);
    }
    let original_get = runtime.get_variable;
    let original_set = runtime.set_variable;
    let original_crc = runtime.header.crc;
    unsafe {
        (code.original_get_variable_slot as *mut u64).write(original_get as usize as u64);
        (code.original_set_variable_slot as *mut u64).write(original_set as usize as u64);
        (code.convert_pointer_slot as *mut u64).write(runtime.convert_pointer as usize as u64);
        (code.bridge_context_slot as *mut u64).write(context);
        (code.runtime_get_variable_slot as *mut u64).write(code.get_variable_bridge);
        (code.runtime_set_variable_slot as *mut u64).write(code.set_variable_bridge);
        runtime.get_variable = core::mem::transmute::<
            usize,
            unsafe extern "efiapi" fn(
                *const uefi_raw::Char16,
                *const uefi_raw::Guid,
                *mut uefi_raw::table::runtime::VariableAttributes,
                *mut usize,
                *mut u8,
            ) -> uefi_raw::Status,
        >(code.get_variable_bridge as usize);
        runtime.set_variable = core::mem::transmute::<
            usize,
            unsafe extern "efiapi" fn(
                *const uefi_raw::Char16,
                *const uefi_raw::Guid,
                uefi_raw::table::runtime::VariableAttributes,
                usize,
                *const u8,
            ) -> uefi_raw::Status,
        >(code.set_variable_bridge as usize);
    }
    runtime.header.crc = 0;
    let table_bytes = unsafe {
        core::slice::from_raw_parts(
            (runtime as *const uefi_raw::table::runtime::RuntimeServices).cast::<u8>(),
            runtime.header.size as usize,
        )
    };
    let result = boot::calculate_crc32(table_bytes)
        .map_err(|error| error.status())
        .and_then(|crc| {
            runtime.header.crc = crc;
            verify_control_bridge(runtime)
        });
    if result.is_err() {
        runtime.get_variable = original_get;
        runtime.set_variable = original_set;
        runtime.header.crc = original_crc;
    }
    result
}

fn verify_control_bridge(
    runtime: &uefi_raw::table::runtime::RuntimeServices,
) -> Result<(), Status> {
    const GUID: uefi_raw::Guid = uefi_raw::guid!("a830e824-19a4-42c4-9178-81ee63c135cc");
    let mut value = ControlStatus::default();
    let mut value_size = size_of::<ControlStatus>();
    let mut attributes = uefi_raw::table::runtime::VariableAttributes::empty();
    let result = unsafe {
        (runtime.get_variable)(
            uefi::cstr16!("MatrixHVControl").as_ptr().cast(),
            &GUID,
            &mut attributes,
            &mut value_size,
            (&mut value as *mut ControlStatus).cast(),
        )
    };
    if result != Status::SUCCESS
        || value_size != size_of::<ControlStatus>()
        || attributes.bits() != 7
        || value.magic != CONTROL_MAGIC
        || value.version != CONTROL_VERSION
    {
        return Err(Status::DEVICE_ERROR);
    }
    Ok(())
}
pub(crate) fn calibrate_reference_tsc() -> u64 {
    use uefi::table::cfg::ConfigTableEntry;

    let root = uefi::system::with_config_table(|entries| {
        entries
            .iter()
            .find(|entry| entry.guid == ConfigTableEntry::ACPI2_GUID)
            .or_else(|| {
                entries
                    .iter()
                    .find(|entry| entry.guid == ConfigTableEntry::ACPI_GUID)
            })
            .map(|entry| entry.address as usize)
    });
    let Some((port, mask)) = root.and_then(|address| unsafe { acpi_pm_timer(address) }) else {
        return 0;
    };
    crate::hyperv::calibrated_tsc_hz(|| {
        let read_timer = || {
            let value: u32;
            unsafe {
                core::arch::asm!("in eax, dx", in("dx") port, out("eax") value,
                    options(nomem, nostack, preserves_flags));
            }
            value & mask
        };
        let read_tsc = || unsafe {
            core::arch::x86_64::_mm_lfence();
            core::arch::x86_64::_rdtsc()
        };
        let start_pm = read_timer();
        let start_tsc = read_tsc();
        for _ in 0..1_000_000 {
            let pm_ticks = read_timer().wrapping_sub(start_pm) & mask;
            let tsc_ticks = read_tsc().wrapping_sub(start_tsc);
            if pm_ticks >= 35_795 {
                return Some((tsc_ticks, pm_ticks));
            }
            core::hint::spin_loop();
        }
        None
    })
}

// Only firmware-installed ACPI pointers are dereferenced, before VMXON/EBS.
unsafe fn acpi_pm_timer(address: usize) -> Option<(u16, u32)> {
    if address == 0 {
        return None;
    }
    let root = unsafe { core::slice::from_raw_parts(address as *const u8, 20) };
    let checksum = |bytes: &[u8]| bytes.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte)) == 0;
    if &root[..8] != b"RSD PTR " || !checksum(root) {
        return None;
    }
    let mut table_address = u32::from_le_bytes(root[16..20].try_into().ok()?) as usize;
    let mut stride = 4;
    if root[15] >= 2 {
        let extended = unsafe { core::slice::from_raw_parts(address as *const u8, 36) };
        let length = u32::from_le_bytes(extended[20..24].try_into().ok()?) as usize;
        if !(36..=4096).contains(&length)
            || !checksum(unsafe { core::slice::from_raw_parts(address as *const u8, length) })
        {
            return None;
        }
        let xsdt = u64::from_le_bytes(extended[24..32].try_into().ok()?) as usize;
        if xsdt != 0 {
            table_address = xsdt;
            stride = 8;
        }
    }
    let table = unsafe { acpi_table(table_address) }?;
    if &table[..4] != if stride == 8 { b"XSDT" } else { b"RSDT" } {
        return None;
    }
    if !(table.len() - 36).is_multiple_of(stride) {
        return None;
    }
    for entry in table[36..].chunks_exact(stride) {
        let mut bytes = [0_u8; 8];
        bytes[..stride].copy_from_slice(entry);
        let Some(child) = (unsafe { acpi_table(u64::from_le_bytes(bytes) as usize) }) else {
            continue;
        };
        if &child[..4] == b"FACP" {
            return acpi_pm_timer_register(child);
        }
    }
    None
}

unsafe fn acpi_table(address: usize) -> Option<&'static [u8]> {
    if address == 0 {
        return None;
    }
    let header = unsafe { core::slice::from_raw_parts(address as *const u8, 36) };
    let length = u32::from_le_bytes(header[4..8].try_into().ok()?) as usize;
    if !(36..=1_048_576).contains(&length) {
        return None;
    }
    let table = unsafe { core::slice::from_raw_parts(address as *const u8, length) };
    (table.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte)) == 0).then_some(table)
}

fn acpi_pm_timer_register(fadt: &[u8]) -> Option<(u16, u32)> {
    if fadt.len() < 116 || fadt[91] != 4 {
        return None;
    }
    let flags = u32::from_le_bytes(fadt[112..116].try_into().ok()?);
    if flags & (1 << 20) != 0 {
        return None;
    }
    let mut port = u64::from(u32::from_le_bytes(fadt[76..80].try_into().ok()?));
    if fadt.len() >= 220 {
        let extended = u64::from_le_bytes(fadt[212..220].try_into().ok()?);
        if extended != 0 {
            if fadt[208] != 1
                || ![24, 32].contains(&fadt[209])
                || fadt[210] != 0
                || ![0, 3].contains(&fadt[211])
            {
                return None;
            }
            port = extended;
        }
    }
    if port == 0 || port > u64::from(u16::MAX) {
        return None;
    }
    Some((
        port as u16,
        if flags & (1 << 8) != 0 {
            u32::MAX
        } else {
            0xff_ffff
        },
    ))
}
