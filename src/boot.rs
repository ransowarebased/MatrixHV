use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use core::mem::{MaybeUninit, size_of_val};
use core::str;
use core::sync::atomic::{AtomicBool, Ordering};

use uefi::boot::{self, LoadImageSource, OpenProtocolAttributes, OpenProtocolParams, SearchType};
use uefi::proto::BootPolicy;
use uefi::proto::device_path::{DevicePath, DeviceSubType, DeviceType, build};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::runtime::{self as uefi_runtime, VariableVendor};
use uefi::{CStr16, Status, cstr16};

use crate::arch::{self, Vendor};
use crate::guest;
use crate::hv_core;
use crate::memory;
use crate::runtime;
use crate::smp;

pub const CONFIG_HEADER: &str = "MATRIXHV_CONFIG_V2";
pub const CPUIDPRESENCE_KEY: &str = "cpuidpresence";
pub const LOGGER_KEY: &str = "logger";
pub const VT_NESTED_KEY: &str = "VtNested";
pub const VMX_TEST_KEY: &str = "VmxTest";

const CONFIG_FILE_PATH: &CStr16 = cstr16!(r"\MatrixConfig.bin");
const CONFIG_FILE_MAX_BYTES: usize = 4096;

static CPUID_PRESENCE: AtomicBool = AtomicBool::new(false);
static LOGGER: AtomicBool = AtomicBool::new(true);
static VT_NESTED: AtomicBool = AtomicBool::new(true);
static VMX_TEST: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatrixConfig {
    pub cpuid_presence: bool,
    pub logger: bool,
    pub vt_nested: bool,
    pub vmx_test: bool,
}

impl Default for MatrixConfig {
    fn default() -> Self {
        Self {
            cpuid_presence: false,
            logger: true,
            vt_nested: true,
            vmx_test: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    MissingHeader,
    InvalidEncoding,
    InvalidLine,
    InvalidBoolean,
    UnknownKey,
    VmxTestRequiresVtNested,
}

pub fn parse(bytes: &[u8]) -> Result<MatrixConfig, ParseError> {
    let text = str::from_utf8(bytes).map_err(|_| ParseError::InvalidEncoding)?;
    let mut config = MatrixConfig::default();
    let mut has_header = false;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line == CONFIG_HEADER {
            has_header = true;
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, value) = line.split_once('=').ok_or(ParseError::InvalidLine)?;
        let parsed = parse_bool(value.trim())?;
        match key.trim() {
            CPUIDPRESENCE_KEY => config.cpuid_presence = parsed,
            LOGGER_KEY => config.logger = parsed,
            VT_NESTED_KEY => config.vt_nested = parsed,
            VMX_TEST_KEY => config.vmx_test = parsed,
            _ => return Err(ParseError::UnknownKey),
        }
    }

    if !has_header {
        return Err(ParseError::MissingHeader);
    }
    if config.vmx_test && !config.vt_nested {
        return Err(ParseError::VmxTestRequiresVtNested);
    }

    Ok(config)
}

fn parse_bool(value: &str) -> Result<bool, ParseError> {
    if value.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(ParseError::InvalidBoolean)
    }
}

pub fn apply(config: MatrixConfig) {
    CPUID_PRESENCE.store(config.cpuid_presence, Ordering::Relaxed);
    LOGGER.store(config.logger, Ordering::Relaxed);
    VT_NESTED.store(config.vt_nested, Ordering::Relaxed);
    VMX_TEST.store(config.vmx_test, Ordering::Relaxed);
}

pub fn current() -> MatrixConfig {
    MatrixConfig {
        cpuid_presence: CPUID_PRESENCE.load(Ordering::Relaxed),
        logger: LOGGER.load(Ordering::Relaxed),
        vt_nested: VT_NESTED.load(Ordering::Relaxed),
        vmx_test: VMX_TEST.load(Ordering::Relaxed),
    }
}

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
    parse(&bytes[..length]).map_err(ConfigLoadError::Parse)
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
            while offset < self.image_path.len() {
                let node_size =
                    u16::from_le_bytes([self.image_path[offset + 2], self.image_path[offset + 3]])
                        as usize;
                let node = &self.image_path[offset..offset + node_size];
                if node[0] == DEVICE_PATH_MEDIA_TYPE && node[1] == DEVICE_PATH_FILE_SUBTYPE {
                    let path: Vec<u16> = node[DEVICE_PATH_HEADER_SIZE..]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|character| u16::from_le_bytes([character[0], character[1]]))
                        .take_while(|character| *character != 0)
                        .collect();
                    return Some(path);
                }
                offset += node_size;
            }
            None
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

mod memory_map {
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

pub mod screen {
    use alloc::boxed::Box;
    use core::fmt::{self, Write};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::time::Duration;

    use uefi::boot::{OpenProtocolAttributes, OpenProtocolParams};
    use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
    use uefi::{boot, system, table};
    use uefi_raw::protocol::console::GraphicsOutputProtocol;

    const RESIDENT_MARKER_X: usize = 16;
    const RESIDENT_MARKER_Y: usize = 16;
    pub(crate) const RESIDENT_MARKER_STEP: usize = 20;
    pub(crate) const RESIDENT_MARKER_ROW_STEP: usize = 24;
    pub(crate) const RESIDENT_MARKER_SIZE: usize = 12;
    const RESIDENT_MARKER_COUNT: usize = 8;
    const RESIDENT_MARKER_ROWS: usize = 4;
    pub(crate) const RESIDENT_HEX_Y: usize = 96;
    pub(crate) const RESIDENT_HEX_ROW_STEP: usize = 16;
    pub(crate) const RESIDENT_HEX_ROWS: usize = 32;
    pub(crate) const RESIDENT_HEX_COLUMN_STEP: usize = 176;
    const VMEXIT_GRID_X: usize = 32;
    const VMEXIT_GRID_STEP: usize = 14;
    const VMEXIT_GRID_SIZE: usize = 12;
    const VMEXIT_HALT_Y: usize = 320;
    const HALT_HEX_X: usize = 300;
    const HALT_GPA_Y: usize = 220;
    const HALT_RIP_Y: usize = 250;
    const HALT_QUALIFICATION_Y: usize = 280;
    const HEX_DIGITS: [[u8; 5]; 16] = [
        [0b111, 0b101, 0b101, 0b101, 0b111],
        [0b010, 0b110, 0b010, 0b010, 0b111],
        [0b111, 0b001, 0b111, 0b100, 0b111],
        [0b111, 0b001, 0b111, 0b001, 0b111],
        [0b101, 0b101, 0b111, 0b001, 0b001],
        [0b111, 0b100, 0b111, 0b001, 0b111],
        [0b111, 0b100, 0b111, 0b101, 0b111],
        [0b111, 0b001, 0b010, 0b010, 0b010],
        [0b111, 0b101, 0b111, 0b101, 0b111],
        [0b111, 0b101, 0b111, 0b001, 0b111],
        [0b111, 0b101, 0b111, 0b101, 0b101],
        [0b110, 0b101, 0b110, 0b101, 0b110],
        [0b111, 0b100, 0b100, 0b100, 0b111],
        [0b110, 0b101, 0b101, 0b101, 0b110],
        [0b111, 0b100, 0b111, 0b100, 0b111],
        [0b111, 0b100, 0b111, 0b100, 0b100],
    ];
    static FRAMEBUFFER_BASE: AtomicUsize = AtomicUsize::new(0);
    static FRAMEBUFFER_SIZE: AtomicUsize = AtomicUsize::new(0);
    static FRAMEBUFFER_STRIDE: AtomicUsize = AtomicUsize::new(0);
    static FRAMEBUFFER_WIDTH: AtomicUsize = AtomicUsize::new(0);
    static FRAMEBUFFER_HEIGHT: AtomicUsize = AtomicUsize::new(0);
    static GOP_PROTOCOL_POINTER: AtomicUsize = AtomicUsize::new(0);
    static GOP_MODE_NUMBER: AtomicUsize = AtomicUsize::new(0);

    fn firmware_calls_allowed(rflags: u64, apic_base: u64) -> bool {
        rflags & (1 << 9) != 0 && apic_base & (1 << 8) != 0
    }

    fn console_available() -> bool {
        if crate::hv_core::vt_resident::boot_services_exited() {
            return false;
        }
        // UEFI protocols run on the BSP with interrupts enabled. In particular,
        // OutputString may restore TPL and enable interrupts inside a VMX probe.
        let rflags = crate::arch::read_rflags();
        let apic_base = unsafe { crate::arch::read_msr(0x1b) };
        if !firmware_calls_allowed(rflags, apic_base) {
            return false;
        }
        let Some(system_table) = table::system_table_raw() else {
            return false;
        };
        // The entry macro owns this pointer while the UEFI image is running.
        let system_table = unsafe { system_table.as_ref() };
        !system_table.boot_services.is_null() && !system_table.stdout.is_null()
    }

    pub fn begin() {
        if !crate::runtime::framebuffer_enabled() || !console_available() {
            return;
        }
        system::with_stdout(|stdout| {
            let _ = stdout.clear();
            let _ = writeln!(stdout, "MatrixHV UEFI boot diagnostics");
            let _ = writeln!(stdout, "BOOTX64.EFI entry reached");
        });
    }

    pub fn stage(name: &str) {
        crate::runtime::phase(name);
    }

    pub fn page(name: &str) {
        if crate::runtime::framebuffer_enabled() && console_available() {
            system::with_stdout(|stdout| {
                let _ = stdout.clear();
                let _ = writeln!(stdout, "MatrixHV resident guest diagnostics");
            });
        }
        stage(name);
    }

    pub fn prepare_resident_visuals() -> bool {
        if !crate::runtime::framebuffer_enabled() {
            return false;
        }
        let Ok(handle) = boot::get_handle_for_protocol::<GraphicsOutput>() else {
            return false;
        };
        let params = OpenProtocolParams {
            handle,
            agent: boot::image_handle(),
            controller: None,
        };
        let Ok(graphics) = (unsafe {
            boot::open_protocol::<GraphicsOutput>(params, OpenProtocolAttributes::GetProtocol)
        }) else {
            return false;
        };
        let mut graphics = graphics;
        let protocol_pointer =
            (&*graphics as *const GraphicsOutput).cast::<GraphicsOutputProtocol>();
        let mode_pointer = unsafe { (*protocol_pointer).mode };
        if mode_pointer.is_null() {
            return false;
        }
        let mode_number = unsafe { (*mode_pointer).mode };
        let mode = graphics.current_mode_info();
        let (width, height) = mode.resolution();
        let stride = mode.stride();
        let required_width = RESIDENT_MARKER_X
            + ((RESIDENT_MARKER_COUNT - 1) * RESIDENT_MARKER_STEP + RESIDENT_MARKER_SIZE)
                .max((RESIDENT_HEX_ROWS - 1) / 16 * RESIDENT_HEX_COLUMN_STEP + 18 * 8);
        let required_height = RESIDENT_MARKER_Y
            + ((RESIDENT_MARKER_ROWS - 1) * RESIDENT_MARKER_ROW_STEP + RESIDENT_MARKER_SIZE)
                .max(RESIDENT_HEX_Y + (RESIDENT_HEX_ROWS.min(16) - 1) * RESIDENT_HEX_ROW_STEP + 10);
        let Some(last_pixel) = (required_height - 1)
            .checked_mul(stride)
            .and_then(|offset| offset.checked_add(required_width))
            .and_then(|pixels| pixels.checked_mul(4))
        else {
            return false;
        };
        if mode.pixel_format() == PixelFormat::BltOnly
            || width < required_width
            || height < required_height
            || stride < width
        {
            return false;
        }
        let (base, size) = {
            let mut framebuffer = graphics.frame_buffer();
            if last_pixel > framebuffer.size() {
                return false;
            }
            let base = framebuffer.as_mut_ptr() as usize;
            if base == 0 {
                return false;
            }
            (base, framebuffer.size())
        };
        // Keep GOP available for fatal diagnostics before ExitBootServices.
        let _ = Box::leak(Box::new(graphics));
        FRAMEBUFFER_SIZE.store(size, Ordering::Relaxed);
        FRAMEBUFFER_STRIDE.store(stride, Ordering::Relaxed);
        FRAMEBUFFER_WIDTH.store(width, Ordering::Relaxed);
        FRAMEBUFFER_HEIGHT.store(height, Ordering::Relaxed);
        GOP_MODE_NUMBER.store(mode_number as usize, Ordering::Relaxed);
        GOP_PROTOCOL_POINTER.store(protocol_pointer as usize, Ordering::Relaxed);
        FRAMEBUFFER_BASE.store(base, Ordering::Release);
        true
    }

    pub fn resident_marker_layout() -> Option<(u64, u64)> {
        let base = FRAMEBUFFER_BASE.load(Ordering::Acquire);
        let stride = FRAMEBUFFER_STRIDE.load(Ordering::Relaxed);
        let offset = RESIDENT_MARKER_Y
            .checked_mul(stride)?
            .checked_add(RESIDENT_MARKER_X)?
            .checked_mul(4)?;
        let marker_base = base.checked_add(offset)?;
        let stride_bytes = stride.checked_mul(4)?;
        (base != 0).then_some((marker_base as u64, stride_bytes as u64))
    }

    pub extern "efiapi" fn vmexit_diagnostic(
        reason: u64,
        halted: u64,
        guest_physical_address: u64,
        guest_rip: u64,
        qualification: u64,
    ) -> u64 {
        if !crate::runtime::framebuffer_enabled() {
            return 0;
        }
        if halted == 0 {
            return u64::from(crate::guest::start_image_entered());
        }
        if !gop_mode_unchanged() {
            return 1;
        }
        let reason = usize::try_from(reason & 0xffff).unwrap_or(127).min(127);
        let x = VMEXIT_GRID_X + reason % 16 * VMEXIT_GRID_STEP;
        let y = VMEXIT_HALT_Y + reason / 16 * VMEXIT_GRID_STEP;
        paint_square(x, y, VMEXIT_GRID_SIZE);
        if halted != 0 && reason == 48 {
            paint_hex(guest_physical_address, HALT_HEX_X, HALT_GPA_Y);
            paint_hex(guest_rip, HALT_HEX_X, HALT_RIP_Y);
            paint_hex(qualification, HALT_HEX_X, HALT_QUALIFICATION_Y);
        }
        1
    }

    fn paint_hex(value: u64, x: usize, y: usize) {
        for digit_index in 0..16 {
            let shift = 60 - digit_index * 4;
            let digit = ((value >> shift) & 0xf) as usize;
            for (row, bits) in HEX_DIGITS[digit].iter().enumerate() {
                for column in 0..3 {
                    if bits & (1 << (2 - column)) != 0 {
                        paint_square(x + (digit_index * 4 + column) * 3, y + row * 3, 3);
                    }
                }
            }
        }
    }

    fn gop_mode_unchanged() -> bool {
        if crate::hv_core::vt_resident::boot_services_exited() {
            return false;
        }
        let protocol =
            GOP_PROTOCOL_POINTER.load(Ordering::Acquire) as *const GraphicsOutputProtocol;
        if protocol.is_null() {
            return false;
        }
        // A changed GOP mode invalidates the saved framebuffer address.
        let mode = unsafe { core::ptr::addr_of!((*protocol).mode).read_volatile() };
        if mode.is_null() {
            return false;
        }
        let mode_number = unsafe { core::ptr::addr_of!((*mode).mode).read_volatile() };
        let base = unsafe { core::ptr::addr_of!((*mode).frame_buffer_base).read_volatile() };
        let size = unsafe { core::ptr::addr_of!((*mode).frame_buffer_size).read_volatile() };
        mode_number as usize == GOP_MODE_NUMBER.load(Ordering::Relaxed)
            && base as usize == FRAMEBUFFER_BASE.load(Ordering::Relaxed)
            && size == FRAMEBUFFER_SIZE.load(Ordering::Relaxed)
    }

    fn paint_square(x: usize, y: usize, side: usize) {
        let base = FRAMEBUFFER_BASE.load(Ordering::Acquire);
        if base == 0 {
            return;
        }
        let size = FRAMEBUFFER_SIZE.load(Ordering::Relaxed);
        let stride = FRAMEBUFFER_STRIDE.load(Ordering::Relaxed);
        if x + side > FRAMEBUFFER_WIDTH.load(Ordering::Relaxed)
            || y + side > FRAMEBUFFER_HEIGHT.load(Ordering::Relaxed)
        {
            return;
        }
        for row in y..y + side {
            for column in x..x + side {
                let Some(offset) = row
                    .checked_mul(stride)
                    .and_then(|pixels| pixels.checked_add(column))
                    .and_then(|pixels| pixels.checked_mul(4))
                else {
                    return;
                };
                if offset > size.saturating_sub(4) {
                    return;
                }
                // Volatile writes reach the device without calling UEFI services.
                unsafe {
                    for byte in 0..4 {
                        (base as *mut u8).add(offset + byte).write_volatile(0xff);
                    }
                }
            }
        }
    }

    pub fn message(arguments: fmt::Arguments<'_>) {
        crate::runtime::info(arguments);
    }

    pub(crate) fn write_record(message: &str) {
        if !console_available() {
            return;
        }
        system::with_stdout(|stdout| {
            let _ = writeln!(stdout, "{message}");
        });
    }

    pub fn error(arguments: fmt::Arguments<'_>) {
        crate::runtime::error(arguments);
    }

    pub fn hold_on_failure() {
        if !crate::runtime::enabled() || !console_available() {
            return;
        }
        message(format_args!("Boot stopped. Press any key to return."));

        let Some(system_table) = table::system_table_raw() else {
            return;
        };
        // Boot services and stdout were checked before the message above.
        let system_table = unsafe { system_table.as_ref() };
        if !system_table.stdin.is_null() {
            system::with_stdin(|stdin| while matches!(stdin.read_key(), Ok(Some(_))) {});
            if let Ok(event) = system::with_stdin(|stdin| stdin.wait_for_key_event()) {
                let mut events = [event];
                if boot::wait_for_event(&mut events).is_ok() {
                    return;
                }
            }
        }

        loop {
            boot::stall(Duration::from_secs(1));
        }
    }
}

pub fn run() -> Result<(), Status> {
    screen::stage("UEFI boot services");
    initialize_boot_environment()?;
    screen::stage("image residency");
    let image_residency = memory::image_residency()?;
    runtime::info(format_args!(
        "residency image code_type={} data_type={}",
        image_residency.code_type.0, image_residency.data_type.0
    ));
    runtime::phase("vmx.residency.image_type.observed");

    screen::stage("Intel VMX capability");
    let capabilities = arch::capabilities();
    if capabilities.vendor != Vendor::Intel {
        log::error!("MatrixHV requires an Intel x86-64 processor");
        screen::error(format_args!("Intel processor required"));
        return Err(Status::UNSUPPORTED);
    }
    if !capabilities.vmx {
        log::error!("Intel VT-x is not exposed by CPUID");
        screen::error(format_args!("VMX not exposed by CPUID"));
        return Err(Status::UNSUPPORTED);
    }
    if !capabilities.feature_control_locked || !capabilities.vmx_outside_smx {
        log::error!("Firmware does not permit VMX operation outside SMX");
        screen::error(format_args!("firmware blocks VMX outside SMX"));
        return Err(Status::UNSUPPORTED);
    }

    log::info!("Intel VT-x is available and enabled by IA32_FEATURE_CONTROL");
    runtime::phase("vmx.capability.ok");

    screen::stage("processor topology");
    runtime::phase("smp.topology.start");
    let topology_report = match smp::enumerate() {
        Ok(report) => {
            runtime::info(format_args!(
                "smp topology total={} enabled={} current={} bsp={} first_enabled_ap={:?}",
                report.total_processors,
                report.enabled_processors,
                report.current_processor,
                report.bsp_processor,
                report.first_enabled_ap
            ));
            runtime::phase("smp.topology.ok");
            Some(report)
        }
        Err(status) => {
            runtime::error(format_args!("smp topology status={status:?}"));
            runtime::phase("smp.topology.unavailable");
            screen::message(format_args!("topology unavailable: {status:?}"));
            None
        }
    };

    if let Some(processor_number) = topology_report.and_then(|report| report.first_enabled_ap) {
        screen::stage("AP VMX proof");
        runtime::phase("smp.cpu1_vmx.start");
        match smp::prove_application_processor_vmx(processor_number) {
            Ok(report) => {
                runtime::info(format_args!(
                    "smp cpu1 vmx proof processor={} id={:#x} apic_id={:#x} vmxon={:#x} vmcs={:#x} guest_stack={:#x} bsp_vmxon={:#x} bsp_vmcs={:#x} bsp_guest_stack={:#x}",
                    report.processor_number,
                    report.processor_id,
                    report.initial_state.apic_id,
                    report.ap_resources.vmxon,
                    report.ap_resources.vmcs,
                    report.ap_resources.guest_stack,
                    report.bsp_resources.vmxon,
                    report.bsp_resources.vmcs,
                    report.bsp_resources.guest_stack
                ));
                runtime::info(format_args!(
                    "smp cpu1 vmx state cr0={:#x}->{:#x} cr3={:#x}->{:#x} cr4={:#x}->{:#x} rflags={:#x}->{:#x} exit_reason={:#x} vmxon_report_pa={:#x} vmcs_report_pa={:#x}",
                    report.initial_state.cr0,
                    report.final_state.cr0,
                    report.initial_state.cr3,
                    report.final_state.cr3,
                    report.initial_state.cr4,
                    report.final_state.cr4,
                    report.initial_state.rflags,
                    report.final_state.rflags,
                    report.vmlaunch.exit_reason,
                    report.vmlaunch.vmxon.region_physical_address,
                    report.vmlaunch.vmcs_physical_address
                ));
                runtime::phase("smp.cpu1_vmx.ok");
            }
            Err(error) => {
                runtime::error(format_args!("smp cpu1 vmx error={error:?}"));
                runtime::phase("smp.cpu1_vmx.failed");
                screen::error(format_args!("AP VMX proof: {error:?}"));
                return Err(Status::DEVICE_ERROR);
            }
        }
    } else {
        screen::message(format_args!("AP VMX proof skipped"));
        runtime::phase("smp.cpu1_vmx.skipped");
    }

    screen::stage("UEFI memory map");
    let memory = memory_map::snapshot()?;
    log::info!(
        "UEFI memory map ready: {} descriptors, {} conventional pages",
        memory.descriptor_count,
        memory.conventional_pages
    );
    runtime::info(format_args!(
        "memory_map descriptors={} conventional_pages={}",
        memory.descriptor_count, memory.conventional_pages
    ));
    runtime::phase("uefi.memory_map.ok");

    if current().vmx_test {
        screen::stage("VMXON proof");
        runtime::phase("vmx.vmxon.start");
        match hv_core::vt_vmxon::probe_vmxon() {
            Ok(report) => {
                log::info!(
                    "VMXON probe succeeded: revision={:#x}, region_size={}, region_pa={:#x}, cr0={:#x}->{:#x}, cr4={:#x}->{:#x}",
                    report.revision_id,
                    report.region_size,
                    report.region_physical_address,
                    report.original_cr0,
                    report.vmx_cr0,
                    report.original_cr4,
                    report.vmx_cr4
                );
                runtime::info(format_args!(
                    "vmxon revision={:#x} region_size={} region_pa={:#x} cr0={:#x}->{:#x} cr4={:#x}->{:#x}",
                    report.revision_id,
                    report.region_size,
                    report.region_physical_address,
                    report.original_cr0,
                    report.vmx_cr0,
                    report.original_cr4,
                    report.vmx_cr4
                ));
                runtime::phase("vmx.vmxon.ok");
            }
            Err(error) => {
                log::error!("VMXON probe failed: {error:?}");
                runtime::error(format_args!("vmxon error={error:?}"));
                runtime::phase("vmx.vmxon.failed");
                screen::error(format_args!("VMXON proof: {error:?}"));
                return Err(Status::DEVICE_ERROR);
            }
        }

        screen::stage("VMCS proof");
        runtime::phase("vmx.vmcs.start");
        match hv_core::vmcs::probe_vmcs() {
            Ok(report) => {
                runtime::info(format_args!(
                    "vmcs revision={:#x} region_pa={:#x} current_pa={:#x} instruction_error={} vmxon_pa={:#x}",
                    report.revision_id,
                    report.region_physical_address,
                    report.current_vmcs_physical_address,
                    report.instruction_error,
                    report.vmxon.region_physical_address
                ));
                runtime::phase("vmx.vmcs.ok");
            }
            Err(error) => {
                log::error!("VMCS probe failed: {error:?}");
                runtime::error(format_args!("vmcs error={error:?}"));
                runtime::phase("vmx.vmcs.failed");
                screen::error(format_args!("VMCS proof: {error:?}"));
                return Err(Status::DEVICE_ERROR);
            }
        }

        screen::stage("VMLAUNCH proof");
        runtime::phase("vmx.vmlaunch_probe.start");
        match hv_core::vt_entry::probe_vmlaunch() {
            Ok(report) => {
                runtime::info(format_args!(
                    "vmlaunch proof vmcs_pa={:#x} exit_reason={:#x} qualification={:#x} instruction_len={} guest_rip_after_exit={:#x}",
                    report.vmcs_physical_address,
                    report.exit_reason,
                    report.exit_qualification,
                    report.exit_instruction_length,
                    report.guest_rip_after_exit
                ));
                runtime::info(format_args!(
                    "vmlaunch proof vmxon_pa={:#x} host_cs={:#x} host_tr={:#x} guest_cs={:#x} guest_tr={:#x} controls primary={:#x} exit={:#x} entry={:#x}",
                    report.vmxon.region_physical_address,
                    report.host.cs_selector,
                    report.host.tr_selector,
                    report.guest.cs_selector,
                    report.guest.tr_selector,
                    report.controls.primary_processor_based,
                    report.controls.vm_exit,
                    report.controls.vm_entry
                ));
                runtime::phase("vmx.vmlaunch_probe.ok");
            }
            Err(error) => {
                log::error!("VMLAUNCH probe failed: {error:?}");
                runtime::error(format_args!("vmlaunch error={error:?}"));
                runtime::phase("vmx.vmlaunch_probe.failed");
                screen::error(format_args!("VMLAUNCH proof: {error:?}"));
                return Err(Status::DEVICE_ERROR);
            }
        }

        screen::stage("VM-exit dispatcher proof");
        runtime::phase("vmx.dispatch_probe.start");
        match hv_core::vt_entry::probe_vmexit_dispatcher() {
            Ok(report) => {
                let diagnostics = report.diagnostics;
                runtime::info(format_args!(
                    "dispatcher proof vmcs_pa={:#x} exits={} cpuid={} vmcall={} resumes={} failure={} cpuid_input={:#x}/{:#x} cpuid_rip={:#x}/{:#x} vmcall_rip={:#x}/{:#x}",
                    report.vmcs_physical_address,
                    diagnostics.exit_count,
                    diagnostics.cpuid_count,
                    diagnostics.vmcall_count,
                    diagnostics.resume_count,
                    diagnostics.failure_code,
                    diagnostics.cpuid_leaf,
                    diagnostics.cpuid_subleaf,
                    diagnostics.cpuid_rip,
                    report.cpuid_rip_expected,
                    diagnostics.vmcall_rip,
                    report.vmcall_rip_expected
                ));
                runtime::info(format_args!(
                    "dispatcher guest-state cpuid eax={:#x} ebx={:#x} ecx={:#x} edx={:#x} final eax={:#x} ebx={:#x} ecx={:#x} edx={:#x} rsp={:#x}/{:#x}",
                    diagnostics.cpuid_eax,
                    diagnostics.cpuid_ebx,
                    diagnostics.cpuid_ecx,
                    diagnostics.cpuid_edx,
                    diagnostics.final_eax,
                    diagnostics.final_ebx,
                    diagnostics.final_ecx,
                    diagnostics.final_edx,
                    diagnostics.final_rsp,
                    report.guest.rsp
                ));
                runtime::info(format_args!(
                    "dispatcher host/guest vmxon_pa={:#x} host_tr={:#x} guest_rip={:#x} primary={:#x} secondary={:#x}",
                    report.vmxon.region_physical_address,
                    report.host.tr_selector,
                    report.guest.rip,
                    report.controls.primary_processor_based,
                    report.controls.secondary_processor_based
                ));
                runtime::phase("vmx.dispatch_probe.ok");
            }
            Err(error) => {
                log::error!("VM-exit dispatcher probe failed: {error:?}");
                runtime::error(format_args!("dispatcher error={error:?}"));
                runtime::phase("vmx.dispatch_probe.failed");
                screen::error(format_args!("VM-exit dispatcher: {error:?}"));
                return Err(Status::DEVICE_ERROR);
            }
        }
    } else {
        runtime::phase("vmx.preboot_probes.skipped");
    }

    screen::stage("resident host proof");
    runtime::phase("vmx.resident_host_probe.start");
    match hv_core::vt_resident::probe() {
        Ok(report) => {
            screen::message(format_args!(
                "resident host tables={}/{}",
                report.host_table_pages, report.host_table_capacity
            ));
            runtime::info(format_args!(
                "resident_host code_pa={:#x}/{} code_type={} data_type={} host_cr3={:#x} guest_cr3={:#x} observed_host_cr3={:#x} observed_guest_cr3={:#x}",
                report.code_physical_address,
                report.code_pages,
                report.code_memory_type,
                report.data_memory_type,
                report.host_cr3,
                report.guest_cr3,
                report.observed_host_cr3,
                report.observed_guest_cr3
            ));
            runtime::info(format_args!(
                "resident_host exit_reason={:#x} guest_rip={:#x} gdt={:#x} idt={:#x} tss={:#x} host_stack={:#x}",
                report.exit_reason,
                report.guest_rip,
                report.host_gdt,
                report.host_idt,
                report.host_tss,
                report.host_stack
            ));
            runtime::phase("vmx.resident_host_probe.ok");
        }
        Err(error) => {
            runtime::error(format_args!("resident_host error={error:?}"));
            runtime::phase("vmx.resident_host_probe.failed");
            screen::error(format_args!("resident host: {error:?}"));
            return Err(hv_core::vt_resident::status_from_error(&error));
        }
    }

    let vcpu_proof = if current().vmx_test {
        screen::stage("guest UEFI loader proof");
        guest::reset_report();
        runtime::phase("vmx.real_boot_vcpu.start");
        let vcpu_report = match guest::run(guest::entry_address()) {
            Ok(report) => report,
            Err(error) => {
                log::error!("Persistent boot vCPU failed: {error:?}");
                runtime::error(format_args!("real_boot_vcpu error={error:?}"));
                runtime::phase("vmx.real_boot_vcpu.failed");
                screen::error(format_args!("guest UEFI loader: {error:?}"));
                return Err(guest::status_from_error(&error));
            }
        };
        let vcpu_diagnostics = vcpu_report.diagnostics;
        let boot_stage = guest::report();
        screen::message(format_args!(
            "guest result={} flags={:#x} status={:#x} handles={}",
            guest::result_name(vcpu_report.result),
            boot_stage.flags,
            boot_stage.status,
            boot_stage.handle_count
        ));
        runtime::info(format_args!(
            "real_boot_vcpu result={:#x} result_name={} exits={} cpuid={} rdmsr={} wrmsr={} vmcall={} resumes={} failure={} guest_rsp={:#x}/{:#x} guest_rflags={:#x} initial_rflags={:#x}",
            vcpu_report.result,
            guest::result_name(vcpu_report.result),
            vcpu_diagnostics.exit_count,
            vcpu_diagnostics.cpuid_count,
            vcpu_diagnostics.rdmsr_count,
            vcpu_diagnostics.wrmsr_count,
            vcpu_diagnostics.vmcall_count,
            vcpu_diagnostics.resume_count,
            vcpu_diagnostics.failure_code,
            vcpu_diagnostics.final_rsp,
            vcpu_report.guest.rsp,
            vcpu_report.guest.rflags,
            vcpu_report.initial_rflags
        ));
        runtime::info(format_args!(
            "real_boot_vcpu firmware_report magic={:#x} version={} flags={:#x} status={:#x} handles={} required={}",
            boot_stage.magic,
            boot_stage.version,
            boot_stage.flags,
            boot_stage.status,
            boot_stage.handle_count,
            boot_stage.required_count
        ));
        runtime::info(format_args!(
            "real_boot_vcpu vmcs_pa={:#x} vmxon_pa={:#x} host_tr={:#x} primary={:#x} secondary={:#x}",
            vcpu_report.vmcs_physical_address,
            vcpu_report.vmxon.region_physical_address,
            vcpu_report.host.tr_selector,
            vcpu_report.controls.primary_processor_based,
            vcpu_report.controls.secondary_processor_based
        ));
        runtime::info(format_args!(
            "real_boot_vcpu address_space source_cr3={:#x} guest_initial_cr3={:#x} host_cr3={:#x} observed_host_cr3={:#x}/{:#x} last_guest_cr3={:#x} host_pt_arena={:#x}/{} host_pt_used={}",
            vcpu_report.host_address_space.source_cr3,
            vcpu_report.guest.cr3,
            vcpu_report.host.cr3,
            vcpu_diagnostics.first_host_cr3,
            vcpu_diagnostics.last_host_cr3,
            vcpu_diagnostics.last_guest_cr3,
            vcpu_report.host_address_space.arena_physical_address,
            vcpu_report.host_address_space.arena_pages,
            vcpu_report.host_address_space.table_pages
        ));
        runtime::phase("vmx.host_address_space.ok");
        Some((vcpu_report, boot_stage))
    } else {
        runtime::phase("vmx.real_boot_vcpu.skipped");
        None
    };

    screen::stage("root UEFI target lookup");
    let root_handle_count = simple_file_system_count()?;
    let root_boot_target = find_boot_target()?;
    let root_boot_target_present = root_boot_target.is_some();
    if let Some(target) = root_boot_target {
        screen::message(format_args!(
            "target={} path={}",
            target.kind.name(),
            target.path
        ));
        runtime::info(format_args!(
            "boot target verified kind={} path={}",
            target.kind.name(),
            target.path
        ));
    }
    if root_boot_target.is_none() {
        screen::error(format_args!(
            "no VeraCrypt, Ubuntu, or Windows loader found"
        ));
    }
    screen::stage("NVRAM BootOrder scan");
    let nvram_boot_option = if current().vmx_test {
        None
    } else {
        match find_veracrypt_boot_option() {
            Ok(option) => option,
            Err(status) => {
                runtime::error(format_args!("NVRAM scan unavailable: {status:?}"));
                None
            }
        }
    };
    if let Some((vcpu_report, boot_stage)) = vcpu_proof {
        runtime::info(format_args!(
            "real_boot_vcpu crosscheck guest_handles={} root_handles={} root_boot_target_present={}",
            boot_stage.handle_count, root_handle_count, root_boot_target_present
        ));
        if vcpu_report.result != guest::BOOT_STAGE_TARGET_IMAGE_LOAD_OK
            || !guest::proof_complete(boot_stage)
            || usize::try_from(boot_stage.handle_count).ok() != Some(root_handle_count)
            || !root_boot_target_present
        {
            runtime::phase("vmx.real_boot_vcpu.crosscheck_failed");
            screen::error(format_args!(
                "guest crosscheck result={} flags={:#x} guest_handles={} root_handles={} target={}",
                guest::result_name(vcpu_report.result),
                boot_stage.flags,
                boot_stage.handle_count,
                root_handle_count,
                root_boot_target_present
            ));
            return Err(Status::DEVICE_ERROR);
        }
        runtime::phase("vmx.real_boot_vcpu.ok");
    }

    screen::stage("resident event setup");
    runtime::phase("vmx.residency_events.arm.start");
    let residency_events = match hv_core::vt_resident::arm_residency_events() {
        Ok(report) => {
            runtime::info(format_args!(
                "residency_events code_pa={:#x} context_pa={:#x} code_type={} data_type={} ebs_event={:#x} va_event={:#x}",
                report.code_physical_address,
                report.context_physical_address,
                report.code_memory_type,
                report.data_memory_type,
                report.exit_boot_services_event,
                report.virtual_address_change_event
            ));
            runtime::phase("vmx.residency_events.armed");
            report
        }
        Err(error) => {
            runtime::error(format_args!("residency_events error={error:?}"));
            runtime::phase("vmx.residency_events.failed");
            screen::error(format_args!("resident events: {error:?}"));
            return Err(hv_core::vt_resident::status_from_error(&error));
        }
    };

    screen::stage("preload boot target");
    let target = root_boot_target.ok_or(Status::NOT_FOUND)?;
    let original_veracrypt_path =
        target.kind == BootTargetKind::VeraCrypt && nvram_boot_option.is_some();
    let child_handle = if original_veracrypt_path {
        let option = nvram_boot_option.as_ref().ok_or(Status::NOT_FOUND)?;
        runtime::info(format_args!(
            "LoadImage Boot{:04X} original path bytes={}",
            option.number,
            option.image_path_size()
        ));
        match load_veracrypt_boot_option(option) {
            Ok(handle) => handle,
            Err(status) => {
                screen::error(format_args!(
                    "LoadImage Boot{:04X}: {status:?}",
                    option.number
                ));
                return Err(status);
            }
        }
    } else {
        screen::message(format_args!("LoadImage fallback path={}", target.path));
        let target_volume = find_image_volume(target.path)?.ok_or(Status::NOT_FOUND)?;
        load_image_on_volume(target_volume, target.path)?
    };
    screen::message(format_args!(
        "LoadImage handle={:#x}",
        child_handle.as_ptr() as usize
    ));
    let nvram_options = if original_veracrypt_path {
        nvram_boot_option
            .as_ref()
            .map(|option| option.optional_data())
    } else {
        None
    };
    screen::message(format_args!(
        "boot load options bytes={}",
        nvram_options.map_or(0, <[u8]>::len)
    ));
    if let Err(status) = configure_image_load_options(child_handle, nvram_options) {
        let _ = ::uefi::boot::unload_image(child_handle);
        screen::error(format_args!("boot target load options: {status:?}"));
        return Err(status);
    }
    screen::message(format_args!(
        "preloaded boot target={} original_nvram_path={}",
        target.kind.name(),
        original_veracrypt_path
    ));

    screen::stage("start target under MatrixHV");
    guest::reset_report();
    guest::set_start_image_handle(child_handle);
    screen::message(format_args!(
        "resident entry={:#x} context={:#x} EPT probe={:#x}",
        guest::start_entry_address(),
        residency_events.context_physical_address,
        guest::ept_probe_fault_address()
    ));
    runtime::phase("vmx.boot_loader_start_vcpu.start");
    if let Some(target) = root_boot_target {
        screen::message(format_args!("chainload target={}", target.kind.name()));
        runtime::info(format_args!(
            "boot target chainload kind={} path={}",
            target.kind.name(),
            target.path
        ));
    }
    runtime::info(format_args!(
        "boot_loader_start_vcpu entry={:#x} residency_context={:#x}",
        guest::start_entry_address(),
        residency_events.context_physical_address
    ));
    match hv_core::vt_resident::run_boot_loader(
        guest::start_entry_address(),
        residency_events.context_physical_address,
        guest::ept_probe_fault_address(),
        guest::ept_probe_resume_address(),
    ) {
        Ok(report) => {
            let guest_report = guest::report();
            screen::error(format_args!(
                "boot vCPU returned: reason={:#x} rip={:#x} result={:#x}",
                report.last_reason, report.last_guest_rip, report.stop_result
            ));
            screen::message(format_args!(
                "guest flags={:#x} status={:#x} exits={} vmcalls={} EPT={}",
                guest_report.flags,
                guest_report.status,
                report.exit_count,
                report.vmcall_count,
                report.ept_test_violation_seen
            ));
            screen::message(format_args!(
                "post start={} post EBS={} post VA={} last GPA={:#x}",
                report.post_start_exit_count,
                report.post_ebs_exit_count,
                report.post_va_exit_count,
                report.last_guest_physical_address
            ));
            runtime::error(format_args!(
                "boot_loader_start_vcpu returned unexpectedly raw_path={} vm_instruction_error={:#x} host_cr3={:#x} guest_cr3={:#x} exits={} cpuid={} rdmsr={} wrmsr={} xsetbv={} vmcall={} checkpoint={} post_start={} post_ebs={} post_va={} ept_test={} last_reason={:#x} len={} qual={:#x} gpa={:#x} rip={:#x} last_guest_cr3={:#x} last_host_cr3={:#x} stop_result={:#x}",
                report.raw_path,
                report.vm_instruction_error,
                report.host_cr3,
                report.initial_guest_cr3,
                report.exit_count,
                report.cpuid_count,
                report.rdmsr_count,
                report.wrmsr_count,
                report.xsetbv_count,
                report.vmcall_count,
                report.start_checkpoint_seen,
                report.post_start_exit_count,
                report.post_ebs_exit_count,
                report.post_va_exit_count,
                report.ept_test_violation_seen,
                report.last_reason,
                report.last_instruction_len,
                report.last_qualification,
                report.last_guest_physical_address,
                report.last_guest_rip,
                report.last_guest_cr3,
                report.last_host_cr3,
                report.stop_result
            ));
            runtime::phase("vmx.boot_loader_start_vcpu.unexpected_return");
            Err(Status::DEVICE_ERROR)
        }
        Err(error) => {
            runtime::error(format_args!("boot_loader_start_vcpu error={error:?}"));
            runtime::phase("vmx.boot_loader_start_vcpu.failed");
            screen::error(format_args!("boot vCPU failed: {error:?}"));
            Err(hv_core::vt_resident::status_from_error(&error))
        }
    }
}

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
        screen::message(format_args!(
            "NVRAM {name} active={} {description}",
            option.is_active()
        ));
        screen::message(format_args!("NVRAM {name} path={file_path}"));
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
    if crate::boot::current().vmx_test {
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
    if !crate::boot::current().vmx_test && nvram_options.is_none_or(|data| data.is_empty()) {
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
    let options = if crate::boot::current().vmx_test {
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
