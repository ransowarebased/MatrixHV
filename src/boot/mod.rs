pub mod config;
pub use crate::runtime::logger;
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
pub mod services;

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
        let rflags = crate::arch::x86_64::registers::read_rflags();
        let apic_base = unsafe { crate::arch::x86_64::msr::read(0x1b) };
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
        if !crate::runtime::logger::framebuffer_enabled() || !console_available() {
            return;
        }
        system::with_stdout(|stdout| {
            let _ = stdout.clear();
            let _ = writeln!(stdout, "MatrixHV UEFI boot diagnostics");
            let _ = writeln!(stdout, "BOOTX64.EFI entry reached");
        });
    }

    pub fn stage(name: &str) {
        crate::runtime::logger::phase(name);
    }

    pub fn page(name: &str) {
        if crate::runtime::logger::framebuffer_enabled() && console_available() {
            system::with_stdout(|stdout| {
                let _ = stdout.clear();
                let _ = writeln!(stdout, "MatrixHV resident guest diagnostics");
            });
        }
        stage(name);
    }

    pub fn prepare_resident_visuals() -> bool {
        if !crate::runtime::logger::framebuffer_enabled() {
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
        if !crate::runtime::logger::framebuffer_enabled() {
            return 0;
        }
        if halted == 0 {
            return u64::from(crate::guest::firmware::start_image_entered());
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
        crate::runtime::logger::info(arguments);
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
        crate::runtime::logger::error(arguments);
    }

    pub fn hold_on_failure() {
        if !crate::runtime::logger::enabled() || !console_available() {
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

use crate::arch::x86_64::cpu::{self, Vendor};
use crate::guest::{firmware, vcpu};
use crate::hv_core;
use crate::memory::resident;
use crate::smp::{startup, topology};
use ::uefi::Status;

pub fn run() -> Result<(), Status> {
    screen::stage("UEFI boot services");
    services::initialize_boot_environment()?;
    screen::stage("image residency");
    let image_residency = resident::image_residency()?;
    logger::info(format_args!(
        "residency image code_type={} data_type={}",
        image_residency.code_type.0, image_residency.data_type.0
    ));
    logger::phase("vmx.residency.image_type.observed");

    screen::stage("Intel VMX capability");
    let capabilities = cpu::capabilities();
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
    logger::phase("vmx.capability.ok");

    screen::stage("processor topology");
    logger::phase("smp.topology.start");
    let topology_report = match topology::enumerate() {
        Ok(report) => {
            logger::info(format_args!(
                "smp topology total={} enabled={} current={} bsp={} first_enabled_ap={:?}",
                report.total_processors,
                report.enabled_processors,
                report.current_processor,
                report.bsp_processor,
                report.first_enabled_ap
            ));
            logger::phase("smp.topology.ok");
            Some(report)
        }
        Err(status) => {
            logger::error(format_args!("smp topology status={status:?}"));
            logger::phase("smp.topology.unavailable");
            screen::message(format_args!("topology unavailable: {status:?}"));
            None
        }
    };

    if let Some(processor_number) = topology_report.and_then(|report| report.first_enabled_ap) {
        screen::stage("AP VMX proof");
        logger::phase("smp.cpu1_vmx.start");
        match startup::prove_application_processor_vmx(processor_number) {
            Ok(report) => {
                logger::info(format_args!(
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
                logger::info(format_args!(
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
                logger::phase("smp.cpu1_vmx.ok");
            }
            Err(error) => {
                logger::error(format_args!("smp cpu1 vmx error={error:?}"));
                logger::phase("smp.cpu1_vmx.failed");
                screen::error(format_args!("AP VMX proof: {error:?}"));
                return Err(Status::DEVICE_ERROR);
            }
        }
    } else {
        screen::message(format_args!("AP VMX proof skipped"));
        logger::phase("smp.cpu1_vmx.skipped");
    }

    screen::stage("UEFI memory map");
    let memory = memory_map::snapshot()?;
    log::info!(
        "UEFI memory map ready: {} descriptors, {} conventional pages",
        memory.descriptor_count,
        memory.conventional_pages
    );
    logger::info(format_args!(
        "memory_map descriptors={} conventional_pages={}",
        memory.descriptor_count, memory.conventional_pages
    ));
    logger::phase("uefi.memory_map.ok");

    screen::stage("VMXON proof");
    logger::phase("vmx.vmxon.start");
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
            logger::info(format_args!(
                "vmxon revision={:#x} region_size={} region_pa={:#x} cr0={:#x}->{:#x} cr4={:#x}->{:#x}",
                report.revision_id,
                report.region_size,
                report.region_physical_address,
                report.original_cr0,
                report.vmx_cr0,
                report.original_cr4,
                report.vmx_cr4
            ));
            logger::phase("vmx.vmxon.ok");
        }
        Err(error) => {
            log::error!("VMXON probe failed: {error:?}");
            logger::error(format_args!("vmxon error={error:?}"));
            logger::phase("vmx.vmxon.failed");
            screen::error(format_args!("VMXON proof: {error:?}"));
            return Err(Status::DEVICE_ERROR);
        }
    }

    screen::stage("VMCS proof");
    logger::phase("vmx.vmcs.start");
    match hv_core::vt_vmcs::probe_vmcs() {
        Ok(report) => {
            logger::info(format_args!(
                "vmcs revision={:#x} region_pa={:#x} current_pa={:#x} instruction_error={} vmxon_pa={:#x}",
                report.revision_id,
                report.region_physical_address,
                report.current_vmcs_physical_address,
                report.instruction_error,
                report.vmxon.region_physical_address
            ));
            logger::phase("vmx.vmcs.ok");
        }
        Err(error) => {
            log::error!("VMCS probe failed: {error:?}");
            logger::error(format_args!("vmcs error={error:?}"));
            logger::phase("vmx.vmcs.failed");
            screen::error(format_args!("VMCS proof: {error:?}"));
            return Err(Status::DEVICE_ERROR);
        }
    }

    screen::stage("VMLAUNCH proof");
    logger::phase("vmx.vmlaunch_probe.start");
    match hv_core::vt_entry::probe_vmlaunch() {
        Ok(report) => {
            logger::info(format_args!(
                "vmlaunch proof vmcs_pa={:#x} exit_reason={:#x} qualification={:#x} instruction_len={} guest_rip_after_exit={:#x}",
                report.vmcs_physical_address,
                report.exit_reason,
                report.exit_qualification,
                report.exit_instruction_length,
                report.guest_rip_after_exit
            ));
            logger::info(format_args!(
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
            logger::phase("vmx.vmlaunch_probe.ok");
        }
        Err(error) => {
            log::error!("VMLAUNCH probe failed: {error:?}");
            logger::error(format_args!("vmlaunch error={error:?}"));
            logger::phase("vmx.vmlaunch_probe.failed");
            screen::error(format_args!("VMLAUNCH proof: {error:?}"));
            return Err(Status::DEVICE_ERROR);
        }
    }

    screen::stage("VM-exit dispatcher proof");
    logger::phase("vmx.dispatch_probe.start");
    match hv_core::vt_entry::probe_vmexit_dispatcher() {
        Ok(report) => {
            let diagnostics = report.diagnostics;
            logger::info(format_args!(
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
            logger::info(format_args!(
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
            logger::info(format_args!(
                "dispatcher host/guest vmxon_pa={:#x} host_tr={:#x} guest_rip={:#x} primary={:#x} secondary={:#x}",
                report.vmxon.region_physical_address,
                report.host.tr_selector,
                report.guest.rip,
                report.controls.primary_processor_based,
                report.controls.secondary_processor_based
            ));
            logger::phase("vmx.dispatch_probe.ok");
        }
        Err(error) => {
            log::error!("VM-exit dispatcher probe failed: {error:?}");
            logger::error(format_args!("dispatcher error={error:?}"));
            logger::phase("vmx.dispatch_probe.failed");
            screen::error(format_args!("VM-exit dispatcher: {error:?}"));
            return Err(Status::DEVICE_ERROR);
        }
    }

    screen::stage("resident host proof");
    logger::phase("vmx.resident_host_probe.start");
    match hv_core::vt_resident::probe() {
        Ok(report) => {
            screen::message(format_args!(
                "resident host tables={}/{}",
                report.host_table_pages, report.host_table_capacity
            ));
            logger::info(format_args!(
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
            logger::info(format_args!(
                "resident_host exit_reason={:#x} guest_rip={:#x} gdt={:#x} idt={:#x} tss={:#x} host_stack={:#x}",
                report.exit_reason,
                report.guest_rip,
                report.host_gdt,
                report.host_idt,
                report.host_tss,
                report.host_stack
            ));
            logger::phase("vmx.resident_host_probe.ok");
        }
        Err(error) => {
            logger::error(format_args!("resident_host error={error:?}"));
            logger::phase("vmx.resident_host_probe.failed");
            screen::error(format_args!("resident host: {error:?}"));
            return Err(hv_core::vt_resident::status_from_error(&error));
        }
    }

    screen::stage("guest UEFI loader proof");
    firmware::reset_report();
    logger::phase("vmx.real_boot_vcpu.start");
    let vcpu_report = match vcpu::run(firmware::entry_address()) {
        Ok(report) => report,
        Err(error) => {
            log::error!("Persistent boot vCPU failed: {error:?}");
            logger::error(format_args!("real_boot_vcpu error={error:?}"));
            logger::phase("vmx.real_boot_vcpu.failed");
            screen::error(format_args!("guest UEFI loader: {error:?}"));
            return Err(vcpu::status_from_error(&error));
        }
    };
    let vcpu_diagnostics = vcpu_report.diagnostics;
    let boot_stage = firmware::report();
    screen::message(format_args!(
        "guest result={} flags={:#x} status={:#x} handles={}",
        firmware::result_name(vcpu_report.result),
        boot_stage.flags,
        boot_stage.status,
        boot_stage.handle_count
    ));
    logger::info(format_args!(
        "real_boot_vcpu result={:#x} result_name={} exits={} cpuid={} rdmsr={} wrmsr={} vmcall={} resumes={} failure={} guest_rsp={:#x}/{:#x} guest_rflags={:#x} initial_rflags={:#x}",
        vcpu_report.result,
        firmware::result_name(vcpu_report.result),
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
    logger::info(format_args!(
        "real_boot_vcpu firmware_report magic={:#x} version={} flags={:#x} status={:#x} handles={} required={}",
        boot_stage.magic,
        boot_stage.version,
        boot_stage.flags,
        boot_stage.status,
        boot_stage.handle_count,
        boot_stage.required_count
    ));
    logger::info(format_args!(
        "real_boot_vcpu vmcs_pa={:#x} vmxon_pa={:#x} host_tr={:#x} primary={:#x} secondary={:#x}",
        vcpu_report.vmcs_physical_address,
        vcpu_report.vmxon.region_physical_address,
        vcpu_report.host.tr_selector,
        vcpu_report.controls.primary_processor_based,
        vcpu_report.controls.secondary_processor_based
    ));
    logger::info(format_args!(
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
    logger::phase("vmx.host_address_space.ok");

    screen::stage("root UEFI target lookup");
    let root_handle_count = services::simple_file_system_count()?;
    let root_boot_target = services::find_boot_target()?;
    let root_boot_target_present = root_boot_target.is_some();
    if let Some(target) = root_boot_target {
        screen::message(format_args!(
            "target={} path={}",
            target.kind.name(),
            target.path
        ));
        logger::info(format_args!(
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
    let nvram_boot_option = if config::current().vmx_test {
        None
    } else {
        match services::find_veracrypt_boot_option() {
            Ok(option) => option,
            Err(status) => {
                logger::error(format_args!("NVRAM scan unavailable: {status:?}"));
                None
            }
        }
    };
    logger::info(format_args!(
        "real_boot_vcpu crosscheck guest_handles={} root_handles={} root_boot_target_present={}",
        boot_stage.handle_count, root_handle_count, root_boot_target_present
    ));
    if vcpu_report.result != firmware::BOOT_STAGE_TARGET_IMAGE_LOAD_OK
        || !firmware::proof_complete(boot_stage)
        || usize::try_from(boot_stage.handle_count).ok() != Some(root_handle_count)
        || !root_boot_target_present
    {
        logger::phase("vmx.real_boot_vcpu.crosscheck_failed");
        screen::error(format_args!(
            "guest crosscheck result={} flags={:#x} guest_handles={} root_handles={} target={}",
            firmware::result_name(vcpu_report.result),
            boot_stage.flags,
            boot_stage.handle_count,
            root_handle_count,
            root_boot_target_present
        ));
        return Err(Status::DEVICE_ERROR);
    }
    logger::phase("vmx.real_boot_vcpu.ok");

    screen::stage("resident event setup");
    logger::phase("vmx.residency_events.arm.start");
    let residency_events = match hv_core::vt_resident::arm_residency_events() {
        Ok(report) => {
            logger::info(format_args!(
                "residency_events code_pa={:#x} context_pa={:#x} code_type={} data_type={} ebs_event={:#x} va_event={:#x}",
                report.code_physical_address,
                report.context_physical_address,
                report.code_memory_type,
                report.data_memory_type,
                report.exit_boot_services_event,
                report.virtual_address_change_event
            ));
            logger::phase("vmx.residency_events.armed");
            report
        }
        Err(error) => {
            logger::error(format_args!("residency_events error={error:?}"));
            logger::phase("vmx.residency_events.failed");
            screen::error(format_args!("resident events: {error:?}"));
            return Err(hv_core::vt_resident::status_from_error(&error));
        }
    };

    screen::stage("preload boot target");
    let target = root_boot_target.ok_or(Status::NOT_FOUND)?;
    let original_veracrypt_path =
        target.kind == services::BootTargetKind::VeraCrypt && nvram_boot_option.is_some();
    let child_handle = if original_veracrypt_path {
        let option = nvram_boot_option.as_ref().ok_or(Status::NOT_FOUND)?;
        logger::info(format_args!(
            "LoadImage Boot{:04X} original path bytes={}",
            option.number,
            option.image_path_size()
        ));
        match services::load_veracrypt_boot_option(option) {
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
        let target_volume = services::find_image_volume(target.path)?.ok_or(Status::NOT_FOUND)?;
        services::load_image_on_volume(target_volume, target.path)?
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
    if let Err(status) = services::configure_image_load_options(child_handle, nvram_options) {
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
    firmware::reset_report();
    firmware::set_start_image_handle(child_handle);
    screen::message(format_args!(
        "resident entry={:#x} context={:#x} EPT probe={:#x}",
        firmware::start_entry_address(),
        residency_events.context_physical_address,
        firmware::ept_probe_fault_address()
    ));
    logger::phase("vmx.boot_loader_start_vcpu.start");
    if let Some(target) = root_boot_target {
        screen::message(format_args!("chainload target={}", target.kind.name()));
        logger::info(format_args!(
            "boot target chainload kind={} path={}",
            target.kind.name(),
            target.path
        ));
    }
    logger::info(format_args!(
        "boot_loader_start_vcpu entry={:#x} residency_context={:#x}",
        firmware::start_entry_address(),
        residency_events.context_physical_address
    ));
    match hv_core::vt_resident::run_boot_loader(
        firmware::start_entry_address(),
        residency_events.context_physical_address,
        firmware::ept_probe_fault_address(),
        firmware::ept_probe_resume_address(),
    ) {
        Ok(report) => {
            let guest_report = firmware::report();
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
            logger::error(format_args!(
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
            logger::phase("vmx.boot_loader_start_vcpu.unexpected_return");
            Err(Status::DEVICE_ERROR)
        }
        Err(error) => {
            logger::error(format_args!("boot_loader_start_vcpu error={error:?}"));
            logger::phase("vmx.boot_loader_start_vcpu.failed");
            screen::error(format_args!("boot vCPU failed: {error:?}"));
            Err(hv_core::vt_resident::status_from_error(&error))
        }
    }
}
