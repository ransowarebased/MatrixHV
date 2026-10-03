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
    if crate::boot::firmware::boot_services_exited() {
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
    if !crate::logging::framebuffer_enabled() || !console_available() {
        return;
    }
    system::with_stdout(|stdout| {
        let _ = stdout.clear();
        let _ = writeln!(stdout, "MatrixHV UEFI boot diagnostics");
        let _ = writeln!(stdout, "BOOTX64.EFI entry reached");
    });
}

pub fn stage(name: &str) {
    crate::logging::phase(name);
}

pub fn page(name: &str) {
    if crate::logging::framebuffer_enabled() && console_available() {
        system::with_stdout(|stdout| {
            let _ = stdout.clear();
            let _ = writeln!(stdout, "MatrixHV resident guest diagnostics");
        });
    }
    stage(name);
}

pub fn prepare_resident_visuals() -> bool {
    if !crate::logging::framebuffer_enabled() {
        return false;
    }
    let Ok(handle) = boot::get_handle_for_protocol::<GraphicsOutput>() else {
        crate::logging::info(format_args!("resident framebuffer GOP unavailable"));
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
    let protocol_pointer = (&*graphics as *const GraphicsOutput).cast::<GraphicsOutputProtocol>();
    let mode_pointer = unsafe { (*protocol_pointer).mode };
    if mode_pointer.is_null() {
        return false;
    }
    let mode_number = unsafe { (*mode_pointer).mode };
    let mode = graphics.current_mode_info();
    let (width, height) = mode.resolution();
    let stride = mode.stride();
    crate::logging::info(format_args!(
        "resident framebuffer mode={mode_number} resolution={width}x{height} stride={stride} format={:?}",
        mode.pixel_format()
    ));
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
    crate::logging::info(format_args!(
        "resident framebuffer base={base:#x} size={size:#x}"
    ));
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
    if !crate::logging::framebuffer_enabled() {
        return 0;
    }
    if halted == 0 {
        return u64::from(crate::boot::guest::start_image_entered());
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
    if crate::boot::firmware::boot_services_exited() {
        return false;
    }
    let protocol = GOP_PROTOCOL_POINTER.load(Ordering::Acquire) as *const GraphicsOutputProtocol;
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
    crate::logging::info(arguments);
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
    crate::logging::error(arguments);
}

pub fn hold_on_failure() {
    if !crate::logging::enabled() || !console_available() {
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
