use core::arch::global_asm;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use uefi::boot::{self, SearchType};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{Handle, Status};

use crate::boot::services;
use crate::hv_core::vt_resident;

pub const BOOT_STAGE_MAGIC: u64 = 0x4d_48_56_42_4f_4f_54_31;
pub const BOOT_STAGE_VERSION: u32 = 1;
pub const BOOT_STAGE_LOCATE_OK: u64 = 0xb010;
pub const BOOT_STAGE_TARGET_PATH_OK: u64 = 0xb020;
pub const BOOT_STAGE_TARGET_IMAGE_LOAD_OK: u64 = 0xb030;
pub const BOOT_STAGE_START_IMAGE_RETURNED: u64 = 0xb040;
pub const BOOT_STAGE_START_IMAGE_ERROR: u64 = 0xb041;
pub const BOOT_STAGE_BUFFER_TOO_SMALL: u64 = 0xb011;
pub const BOOT_STAGE_NOT_FOUND: u64 = 0xb012;
pub const BOOT_STAGE_ERROR: u64 = 0xb0ee;

const FLAG_ENTERED: u32 = 1 << 0;
const FLAG_LOCATE_OK: u32 = 1 << 1;
const FLAG_TARGET_PATH_OK: u32 = 1 << 2;
const FLAG_TARGET_IMAGE_LOAD_OK: u32 = 1 << 3;
const FLAG_TERMINAL_READY: u32 = 1 << 4;
const HANDLE_CAPACITY: usize = 128;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BootStageReport {
    pub magic: u64,
    pub version: u32,
    pub flags: u32,
    pub status: u64,
    pub handle_count: u32,
    pub required_count: u32,
}

static REPORT_MAGIC: AtomicU64 = AtomicU64::new(0);
static REPORT_VERSION: AtomicU32 = AtomicU32::new(0);
static REPORT_FLAGS: AtomicU32 = AtomicU32::new(0);
static REPORT_STATUS: AtomicU64 = AtomicU64::new(0);
static REPORT_HANDLE_COUNT: AtomicU32 = AtomicU32::new(0);
static REPORT_REQUIRED_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn reset_report() {
    REPORT_MAGIC.store(BOOT_STAGE_MAGIC, Ordering::Relaxed);
    REPORT_VERSION.store(BOOT_STAGE_VERSION, Ordering::Relaxed);
    REPORT_FLAGS.store(0, Ordering::Relaxed);
    REPORT_STATUS.store(0, Ordering::Relaxed);
    REPORT_HANDLE_COUNT.store(0, Ordering::Relaxed);
    REPORT_REQUIRED_COUNT.store(0, Ordering::Relaxed);
}

pub fn report() -> BootStageReport {
    BootStageReport {
        magic: REPORT_MAGIC.load(Ordering::Acquire),
        version: REPORT_VERSION.load(Ordering::Acquire),
        flags: REPORT_FLAGS.load(Ordering::Acquire),
        status: REPORT_STATUS.load(Ordering::Acquire),
        handle_count: REPORT_HANDLE_COUNT.load(Ordering::Acquire),
        required_count: REPORT_REQUIRED_COUNT.load(Ordering::Acquire),
    }
}

pub fn proof_complete(report: BootStageReport) -> bool {
    report.magic == BOOT_STAGE_MAGIC
        && report.version == BOOT_STAGE_VERSION
        && report.flags & (FLAG_ENTERED | FLAG_LOCATE_OK | FLAG_TERMINAL_READY)
            == (FLAG_ENTERED | FLAG_LOCATE_OK | FLAG_TERMINAL_READY)
        && report.flags & FLAG_TARGET_PATH_OK != 0
        && report.flags & FLAG_TARGET_IMAGE_LOAD_OK != 0
        && report.status == Status::SUCCESS.0 as u64
        && report.handle_count > 0
}

pub fn entry_address() -> u64 {
    matrixhv_real_boot_guest_asm as *const () as usize as u64
}

pub fn start_entry_address() -> u64 {
    matrixhv_boot_loader_start_guest_asm as *const () as usize as u64
}

pub fn ept_probe_fault_address() -> u64 {
    core::ptr::addr_of!(matrixhv_boot_loader_ept_probe_fault) as u64
}

pub fn ept_probe_resume_address() -> u64 {
    core::ptr::addr_of!(matrixhv_boot_loader_ept_probe_resume) as u64
}

pub fn result_name(result: u64) -> &'static str {
    match result {
        BOOT_STAGE_LOCATE_OK => "locate_sfs_ok",
        BOOT_STAGE_TARGET_PATH_OK => "target_path_ok",
        BOOT_STAGE_TARGET_IMAGE_LOAD_OK => "target_image_load_ok",
        BOOT_STAGE_START_IMAGE_RETURNED => "start_image_returned",
        BOOT_STAGE_START_IMAGE_ERROR => "start_image_error",
        BOOT_STAGE_BUFFER_TOO_SMALL => "buffer_too_small",
        BOOT_STAGE_NOT_FOUND => "not_found",
        BOOT_STAGE_ERROR => "error",
        _ => "unknown",
    }
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn matrixhv_vt_nested_enabled() -> u64 {
    u64::from(crate::boot::config::current().vt_nested)
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn matrixhv_boot_loader_start_guest_stage() -> u64 {
    REPORT_FLAGS.fetch_or(FLAG_ENTERED, Ordering::Release);

    let mut handles: [MaybeUninit<Handle>; HANDLE_CAPACITY] =
        [const { MaybeUninit::uninit() }; HANDLE_CAPACITY];
    let found =
        match boot::locate_handle(SearchType::from_proto::<SimpleFileSystem>(), &mut handles) {
            Ok(found) => found,
            Err(error) => {
                REPORT_STATUS.store(error.status().0 as u64, Ordering::Relaxed);
                REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
                return BOOT_STAGE_ERROR;
            }
        };
    REPORT_HANDLE_COUNT.store(found.len() as u32, Ordering::Relaxed);
    REPORT_FLAGS.fetch_or(FLAG_LOCATE_OK, Ordering::Release);

    for target in services::boot_target_candidates() {
        for handle in found.iter() {
            if !services::volume_contains(*handle, target.path) {
                continue;
            }
            REPORT_FLAGS.fetch_or(FLAG_TARGET_PATH_OK, Ordering::Release);

            let child_handle = match services::load_image_on_volume(*handle, target.path) {
                Ok(handle) => handle,
                Err(status) => {
                    REPORT_STATUS.store(status.0 as u64, Ordering::Relaxed);
                    REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
                    return BOOT_STAGE_START_IMAGE_ERROR;
                }
            };
            REPORT_STATUS.store(Status::SUCCESS.0 as u64, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(FLAG_TARGET_IMAGE_LOAD_OK, Ordering::Release);
            if let Err(status) = services::configure_image_load_options(child_handle) {
                REPORT_STATUS.store(status.0 as u64, Ordering::Relaxed);
                REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
                let _ = boot::unload_image(child_handle);
                return BOOT_STAGE_START_IMAGE_ERROR;
            }

            unsafe {
                matrixhv_boot_loader_start_checkpoint_asm();
            }
            let ept_test_page_gpa = vt_resident::ept_test_page_gpa();
            if ept_test_page_gpa != 0 {
                unsafe {
                    matrixhv_boot_loader_ept_probe_asm(ept_test_page_gpa);
                }
            }
            return match boot::start_image(child_handle) {
                Ok(()) => BOOT_STAGE_START_IMAGE_RETURNED,
                Err(_) => BOOT_STAGE_START_IMAGE_ERROR,
            };
        }
    }

    REPORT_STATUS.store(Status::NOT_FOUND.0 as u64, Ordering::Relaxed);
    REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
    BOOT_STAGE_NOT_FOUND
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn matrixhv_real_boot_guest_stage() -> u64 {
    REPORT_FLAGS.fetch_or(FLAG_ENTERED, Ordering::Release);

    let mut handles: [MaybeUninit<Handle>; HANDLE_CAPACITY] =
        [const { MaybeUninit::uninit() }; HANDLE_CAPACITY];
    match boot::locate_handle(SearchType::from_proto::<SimpleFileSystem>(), &mut handles) {
        Ok(found) => {
            REPORT_STATUS.store(Status::SUCCESS.0 as u64, Ordering::Relaxed);
            REPORT_HANDLE_COUNT.store(found.len() as u32, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(FLAG_LOCATE_OK, Ordering::Release);

            for target in services::boot_target_candidates() {
                for handle in found.iter() {
                    if services::volume_contains(*handle, target.path) {
                        REPORT_FLAGS.fetch_or(FLAG_TARGET_PATH_OK, Ordering::Release);
                        match services::load_and_unload_image_on_volume(*handle, target.path) {
                            Ok(()) => {
                                REPORT_STATUS.store(Status::SUCCESS.0 as u64, Ordering::Relaxed);
                                REPORT_FLAGS.fetch_or(
                                    FLAG_TARGET_IMAGE_LOAD_OK | FLAG_TERMINAL_READY,
                                    Ordering::Release,
                                );
                                return BOOT_STAGE_TARGET_IMAGE_LOAD_OK;
                            }
                            Err(status) => {
                                REPORT_STATUS.store(status.0 as u64, Ordering::Relaxed);
                                REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
                                return BOOT_STAGE_ERROR;
                            }
                        }
                    }
                }
            }

            REPORT_STATUS.store(Status::NOT_FOUND.0 as u64, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
            BOOT_STAGE_NOT_FOUND
        }
        Err(error) if error.status() == Status::BUFFER_TOO_SMALL => {
            REPORT_STATUS.store(error.status().0 as u64, Ordering::Relaxed);
            REPORT_REQUIRED_COUNT.store(error.data().unwrap_or(0) as u32, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
            BOOT_STAGE_BUFFER_TOO_SMALL
        }
        Err(error) if error.status() == Status::NOT_FOUND => {
            REPORT_STATUS.store(error.status().0 as u64, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
            BOOT_STAGE_NOT_FOUND
        }
        Err(error) => {
            REPORT_STATUS.store(error.status().0 as u64, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
            BOOT_STAGE_ERROR
        }
    }
}

unsafe extern "efiapi" {
    fn matrixhv_real_boot_guest_asm();
    fn matrixhv_boot_loader_start_guest_asm();
    fn matrixhv_boot_loader_start_checkpoint_asm();
    fn matrixhv_boot_loader_ept_probe_asm(physical_address: u64);
    static matrixhv_boot_loader_ept_probe_fault: u8;
    static matrixhv_boot_loader_ept_probe_resume: u8;
}

global_asm!(
    ".text",
    ".globl matrixhv_real_boot_guest_asm",
    "matrixhv_real_boot_guest_asm:",
    "sub rsp, 32",
    "call matrixhv_real_boot_guest_stage",
    "add rsp, 32",
    "vmcall",
    "ud2",
);

global_asm!(
    ".text",
    ".globl matrixhv_boot_loader_ept_probe_asm",
    ".globl matrixhv_boot_loader_ept_probe_fault",
    ".globl matrixhv_boot_loader_ept_probe_resume",
    "matrixhv_boot_loader_ept_probe_asm:",
    "matrixhv_boot_loader_ept_probe_fault:",
    "mov rax, qword ptr [rcx]",
    "matrixhv_boot_loader_ept_probe_resume:",
    "ret",
);

global_asm!(
    ".text",
    ".globl matrixhv_boot_loader_start_checkpoint_asm",
    "matrixhv_boot_loader_start_checkpoint_asm:",
    "mov rax, {checkpoint_magic}",
    "vmcall",
    "ret",
    ".globl matrixhv_boot_loader_start_guest_asm",
    "matrixhv_boot_loader_start_guest_asm:",
    "mov r8, qword ptr [rax + 8]",
    "mov r9, qword ptr [rax + 16]",
    "mov rbx, rax",
    "mov r10, cr4",
    "or r10, 0x2000",
    "mov cr4, r10",
    "vmxon [rax]",
    "jna .Lwindows_nested_probe_failed",
    "vmclear [r8]",
    "jna .Lwindows_nested_probe_failed",
    "vmptrld [r8]",
    "jna .Lwindows_nested_probe_failed",
    "vmxon [rax]",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "cmp r10d, 0x40",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {instruction_error_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {vmxon_active_error}",
    "jne .Lwindows_nested_probe_failed",
    "vmptrst [r9]",
    "jna .Lwindows_nested_probe_failed",
    "mov r10, qword ptr [r8]",
    "cmp qword ptr [r9], r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rip_field}",
    "mov rdx, {vmcs12_test_value}",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "mov r10, {vmcs12_test_value}",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {exception_bitmap_field}",
    "mov edx, 0x40",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, 0x40",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_cr3_field}",
    "mov rdx, cr3",
    "mov r10, rdx",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {host_cr3_field}",
    "mov rdx, cr3",
    "mov r10, rdx",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_cr0_field}",
    "mov rdx, cr0",
    "mov r10, rdx",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {host_cr0_field}",
    "mov rdx, r10",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_cr4_field}",
    "mov rdx, cr4",
    "mov r10, rdx",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {host_cr4_field}",
    "mov rdx, r10",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov ecx, {sysenter_cs_msr}",
    "rdmsr",
    "shl rdx, 32",
    "or rdx, rax",
    "mov r10, rdx",
    "mov rcx, {guest_sysenter_cs_field}",
    "vmwrite rcx, r10",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {host_sysenter_cs_field}",
    "vmwrite rcx, r10",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov ecx, {sysenter_esp_msr}",
    "rdmsr",
    "shl rdx, 32",
    "or rdx, rax",
    "mov r10, rdx",
    "mov rcx, {guest_sysenter_esp_field}",
    "vmwrite rcx, r10",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {host_sysenter_esp_field}",
    "vmwrite rcx, r10",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov ecx, {sysenter_eip_msr}",
    "rdmsr",
    "shl rdx, 32",
    "or rdx, rax",
    "mov r10, rdx",
    "mov rcx, {guest_sysenter_eip_field}",
    "vmwrite rcx, r10",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {host_sysenter_eip_field}",
    "vmwrite rcx, r10",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "vmlaunch",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "cmp r10d, 64",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {instruction_error_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {invalid_control_error}",
    "jne .Lwindows_nested_probe_failed",
    "vmresume",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "cmp r10d, 64",
    "jne .Lwindows_nested_probe_failed",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {non_launched_error}",
    "jne .Lwindows_nested_probe_failed",
    "vmclear [r8]",
    "jna .Lwindows_nested_probe_failed",
    "vmlaunch",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "cmp r10d, 1",
    "jne .Lwindows_nested_probe_failed",
    "vmresume",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "cmp r10d, 1",
    "jne .Lwindows_nested_probe_failed",
    "vmptrld [r8]",
    "jna .Lwindows_nested_probe_failed",
    "mov rcx, {exception_bitmap_field}",
    "xor edx, edx",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rcx, {pin_based_control_field}",
    "xor edx, edx",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "test edx, edx",
    "jnz .Lwindows_nested_probe_failed",
    "mov rcx, {primary_control_field}",
    "mov edx, {primary_activate_secondary_controls}",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {primary_activate_secondary_controls}",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {secondary_control_field}",
    "mov edx, {secondary_enable_ept}",
    "or edx, {secondary_enable_vpid}",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "mov r10d, {secondary_enable_ept}",
    "or r10d, {secondary_enable_vpid}",
    "cmp edx, r10d",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {vpid_field}",
    "mov edx, 1",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, 1",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {ept_pointer_field}",
    "mov rdx, qword ptr [rbx + 24]",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp rdx, qword ptr [rbx + 24]",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {vm_exit_controls_field}",
    "mov edx, {vm_exit_host_address_space_size}",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {vm_exit_host_address_space_size}",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {vm_entry_controls_field}",
    "mov edx, {vm_entry_ia32e_mode_guest}",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "xor edx, edx",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {vm_entry_ia32e_mode_guest}",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rip_field}",
    "lea rdx, [rip + .Lwindows_nested_l2_entry]",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rsp_field}",
    "mov rdx, rsp",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rflags_field}",
    "mov rdx, 2",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rcx, {host_rip_field}",
    "lea rdx, [rip + .Lwindows_nested_l1_exit]",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rcx, {host_rsp_field}",
    "mov rdx, rsp",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov r14, qword ptr [rbx + 32]",
    "mov r15, qword ptr [rbx + 40]",
    "mov r10, qword ptr [r14]",
    "mov r11, {ept_source_marker}",
    "cmp r10, r11",
    "jne .Lwindows_nested_probe_failed",
    "mov r10, qword ptr [r15]",
    "mov r11, {ept_target_marker}",
    "cmp r10, r11",
    "jne .Lwindows_nested_probe_failed",
    "vmlaunch",
    "jmp .Lwindows_nested_probe_failed",
    ".Lwindows_nested_l2_entry:",
    "mov r13, qword ptr [r14]",
    "mov r11, {ept_target_marker}",
    "cmp r13, r11",
    "jne .Lwindows_nested_l2_bad_resume",
    "mov rax, {l2_vmcall_magic}",
    ".Lwindows_nested_l2_vmcall:",
    "vmcall",
    ".Lwindows_nested_l2_after_first:",
    "mov r13, qword ptr [r14]",
    "mov r11, {ept_target_marker}",
    "cmp r13, r11",
    "jne .Lwindows_nested_l2_bad_resume",
    "mov r10, {l2_vmresume_magic}",
    "cmp rax, r10",
    "jne .Lwindows_nested_l2_bad_resume",
    ".Lwindows_nested_l2_before_invept_vmcall:",
    "vmcall",
    ".Lwindows_nested_l2_after_invept:",
    "mov r13, qword ptr [r14]",
    "mov r11, {ept_second_target_marker}",
    "cmp r13, r11",
    "jne .Lwindows_nested_l2_bad_resume",
    "mov r10, {l2_post_invept_magic}",
    "cmp rax, r10",
    "jne .Lwindows_nested_l2_bad_resume",
    ".Lwindows_nested_l2_after_invept_vmcall:",
    "vmcall",
    ".Lwindows_nested_l2_bad_resume:",
    "ud2",
    ".Lwindows_nested_l1_exit:",
    "mov r10, {l2_vmcall_magic}",
    "cmp rax, r10",
    "je .Lwindows_nested_l1_first_exit",
    "mov r10, {l2_vmresume_magic}",
    "cmp rax, r10",
    "je .Lwindows_nested_l1_resume_exit",
    "mov r10, {l2_post_invept_magic}",
    "cmp rax, r10",
    "je .Lwindows_nested_l1_after_invept_exit",
    "jmp .Lwindows_nested_probe_failed",
    ".Lwindows_nested_l1_first_exit:",
    "mov rcx, {exit_reason_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "and edx, 0xffff",
    "cmp edx, 18",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rip_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "lea r10, [rip + .Lwindows_nested_l2_vmcall]",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {exit_instruction_len_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, 3",
    "jne .Lwindows_nested_probe_failed",
    "mov r11, {ept_target_marker}",
    "cmp r13, r11",
    "jne .Lwindows_nested_probe_failed",
    "mov r10, qword ptr [r14]",
    "mov r11, {ept_source_marker}",
    "cmp r10, r11",
    "jne .Lwindows_nested_probe_failed",
    "mov r10, qword ptr [rbx + 56]",
    "mov r11, qword ptr [r10]",
    "and r11, 0xfff",
    "mov rdx, qword ptr [rbx + 48]",
    "or r11, rdx",
    "mov qword ptr [r10], r11",
    "mov rcx, {guest_rip_field}",
    "lea rdx, [rip + .Lwindows_nested_l2_after_first]",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rax, {l2_vmresume_magic}",
    "vmresume",
    "jmp .Lwindows_nested_probe_failed",
    ".Lwindows_nested_l1_resume_exit:",
    "mov rcx, {exit_reason_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "and edx, 0xffff",
    "cmp edx, 18",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rip_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "lea r10, [rip + .Lwindows_nested_l2_before_invept_vmcall]",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {exit_instruction_len_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, 3",
    "jne .Lwindows_nested_probe_failed",
    "mov r11, {ept_target_marker}",
    "cmp r13, r11",
    "jne .Lwindows_nested_probe_failed",
    "lea r10, [rip + .Lwindows_nested_invept_invalid]",
    "mov qword ptr [rbx + 80], r10",
    "lea r10, [rip + .Lwindows_nested_invept_invalid_after]",
    "mov qword ptr [rbx + 88], r10",
    "mov rcx, 2",
    ".Lwindows_nested_invept_invalid:",
    "invept rcx, xmmword ptr [rbx + 64]",
    ".Lwindows_nested_invept_invalid_after:",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "cmp r10d, 0x40",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {instruction_error_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {invalid_invalidation_operand_error}",
    "jne .Lwindows_nested_probe_failed",
    "lea r10, [rip + .Lwindows_nested_invept_valid]",
    "mov qword ptr [rbx + 80], r10",
    "lea r10, [rip + .Lwindows_nested_invept_valid_after]",
    "mov qword ptr [rbx + 88], r10",
    "mov rcx, 1",
    ".Lwindows_nested_invept_valid:",
    "invept rcx, xmmword ptr [rbx + 64]",
    ".Lwindows_nested_invept_valid_after:",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "test r10d, r10d",
    "jnz .Lwindows_nested_probe_failed",
    "mov qword ptr [rbx + 96], 0",
    "lea r10, [rip + .Lwindows_nested_invvpid_invalid]",
    "mov qword ptr [rbx + 112], r10",
    "lea r10, [rip + .Lwindows_nested_invvpid_invalid_after]",
    "mov qword ptr [rbx + 120], r10",
    "mov rcx, 1",
    ".Lwindows_nested_invvpid_invalid:",
    "invvpid rcx, xmmword ptr [rbx + 96]",
    ".Lwindows_nested_invvpid_invalid_after:",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "cmp r10d, 0x40",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {instruction_error_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, {invalid_invalidation_operand_error}",
    "jne .Lwindows_nested_probe_failed",
    "mov qword ptr [rbx + 96], 1",
    "lea r10, [rip + .Lwindows_nested_invvpid_valid]",
    "mov qword ptr [rbx + 112], r10",
    "lea r10, [rip + .Lwindows_nested_invvpid_valid_after]",
    "mov qword ptr [rbx + 120], r10",
    "mov rcx, 1",
    ".Lwindows_nested_invvpid_valid:",
    "invvpid rcx, xmmword ptr [rbx + 96]",
    ".Lwindows_nested_invvpid_valid_after:",
    "pushfq",
    "pop r10",
    "and r10d, 0x8d5",
    "test r10d, r10d",
    "jnz .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rip_field}",
    "lea rdx, [rip + .Lwindows_nested_l2_after_invept]",
    "vmwrite rcx, rdx",
    "jna .Lwindows_nested_probe_failed",
    "mov rax, {l2_post_invept_magic}",
    "vmresume",
    "jmp .Lwindows_nested_probe_failed",
    ".Lwindows_nested_l1_after_invept_exit:",
    "mov rcx, {exit_reason_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "and edx, 0xffff",
    "cmp edx, 18",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {guest_rip_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "lea r10, [rip + .Lwindows_nested_l2_after_invept_vmcall]",
    "cmp rdx, r10",
    "jne .Lwindows_nested_probe_failed",
    "mov rcx, {exit_instruction_len_field}",
    "vmread rdx, rcx",
    "jna .Lwindows_nested_probe_failed",
    "cmp edx, 3",
    "jne .Lwindows_nested_probe_failed",
    "mov r11, {ept_second_target_marker}",
    "cmp r13, r11",
    "jne .Lwindows_nested_probe_failed",
    "vmxoff",
    "jna .Lwindows_nested_probe_failed",
    "sub rsp, 32",
    "call matrixhv_vt_nested_enabled",
    "add rsp, 32",
    "test rax, rax",
    "jnz .Lwindows_cpuid_done",
    "mov eax, 1",
    "xor ecx, ecx",
    "cpuid",
    "test ecx, 0x20",
    "jnz .Lwindows_nested_probe_failed",
    "test ecx, 0x80000000",
    "jnz .Lwindows_cpuid_done",
    "mov eax, 0x40000000",
    "xor ecx, ecx",
    "cpuid",
    "or eax, ebx",
    "or eax, ecx",
    "or eax, edx",
    "jnz .Lwindows_nested_probe_failed",
    "mov eax, 0x40000003",
    "xor ecx, ecx",
    "cpuid",
    "or eax, ebx",
    "or eax, ecx",
    "or eax, edx",
    "jnz .Lwindows_nested_probe_failed",
    "mov eax, 0x40000010",
    "xor ecx, ecx",
    "cpuid",
    "or eax, ebx",
    "or eax, ecx",
    "or eax, edx",
    "jnz .Lwindows_nested_probe_failed",
    "mov eax, 0x40000100",
    "xor ecx, ecx",
    "cpuid",
    "or eax, ebx",
    "or eax, ecx",
    "or eax, edx",
    "jnz .Lwindows_nested_probe_failed",
    ".Lwindows_cpuid_done:",
    "sub rsp, 32",
    "call matrixhv_boot_loader_start_guest_stage",
    "add rsp, 32",
    "mov rdx, rax",
    "mov rax, {stop_magic}",
    "vmcall",
    "ud2",
    ".Lwindows_nested_probe_failed:",
    "mov rax, {nested_probe_failed}",
    "vmcall",
    "ud2",
    checkpoint_magic = const vt_resident::RESIDENT_VMCALL_START_CHECKPOINT,
    stop_magic = const vt_resident::RESIDENT_VMCALL_STOP,
    nested_probe_failed = const vt_resident::RESIDENT_VMCALL_NESTED_PROBE_FAILED,
    guest_rip_field = const crate::nested::vmcs::VMCS_FIELD_GUEST_RIP,
    guest_rsp_field = const crate::nested::vmcs::VMCS_FIELD_GUEST_RSP,
    guest_rflags_field = const crate::nested::vmcs::VMCS_FIELD_GUEST_RFLAGS,
    host_rip_field = const crate::nested::vmcs::VMCS_FIELD_HOST_RIP,
    host_rsp_field = const crate::nested::vmcs::VMCS_FIELD_HOST_RSP,
    exception_bitmap_field = const crate::nested::vmcs::VMCS_FIELD_EXCEPTION_BITMAP,
    guest_cr0_field = const crate::nested::vmcs::VMCS_FIELD_GUEST_CR0,
    guest_cr3_field = const crate::nested::vmcs::VMCS_FIELD_GUEST_CR3,
    guest_cr4_field = const crate::nested::vmcs::VMCS_FIELD_GUEST_CR4,
    host_cr0_field = const crate::nested::vmcs::VMCS_FIELD_HOST_CR0,
    host_cr3_field = const crate::nested::vmcs::VMCS_FIELD_HOST_CR3,
    host_cr4_field = const crate::nested::vmcs::VMCS_FIELD_HOST_CR4,
    guest_sysenter_cs_field = const crate::nested::vmcs::VMCS_FIELD_GUEST_SYSENTER_CS,
    guest_sysenter_esp_field = const crate::nested::vmcs::VMCS_FIELD_GUEST_SYSENTER_ESP,
    guest_sysenter_eip_field = const crate::nested::vmcs::VMCS_FIELD_GUEST_SYSENTER_EIP,
    host_sysenter_cs_field = const crate::nested::vmcs::VMCS_FIELD_HOST_SYSENTER_CS,
    host_sysenter_esp_field = const crate::nested::vmcs::VMCS_FIELD_HOST_SYSENTER_ESP,
    host_sysenter_eip_field = const crate::nested::vmcs::VMCS_FIELD_HOST_SYSENTER_EIP,
    pin_based_control_field = const crate::nested::vmcs::VMCS_FIELD_PIN_BASED_VM_EXEC_CONTROL,
    primary_control_field = const crate::nested::vmcs::VMCS_FIELD_CPU_BASED_VM_EXEC_CONTROL,
    secondary_control_field = const crate::nested::vmcs::VMCS_FIELD_SECONDARY_VM_EXEC_CONTROL,
    vpid_field = const crate::nested::vmcs::VMCS_FIELD_VPID,
    ept_pointer_field = const crate::nested::vmcs::VMCS_FIELD_EPT_POINTER,
    vm_exit_controls_field = const crate::nested::vmcs::VMCS_FIELD_VM_EXIT_CONTROLS,
    vm_entry_controls_field = const crate::nested::vmcs::VMCS_FIELD_VM_ENTRY_CONTROLS,
    primary_activate_secondary_controls = const crate::nested::capabilities::VMX_PRIMARY_ACTIVATE_SECONDARY_CONTROLS,
    secondary_enable_ept = const crate::nested::capabilities::VMX_SECONDARY_ENABLE_EPT,
    secondary_enable_vpid = const crate::nested::capabilities::VMX_SECONDARY_ENABLE_VPID,
    vm_exit_host_address_space_size = const crate::nested::capabilities::VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
    vm_entry_ia32e_mode_guest = const crate::nested::capabilities::VM_ENTRY_IA32E_MODE_GUEST,
    ept_source_marker = const crate::smp::per_cpu::NESTED_EPT_SOURCE_MARKER,
    ept_target_marker = const crate::smp::per_cpu::NESTED_EPT_TARGET_MARKER,
    ept_second_target_marker = const crate::smp::per_cpu::NESTED_EPT_SECOND_TARGET_MARKER,
    exit_reason_field = const crate::nested::vmcs::VMCS_FIELD_VM_EXIT_REASON,
    exit_instruction_len_field = const crate::nested::vmcs::VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN,
    instruction_error_field = const crate::nested::vmcs::VMCS_FIELD_VM_INSTRUCTION_ERROR,
    vmxon_active_error = const crate::nested::vmcs::VMXON_IN_VMX_ROOT_ERROR,
    invalid_control_error = const crate::nested::vmcs::VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR,
    non_launched_error = const crate::nested::vmcs::VMRESUME_NON_LAUNCHED_VMCS_ERROR,
    invalid_invalidation_operand_error = const crate::nested::vmcs::INVALID_OPERAND_TO_INVEPT_INVVPID_ERROR,
    vmcs12_test_value = const vt_resident::NESTED_VMCS12_TEST_VALUE,
    l2_vmcall_magic = const vt_resident::NESTED_L2_VMCALL_MAGIC,
    l2_vmresume_magic = const vt_resident::NESTED_L2_VMRESUME_MAGIC,
    l2_post_invept_magic = const vt_resident::NESTED_L2_POST_INVEPT_MAGIC,
    sysenter_cs_msr = const crate::arch::x86_64::msr::IA32_SYSENTER_CS,
    sysenter_esp_msr = const crate::arch::x86_64::msr::IA32_SYSENTER_ESP,
    sysenter_eip_msr = const crate::arch::x86_64::msr::IA32_SYSENTER_EIP,
);
