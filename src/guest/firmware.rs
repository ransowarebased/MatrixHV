use core::arch::global_asm;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, SearchType};
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{Handle, Status, cstr16};

use crate::boot::services;
use crate::hv_core::vt_resident;

pub const BOOT_STAGE_MAGIC: u64 = 0x4d_48_56_42_4f_4f_54_31;
pub const BOOT_STAGE_VERSION: u32 = 1;
pub const BOOT_STAGE_LOCATE_OK: u64 = 0xb010;
pub const BOOT_STAGE_WINDOWS_PATH_OK: u64 = 0xb020;
pub const BOOT_STAGE_WINDOWS_IMAGE_LOAD_OK: u64 = 0xb030;
pub const BOOT_STAGE_START_IMAGE_RETURNED: u64 = 0xb040;
pub const BOOT_STAGE_START_IMAGE_ERROR: u64 = 0xb041;
pub const BOOT_STAGE_BUFFER_TOO_SMALL: u64 = 0xb011;
pub const BOOT_STAGE_NOT_FOUND: u64 = 0xb012;
pub const BOOT_STAGE_ERROR: u64 = 0xb0ee;

const FLAG_ENTERED: u32 = 1 << 0;
const FLAG_LOCATE_OK: u32 = 1 << 1;
const FLAG_WINDOWS_PATH_OK: u32 = 1 << 2;
const FLAG_WINDOWS_IMAGE_LOAD_OK: u32 = 1 << 3;
const FLAG_TERMINAL_READY: u32 = 1 << 4;
const HANDLE_CAPACITY: usize = 128;
const WINDOWS_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\Microsoft\Boot\bootmgfw.efi");

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
        && report.flags & FLAG_WINDOWS_PATH_OK != 0
        && report.flags & FLAG_WINDOWS_IMAGE_LOAD_OK != 0
        && report.status == Status::SUCCESS.0 as u64
        && report.handle_count > 0
}

pub fn entry_address() -> u64 {
    matrixhv_real_boot_guest_asm as *const () as usize as u64
}

pub fn start_entry_address() -> u64 {
    matrixhv_windows_start_guest_asm as *const () as usize as u64
}

pub fn ept_probe_fault_address() -> u64 {
    core::ptr::addr_of!(matrixhv_windows_ept_probe_fault) as u64
}

pub fn ept_probe_resume_address() -> u64 {
    core::ptr::addr_of!(matrixhv_windows_ept_probe_resume) as u64
}

pub fn result_name(result: u64) -> &'static str {
    match result {
        BOOT_STAGE_LOCATE_OK => "locate_sfs_ok",
        BOOT_STAGE_WINDOWS_PATH_OK => "windows_path_ok",
        BOOT_STAGE_WINDOWS_IMAGE_LOAD_OK => "windows_image_load_ok",
        BOOT_STAGE_START_IMAGE_RETURNED => "start_image_returned",
        BOOT_STAGE_START_IMAGE_ERROR => "start_image_error",
        BOOT_STAGE_BUFFER_TOO_SMALL => "buffer_too_small",
        BOOT_STAGE_NOT_FOUND => "not_found",
        BOOT_STAGE_ERROR => "error",
        _ => "unknown",
    }
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn matrixhv_windows_start_guest_stage() -> u64 {
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

    for handle in found {
        let params = OpenProtocolParams {
            handle: *handle,
            agent: boot::image_handle(),
            controller: None,
        };
        let Ok(mut file_system) = (unsafe {
            boot::open_protocol::<SimpleFileSystem>(params, OpenProtocolAttributes::GetProtocol)
        }) else {
            continue;
        };
        let Ok(mut root) = file_system.open_volume() else {
            continue;
        };
        if root
            .open(WINDOWS_BOOT_PATH, FileMode::Read, FileAttribute::empty())
            .is_err()
        {
            continue;
        }
        REPORT_FLAGS.fetch_or(FLAG_WINDOWS_PATH_OK, Ordering::Release);

        let child_handle = match services::load_image_on_volume(*handle, WINDOWS_BOOT_PATH) {
            Ok(handle) => handle,
            Err(status) => {
                REPORT_STATUS.store(status.0 as u64, Ordering::Relaxed);
                REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
                return BOOT_STAGE_START_IMAGE_ERROR;
            }
        };
        REPORT_STATUS.store(Status::SUCCESS.0 as u64, Ordering::Relaxed);
        REPORT_FLAGS.fetch_or(FLAG_WINDOWS_IMAGE_LOAD_OK, Ordering::Release);

        unsafe {
            matrixhv_windows_start_checkpoint_asm();
        }
        let ept_test_page_gpa = vt_resident::ept_test_page_gpa();
        if ept_test_page_gpa != 0 {
            unsafe {
                matrixhv_windows_ept_probe_asm(ept_test_page_gpa);
            }
        }
        return match boot::start_image(child_handle) {
            Ok(()) => BOOT_STAGE_START_IMAGE_RETURNED,
            Err(_) => BOOT_STAGE_START_IMAGE_ERROR,
        };
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

            for handle in found {
                let params = OpenProtocolParams {
                    handle: *handle,
                    agent: boot::image_handle(),
                    controller: None,
                };
                let Ok(mut file_system) = (unsafe {
                    boot::open_protocol::<SimpleFileSystem>(
                        params,
                        OpenProtocolAttributes::GetProtocol,
                    )
                }) else {
                    continue;
                };
                let Ok(mut root) = file_system.open_volume() else {
                    continue;
                };
                if root
                    .open(WINDOWS_BOOT_PATH, FileMode::Read, FileAttribute::empty())
                    .is_ok()
                {
                    REPORT_FLAGS.fetch_or(FLAG_WINDOWS_PATH_OK, Ordering::Release);
                    match services::load_and_unload_image_on_volume(*handle, WINDOWS_BOOT_PATH) {
                        Ok(()) => {
                            REPORT_STATUS.store(Status::SUCCESS.0 as u64, Ordering::Relaxed);
                            REPORT_FLAGS.fetch_or(
                                FLAG_WINDOWS_IMAGE_LOAD_OK | FLAG_TERMINAL_READY,
                                Ordering::Release,
                            );
                            return BOOT_STAGE_WINDOWS_IMAGE_LOAD_OK;
                        }
                        Err(status) => {
                            REPORT_STATUS.store(status.0 as u64, Ordering::Relaxed);
                            REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
                            return BOOT_STAGE_ERROR;
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
    fn matrixhv_windows_start_guest_asm();
    fn matrixhv_windows_start_checkpoint_asm();
    fn matrixhv_windows_ept_probe_asm(physical_address: u64);
    static matrixhv_windows_ept_probe_fault: u8;
    static matrixhv_windows_ept_probe_resume: u8;
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
    ".globl matrixhv_windows_ept_probe_asm",
    ".globl matrixhv_windows_ept_probe_fault",
    ".globl matrixhv_windows_ept_probe_resume",
    "matrixhv_windows_ept_probe_asm:",
    "matrixhv_windows_ept_probe_fault:",
    "mov rax, qword ptr [rcx]",
    "matrixhv_windows_ept_probe_resume:",
    "ret",
);

global_asm!(
    ".text",
    ".globl matrixhv_windows_start_checkpoint_asm",
    "matrixhv_windows_start_checkpoint_asm:",
    "mov rax, {checkpoint_magic}",
    "vmcall",
    "ret",
    ".globl matrixhv_windows_start_guest_asm",
    "matrixhv_windows_start_guest_asm:",
    "mov r8, qword ptr [rax + 8]",
    "mov r9, qword ptr [rax + 16]",
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
    "vmxoff",
    "jna .Lwindows_nested_probe_failed",
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
    "call matrixhv_windows_start_guest_stage",
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
    instruction_error_field = const crate::nested::vmcs::VMCS_FIELD_VM_INSTRUCTION_ERROR,
    vmxon_active_error = const crate::nested::instructions::VMXON_IN_VMX_ROOT_ERROR,
    invalid_control_error = const crate::nested::instructions::VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR,
    non_launched_error = const crate::nested::instructions::VMRESUME_NON_LAUNCHED_VMCS_ERROR,
    vmcs12_test_value = const vt_resident::NESTED_VMCS12_TEST_VALUE,
);
