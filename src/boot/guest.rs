use crate::boot::firmware as boot_environment;
use crate::vmx::resident;
use core::arch::global_asm;
use core::mem::MaybeUninit;
use core::mem::size_of_val;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use uefi::boot::{self, SearchType};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{CStr16, Handle, Status, cstr16};

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
const FLAG_START_CHECKPOINT_COMPLETE: u32 = 1 << 5;
const FLAG_EPT_PROBE_COMPLETE: u32 = 1 << 6;
const FLAG_START_IMAGE_ENTERED: u32 = 1 << 7;
const FLAG_START_IMAGE_RETURNED: u32 = 1 << 8;
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
static START_IMAGE_HANDLE: AtomicUsize = AtomicUsize::new(0);

pub fn reset_report() {
    REPORT_MAGIC.store(BOOT_STAGE_MAGIC, Ordering::Relaxed);
    REPORT_VERSION.store(BOOT_STAGE_VERSION, Ordering::Relaxed);
    REPORT_FLAGS.store(0, Ordering::Relaxed);
    REPORT_STATUS.store(0, Ordering::Relaxed);
    REPORT_HANDLE_COUNT.store(0, Ordering::Relaxed);
    REPORT_REQUIRED_COUNT.store(0, Ordering::Relaxed);
}

pub fn set_start_image_handle(handle: Handle) {
    START_IMAGE_HANDLE.store(handle.as_ptr() as usize, Ordering::Release);
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

pub fn start_image_entered() -> bool {
    REPORT_FLAGS.load(Ordering::Acquire) & FLAG_START_IMAGE_ENTERED != 0
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
    u64::from(NESTED_ENABLED.load(Ordering::Acquire))
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn matrixhv_vmx_test_enabled() -> u64 {
    u64::from(VMX_TEST_ENABLED.load(Ordering::Acquire))
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn matrixhv_boot_loader_start_guest_stage() -> u64 {
    REPORT_FLAGS.fetch_or(FLAG_ENTERED, Ordering::Release);
    crate::diagnostics::message(format_args!("resident guest stage entered"));
    let handle_address = START_IMAGE_HANDLE.load(Ordering::Acquire);
    let Some(child_handle) = (unsafe { Handle::from_ptr(handle_address as *mut _) }) else {
        REPORT_STATUS.store(Status::NOT_FOUND.0 as u64, Ordering::Relaxed);
        REPORT_FLAGS.fetch_or(FLAG_TERMINAL_READY, Ordering::Release);
        return BOOT_STAGE_NOT_FOUND;
    };
    REPORT_FLAGS.fetch_or(FLAG_TARGET_IMAGE_LOAD_OK, Ordering::Release);
    unsafe {
        matrixhv_boot_loader_start_checkpoint_asm();
    }
    REPORT_FLAGS.fetch_or(FLAG_START_CHECKPOINT_COMPLETE, Ordering::Release);
    crate::diagnostics::message(format_args!("resident guest checkpoint complete"));
    let ept_test_page_gpa = resident::ept_test_page_gpa();
    if ept_test_page_gpa != 0 {
        unsafe {
            matrixhv_boot_loader_ept_probe_asm(ept_test_page_gpa);
        }
        REPORT_FLAGS.fetch_or(FLAG_EPT_PROBE_COMPLETE, Ordering::Release);
        crate::diagnostics::message(format_args!("resident guest EPT probe complete"));
    }
    REPORT_FLAGS.fetch_or(FLAG_START_IMAGE_ENTERED, Ordering::Release);
    crate::diagnostics::message(format_args!("resident guest starting boot target"));
    match boot::start_image(child_handle) {
        Ok(()) => {
            REPORT_STATUS.store(Status::SUCCESS.0 as u64, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(
                FLAG_START_IMAGE_RETURNED | FLAG_TERMINAL_READY,
                Ordering::Release,
            );
            BOOT_STAGE_START_IMAGE_RETURNED
        }
        Err(error) => {
            REPORT_STATUS.store(error.status().0 as u64, Ordering::Relaxed);
            REPORT_FLAGS.fetch_or(
                FLAG_START_IMAGE_RETURNED | FLAG_TERMINAL_READY,
                Ordering::Release,
            );
            BOOT_STAGE_START_IMAGE_ERROR
        }
    }
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

            for target in boot_target_candidates(VMX_TEST_ENABLED.load(Ordering::Acquire)) {
                for handle in found.iter() {
                    if boot_environment::volume_contains(*handle, target.path) {
                        REPORT_FLAGS.fetch_or(FLAG_TARGET_PATH_OK, Ordering::Release);
                        match boot_environment::load_and_unload_image_on_volume(
                            *handle,
                            target.path,
                        ) {
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
    include_str!("../asm/guest_boot.S"),
    "matrixhv_boot_guest_flow",
    ".purgem matrixhv_boot_guest_flow",
    ".purgem matrixhv_ap_guest_probe",
    checkpoint_magic = const resident::RESIDENT_VMCALL_START_CHECKPOINT,
    stop_magic = const resident::RESIDENT_VMCALL_STOP,
    nested_probe_failed = const resident::RESIDENT_VMCALL_NESTED_PROBE_FAILED,
    guest_rip_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_RIP,
    guest_rsp_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_RSP,
    guest_rflags_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_RFLAGS,
    host_rip_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_RIP,
    host_rsp_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_RSP,
    exception_bitmap_field = const crate::vmx::vmcs12::VMCS_FIELD_EXCEPTION_BITMAP,
    cr3_target_count_field = const crate::vmx::vmcs12::VMCS_FIELD_CR3_TARGET_COUNT,
    guest_cr0_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_CR0,
    guest_cr3_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_CR3,
    guest_cr4_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_CR4,
    host_cr0_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_CR0,
    host_cr3_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_CR3,
    host_cr4_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_CR4,
    guest_sysenter_cs_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_SYSENTER_CS,
    guest_sysenter_esp_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_SYSENTER_ESP,
    guest_sysenter_eip_field = const crate::vmx::vmcs12::VMCS_FIELD_GUEST_SYSENTER_EIP,
    host_sysenter_cs_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_SYSENTER_CS,
    host_sysenter_esp_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_SYSENTER_ESP,
    host_sysenter_eip_field = const crate::vmx::vmcs12::VMCS_FIELD_HOST_SYSENTER_EIP,
    pin_based_control_field = const crate::vmx::vmcs12::VMCS_FIELD_PIN_BASED_VM_EXEC_CONTROL,
    primary_control_field = const crate::vmx::vmcs12::VMCS_FIELD_CPU_BASED_VM_EXEC_CONTROL,
    secondary_control_field = const crate::vmx::vmcs12::VMCS_FIELD_SECONDARY_VM_EXEC_CONTROL,
    vpid_field = const crate::vmx::vmcs12::VMCS_FIELD_VPID,
    ept_pointer_field = const crate::vmx::vmcs12::VMCS_FIELD_EPT_POINTER,
    vm_exit_controls_field = const crate::vmx::vmcs12::VMCS_FIELD_VM_EXIT_CONTROLS,
    vm_entry_controls_field = const crate::vmx::vmcs12::VMCS_FIELD_VM_ENTRY_CONTROLS,
    primary_activate_secondary_controls = const crate::vmx::nested::VMX_PRIMARY_ACTIVATE_SECONDARY_CONTROLS,
    secondary_enable_ept = const crate::vmx::nested::VMX_SECONDARY_ENABLE_EPT,
    secondary_enable_vpid = const crate::vmx::nested::VMX_SECONDARY_ENABLE_VPID,
    vm_exit_host_address_space_size = const crate::vmx::nested::VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
    vm_entry_ia32e_mode_guest = const crate::vmx::nested::VM_ENTRY_IA32E_MODE_GUEST,
    ept_source_marker = const crate::vmx::vcpu::NESTED_EPT_SOURCE_MARKER,
    ept_target_marker = const crate::vmx::vcpu::NESTED_EPT_TARGET_MARKER,
    ept_second_target_marker = const crate::vmx::vcpu::NESTED_EPT_SECOND_TARGET_MARKER,
    exit_reason_field = const crate::vmx::vmcs12::VMCS_FIELD_VM_EXIT_REASON,
    exit_instruction_len_field = const crate::vmx::vmcs12::VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN,
    instruction_error_field = const crate::vmx::vmcs12::VMCS_FIELD_VM_INSTRUCTION_ERROR,
    vmxon_active_error = const crate::vmx::nested::VMXON_IN_VMX_ROOT_ERROR,
    invalid_control_error = const crate::vmx::nested::VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR,
    non_launched_error = const crate::vmx::nested::VMRESUME_NON_LAUNCHED_VMCS_ERROR,
    invalid_invalidation_operand_error = const crate::vmx::nested::INVALID_OPERAND_TO_INVEPT_INVVPID_ERROR,
    vmcs12_test_value = const resident::NESTED_VMCS12_TEST_VALUE,
    l2_vmcall_magic = const resident::NESTED_L2_VMCALL_MAGIC,
    l2_vmresume_magic = const resident::NESTED_L2_VMRESUME_MAGIC,
    l2_post_invept_magic = const resident::NESTED_L2_POST_INVEPT_MAGIC,
    sysenter_cs_msr = const crate::arch::IA32_SYSENTER_CS,
    sysenter_esp_msr = const crate::arch::IA32_SYSENTER_ESP,
    sysenter_eip_msr = const crate::arch::IA32_SYSENTER_EIP,
);

static NESTED_ENABLED: AtomicBool = AtomicBool::new(true);
static VMX_TEST_ENABLED: AtomicBool = AtomicBool::new(false);

pub(crate) fn configure(options: crate::boot::config::MatrixConfig) {
    NESTED_ENABLED.store(options.vt_nested, Ordering::Release);
    VMX_TEST_ENABLED.store(options.vmx_test, Ordering::Release);
}

const VERACRYPT_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\VeraCrypt\DcsBoot.efi");
const UBUNTU_SHIM_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\ubuntu\shimx64.efi");
const UBUNTU_GRUB_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\ubuntu\grubx64.efi");
const WINDOWS_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\Microsoft\Boot\bootmgfw.efi");
const VMX_FLAT_BOOT_PATH: &uefi::CStr16 = cstr16!(r"\EFI\BOOT\VMXFLAT.EFI");
const VMX_FLAT_LOAD_OPTIONS: &uefi::CStr16 = cstr16!(
    "vmx.efi test_vmx_feature_control test_vmxon test_vmptrld test_vmclear test_vmptrst test_vmwrite_vmread test_vmcs_high test_vmcs_lifecycle test_vmx_caps vmenter vmx_controls_test vmx_host_state_area_test vmx_guest_state_area_test CR_shadowing I/O_bitmap MSR_switch instruction_intercept vmx_store_tsc_test vmx_intr_window_test vmx_nmi_window_test interrupt nmi_hlt ept_access_test_not_present ept_access_test_read_only ept_access_test_read_write ept_access_test_read_execute ept_access_test_read_write_execute"
);

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

pub(crate) fn boot_target_candidates(vmx_test: bool) -> &'static [BootTargetSpec] {
    if vmx_test {
        VMX_TEST_BOOT_TARGETS
    } else {
        NORMAL_BOOT_TARGETS
    }
}

pub(crate) fn find_boot_target(vmx_test: bool) -> Result<Option<BootTargetSpec>, Status> {
    for spec in boot_target_candidates(vmx_test) {
        if boot_environment::find_image_volume(spec.path)?.is_some() {
            return Ok(Some(*spec));
        }
    }

    Ok(None)
}

pub(crate) fn image_load_options(vmx_test: bool, nvram_options: Option<&[u8]>) -> &[u8] {
    let test_options = VMX_FLAT_LOAD_OPTIONS.as_slice_with_nul();
    if vmx_test {
        unsafe {
            core::slice::from_raw_parts(test_options.as_ptr().cast(), size_of_val(test_options))
        }
    } else {
        nvram_options.unwrap_or_default()
    }
}
