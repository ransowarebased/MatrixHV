use core::arch::global_asm;
use core::mem::size_of;

use uefi::Status;

use super::vt_controls::{self, VmxControlsError};
use super::vt_guest;
use super::vt_vmcs::{self, VmcsError, VmcsRegion, vmwrite};
use super::vt_vmcs_fields::*;
use super::vt_vmxon::{self, VmxInstructionResult, VmxonError};
use crate::arch::x86_64::{control_regs, msr, segmentation};
use crate::memory::paging::{HostAddressSpace, HostPagingError};
use crate::memory::resident::{
    AddressConstraint, PAGE_SIZE, RESIDENT_CODE_MEMORY_TYPE, RESIDENT_MEMORY_TYPE, ResidentPages,
};

const GUEST_STACK_PAGES: usize = 4;
const HOST_STACK_PAGES: usize = 4;
const HOST_TABLE_PAGES: usize = 2;
const CONTEXT_CANARY_START: u64 = 0x4856_5245_5349_4431;
const CONTEXT_CANARY_END: u64 = 0x4856_5245_5349_4432;
const CONTEXT_COMPLETE: u64 = 0x4856_5245_534f_4b21;
const VMCALL_EXIT_REASON: u64 = 18;
const HOST_TSS_SELECTOR: u16 = 0x40;
const TSS_OFFSET: usize = 0x100;
const TSS_LIMIT: u32 = 0x67;
const IDT_ENTRY_COUNT: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentProbeError {
    Allocation(Status),
    Vmxon(VmxonError),
    Vmcs(VmcsError),
    Controls(VmxControlsError),
    Paging(HostPagingError),
    CodeTooLarge(usize),
    InvalidCodeLayout,
    HostRspVmwrite,
    HostRipVmwrite,
    VmlaunchVmFailInvalid,
    VmlaunchVmFailValid(u64),
    UnexpectedRunPath(u64),
    Vmclear(VmxInstructionResult),
    Incomplete(u64),
    CanaryCorrupted,
    UnexpectedExitReason(u64),
    HostCr3Mismatch { expected: u64, observed: u64 },
    GuestCr3Mismatch { expected: u64, observed: u64 },
}

impl From<VmcsError> for ResidentProbeError {
    fn from(value: VmcsError) -> Self {
        Self::Vmcs(value)
    }
}

impl From<VmxControlsError> for ResidentProbeError {
    fn from(value: VmxControlsError) -> Self {
        Self::Controls(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentProbeReport {
    pub code_physical_address: u64,
    pub code_pages: usize,
    pub data_memory_type: u32,
    pub code_memory_type: u32,
    pub host_cr3: u64,
    pub guest_cr3: u64,
    pub observed_host_cr3: u64,
    pub observed_guest_cr3: u64,
    pub exit_reason: u64,
    pub guest_rip: u64,
    pub host_gdt: u64,
    pub host_idt: u64,
    pub host_tss: u64,
    pub host_stack: u64,
}

#[repr(C, align(16))]
struct ResidentContext {
    root_rsp: u64,
    return_rip: u64,
    source_cr3: u64,
    expected_host_cr3: u64,
    observed_host_cr3: u64,
    observed_guest_cr3: u64,
    exit_reason: u64,
    guest_rip: u64,
    canary_start: u64,
    completed: u64,
    canary_end: u64,
    original_gdtr: [u8; 10],
    original_idtr: [u8; 10],
}

impl ResidentContext {
    fn new(source_cr3: u64, expected_host_cr3: u64) -> Self {
        Self {
            root_rsp: 0,
            return_rip: 0,
            source_cr3,
            expected_host_cr3,
            observed_host_cr3: 0,
            observed_guest_cr3: 0,
            exit_reason: 0,
            guest_rip: 0,
            canary_start: CONTEXT_CANARY_START,
            completed: 0,
            canary_end: CONTEXT_CANARY_END,
            original_gdtr: [0; 10],
            original_idtr: [0; 10],
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    fn interrupt_gate(address: u64, code_selector: u16) -> Self {
        Self {
            offset_low: address as u16,
            selector: code_selector,
            ist: 0,
            attributes: 0x8e,
            offset_mid: (address >> 16) as u16,
            offset_high: (address >> 32) as u32,
            reserved: 0,
        }
    }
}

struct ResidentCode {
    pages: ResidentPages,
    entry: u64,
    fatal: u64,
}

impl ResidentCode {
    fn allocate() -> Result<Self, ResidentProbeError> {
        let start = core::ptr::addr_of!(matrixhv_resident_island_start) as u64;
        let entry = core::ptr::addr_of!(matrixhv_resident_island_entry) as u64;
        let fatal = core::ptr::addr_of!(matrixhv_resident_island_fatal) as u64;
        let end = core::ptr::addr_of!(matrixhv_resident_island_end) as u64;
        if entry < start || fatal < start || end <= start || entry >= end || fatal >= end {
            return Err(ResidentProbeError::InvalidCodeLayout);
        }
        let length =
            usize::try_from(end - start).map_err(|_| ResidentProbeError::InvalidCodeLayout)?;
        if length > PAGE_SIZE {
            return Err(ResidentProbeError::CodeTooLarge(length));
        }

        let pages =
            ResidentPages::allocate_typed(1, AddressConstraint::Any, RESIDENT_CODE_MEMORY_TYPE)
                .map_err(ResidentProbeError::Allocation)?;
        unsafe {
            core::ptr::copy_nonoverlapping(start as *const u8, pages.pointer().as_ptr(), length);
        }
        let base = pages.physical_address();
        Ok(Self {
            entry: base + (entry - start),
            fatal: base + (fatal - start),
            pages,
        })
    }
}

struct ResidentHostTables {
    pages: ResidentPages,
    gdt: u64,
    tss: u64,
    idt: u64,
}

impl ResidentHostTables {
    fn allocate(
        fatal_handler: u64,
        segments: segmentation::SegmentationState,
    ) -> Result<Self, ResidentProbeError> {
        let pages = ResidentPages::allocate(HOST_TABLE_PAGES, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let base = pages.physical_address();
        let gdt = base;
        let tss = base + TSS_OFFSET as u64;
        let idt = base + PAGE_SIZE as u64;

        unsafe {
            let gdt_pointer = gdt as *mut u64;
            let code_selector = host_selector(segments.cs.selector);
            let data_selectors = [
                host_selector(segments.es.selector),
                host_selector(segments.ss.selector),
                host_selector(segments.ds.selector),
                host_selector(segments.fs.selector),
                host_selector(segments.gs.selector),
            ];
            if code_selector == 0 {
                return Err(ResidentProbeError::InvalidCodeLayout);
            }
            gdt_pointer
                .add(usize::from(code_selector >> 3))
                .write(0x00af_9a00_0000_ffff);
            for selector in data_selectors {
                if selector != 0 && selector != code_selector {
                    gdt_pointer
                        .add(usize::from(selector >> 3))
                        .write(0x00af_9200_0000_ffff);
                }
            }
            let (tss_low, tss_high) = tss_descriptor(tss);
            let tss_index = usize::from(HOST_TSS_SELECTOR >> 3);
            gdt_pointer.add(tss_index).write(tss_low);
            gdt_pointer.add(tss_index + 1).write(tss_high);

            (tss as *mut u8).write_bytes(0, (TSS_LIMIT + 1) as usize);

            let idt_pointer = idt as *mut IdtEntry;
            for index in 0..IDT_ENTRY_COUNT {
                idt_pointer
                    .add(index)
                    .write(IdtEntry::interrupt_gate(fatal_handler, code_selector));
            }
        }

        Ok(Self {
            pages,
            gdt,
            tss,
            idt,
        })
    }
}

pub fn probe() -> Result<ResidentProbeReport, ResidentProbeError> {
    if size_of::<ResidentContext>() > PAGE_SIZE {
        return Err(ResidentProbeError::Allocation(Status::OUT_OF_RESOURCES));
    }

    let code = ResidentCode::allocate()?;
    let root_segments = segmentation::capture();
    let tables = ResidentHostTables::allocate(code.fatal, root_segments)?;
    let context_pages = ResidentPages::allocate(1, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let guest_stack = ResidentPages::allocate(GUEST_STACK_PAGES, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let host_stack = ResidentPages::allocate(HOST_STACK_PAGES, AddressConstraint::Any)
        .map_err(ResidentProbeError::Allocation)?;
    let mut host_address_space = HostAddressSpace::reserve().map_err(ResidentProbeError::Paging)?;

    let vmx_basic = vt_vmxon::vmx_basic();
    let revision_id = vt_vmxon::revision_id(vmx_basic);
    let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
    vmcs_region.write_revision_id(revision_id);
    let vmcs_physical_address = vmcs_region.physical_address();
    let session = vt_vmxon::enter_vmx_root().map_err(ResidentProbeError::Vmxon)?;

    let host_space = host_address_space
        .clone_current()
        .map_err(ResidentProbeError::Paging)?;
    let source_cr3 = host_space.source_cr3;
    let context = context_pages.pointer().as_ptr().cast::<ResidentContext>();
    unsafe {
        context.write(ResidentContext::new(source_cr3, host_space.host_cr3));
    }

    let clear_result = unsafe { vt_vmcs::vmclear(vmcs_physical_address) };
    if clear_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(ResidentProbeError::Vmclear(clear_result));
    }
    let load_result = unsafe { vt_vmcs::vmptrld(vmcs_physical_address) };
    if load_result != VmxInstructionResult::Succeeded {
        drop(session);
        return Err(ResidentProbeError::Vmcs(VmcsError::Vmptrld(load_result)));
    }

    let _controls = vt_controls::configure()?;
    configure_resident_host(host_space.host_cr3, &tables, root_segments)?;
    let guest_rsp = guest_stack.physical_address() + guest_stack.byte_len() as u64;
    let guest = vt_guest::configure(guest_probe_address(), guest_rsp & !0xf)?;

    let host_rsp = (host_stack.physical_address() + host_stack.byte_len() as u64 - 8) & !0xf;
    unsafe {
        (host_rsp as *mut u64).write(context as u64);
    }

    let raw_path = unsafe { matrixhv_resident_probe_run_asm(context, host_rsp, code.entry) };
    let vm_instruction_error = vt_vmcs::vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
    let final_clear = unsafe { vt_vmcs::vmclear(vmcs_physical_address) };
    host_address_space.restore_source_cr3();
    drop(session);
    if final_clear != VmxInstructionResult::Succeeded {
        return Err(ResidentProbeError::Vmclear(final_clear));
    }
    validate_run_path(raw_path, vm_instruction_error)?;

    let result = unsafe { &*context };
    if result.completed != CONTEXT_COMPLETE {
        return Err(ResidentProbeError::Incomplete(result.completed));
    }
    if result.canary_start != CONTEXT_CANARY_START || result.canary_end != CONTEXT_CANARY_END {
        return Err(ResidentProbeError::CanaryCorrupted);
    }
    if result.exit_reason & 0xffff != VMCALL_EXIT_REASON {
        return Err(ResidentProbeError::UnexpectedExitReason(result.exit_reason));
    }
    if result.observed_host_cr3 != host_space.host_cr3 {
        return Err(ResidentProbeError::HostCr3Mismatch {
            expected: host_space.host_cr3,
            observed: result.observed_host_cr3,
        });
    }
    if result.observed_guest_cr3 != guest.cr3 {
        return Err(ResidentProbeError::GuestCr3Mismatch {
            expected: guest.cr3,
            observed: result.observed_guest_cr3,
        });
    }

    let report = ResidentProbeReport {
        code_physical_address: code.pages.physical_address(),
        code_pages: code.pages.pages(),
        data_memory_type: RESIDENT_MEMORY_TYPE.0,
        code_memory_type: RESIDENT_CODE_MEMORY_TYPE.0,
        host_cr3: host_space.host_cr3,
        guest_cr3: guest.cr3,
        observed_host_cr3: result.observed_host_cr3,
        observed_guest_cr3: result.observed_guest_cr3,
        exit_reason: result.exit_reason,
        guest_rip: result.guest_rip,
        host_gdt: tables.gdt,
        host_idt: tables.idt,
        host_tss: tables.tss,
        host_stack: host_rsp,
    };

    let _ = &tables.pages;
    Ok(report)
}

pub fn status_from_error(error: &ResidentProbeError) -> Status {
    match error {
        ResidentProbeError::Allocation(status)
        | ResidentProbeError::Vmxon(VmxonError::Allocation(status))
        | ResidentProbeError::Vmcs(VmcsError::Allocation(status))
        | ResidentProbeError::Paging(HostPagingError::Allocation(status)) => *status,
        _ => Status::DEVICE_ERROR,
    }
}

fn configure_resident_host(
    host_cr3: u64,
    tables: &ResidentHostTables,
    segments: segmentation::SegmentationState,
) -> Result<(), VmcsError> {
    vmwrite(
        HOST_ES_SELECTOR,
        u64::from(host_selector(segments.es.selector)),
    )?;
    vmwrite(
        HOST_CS_SELECTOR,
        u64::from(host_selector(segments.cs.selector)),
    )?;
    vmwrite(
        HOST_SS_SELECTOR,
        u64::from(host_selector(segments.ss.selector)),
    )?;
    vmwrite(
        HOST_DS_SELECTOR,
        u64::from(host_selector(segments.ds.selector)),
    )?;
    vmwrite(
        HOST_FS_SELECTOR,
        u64::from(host_selector(segments.fs.selector)),
    )?;
    vmwrite(
        HOST_GS_SELECTOR,
        u64::from(host_selector(segments.gs.selector)),
    )?;
    vmwrite(HOST_TR_SELECTOR, u64::from(HOST_TSS_SELECTOR))?;
    vmwrite(HOST_CR0, control_regs::read_cr0())?;
    vmwrite(HOST_CR3, host_cr3)?;
    vmwrite(HOST_CR4, control_regs::read_cr4())?;
    vmwrite(HOST_FS_BASE, segments.fs.base)?;
    vmwrite(HOST_GS_BASE, segments.gs.base)?;
    vmwrite(HOST_TR_BASE, tables.tss)?;
    vmwrite(HOST_GDTR_BASE, tables.gdt)?;
    vmwrite(HOST_IDTR_BASE, tables.idt)?;
    vmwrite(
        HOST_SYSENTER_CS,
        unsafe { msr::read(msr::IA32_SYSENTER_CS) } & 0xffff_ffff,
    )?;
    vmwrite(HOST_SYSENTER_ESP, unsafe {
        msr::read(msr::IA32_SYSENTER_ESP)
    })?;
    vmwrite(HOST_SYSENTER_EIP, unsafe {
        msr::read(msr::IA32_SYSENTER_EIP)
    })?;
    Ok(())
}

fn host_selector(selector: u16) -> u16 {
    selector & !0x7
}

fn validate_run_path(raw_path: u64, vm_instruction_error: u64) -> Result<(), ResidentProbeError> {
    match raw_path {
        0 => Ok(()),
        1 => Err(ResidentProbeError::VmlaunchVmFailInvalid),
        2 => Err(ResidentProbeError::VmlaunchVmFailValid(
            vm_instruction_error,
        )),
        3 => Err(ResidentProbeError::HostRspVmwrite),
        4 => Err(ResidentProbeError::HostRipVmwrite),
        other => Err(ResidentProbeError::UnexpectedRunPath(other)),
    }
}

fn tss_descriptor(base: u64) -> (u64, u64) {
    let limit = u64::from(TSS_LIMIT);
    let low = (limit & 0xffff)
        | ((base & 0xffff) << 16)
        | (((base >> 16) & 0xff) << 32)
        | (0x8b_u64 << 40)
        | (((limit >> 16) & 0xf) << 48)
        | (((base >> 24) & 0xff) << 56);
    (low, base >> 32)
}

fn guest_probe_address() -> u64 {
    matrixhv_resident_guest_probe_asm as *const () as usize as u64
}

unsafe extern "efiapi" {
    fn matrixhv_resident_probe_run_asm(
        context: *mut ResidentContext,
        host_rsp: u64,
        host_rip: u64,
    ) -> u64;
    fn matrixhv_resident_guest_probe_asm();
}

unsafe extern "C" {
    static matrixhv_resident_island_start: u8;
    static matrixhv_resident_island_entry: u8;
    static matrixhv_resident_island_fatal: u8;
    static matrixhv_resident_island_end: u8;
}

global_asm!(
    ".text",
    ".globl matrixhv_resident_guest_probe_asm",
    "matrixhv_resident_guest_probe_asm:",
    "vmcall",
    "ud2",
    ".globl matrixhv_resident_probe_run_asm",
    "matrixhv_resident_probe_run_asm:",
    "push rbx",
    "push rbp",
    "push rdi",
    "push rsi",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov qword ptr [rcx + 0], rsp",
    "lea rax, [rip + 9f]",
    "mov qword ptr [rcx + 8], rax",
    "sgdt [rcx + 88]",
    "sidt [rcx + 98]",
    "mov rax, {host_rsp}",
    "vmwrite rax, rdx",
    "jc 3f",
    "jz 3f",
    "mov rax, {host_rip}",
    "vmwrite rax, r8",
    "jc 4f",
    "jz 4f",
    "vmlaunch",
    "jc 1f",
    "jz 2f",
    "mov eax, 5",
    "jmp 8f",
    "1:",
    "mov eax, 1",
    "jmp 8f",
    "2:",
    "mov eax, 2",
    "jmp 8f",
    "3:",
    "mov eax, 3",
    "jmp 8f",
    "4:",
    "mov eax, 4",
    "jmp 8f",
    "9:",
    "lgdt [r10 + 88]",
    "lidt [r10 + 98]",
    "xor eax, eax",
    "8:",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rsi",
    "pop rdi",
    "pop rbp",
    "pop rbx",
    "ret",
    host_rsp = const HOST_RSP,
    host_rip = const HOST_RIP,
);

global_asm!(
    ".section .text.matrixhv_resident_island,\"ax\"",
    ".p2align 4",
    ".globl matrixhv_resident_island_start",
    ".globl matrixhv_resident_island_entry",
    "matrixhv_resident_island_start:",
    "matrixhv_resident_island_entry:",
    "cld",
    "mov r10, qword ptr [rsp]",
    "mov rax, cr3",
    "mov qword ptr [r10 + 32], rax",
    "mov rax, {guest_cr3}",
    "vmread r11, rax",
    "jc matrixhv_resident_island_fatal",
    "jz matrixhv_resident_island_fatal",
    "mov qword ptr [r10 + 40], r11",
    "mov rax, {exit_reason}",
    "vmread r11, rax",
    "jc matrixhv_resident_island_fatal",
    "jz matrixhv_resident_island_fatal",
    "mov qword ptr [r10 + 48], r11",
    "mov rax, {guest_rip}",
    "vmread r11, rax",
    "jc matrixhv_resident_island_fatal",
    "jz matrixhv_resident_island_fatal",
    "mov qword ptr [r10 + 56], r11",
    "mov rax, {complete}",
    "mov qword ptr [r10 + 72], rax",
    "mov rax, qword ptr [r10 + 16]",
    "mov cr3, rax",
    "mov rsp, qword ptr [r10 + 0]",
    "jmp qword ptr [r10 + 8]",
    ".globl matrixhv_resident_island_fatal",
    "matrixhv_resident_island_fatal:",
    "cli",
    "mov dx, 0x3f8",
    "mov al, 0x21",
    "out dx, al",
    "1:",
    "hlt",
    "jmp 1b",
    ".globl matrixhv_resident_island_end",
    "matrixhv_resident_island_end:",
    ".text",
    guest_cr3 = const GUEST_CR3,
    guest_rip = const GUEST_RIP,
    exit_reason = const VM_EXIT_REASON,
    complete = const CONTEXT_COMPLETE,
);
