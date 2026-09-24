use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::vt_vmcs::{self, VmcsError};
use super::vt_vmcs_fields::{
    EXIT_QUALIFICATION, GUEST_CR3, GUEST_RIP, VM_EXIT_INSTRUCTION_LEN, VM_EXIT_REASON,
};
use crate::arch::x86_64::{control_regs, cpuid, msr};
use crate::boot::logger;

pub const VM_ENTRY_FAILURE_BIT: u32 = 1 << 31;
pub const BASIC_EXIT_REASON_MASK: u32 = 0xffff;
pub const CPUID: u32 = 10;
pub const VMCALL: u32 = 18;
pub const RDMSR: u32 = 31;
pub const WRMSR: u32 = 32;

pub fn basic_reason(raw: u32) -> u32 {
    raw & BASIC_EXIT_REASON_MASK
}

pub fn is_vm_entry_failure(raw: u32) -> bool {
    raw & VM_ENTRY_FAILURE_BIT != 0
}

pub fn reason_name(raw: u32) -> &'static str {
    match basic_reason(raw) {
        0 => "exception_or_nmi",
        1 => "external_interrupt",
        2 => "triple_fault",
        10 => "cpuid",
        18 => "vmcall",
        31 => "rdmsr",
        32 => "wrmsr",
        33 => "vm_entry_invalid_guest_state",
        34 => "vm_entry_msr_load_failure",
        41 => "vm_entry_machine_check",
        _ => "other",
    }
}

const DISPATCH_FAILURE_NONE: u32 = 0;
const DISPATCH_FAILURE_VMREAD: u32 = 1;
const DISPATCH_FAILURE_ENTRY: u32 = 2;
const DISPATCH_FAILURE_UNEXPECTED_EXIT: u32 = 3;
const DISPATCH_FAILURE_CPUID_LENGTH: u32 = 4;
const DISPATCH_FAILURE_VMCALL_LENGTH: u32 = 5;
const DISPATCH_FAILURE_RIP_ADVANCE: u32 = 6;
const DISPATCH_FAILURE_EXIT_LIMIT: u32 = 7;
const MAX_DISPATCH_EXITS: u32 = 4096;
const MAX_BOOT_DISPATCH_EXITS: u32 = 65536;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rsp: u64,
}

#[repr(C, align(16))]
#[derive(Debug)]
pub struct VmRunContext {
    pub root_rsp: u64,
    _alignment_padding: u64,
    root_fx_state: [u8; 512],
    guest_fx_state: [u8; 512],
    exit_limit: u32,
    trace_every_exit: bool,
}

impl Default for VmRunContext {
    fn default() -> Self {
        Self {
            root_rsp: 0,
            _alignment_padding: 0,
            root_fx_state: [0; 512],
            guest_fx_state: [0; 512],
            exit_limit: MAX_DISPATCH_EXITS,
            trace_every_exit: true,
        }
    }
}

impl VmRunContext {
    pub fn for_boot_target() -> Self {
        Self {
            exit_limit: MAX_BOOT_DISPATCH_EXITS,
            trace_every_exit: false,
            ..Self::default()
        }
    }
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchAction {
    Stop = 0,
    Resume = 1,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DispatchDiagnostics {
    pub exit_count: u32,
    pub cpuid_count: u32,
    pub rdmsr_count: u32,
    pub wrmsr_count: u32,
    pub vmcall_count: u32,
    pub resume_count: u32,
    pub failure_code: u32,
    pub cpuid_rip: u64,
    pub vmcall_rip: u64,
    pub last_reason: u32,
    pub last_instruction_length: u32,
    pub last_qualification: u64,
    pub cpuid_leaf: u32,
    pub cpuid_subleaf: u32,
    pub cpuid_eax: u32,
    pub cpuid_ebx: u32,
    pub cpuid_ecx: u32,
    pub cpuid_edx: u32,
    pub final_eax: u64,
    pub final_ebx: u64,
    pub final_ecx: u64,
    pub final_edx: u64,
    pub final_rsp: u64,
    pub first_host_cr3: u64,
    pub last_host_cr3: u64,
    pub last_guest_cr3: u64,
}

static EXIT_COUNT: AtomicU32 = AtomicU32::new(0);
static CPUID_COUNT: AtomicU32 = AtomicU32::new(0);
static RDMSR_COUNT: AtomicU32 = AtomicU32::new(0);
static WRMSR_COUNT: AtomicU32 = AtomicU32::new(0);
static VMCALL_COUNT: AtomicU32 = AtomicU32::new(0);
static RESUME_COUNT: AtomicU32 = AtomicU32::new(0);
static FAILURE_CODE: AtomicU32 = AtomicU32::new(DISPATCH_FAILURE_NONE);
static CPUID_RIP: AtomicU64 = AtomicU64::new(0);
static VMCALL_RIP: AtomicU64 = AtomicU64::new(0);
static LAST_REASON: AtomicU32 = AtomicU32::new(0);
static LAST_INSTRUCTION_LENGTH: AtomicU32 = AtomicU32::new(0);
static LAST_QUALIFICATION: AtomicU64 = AtomicU64::new(0);
static CPUID_LEAF: AtomicU32 = AtomicU32::new(0);
static CPUID_SUBLEAF: AtomicU32 = AtomicU32::new(0);
static CPUID_EAX: AtomicU32 = AtomicU32::new(0);
static CPUID_EBX: AtomicU32 = AtomicU32::new(0);
static CPUID_ECX: AtomicU32 = AtomicU32::new(0);
static CPUID_EDX: AtomicU32 = AtomicU32::new(0);
static FINAL_EAX: AtomicU64 = AtomicU64::new(0);
static FINAL_EBX: AtomicU64 = AtomicU64::new(0);
static FINAL_ECX: AtomicU64 = AtomicU64::new(0);
static FINAL_EDX: AtomicU64 = AtomicU64::new(0);
static FINAL_RSP: AtomicU64 = AtomicU64::new(0);
static FIRST_HOST_CR3: AtomicU64 = AtomicU64::new(0);
static LAST_HOST_CR3: AtomicU64 = AtomicU64::new(0);
static LAST_GUEST_CR3: AtomicU64 = AtomicU64::new(0);

pub fn reset_diagnostics() {
    EXIT_COUNT.store(0, Ordering::Relaxed);
    CPUID_COUNT.store(0, Ordering::Relaxed);
    RDMSR_COUNT.store(0, Ordering::Relaxed);
    WRMSR_COUNT.store(0, Ordering::Relaxed);
    VMCALL_COUNT.store(0, Ordering::Relaxed);
    RESUME_COUNT.store(0, Ordering::Relaxed);
    FAILURE_CODE.store(DISPATCH_FAILURE_NONE, Ordering::Relaxed);
    CPUID_RIP.store(0, Ordering::Relaxed);
    VMCALL_RIP.store(0, Ordering::Relaxed);
    LAST_REASON.store(0, Ordering::Relaxed);
    LAST_INSTRUCTION_LENGTH.store(0, Ordering::Relaxed);
    LAST_QUALIFICATION.store(0, Ordering::Relaxed);
    CPUID_LEAF.store(0, Ordering::Relaxed);
    CPUID_SUBLEAF.store(0, Ordering::Relaxed);
    CPUID_EAX.store(0, Ordering::Relaxed);
    CPUID_EBX.store(0, Ordering::Relaxed);
    CPUID_ECX.store(0, Ordering::Relaxed);
    CPUID_EDX.store(0, Ordering::Relaxed);
    FINAL_EAX.store(0, Ordering::Relaxed);
    FINAL_EBX.store(0, Ordering::Relaxed);
    FINAL_ECX.store(0, Ordering::Relaxed);
    FINAL_EDX.store(0, Ordering::Relaxed);
    FINAL_RSP.store(0, Ordering::Relaxed);
    FIRST_HOST_CR3.store(0, Ordering::Relaxed);
    LAST_HOST_CR3.store(0, Ordering::Relaxed);
    LAST_GUEST_CR3.store(0, Ordering::Relaxed);
}

pub fn diagnostics() -> DispatchDiagnostics {
    DispatchDiagnostics {
        exit_count: EXIT_COUNT.load(Ordering::Relaxed),
        cpuid_count: CPUID_COUNT.load(Ordering::Relaxed),
        rdmsr_count: RDMSR_COUNT.load(Ordering::Relaxed),
        wrmsr_count: WRMSR_COUNT.load(Ordering::Relaxed),
        vmcall_count: VMCALL_COUNT.load(Ordering::Relaxed),
        resume_count: RESUME_COUNT.load(Ordering::Relaxed),
        failure_code: FAILURE_CODE.load(Ordering::Relaxed),
        cpuid_rip: CPUID_RIP.load(Ordering::Relaxed),
        vmcall_rip: VMCALL_RIP.load(Ordering::Relaxed),
        last_reason: LAST_REASON.load(Ordering::Relaxed),
        last_instruction_length: LAST_INSTRUCTION_LENGTH.load(Ordering::Relaxed),
        last_qualification: LAST_QUALIFICATION.load(Ordering::Relaxed),
        cpuid_leaf: CPUID_LEAF.load(Ordering::Relaxed),
        cpuid_subleaf: CPUID_SUBLEAF.load(Ordering::Relaxed),
        cpuid_eax: CPUID_EAX.load(Ordering::Relaxed),
        cpuid_ebx: CPUID_EBX.load(Ordering::Relaxed),
        cpuid_ecx: CPUID_ECX.load(Ordering::Relaxed),
        cpuid_edx: CPUID_EDX.load(Ordering::Relaxed),
        final_eax: FINAL_EAX.load(Ordering::Relaxed),
        final_ebx: FINAL_EBX.load(Ordering::Relaxed),
        final_ecx: FINAL_ECX.load(Ordering::Relaxed),
        final_edx: FINAL_EDX.load(Ordering::Relaxed),
        final_rsp: FINAL_RSP.load(Ordering::Relaxed),
        first_host_cr3: FIRST_HOST_CR3.load(Ordering::Relaxed),
        last_host_cr3: LAST_HOST_CR3.load(Ordering::Relaxed),
        last_guest_cr3: LAST_GUEST_CR3.load(Ordering::Relaxed),
    }
}

pub fn failure_name(code: u32) -> &'static str {
    match code {
        DISPATCH_FAILURE_NONE => "none",
        DISPATCH_FAILURE_VMREAD => "vmread_failed",
        DISPATCH_FAILURE_ENTRY => "vm_entry_failure",
        DISPATCH_FAILURE_UNEXPECTED_EXIT => "unexpected_exit",
        DISPATCH_FAILURE_CPUID_LENGTH => "invalid_cpuid_length",
        DISPATCH_FAILURE_VMCALL_LENGTH => "invalid_vmcall_length",
        DISPATCH_FAILURE_RIP_ADVANCE => "guest_rip_advance_failed",
        DISPATCH_FAILURE_EXIT_LIMIT => "exit_limit_exceeded",
        _ => "unknown",
    }
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn matrixhv_vmexit_dispatch(
    registers: *mut GuestRegisters,
    context: *mut VmRunContext,
) -> u64 {
    let Some(registers) = (unsafe { registers.as_mut() }) else {
        FAILURE_CODE.store(DISPATCH_FAILURE_UNEXPECTED_EXIT, Ordering::Relaxed);
        return DispatchAction::Stop as u64;
    };
    let Some(context) = (unsafe { context.as_ref() }) else {
        FAILURE_CODE.store(DISPATCH_FAILURE_UNEXPECTED_EXIT, Ordering::Relaxed);
        return DispatchAction::Stop as u64;
    };

    let (raw_reason, guest_rip, instruction_length, qualification, guest_cr3) =
        match read_exit_state() {
            Ok(state) => state,
            Err(error) => {
                FAILURE_CODE.store(DISPATCH_FAILURE_VMREAD, Ordering::Relaxed);
                logger::error(format_args!("vmexit vmread error={error:?}"));
                return DispatchAction::Stop as u64;
            }
        };
    let host_cr3 = control_regs::read_cr3();
    let _ = FIRST_HOST_CR3.compare_exchange(0, host_cr3, Ordering::Relaxed, Ordering::Relaxed);
    LAST_HOST_CR3.store(host_cr3, Ordering::Relaxed);
    LAST_GUEST_CR3.store(guest_cr3, Ordering::Relaxed);

    let basic_code = basic_reason(raw_reason);
    let exit_index = EXIT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if exit_index > context.exit_limit {
        FAILURE_CODE.store(DISPATCH_FAILURE_EXIT_LIMIT, Ordering::Relaxed);
        logger::error(format_args!(
            "vmexit exit_limit_exceeded count={} limit={}",
            exit_index, context.exit_limit
        ));
        logger::phase("vmx.dispatch.exit_limit_exceeded");
        return DispatchAction::Stop as u64;
    }
    LAST_REASON.store(raw_reason, Ordering::Relaxed);
    LAST_INSTRUCTION_LENGTH.store(instruction_length, Ordering::Relaxed);
    LAST_QUALIFICATION.store(qualification, Ordering::Relaxed);
    let trace_exit = context.trace_every_exit || exit_index <= 16 || exit_index.is_power_of_two();

    if trace_exit {
        logger::info(format_args!(
            "vmexit dispatch index={} raw_reason={:#x} name={} basic_reason={} rip={:#x} len={} qualification={:#x} host_cr3={:#x} guest_cr3={:#x}",
            exit_index,
            raw_reason,
            reason_name(raw_reason),
            basic_code,
            guest_rip,
            instruction_length,
            qualification,
            host_cr3,
            guest_cr3
        ));
    }

    if is_vm_entry_failure(raw_reason) {
        FAILURE_CODE.store(DISPATCH_FAILURE_ENTRY, Ordering::Relaxed);
        logger::phase("vmx.dispatch.vm_entry_failure");
        return DispatchAction::Stop as u64;
    }

    match basic_code {
        CPUID => dispatch_cpuid(registers, guest_rip, instruction_length, trace_exit),
        RDMSR => dispatch_rdmsr(registers, guest_rip, instruction_length, trace_exit),
        WRMSR => dispatch_wrmsr(registers, guest_rip, instruction_length, trace_exit),
        VMCALL => dispatch_vmcall(registers, guest_rip, instruction_length),
        _ => {
            FAILURE_CODE.store(DISPATCH_FAILURE_UNEXPECTED_EXIT, Ordering::Relaxed);
            logger::error(format_args!(
                "vmexit unexpected reason={} name={} rip={:#x}",
                basic_code,
                reason_name(raw_reason),
                guest_rip
            ));
            logger::phase("vmx.dispatch.unexpected_exit");
            DispatchAction::Stop as u64
        }
    }
}

fn dispatch_rdmsr(
    registers: &mut GuestRegisters,
    guest_rip: u64,
    instruction_length: u32,
    trace_exit: bool,
) -> u64 {
    if trace_exit {
        logger::phase("vmx.dispatch.rdmsr.start");
    }
    if instruction_length != 2 {
        FAILURE_CODE.store(DISPATCH_FAILURE_UNEXPECTED_EXIT, Ordering::Relaxed);
        return DispatchAction::Stop as u64;
    }
    let index = registers.rcx as u32;
    let value = unsafe { msr::read(index) };
    registers.rax = u64::from(value as u32);
    registers.rdx = u64::from((value >> 32) as u32);

    if advance_guest_rip(guest_rip, instruction_length).is_err() {
        FAILURE_CODE.store(DISPATCH_FAILURE_RIP_ADVANCE, Ordering::Relaxed);
        return DispatchAction::Stop as u64;
    }
    RDMSR_COUNT.fetch_add(1, Ordering::Relaxed);
    RESUME_COUNT.fetch_add(1, Ordering::Relaxed);
    if trace_exit {
        logger::info(format_args!(
            "vmexit rdmsr index={:#x} value={:#x} next_rip={:#x}",
            index,
            value,
            guest_rip + u64::from(instruction_length)
        ));
        logger::phase("vmx.dispatch.rdmsr.resume");
    }
    DispatchAction::Resume as u64
}

fn dispatch_wrmsr(
    registers: &GuestRegisters,
    guest_rip: u64,
    instruction_length: u32,
    trace_exit: bool,
) -> u64 {
    if trace_exit {
        logger::phase("vmx.dispatch.wrmsr.start");
    }
    if instruction_length != 2 {
        FAILURE_CODE.store(DISPATCH_FAILURE_UNEXPECTED_EXIT, Ordering::Relaxed);
        return DispatchAction::Stop as u64;
    }
    let index = registers.rcx as u32;
    let value = ((registers.rdx as u32 as u64) << 32) | u64::from(registers.rax as u32);
    unsafe {
        msr::write(index, value);
    }
    if advance_guest_rip(guest_rip, instruction_length).is_err() {
        FAILURE_CODE.store(DISPATCH_FAILURE_RIP_ADVANCE, Ordering::Relaxed);
        return DispatchAction::Stop as u64;
    }
    WRMSR_COUNT.fetch_add(1, Ordering::Relaxed);
    RESUME_COUNT.fetch_add(1, Ordering::Relaxed);
    if trace_exit {
        logger::info(format_args!(
            "vmexit wrmsr index={:#x} value={:#x} next_rip={:#x}",
            index,
            value,
            guest_rip + u64::from(instruction_length)
        ));
        logger::phase("vmx.dispatch.wrmsr.resume");
    }
    DispatchAction::Resume as u64
}

fn dispatch_cpuid(
    registers: &mut GuestRegisters,
    guest_rip: u64,
    instruction_length: u32,
    trace_exit: bool,
) -> u64 {
    if trace_exit {
        logger::phase("vmx.dispatch.cpuid.start");
    }
    if instruction_length != 2 {
        FAILURE_CODE.store(DISPATCH_FAILURE_CPUID_LENGTH, Ordering::Relaxed);
        return DispatchAction::Stop as u64;
    }

    let leaf = registers.rax as u32;
    let subleaf = registers.rcx as u32;
    let result = cpuid::leaf_with_subleaf(leaf, subleaf);

    registers.rax = u64::from(result.eax);
    registers.rbx = u64::from(result.ebx);
    registers.rcx = u64::from(result.ecx);
    registers.rdx = u64::from(result.edx);

    if advance_guest_rip(guest_rip, instruction_length).is_err() {
        FAILURE_CODE.store(DISPATCH_FAILURE_RIP_ADVANCE, Ordering::Relaxed);
        return DispatchAction::Stop as u64;
    }

    CPUID_COUNT.fetch_add(1, Ordering::Relaxed);
    CPUID_RIP.store(guest_rip, Ordering::Relaxed);
    CPUID_LEAF.store(leaf, Ordering::Relaxed);
    CPUID_SUBLEAF.store(subleaf, Ordering::Relaxed);
    CPUID_EAX.store(result.eax, Ordering::Relaxed);
    CPUID_EBX.store(result.ebx, Ordering::Relaxed);
    CPUID_ECX.store(result.ecx, Ordering::Relaxed);
    CPUID_EDX.store(result.edx, Ordering::Relaxed);
    RESUME_COUNT.fetch_add(1, Ordering::Relaxed);

    if trace_exit {
        logger::info(format_args!(
            "vmexit cpuid leaf={:#x} subleaf={:#x} eax={:#x} ebx={:#x} ecx={:#x} edx={:#x} next_rip={:#x}",
            leaf,
            subleaf,
            result.eax,
            result.ebx,
            result.ecx,
            result.edx,
            guest_rip + u64::from(instruction_length)
        ));
        logger::phase("vmx.dispatch.cpuid.resume");
    }
    DispatchAction::Resume as u64
}

fn dispatch_vmcall(registers: &GuestRegisters, guest_rip: u64, instruction_length: u32) -> u64 {
    logger::phase("vmx.dispatch.vmcall.start");
    if instruction_length != 3 {
        FAILURE_CODE.store(DISPATCH_FAILURE_VMCALL_LENGTH, Ordering::Relaxed);
        return DispatchAction::Stop as u64;
    }

    VMCALL_COUNT.fetch_add(1, Ordering::Relaxed);
    VMCALL_RIP.store(guest_rip, Ordering::Relaxed);
    FINAL_EAX.store(registers.rax, Ordering::Relaxed);
    FINAL_EBX.store(registers.rbx, Ordering::Relaxed);
    FINAL_ECX.store(registers.rcx, Ordering::Relaxed);
    FINAL_EDX.store(registers.rdx, Ordering::Relaxed);
    FINAL_RSP.store(registers.rsp, Ordering::Relaxed);
    logger::info(format_args!(
        "vmexit vmcall final_regs rax={:#x} rbx={:#x} rcx={:#x} rdx={:#x} rsp={:#x}",
        registers.rax, registers.rbx, registers.rcx, registers.rdx, registers.rsp
    ));
    logger::phase("vmx.dispatch.vmcall.stop");
    DispatchAction::Stop as u64
}

fn read_exit_state() -> Result<(u32, u64, u32, u64, u64), VmcsError> {
    Ok((
        vt_vmcs::vmread(VM_EXIT_REASON)? as u32,
        vt_vmcs::vmread(GUEST_RIP)?,
        vt_vmcs::vmread(VM_EXIT_INSTRUCTION_LEN)? as u32,
        vt_vmcs::vmread(EXIT_QUALIFICATION)?,
        vt_vmcs::vmread(GUEST_CR3)?,
    ))
}

fn advance_guest_rip(guest_rip: u64, instruction_length: u32) -> Result<(), VmcsError> {
    vt_vmcs::vmwrite(
        GUEST_RIP,
        guest_rip.wrapping_add(u64::from(instruction_length)),
    )
}
