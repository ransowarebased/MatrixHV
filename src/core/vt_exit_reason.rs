pub const VM_ENTRY_FAILURE_BIT: u32 = 1 << 31;
pub const BASIC_EXIT_REASON_MASK: u32 = 0xffff;
pub const CPUID: u32 = 10;
pub const VMCALL: u32 = 18;
pub const RDMSR: u32 = 31;
pub const WRMSR: u32 = 32;

pub fn basic(raw: u32) -> u32 {
    raw & BASIC_EXIT_REASON_MASK
}

pub fn is_vm_entry_failure(raw: u32) -> bool {
    raw & VM_ENTRY_FAILURE_BIT != 0
}

pub fn name(raw: u32) -> &'static str {
    match basic(raw) {
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
