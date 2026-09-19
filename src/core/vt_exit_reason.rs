pub const VM_ENTRY_FAILURE_BIT: u32 = 1 << 31;
pub const BASIC_EXIT_REASON_MASK: u32 = 0xffff;
pub const VMCALL: u32 = 18;

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
        18 => "vmcall",
        33 => "vm_entry_invalid_guest_state",
        34 => "vm_entry_msr_load_failure",
        41 => "vm_entry_machine_check",
        _ => "other",
    }
}
