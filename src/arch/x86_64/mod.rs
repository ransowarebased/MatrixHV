pub mod registers;
pub mod segmentation;

pub mod control_regs {
    pub use super::registers::{
        CR4_LA57, CR4_VMXE, read_cr0, read_cr3, read_cr4, write_cr0, write_cr3, write_cr4,
    };
}

pub mod msr {
    pub use super::registers::{
        IA32_DEBUGCTL, IA32_EFER, IA32_FS_BASE, IA32_GS_BASE, IA32_PAT, IA32_SYSENTER_CS,
        IA32_SYSENTER_EIP, IA32_SYSENTER_ESP, IA32_VMX_BASIC, IA32_VMX_CR0_FIXED0,
        IA32_VMX_CR0_FIXED1, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1, IA32_VMX_ENTRY_CTLS,
        IA32_VMX_EPT_VPID_CAP, IA32_VMX_EXIT_CTLS, IA32_VMX_PINBASED_CTLS, IA32_VMX_PROCBASED_CTLS,
        IA32_VMX_PROCBASED_CTLS2, IA32_VMX_TRUE_ENTRY_CTLS, IA32_VMX_TRUE_EXIT_CTLS,
        IA32_VMX_TRUE_PINBASED_CTLS, IA32_VMX_TRUE_PROCBASED_CTLS, read_msr as read,
        write_msr as write,
    };
}

pub mod cpuid {
    pub use super::registers::{leaf, leaf_with_subleaf};
}

pub mod cpu {
    pub use super::registers::{Vendor, capabilities};
}
