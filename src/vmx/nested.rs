use super::vmcs12::{NestedVmcs12State, VMCS12_EXTENDED_FIELD_COUNT, VMCS12_MAX_ENUM_INDEX};

use core::arch::x86_64::__cpuid;

pub const IA32_FEATURE_CONTROL_LOCKED: u64 = 1 << 0;
pub const IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX: u64 = 1 << 2;
pub const VMX_MEMORY_TYPE_WRITE_BACK: u64 = 6;
pub const VMX_REGION_SIZE: u64 = 4096;
pub const VMX_BASIC_TRUE_CONTROLS: u64 = 1 << 55;
pub const VMX_BASIC_IO_EXIT_INFORMATION: u64 = 1 << 54;

pub const IA32_VMX_BASIC_MSR: u32 = 0x480;
pub const IA32_VMX_PINBASED_CTLS_MSR: u32 = 0x481;
pub const IA32_VMX_PROCBASED_CTLS_MSR: u32 = 0x482;
pub const IA32_VMX_EXIT_CTLS_MSR: u32 = 0x483;
pub const IA32_VMX_ENTRY_CTLS_MSR: u32 = 0x484;
pub const IA32_VMX_MISC_MSR: u32 = 0x485;
pub const IA32_VMX_CR0_FIXED0_MSR: u32 = 0x486;
pub const IA32_VMX_CR0_FIXED1_MSR: u32 = 0x487;
pub const IA32_VMX_CR4_FIXED0_MSR: u32 = 0x488;
pub const IA32_VMX_CR4_FIXED1_MSR: u32 = 0x489;
pub const IA32_VMX_VMCS_ENUM_MSR: u32 = 0x48a;
pub const IA32_VMX_PROCBASED_CTLS2_MSR: u32 = 0x48b;
pub const IA32_VMX_EPT_VPID_CAP_MSR: u32 = 0x48c;
pub const IA32_VMX_TRUE_PINBASED_CTLS_MSR: u32 = 0x48d;
pub const IA32_VMX_TRUE_PROCBASED_CTLS_MSR: u32 = 0x48e;
pub const IA32_VMX_TRUE_EXIT_CTLS_MSR: u32 = 0x48f;
pub const IA32_VMX_TRUE_ENTRY_CTLS_MSR: u32 = 0x490;
pub const IA32_VMX_VMFUNC_MSR: u32 = 0x491;

pub const VMX_PIN_EXTERNAL_INTERRUPT_EXITING: u32 = 1 << 0;
pub const VMX_PIN_NMI_EXITING: u32 = 1 << 3;
pub const VMX_PIN_VIRTUAL_NMIS: u32 = 1 << 5;
pub const VM_EXIT_ACK_INTERRUPT_ON_EXIT: u32 = 1 << 15;
pub const VM_EXIT_HOST_ADDRESS_SPACE_SIZE: u32 = 1 << 9;
pub const VM_EXIT_LOAD_IA32_PAT: u32 = 1 << 19;
pub const VM_EXIT_SAVE_IA32_EFER: u32 = 1 << 20;
pub const VM_EXIT_LOAD_IA32_EFER: u32 = 1 << 21;
pub const VM_ENTRY_IA32E_MODE_GUEST: u32 = 1 << 9;
pub const VM_ENTRY_LOAD_IA32_PAT: u32 = 1 << 14;
pub const VM_ENTRY_LOAD_IA32_EFER: u32 = 1 << 15;
pub const VMX_PRIMARY_INTERRUPT_WINDOW_EXITING: u32 = 1 << 2;
pub const VMX_PRIMARY_USE_TSC_OFFSETTING: u32 = 1 << 3;
pub const VMX_PRIMARY_HLT_EXITING: u32 = 1 << 7;
pub const VMX_PRIMARY_INVLPG_EXITING: u32 = 1 << 9;
pub const VMX_PRIMARY_MWAIT_EXITING: u32 = 1 << 10;
pub const VMX_PRIMARY_RDPMC_EXITING: u32 = 1 << 11;
pub const VMX_PRIMARY_RDTSC_EXITING: u32 = 1 << 12;
pub const VMX_PRIMARY_CR3_LOAD_EXITING: u32 = 1 << 15;
pub const VMX_PRIMARY_CR3_STORE_EXITING: u32 = 1 << 16;
pub const VMX_PRIMARY_CR8_LOAD_EXITING: u32 = 1 << 19;
pub const VMX_PRIMARY_CR8_STORE_EXITING: u32 = 1 << 20;
pub const VMX_PRIMARY_TPR_SHADOW: u32 = 1 << 21;
pub const VMX_PRIMARY_NMI_WINDOW_EXITING: u32 = 1 << 22;
pub const VMX_PRIMARY_MOV_DR_EXITING: u32 = 1 << 23;
pub const VMX_PRIMARY_UNCONDITIONAL_IO_EXITING: u32 = 1 << 24;
pub const VMX_PRIMARY_USE_IO_BITMAPS: u32 = 1 << 25;
pub const VMX_PRIMARY_MONITOR_TRAP_FLAG: u32 = 1 << 27;
pub const VMX_PRIMARY_USE_MSR_BITMAPS: u32 = 1 << 28;
pub const VMX_PRIMARY_MONITOR_EXITING: u32 = 1 << 29;
pub const VMX_PRIMARY_PAUSE_EXITING: u32 = 1 << 30;
pub const VMX_PRIMARY_ACTIVATE_SECONDARY_CONTROLS: u32 = 1 << 31;
pub const VMX_PRIMARY_KVM_EXITING_CONTROLS: u32 = VMX_PRIMARY_INTERRUPT_WINDOW_EXITING
    | VMX_PRIMARY_USE_TSC_OFFSETTING
    | VMX_PRIMARY_HLT_EXITING
    | VMX_PRIMARY_INVLPG_EXITING
    | VMX_PRIMARY_MWAIT_EXITING
    | VMX_PRIMARY_RDPMC_EXITING
    | VMX_PRIMARY_CR3_LOAD_EXITING
    | VMX_PRIMARY_CR3_STORE_EXITING
    | VMX_PRIMARY_CR8_LOAD_EXITING
    | VMX_PRIMARY_CR8_STORE_EXITING
    | VMX_PRIMARY_NMI_WINDOW_EXITING
    | VMX_PRIMARY_MOV_DR_EXITING
    | VMX_PRIMARY_MONITOR_EXITING;
pub const VMX_SECONDARY_ENABLE_EPT: u32 = 1 << 1;
pub const VMX_SECONDARY_DESCRIPTOR_TABLE_EXITING: u32 = 1 << 2;
pub const VMX_SECONDARY_ENABLE_RDTSCP: u32 = 1 << 3;
pub const VMX_SECONDARY_ENABLE_VPID: u32 = 1 << 5;
pub const VMX_SECONDARY_WBINVD_EXITING: u32 = 1 << 6;
pub const VMX_SECONDARY_UNRESTRICTED_GUEST: u32 = 1 << 7;
pub const VMX_SECONDARY_RDRAND_EXITING: u32 = 1 << 11;
pub const VMX_SECONDARY_ENABLE_INVPCID: u32 = 1 << 12;
pub const VMX_SECONDARY_ENABLE_VM_FUNCTIONS: u32 = 1 << 13;
pub const VMX_SECONDARY_VMCS_SHADOWING: u32 = 1 << 14;
pub const VMX_SECONDARY_ENABLE_XSAVES: u32 = 1 << 20;
pub const VMX_SECONDARY_MODE_BASED_EXECUTE: u32 = 1 << 22;
pub const VMX_LEGACY_PINBASED_DEFAULT1: u32 = 0x0000_0016;
pub const VMX_LEGACY_PROCBASED_DEFAULT1: u32 = 0x0401_e172;
pub const VMX_LEGACY_EXIT_DEFAULT1: u32 = 0x0003_6dff;
pub const VMX_LEGACY_ENTRY_DEFAULT1: u32 = 0x0000_11ff;
pub const VMX_EPT_EXECUTE_ONLY: u64 = 1;
pub const VMX_EPT_ADVANCED_EXIT_INFO: u64 = 1 << 22;
pub const VMX_EPT_ACCESSED_DIRTY: u64 = 1 << 21;
pub const VMX_EPT_PAGE_WALK_LENGTH_4: u64 = 1 << 6;
pub const VMX_EPT_MEMORY_TYPE_WB: u64 = 1 << 14;
pub const VMX_EPT_2MB_PAGE: u64 = 1 << 16;
pub const VMX_EPT_INVEPT: u64 = 1 << 20;
pub const VMX_EPT_INVEPT_SINGLE_CONTEXT: u64 = 1 << 25;
pub const VMX_EPT_INVEPT_ALL_CONTEXTS: u64 = 1 << 26;
pub const VMX_VPID_INVVPID: u64 = 1 << 32;
pub const VMX_VPID_INVVPID_INDIVIDUAL_ADDRESS: u64 = 1 << 40;
pub const VMX_VPID_INVVPID_SINGLE_CONTEXT: u64 = 1 << 41;
pub const VMX_VPID_INVVPID_ALL_CONTEXTS: u64 = 1 << 42;
pub const VMX_VPID_INVVPID_SINGLE_CONTEXT_RETAINING_GLOBALS: u64 = 1 << 43;
pub const VMX_EPT_CAPABILITIES: u64 = VMX_EPT_EXECUTE_ONLY
    | VMX_EPT_PAGE_WALK_LENGTH_4
    | VMX_EPT_MEMORY_TYPE_WB
    | VMX_EPT_2MB_PAGE
    | VMX_EPT_ACCESSED_DIRTY
    | VMX_EPT_ADVANCED_EXIT_INFO;
pub const VMX_SOFTWARE_INVALIDATION_CAPABILITIES: u64 = VMX_EPT_INVEPT
    | VMX_EPT_INVEPT_SINGLE_CONTEXT
    | VMX_EPT_INVEPT_ALL_CONTEXTS
    | VMX_VPID_INVVPID
    | VMX_VPID_INVVPID_INDIVIDUAL_ADDRESS
    | VMX_VPID_INVVPID_SINGLE_CONTEXT
    | VMX_VPID_INVVPID_ALL_CONTEXTS
    | VMX_VPID_INVVPID_SINGLE_CONTEXT_RETAINING_GLOBALS;
pub const VMX_MSR_LIST_CAPACITY: usize = 512;
pub const VMX_CR3_TARGET_COUNT: u64 = 4;

pub const CPUID_VMX_BIT: u32 = 1 << 5;
pub const CPUID_OSXSAVE_BIT: u32 = 1 << 27;
pub const NESTED_FAILURE_TRACE_CAPACITY: usize = 32;
pub const NESTED_FAILURE_TRACE_WORD_COUNT: usize = 192;
const _: () = assert!(NESTED_FAILURE_TRACE_WORD_COUNT == NESTED_FAILURE_TRACE_CAPACITY * 6);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostVmxCapabilities {
    pub vmx_basic: u64,
    pub pinbased_ctls: u64,
    pub procbased_ctls: u64,
    pub exit_ctls: u64,
    pub entry_ctls: u64,
    pub misc: u64,
    pub cr0_fixed0: u64,
    pub cr0_fixed1: u64,
    pub cr4_fixed0: u64,
    pub cr4_fixed1: u64,
    pub vmcs_enum: u64,
    pub procbased_ctls2: u64,
    pub ept_vpid_cap: u64,
    pub true_pinbased_ctls: u64,
    pub true_procbased_ctls: u64,
    pub true_exit_ctls: u64,
    pub true_entry_ctls: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedVmxCapabilities {
    pub revision_id: u32,
    pub host_procbased_ctls2: u64,
    pub host_misc: u64,
    pub feature_control: u64,
    pub vmx_basic: u64,
    pub vmx_pinbased_ctls: u64,
    pub vmx_procbased_ctls: u64,
    pub vmx_exit_ctls: u64,
    pub vmx_entry_ctls: u64,
    pub vmx_misc: u64,
    pub vmx_cr0_fixed0: u64,
    pub vmx_cr0_fixed1: u64,
    pub vmx_cr4_fixed0: u64,
    pub vmx_cr4_fixed1: u64,
    pub vmx_vmcs_enum: u64,
    pub vmx_procbased_ctls2: u64,
    pub vmx_ept_vpid_cap: u64,
    pub vmx_true_pinbased_ctls: u64,
    pub vmx_true_procbased_ctls: u64,
    pub vmx_true_exit_ctls: u64,
    pub vmx_true_entry_ctls: u64,
    pub expose_vmx: bool,
}

impl NestedVmxCapabilities {
    pub fn vmxon_vmxoff(host_vmx_basic: u64) -> Self {
        let revision_id = host_vmx_basic as u32 & 0x7fff_ffff;
        Self {
            revision_id,
            host_procbased_ctls2: 0,
            host_misc: 0,
            feature_control: IA32_FEATURE_CONTROL_LOCKED | IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX,
            vmx_basic: u64::from(revision_id)
                | (VMX_REGION_SIZE << 32)
                | (VMX_MEMORY_TYPE_WRITE_BACK << 50),
            vmx_pinbased_ctls: 0,
            vmx_procbased_ctls: 0,
            vmx_exit_ctls: 0,
            vmx_entry_ctls: 0,
            vmx_misc: 0,
            vmx_cr0_fixed0: 0,
            vmx_cr0_fixed1: 0,
            vmx_cr4_fixed0: 0,
            vmx_cr4_fixed1: 0,
            vmx_vmcs_enum: 0,
            vmx_procbased_ctls2: 0,
            vmx_ept_vpid_cap: 0,
            vmx_true_pinbased_ctls: 0,
            vmx_true_procbased_ctls: 0,
            vmx_true_exit_ctls: 0,
            vmx_true_entry_ctls: 0,
            expose_vmx: false,
        }
    }

    pub fn from_host(host: HostVmxCapabilities) -> Self {
        let revision_id = host.vmx_basic as u32 & 0x7fff_ffff;
        let has_true_controls = host.vmx_basic & VMX_BASIC_TRUE_CONTROLS != 0;
        let selected_primary = if has_true_controls {
            host.true_procbased_ctls
        } else {
            host.procbased_ctls
        };
        let ept_supported =
            control_may_be_one(selected_primary, VMX_PRIMARY_ACTIVATE_SECONDARY_CONTROLS)
                && control_may_be_one(host.procbased_ctls2, VMX_SECONDARY_ENABLE_EPT)
                && host.ept_vpid_cap & (VMX_EPT_PAGE_WALK_LENGTH_4 | VMX_EPT_MEMORY_TYPE_WB)
                    == (VMX_EPT_PAGE_WALK_LENGTH_4 | VMX_EPT_MEMORY_TYPE_WB);
        let optional_primary = if ept_supported {
            VMX_PRIMARY_ACTIVATE_SECONDARY_CONTROLS
        } else {
            0
        };
        let pinbased_supported = VMX_LEGACY_PINBASED_DEFAULT1
            | VMX_PIN_EXTERNAL_INTERRUPT_EXITING
            | VMX_PIN_NMI_EXITING
            | VMX_PIN_VIRTUAL_NMIS;
        let procbased_supported = VMX_LEGACY_PROCBASED_DEFAULT1
            | VMX_PRIMARY_KVM_EXITING_CONTROLS
            | VMX_PRIMARY_RDTSC_EXITING
            | VMX_PRIMARY_TPR_SHADOW
            | VMX_PRIMARY_UNCONDITIONAL_IO_EXITING
            | VMX_PRIMARY_USE_IO_BITMAPS
            | VMX_PRIMARY_MONITOR_TRAP_FLAG
            | VMX_PRIMARY_USE_MSR_BITMAPS
            | VMX_PRIMARY_PAUSE_EXITING
            | optional_primary;
        let exit_supported = VMX_LEGACY_EXIT_DEFAULT1
            | VM_EXIT_HOST_ADDRESS_SPACE_SIZE
            | VM_EXIT_ACK_INTERRUPT_ON_EXIT
            | VM_EXIT_LOAD_IA32_PAT
            | VM_EXIT_SAVE_IA32_EFER
            | VM_EXIT_LOAD_IA32_EFER;
        let entry_supported = VMX_LEGACY_ENTRY_DEFAULT1
            | VM_ENTRY_IA32E_MODE_GUEST
            | VM_ENTRY_LOAD_IA32_PAT
            | VM_ENTRY_LOAD_IA32_EFER;
        let secondary_ept = restrict_control(host.procbased_ctls2, VMX_SECONDARY_ENABLE_EPT, 0);
        let secondary_descriptor_table = restrict_control(
            host.procbased_ctls2,
            VMX_SECONDARY_DESCRIPTOR_TABLE_EXITING,
            0,
        );
        let secondary_rdtscp =
            restrict_control(host.procbased_ctls2, VMX_SECONDARY_ENABLE_RDTSCP, 0);
        let secondary_wbinvd =
            restrict_control(host.procbased_ctls2, VMX_SECONDARY_WBINVD_EXITING, 0);
        let secondary_unrestricted =
            restrict_control(host.procbased_ctls2, VMX_SECONDARY_UNRESTRICTED_GUEST, 0);
        let secondary_rdrand =
            restrict_control(host.procbased_ctls2, VMX_SECONDARY_RDRAND_EXITING, 0);
        let secondary_invpcid =
            restrict_control(host.procbased_ctls2, VMX_SECONDARY_ENABLE_INVPCID, 0);
        let secondary_xsaves =
            restrict_control(host.procbased_ctls2, VMX_SECONDARY_ENABLE_XSAVES, 0);
        let secondary_mbec = if host.ept_vpid_cap & VMX_EPT_ADVANCED_EXIT_INFO != 0 {
            restrict_control(host.procbased_ctls2, VMX_SECONDARY_MODE_BASED_EXECUTE, 0)
        } else {
            0
        };
        let secondary_supported = if ept_supported {
            secondary_ept
                | secondary_descriptor_table
                | secondary_rdtscp
                | secondary_wbinvd
                | secondary_unrestricted
                | secondary_rdrand
                | secondary_invpcid
                | secondary_xsaves
                | secondary_mbec
                | restrict_control(host.procbased_ctls2, VMX_SECONDARY_VMCS_SHADOWING, 0)
                | restrict_control(host.procbased_ctls2, VMX_SECONDARY_ENABLE_VM_FUNCTIONS, 0)
                | (u64::from(VMX_SECONDARY_ENABLE_VPID) << 32)
        } else {
            0
        };
        let true_pinbased_ctls = if has_true_controls {
            restrict_emulated_control(host.true_pinbased_ctls, pinbased_supported, 0)
        } else {
            0
        };
        let true_procbased_ctls = if has_true_controls {
            restrict_emulated_control(host.true_procbased_ctls, procbased_supported, 0)
        } else {
            0
        };
        let true_exit_ctls = if has_true_controls {
            restrict_emulated_control(
                host.true_exit_ctls,
                exit_supported,
                VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
            )
        } else {
            0
        };
        let true_entry_ctls = if has_true_controls {
            restrict_emulated_control(host.true_entry_ctls, entry_supported, 0)
        } else {
            0
        };
        let pinbased_ctls = if has_true_controls {
            legacy_control_from_true(true_pinbased_ctls, VMX_LEGACY_PINBASED_DEFAULT1)
        } else {
            restrict_control(
                host.pinbased_ctls,
                pinbased_supported,
                VMX_LEGACY_PINBASED_DEFAULT1,
            )
        };
        let procbased_ctls = if has_true_controls {
            legacy_control_from_true(true_procbased_ctls, VMX_LEGACY_PROCBASED_DEFAULT1)
        } else {
            restrict_control(
                host.procbased_ctls,
                procbased_supported,
                VMX_LEGACY_PROCBASED_DEFAULT1,
            )
        };
        let exit_ctls = if has_true_controls {
            legacy_control_from_true(true_exit_ctls, VMX_LEGACY_EXIT_DEFAULT1)
        } else {
            restrict_control(
                host.exit_ctls,
                exit_supported,
                VMX_LEGACY_EXIT_DEFAULT1 | VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
            )
        };
        let entry_ctls = if has_true_controls {
            legacy_control_from_true(true_entry_ctls, VMX_LEGACY_ENTRY_DEFAULT1)
        } else {
            restrict_control(host.entry_ctls, entry_supported, VMX_LEGACY_ENTRY_DEFAULT1)
        };

        Self {
            revision_id,
            feature_control: IA32_FEATURE_CONTROL_LOCKED | IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX,
            vmx_basic: u64::from(revision_id)
                | (VMX_REGION_SIZE << 32)
                | (VMX_MEMORY_TYPE_WRITE_BACK << 50)
                | (host.vmx_basic & (VMX_BASIC_TRUE_CONTROLS | VMX_BASIC_IO_EXIT_INFORMATION)),
            vmx_pinbased_ctls: pinbased_ctls,
            vmx_procbased_ctls: procbased_ctls,
            vmx_exit_ctls: exit_ctls,
            vmx_entry_ctls: entry_ctls,
            host_procbased_ctls2: host.procbased_ctls2,
            host_misc: host.misc,
            // Preserve native activity states, EFER.LMA capture, shadow write
            // semantics and zero-length event injection. PT and dual-monitor
            // SMM are not virtualized; CR3 targets and MSR lists have local limits.
            vmx_misc: (host.misc & (0x1ff | (1_u64 << 29) | (1_u64 << 30)))
                | (VMX_CR3_TARGET_COUNT << 16)
                | (((VMX_MSR_LIST_CAPACITY / 512 - 1) as u64) << 25),
            vmx_cr0_fixed0: host.cr0_fixed0,
            vmx_cr0_fixed1: host.cr0_fixed1,
            vmx_cr4_fixed0: host.cr4_fixed0,
            vmx_cr4_fixed1: host.cr4_fixed1,
            vmx_vmcs_enum: restrict_vmcs_enum(host.vmcs_enum),
            vmx_procbased_ctls2: secondary_supported,
            vmx_ept_vpid_cap: if ept_supported {
                (host.ept_vpid_cap & VMX_EPT_CAPABILITIES) | VMX_SOFTWARE_INVALIDATION_CAPABILITIES
            } else {
                0
            },
            vmx_true_pinbased_ctls: true_pinbased_ctls,
            vmx_true_procbased_ctls: true_procbased_ctls,
            vmx_true_exit_ctls: true_exit_ctls,
            vmx_true_entry_ctls: true_entry_ctls,
            expose_vmx: false,
        }
    }

    pub fn vmx_msr(&self, msr: u32) -> Option<u64> {
        match msr {
            IA32_VMX_BASIC_MSR => Some(self.vmx_basic),
            IA32_VMX_PINBASED_CTLS_MSR => Some(self.vmx_pinbased_ctls),
            IA32_VMX_PROCBASED_CTLS_MSR => Some(self.vmx_procbased_ctls),
            IA32_VMX_EXIT_CTLS_MSR => Some(self.vmx_exit_ctls),
            IA32_VMX_ENTRY_CTLS_MSR => Some(self.vmx_entry_ctls),
            IA32_VMX_MISC_MSR => Some(self.vmx_misc),
            IA32_VMX_CR0_FIXED0_MSR => Some(self.vmx_cr0_fixed0),
            IA32_VMX_CR0_FIXED1_MSR => Some(self.vmx_cr0_fixed1),
            IA32_VMX_CR4_FIXED0_MSR => Some(self.vmx_cr4_fixed0),
            IA32_VMX_CR4_FIXED1_MSR => Some(self.vmx_cr4_fixed1),
            IA32_VMX_VMCS_ENUM_MSR => Some(self.vmx_vmcs_enum),
            IA32_VMX_PROCBASED_CTLS2_MSR => Some(self.vmx_procbased_ctls2),
            IA32_VMX_EPT_VPID_CAP_MSR => Some(self.vmx_ept_vpid_cap),
            IA32_VMX_VMFUNC_MSR
                if control_may_be_one(
                    self.vmx_procbased_ctls2,
                    VMX_SECONDARY_ENABLE_VM_FUNCTIONS,
                ) =>
            {
                Some(1)
            }
            IA32_VMX_TRUE_PINBASED_CTLS_MSR if self.has_true_controls() => {
                Some(self.vmx_true_pinbased_ctls)
            }
            IA32_VMX_TRUE_PROCBASED_CTLS_MSR if self.has_true_controls() => {
                Some(self.vmx_true_procbased_ctls)
            }
            IA32_VMX_TRUE_EXIT_CTLS_MSR if self.has_true_controls() => {
                Some(self.vmx_true_exit_ctls)
            }
            IA32_VMX_TRUE_ENTRY_CTLS_MSR if self.has_true_controls() => {
                Some(self.vmx_true_entry_ctls)
            }
            _ => None,
        }
    }

    fn has_true_controls(&self) -> bool {
        self.vmx_basic & VMX_BASIC_TRUE_CONTROLS != 0
    }
}

fn restrict_control(host: u64, supported: u32, required: u32) -> u64 {
    let host_must_be_one = host as u32;
    let host_may_be_one = (host >> 32) as u32;
    let may_be_one = host_may_be_one & supported;
    let must_be_one = (host_must_be_one | required) & may_be_one;
    u64::from(must_be_one) | (u64::from(may_be_one) << 32)
}

fn restrict_emulated_control(host: u64, supported: u32, required: u32) -> u64 {
    let host_may_be_one = (host >> 32) as u32;
    let may_be_one = host_may_be_one & supported;
    let must_be_one = required & may_be_one;
    u64::from(must_be_one) | (u64::from(may_be_one) << 32)
}

fn control_may_be_one(capabilities: u64, control: u32) -> bool {
    (capabilities >> 32) as u32 & control != 0
}

fn legacy_control_from_true(true_control: u64, default_one: u32) -> u64 {
    let may_be_one = (true_control >> 32) as u32;
    let must_be_one = (true_control as u32 | default_one) & may_be_one;
    u64::from(must_be_one) | (u64::from(may_be_one) << 32)
}

fn restrict_vmcs_enum(host: u64) -> u64 {
    let host_index = (host >> 1) & 0x1ff;
    host_index.min(VMCS12_MAX_ENUM_INDEX) << 1
}

pub const VMCLEAR_EXIT_REASON: u64 = 19;
pub const VMLAUNCH_EXIT_REASON: u64 = 20;
pub const VMPTRLD_EXIT_REASON: u64 = 21;
pub const VMPTRST_EXIT_REASON: u64 = 22;
pub const VMREAD_EXIT_REASON: u64 = 23;
pub const VMRESUME_EXIT_REASON: u64 = 24;
pub const VMWRITE_EXIT_REASON: u64 = 25;
pub const VMXOFF_EXIT_REASON: u64 = 26;
pub const VMXON_EXIT_REASON: u64 = 27;
pub const INVEPT_EXIT_REASON: u64 = 50;
pub const VMFUNC_EXIT_REASON: u64 = 59;
pub const INVVPID_EXIT_REASON: u64 = 53;

pub const VMCLEAR_INVALID_PHYSICAL_ADDRESS_ERROR: u32 = 2;
pub const VMCLEAR_VMXON_POINTER_ERROR: u32 = 3;
pub const VMLAUNCH_NON_CLEAR_VMCS_ERROR: u32 = 4;
pub const VMRESUME_NON_LAUNCHED_VMCS_ERROR: u32 = 5;
pub const VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR: u32 = 7;
pub const VM_ENTRY_INVALID_HOST_STATE_FIELD_ERROR: u32 = 8;
pub const VM_ENTRY_BLOCKED_BY_MOV_SS_ERROR: u32 = 26;
pub const INVALID_OPERAND_TO_INVEPT_INVVPID_ERROR: u32 = 28;
pub const VMPTRLD_INVALID_PHYSICAL_ADDRESS_ERROR: u32 = 9;
pub const VMPTRLD_VMXON_POINTER_ERROR: u32 = 10;
pub const VMPTRLD_INCORRECT_REVISION_ERROR: u32 = 11;
pub const VMCS_UNSUPPORTED_COMPONENT_ERROR: u32 = 12;
pub const VMWRITE_READ_ONLY_COMPONENT_ERROR: u32 = 13;
pub const VMXON_IN_VMX_ROOT_ERROR: u32 = 15;

pub const VMX_STATUS_FLAGS: u32 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
pub const VMX_STATUS_FLAGS_CLEAR_MASK: i32 = !(VMX_STATUS_FLAGS as i32);
pub const VMFAIL_INVALID_STATUS: u32 = 1 << 0;
pub const VMFAIL_VALID_STATUS: u32 = 1 << 6;

pub fn native_vmcs_shadowing_available(host_secondary_controls: u64) -> bool {
    control_may_be_one(host_secondary_controls, VMX_SECONDARY_VMCS_SHADOWING)
}

pub const INVALID_VMCS_POINTER: u64 = u64::MAX;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedVmxState {
    // Keep entry/exit routing and validity flags in the first two cache lines.
    pub current_vmcs: u64,
    pub current_vmcs_hpa: u64,
    pub evmcs_active: u64,
    pub l2_active: u64,
    pub active: u64,
    pub expose_vmx: u64,
    pub evmcs_enabled: u64,
    pub vp_assist_msr: u64,
    pub current_vmcs_is_shadow: u64,
    pub vmcs02_guest_cache_valid: u64,
    pub vmcs02_control_cache_valid: [u64; 2],
    pub vmcs02_launched: u64,
    pub physical_address_bits: u32,
    pub vmcs02_vpid_cache: u32,
    pub ept01_pointer: u64,
    pub host_procbased_ctls2: u64,
    pub host_misc: u64,
    pub feature_control: u64,
    pub vmx_basic: u64,
    pub vmx_pinbased_ctls: u64,
    pub vmx_procbased_ctls: u64,
    pub vmx_exit_ctls: u64,
    pub vmx_entry_ctls: u64,
    pub vmx_misc: u64,
    pub vmx_cr0_fixed0: u64,
    pub vmx_cr0_fixed1: u64,
    pub vmx_cr4_fixed0: u64,
    pub vmx_cr4_fixed1: u64,
    pub vmx_vmcs_enum: u64,
    pub vmx_procbased_ctls2: u64,
    pub vmx_ept_vpid_cap: u64,
    pub vmx_true_pinbased_ctls: u64,
    pub vmx_true_procbased_ctls: u64,
    pub vmx_true_exit_ctls: u64,
    pub vmx_true_entry_ctls: u64,
    pub l1_cr4: u64,
    pub vmxon_operand: u64,
    pub vmxon_region: u64,
    pub last_operand: u64,
    pub last_vmcs_field: u64,
    pub vmxon_count: u64,
    pub vmxoff_count: u64,
    pub failure_count: u64,
    pub probe_complete: u64,
    pub vmcs12: NestedVmcs12State,
    pub vmcs01_region: u64,
    pub vmcs02_region: u64,
    pub shadow_vmcs_region: u64,
    pub shadow_vmread_bitmap: u64,
    pub l2_entry_was_resume: u64,
    pub l2_entry_count: u64,
    pub l2_exit_count: u64,
    pub l2_last_exit_reason: u64,
    pub l2_last_exit_rip: u64,
    pub l2_last_exit_rsp: u64,
    pub l1_reflection_count: u64,
    pub l2_resume_count: u64,
    pub l2_resume_exit_count: u64,
    pub ept12_pointer: u64,
    pub ept02_pointer: u64,
    pub ept_source_gpa: u64,
    pub ept_target_gpa: u64,
    pub ept_composed_hpa: u64,
    pub ept_permissions: u64,
    pub ept_composition_count: u64,
    pub ept_probe_count: u64,
    pub ept_observed_value: u64,
    pub ept02_alternate_pointer: u64,
    pub ept_second_target_gpa: u64,
    pub ept12_source_leaf: u64,
    pub ept_alternate_composed_hpa: u64,
    pub ept_alternate_permissions: u64,
    pub invept_count: u64,
    pub invept_software_count: u64,
    pub invvpid_count: u64,
    pub invvpid_software_count: u64,
    pub ept_observed_value_after_invept: u64,
    pub ept02_initial_pointer: u64,
    pub ept12_source_leaf_attributes: u64,
    pub ept_observed_value_before_invept: u64,
    pub control_merge_count: u64,
    pub guest_state_sync_count: u64,
    pub l1_host_restore_count: u64,
    pub last_synced_guest_cr0: u64,
    pub last_synced_guest_cr3: u64,
    pub last_synced_guest_cr4: u64,
    pub last_restored_host_cr0: u64,
    pub last_restored_host_cr3: u64,
    pub last_restored_host_cr4: u64,
    pub last_synced_guest_sysenter_eip: u64,
    pub last_restored_host_sysenter_eip: u64,
    pub inherited_l1_pat: u64,
    pub inherited_l1_efer: u64,
    pub inherited_l1_tsc_offset: u64,
    pub vmcs01_pin_based_controls: u64,
    pub vmcs01_primary_controls: u64,
    pub vmcs01_secondary_controls: u64,
    pub vmcs01_exit_controls: u64,
    pub vmcs01_entry_controls: u64,
    pub l2_saved_pat: u64,
    pub l2_saved_efer: u64,
    pub last_merged_secondary_controls: u64,
    pub last_synced_guest_gs_base: u64,
    pub last_captured_guest_gs_base: u64,
    pub last_restored_host_gs_base: u64,
    pub last_restored_host_cs_ar: u64,
    pub l0_msr_bitmap: u64,
    pub composed_msr_bitmap: u64,
    pub l0_msr_guest_list: u64,
    pub l0_msr_host_list: u64,
    pub vmcs02_entry_msr_list: u64,
    pub vmcs02_exit_store_msr_list: u64,
    pub vmcs01_entry_msr_list: u64,
    pub vmcs01_msr_entry_composed: u64,
    pub ept02_table_pool: u64,
    pub ept02_table_pool_pages: u64,
    pub ept02_table_pool_used: u64,
    pub ept02_invalidation_count: u64,
    pub ept02_cache_initialized: u64,
    pub ept02_cached_ept12_pointer: u64,
    pub ept02_cached_pointer: u64,
    pub ept02_cached_table_pool: u64,
    pub ept02_cached_table_pool_pages: u64,
    pub ept02_cached_table_pool_used: u64,
    pub ept02_mbec: u64,
    pub vmcs02_field_cache: [u64; VMCS12_EXTENDED_FIELD_COUNT],
    pub vmcs02_last_vpid: u64,
    pub ept02_cached_mbec: u64,
    pub exit_started_tsc: u64,
    pub exit_handler_cycles: [u64; 4],
    pub reflected_exit_counts: [u32; 44],
    pub host_mapping_cache: [u64; 4],
    pub evmcs_page_cache: [u64; 24],
    pub vmcs02_rare_state_pending: [u64; 2],
    pub ept02_recycle_count: u64,
    pub ept02_eviction_cursor: u64,
    pub ept02_table_eviction_count: u64,
    pub failure_trace: [u64; NESTED_FAILURE_TRACE_WORD_COUNT],
    pub eptp_shadow_list: u64,
    pub eptp_native_supported: u64,
    pub eptp_native_enabled: u64,
    pub eptp_sync_ack: u64,
    pub eptp_sync_safe: u64,
    pub eptp_sync_nmi: u64,
    pub eptp_sync_apic_id: u64,
    pub eptp_admission: u64,
    pub eptp_write_retry: u64,
    pub eptp_table_pool: u64,
    pub eptp_table_pages: u64,
    pub eptp_table_used: u64,
    pub exit_reason_counts: [u64; 128],
    pub captured_msr_store_count: u64,
    pub entry_msr_prefix_count: u64,
    pub l2_msr_gp_pending: u64,
    pub operand_linear_address: u64,
    pub operand_data: [u64; 2],
    pub l2_nmi_exit_pending: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedMsrComposition {
    pub l0_msr_bitmap: u64,
    pub composed_msr_bitmap: u64,
    pub l0_msr_guest_list: u64,
    pub l0_msr_host_list: u64,
    pub vmcs02_entry_msr_list: u64,
    pub vmcs02_exit_store_msr_list: u64,
    pub vmcs01_entry_msr_list: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedEptConfiguration {
    pub ept12_pointer: u64,
    pub ept02_pointer: u64,
    pub source_gpa: u64,
    pub target_gpa: u64,
    pub composed_hpa: u64,
    pub permissions: u64,
    pub alternate_ept02_pointer: u64,
    pub second_target_gpa: u64,
    pub source_leaf: u64,
    pub source_leaf_attributes: u64,
    pub alternate_composed_hpa: u64,
    pub alternate_permissions: u64,
}

impl NestedVmxState {
    pub fn new(
        capabilities: NestedVmxCapabilities,
        vmxon_operand: u64,
        vmxon_region: u64,
        vmcs12: NestedVmcs12State,
        vmcs01_region: u64,
        vmcs02_region: u64,
    ) -> Self {
        // MAXPHYADDR is stable for this vCPU; avoid serializing CPUID on each entry.
        let physical_address_bits = if __cpuid(0x8000_0000).eax >= 0x8000_0008 {
            __cpuid(0x8000_0008).eax & 0xff
        } else {
            36
        };
        Self {
            host_procbased_ctls2: capabilities.host_procbased_ctls2,
            host_misc: capabilities.host_misc,
            feature_control: capabilities.feature_control,
            vmx_basic: capabilities.vmx_basic,
            vmx_pinbased_ctls: capabilities.vmx_pinbased_ctls,
            vmx_procbased_ctls: capabilities.vmx_procbased_ctls,
            vmx_exit_ctls: capabilities.vmx_exit_ctls,
            vmx_entry_ctls: capabilities.vmx_entry_ctls,
            vmx_misc: capabilities.vmx_misc,
            vmx_cr0_fixed0: capabilities.vmx_cr0_fixed0,
            vmx_cr0_fixed1: capabilities.vmx_cr0_fixed1,
            vmx_cr4_fixed0: capabilities.vmx_cr4_fixed0,
            vmx_cr4_fixed1: capabilities.vmx_cr4_fixed1,
            vmx_vmcs_enum: capabilities.vmx_vmcs_enum,
            vmx_procbased_ctls2: capabilities.vmx_procbased_ctls2,
            vmx_ept_vpid_cap: capabilities.vmx_ept_vpid_cap,
            vmx_true_pinbased_ctls: capabilities.vmx_true_pinbased_ctls,
            vmx_true_procbased_ctls: capabilities.vmx_true_procbased_ctls,
            vmx_true_exit_ctls: capabilities.vmx_true_exit_ctls,
            vmx_true_entry_ctls: capabilities.vmx_true_entry_ctls,
            expose_vmx: u64::from(capabilities.expose_vmx),
            l1_cr4: 0,
            vmxon_operand,
            vmxon_region,
            current_vmcs: INVALID_VMCS_POINTER,
            current_vmcs_is_shadow: 0,
            last_operand: 0,
            last_vmcs_field: 0,
            vmxon_count: 0,
            vmxoff_count: 0,
            failure_count: 0,
            active: 0,
            probe_complete: 0,
            vmcs12,
            vmcs01_region,
            vmcs02_region,
            shadow_vmcs_region: 0,
            shadow_vmread_bitmap: 0,
            l2_active: 0,
            l2_entry_was_resume: 0,
            l2_entry_count: 0,
            l2_exit_count: 0,
            l2_last_exit_reason: 0,
            l2_last_exit_rip: 0,
            l2_last_exit_rsp: 0,
            l1_reflection_count: 0,
            l2_resume_count: 0,
            l2_resume_exit_count: 0,
            ept12_pointer: 0,
            ept02_pointer: 0,
            ept_source_gpa: 0,
            ept_target_gpa: 0,
            ept_composed_hpa: 0,
            ept_permissions: 0,
            ept_composition_count: 0,
            ept_probe_count: 0,
            ept_observed_value: 0,
            ept02_alternate_pointer: 0,
            ept_second_target_gpa: 0,
            ept12_source_leaf: 0,
            ept_alternate_composed_hpa: 0,
            ept_alternate_permissions: 0,
            invept_count: 0,
            invept_software_count: 0,
            invvpid_count: 0,
            invvpid_software_count: 0,
            ept_observed_value_after_invept: 0,
            ept02_initial_pointer: 0,
            ept12_source_leaf_attributes: 0,
            ept_observed_value_before_invept: 0,
            control_merge_count: 0,
            guest_state_sync_count: 0,
            l1_host_restore_count: 0,
            last_synced_guest_cr0: 0,
            last_synced_guest_cr3: 0,
            last_synced_guest_cr4: 0,
            last_restored_host_cr0: 0,
            last_restored_host_cr3: 0,
            last_restored_host_cr4: 0,
            last_synced_guest_sysenter_eip: 0,
            last_restored_host_sysenter_eip: 0,
            inherited_l1_pat: 0,
            inherited_l1_efer: 0,
            inherited_l1_tsc_offset: 0,
            vmcs01_pin_based_controls: 0,
            vmcs01_primary_controls: 0,
            vmcs01_secondary_controls: 0,
            vmcs01_exit_controls: 0,
            vmcs01_entry_controls: 0,
            l2_saved_pat: 0,
            l2_saved_efer: 0,
            last_merged_secondary_controls: 0,
            last_synced_guest_gs_base: 0,
            last_captured_guest_gs_base: 0,
            last_restored_host_gs_base: 0,
            last_restored_host_cs_ar: 0,
            l0_msr_bitmap: 0,
            composed_msr_bitmap: 0,
            l0_msr_guest_list: 0,
            l0_msr_host_list: 0,
            vmcs02_entry_msr_list: 0,
            vmcs02_exit_store_msr_list: 0,
            vmcs01_entry_msr_list: 0,
            vmcs01_msr_entry_composed: 0,
            ept02_table_pool: 0,
            ept02_table_pool_pages: 0,
            ept02_table_pool_used: 0,
            ept01_pointer: 0,
            ept02_invalidation_count: 0,
            vmcs02_launched: 0,
            ept02_cache_initialized: 0,
            ept02_cached_ept12_pointer: 0,
            ept02_cached_pointer: 0,
            ept02_cached_table_pool: 0,
            ept02_cached_table_pool_pages: 0,
            ept02_cached_table_pool_used: 0,
            ept02_mbec: 0,
            vmcs02_guest_cache_valid: 0,
            vmcs02_control_cache_valid: [0; 2],
            vmcs02_field_cache: [0; VMCS12_EXTENDED_FIELD_COUNT],
            vmcs02_last_vpid: 0,
            ept02_cached_mbec: 0,
            exit_started_tsc: 0,
            exit_handler_cycles: [0; 4],
            reflected_exit_counts: [0; 44],
            vmcs02_vpid_cache: 0,
            physical_address_bits,
            host_mapping_cache: [0; 4],
            evmcs_page_cache: [0; 24],
            vmcs02_rare_state_pending: [0; 2],
            ept02_recycle_count: 0,
            ept02_eviction_cursor: 0,
            ept02_table_eviction_count: 0,
            failure_trace: [0; NESTED_FAILURE_TRACE_WORD_COUNT],
            eptp_shadow_list: 0,
            eptp_native_supported: 0,
            eptp_native_enabled: 0,
            eptp_sync_ack: 0,
            eptp_sync_safe: 0,
            eptp_sync_nmi: 0,
            eptp_sync_apic_id: 0,
            eptp_admission: 0,
            eptp_write_retry: 0,
            eptp_table_pool: 0,
            eptp_table_pages: 0,
            eptp_table_used: 0,
            exit_reason_counts: [0; 128],
            evmcs_enabled: 0,
            vp_assist_msr: 0,
            evmcs_active: 0,
            current_vmcs_hpa: 0,
            captured_msr_store_count: 0,
            entry_msr_prefix_count: 0,
            l2_msr_gp_pending: 0,
            operand_linear_address: 0,
            operand_data: [0; 2],
            l2_nmi_exit_pending: 0,
        }
    }

    pub fn configure_msr_composition(&mut self, composition: NestedMsrComposition) {
        self.l0_msr_bitmap = composition.l0_msr_bitmap;
        self.composed_msr_bitmap = composition.composed_msr_bitmap;
        self.l0_msr_guest_list = composition.l0_msr_guest_list;
        self.l0_msr_host_list = composition.l0_msr_host_list;
        self.vmcs02_entry_msr_list = composition.vmcs02_entry_msr_list;
        self.vmcs02_exit_store_msr_list = composition.vmcs02_exit_store_msr_list;
        self.vmcs01_entry_msr_list = composition.vmcs01_entry_msr_list;
    }

    pub fn configure_ept02_table_pools(&mut self, pools: [(u64, usize, usize); 2]) -> bool {
        if pools
            .iter()
            .any(|(_, pages, used_pages)| used_pages > pages)
        {
            return false;
        }
        let [
            (base, pages, used_pages),
            (cached_base, cached_pages, cached_used_pages),
        ] = pools;
        self.ept02_table_pool = base;
        self.ept02_table_pool_pages = pages as u64;
        self.ept02_table_pool_used = used_pages as u64;
        self.ept02_cached_table_pool = cached_base;
        self.ept02_cached_table_pool_pages = cached_pages as u64;
        self.ept02_cached_table_pool_used = cached_used_pages as u64;
        true
    }

    pub fn configure_ept(&mut self, configuration: NestedEptConfiguration) {
        self.ept12_pointer = configuration.ept12_pointer;
        self.ept02_pointer = configuration.ept02_pointer;
        self.ept_source_gpa = configuration.source_gpa;
        self.ept_target_gpa = configuration.target_gpa;
        self.ept_composed_hpa = configuration.composed_hpa;
        self.ept_permissions = configuration.permissions;
        self.ept_composition_count = 2;
        self.ept02_alternate_pointer = configuration.alternate_ept02_pointer;
        self.ept_second_target_gpa = configuration.second_target_gpa;
        self.ept12_source_leaf = configuration.source_leaf;
        self.ept12_source_leaf_attributes = configuration.source_leaf_attributes;
        self.ept_alternate_composed_hpa = configuration.alternate_composed_hpa;
        self.ept_alternate_permissions = configuration.alternate_permissions;
        self.ept02_initial_pointer = configuration.ept02_pointer;
        self.ept02_cached_pointer = configuration.alternate_ept02_pointer;
    }
}

#[cfg(target_os = "uefi")]
use super::ept::EptError;
#[cfg(target_os = "uefi")]
use super::msr::{RESIDENT_MSR_SWITCH_CAPACITY, VmxMsrEntry, configure_resident_msr_switch};
#[cfg(target_os = "uefi")]
use super::state::{ResidentHostTables, configure_resident_host};
#[cfg(target_os = "uefi")]
use super::vmcs::*;
#[cfg(target_os = "uefi")]
use super::vmcs12::{NestedVmcs12CoreState, NestedVmcs12SegmentState};
#[cfg(target_os = "uefi")]
use super::vmxon::VmxInstructionResult;
#[cfg(target_os = "uefi")]
use super::{controls, state, vmcs};
#[cfg(target_os = "uefi")]
use crate::arch;
#[cfg(target_os = "uefi")]
use crate::memory::host::{PAGE_SIZE, ResidentPages};
#[cfg(target_os = "uefi")]
use crate::vmx::hyperv;
#[cfg(target_os = "uefi")]
use core::mem::size_of;

#[cfg(target_os = "uefi")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NestedHardwareError {
    Vmclear(VmxInstructionResult),
    Vmcs(VmcsError),
    Controls(controls::VmxControlsError),
    Ept(EptError),
    InvalidEptPoolUsage,
}
#[cfg(target_os = "uefi")]
impl From<VmcsError> for NestedHardwareError {
    fn from(value: VmcsError) -> Self {
        Self::Vmcs(value)
    }
}
#[cfg(target_os = "uefi")]
impl From<controls::VmxControlsError> for NestedHardwareError {
    fn from(value: controls::VmxControlsError) -> Self {
        Self::Controls(value)
    }
}
#[cfg(target_os = "uefi")]
const NESTED_MSR_BITMAP_OFFSET: u64 = 0;
#[cfg(target_os = "uefi")]
const NESTED_VMCS02_ENTRY_MSR_LIST_OFFSET: u64 = PAGE_SIZE as u64;
#[cfg(target_os = "uefi")]
const NESTED_VMCS02_EXIT_STORE_MSR_LIST_OFFSET: u64 = (PAGE_SIZE * 4) as u64;
#[cfg(target_os = "uefi")]
const NESTED_VMCS01_ENTRY_MSR_LIST_OFFSET: u64 = (PAGE_SIZE * 7) as u64;
#[cfg(target_os = "uefi")]
pub(crate) const NESTED_GUEST_MSR_LIST_CAPACITY: usize = crate::vmx::nested::VMX_MSR_LIST_CAPACITY;
#[cfg(target_os = "uefi")]
pub(crate) const NESTED_MSR_BITMAP_QWORD_COUNT: usize = PAGE_SIZE / size_of::<u64>();

#[cfg(target_os = "uefi")]
pub(crate) fn configure_nested_msr_composition(
    nested_state: &mut NestedVmxState,
    l0_msr_bitmap: u64,
    l0_msr_guest_list: u64,
    nested_msr_state: u64,
) {
    let l0_msr_host_list =
        l0_msr_guest_list + (RESIDENT_MSR_SWITCH_CAPACITY * size_of::<VmxMsrEntry>()) as u64;
    nested_state.configure_msr_composition(NestedMsrComposition {
        l0_msr_bitmap,
        composed_msr_bitmap: nested_msr_state + NESTED_MSR_BITMAP_OFFSET,
        l0_msr_guest_list,
        l0_msr_host_list,
        vmcs02_entry_msr_list: nested_msr_state + NESTED_VMCS02_ENTRY_MSR_LIST_OFFSET,
        vmcs02_exit_store_msr_list: nested_msr_state + NESTED_VMCS02_EXIT_STORE_MSR_LIST_OFFSET,
        vmcs01_entry_msr_list: nested_msr_state + NESTED_VMCS01_ENTRY_MSR_LIST_OFFSET,
    });
}

#[cfg(target_os = "uefi")]
pub(crate) struct NestedVmcs02Configuration<'a> {
    pub(crate) vmcs01_region: u64,
    pub(crate) vmcs02_region: u64,
    pub(crate) msr_bitmap: u64,
    pub(crate) ept_pointer: u64,
    pub(crate) msr_state: &'a ResidentPages,
    pub(crate) host_cr3: u64,
    pub(crate) host_tables: &'a ResidentHostTables,
    pub(crate) segments: arch::SegmentationState,
    pub(crate) host_rsp: u64,
    pub(crate) host_rip: u64,
    pub(crate) guest_rip: u64,
    pub(crate) guest_rsp: u64,
    pub(crate) guest_rflags: u64,
    pub(crate) l1_cr4: u64,
}

#[cfg(target_os = "uefi")]
pub(crate) fn configure_nested_vmcs02(
    configuration: NestedVmcs02Configuration<'_>,
) -> Result<(), NestedHardwareError> {
    let clear = unsafe { vmcs::vmclear(configuration.vmcs02_region) };
    if clear != VmxInstructionResult::Succeeded {
        return Err(NestedHardwareError::Vmclear(clear));
    }
    let load = unsafe { vmcs::vmptrld(configuration.vmcs02_region) };
    if load != VmxInstructionResult::Succeeded {
        return Err(NestedHardwareError::Vmcs(VmcsError::Vmptrld(load)));
    }

    let configure_result = (|| -> Result<(), NestedHardwareError> {
        let mut controls =
            controls::configure_resident_boot(configuration.msr_bitmap, configuration.ept_pointer)?;
        controls::enable_resident_vpid(&mut controls, 2)?;
        if unsafe { arch::read_msr(arch::IA32_VMX_PROCBASED_CTLS2) }
            & (u64::from(crate::vmx::nested::VMX_SECONDARY_ENABLE_VM_FUNCTIONS) << 32)
            != 0
        {
            // Trap VMFUNC so L1 EPTPs are composed through EPT01 before use by L2.
            vmwrite(VM_FUNCTION_CONTROL, 0)?;
        }
        vmwrite(EXCEPTION_BITMAP, 0)?;
        configure_resident_msr_switch(configuration.msr_state)?;
        configure_resident_host(
            configuration.host_cr3,
            configuration.host_tables,
            configuration.segments,
        )?;
        state::configure_guest_with_rflags(
            configuration.guest_rip,
            configuration.guest_rsp,
            configuration.guest_rflags,
        )?;
        controls::virtualize_resident_cr4_vmxe(configuration.l1_cr4)?;
        vmwrite(HOST_RSP, configuration.host_rsp)?;
        vmwrite(HOST_RIP, configuration.host_rip)?;
        Ok(())
    })();

    // VMPTRLD of VMCS01 leaves VMCS02 active; flush it before BSP executes VMXOFF.
    let clear = unsafe { vmcs::vmclear(configuration.vmcs02_region) };
    let restore = unsafe { vmcs::vmptrld(configuration.vmcs01_region) };
    if restore != VmxInstructionResult::Succeeded {
        return Err(NestedHardwareError::Vmcs(VmcsError::Vmptrld(restore)));
    }
    if clear != VmxInstructionResult::Succeeded {
        return Err(NestedHardwareError::Vmclear(clear));
    }
    configure_result
}

#[cfg(target_os = "uefi")]
pub(crate) fn configure_resident_vmcs_shadowing(
    controls: &mut controls::VmxControls,
    shadow_resources: Option<(u64, u64, u64)>,
) -> Result<Option<(u64, u64)>, NestedHardwareError> {
    let Some((shadow_vmcs, vmread_bitmap, vmwrite_bitmap)) = shadow_resources else {
        return Ok(None);
    };
    if !crate::vmx::nested::native_vmcs_shadowing_available(unsafe {
        arch::read_msr(arch::IA32_VMX_PROCBASED_CTLS2)
    }) {
        return Ok(None);
    }
    let clear = unsafe { vmcs::vmclear(shadow_vmcs) };
    if clear != VmxInstructionResult::Succeeded {
        return Err(NestedHardwareError::Vmclear(clear));
    }
    if controls::enable_resident_vmcs_shadowing(
        controls,
        shadow_vmcs,
        vmread_bitmap,
        vmwrite_bitmap,
    )? {
        Ok(Some((shadow_vmcs, vmread_bitmap)))
    } else {
        Ok(None)
    }
}

#[cfg(target_os = "uefi")]
pub(crate) fn capture_nested_vmcs12_core_state(
    mut segments: arch::SegmentationState,
    l1_cr4: u64,
) -> NestedVmcs12CoreState {
    segments.tr = arch::vmx_usable_tr(segments.tr);
    let segment_state = |segment: arch::SegmentState| NestedVmcs12SegmentState {
        selector: segment.selector,
        base: segment.base,
        limit: segment.limit,
        access_rights: segment.access_rights,
    };
    NestedVmcs12CoreState {
        guest_cr0: arch::read_cr0(),
        guest_cr3: arch::read_cr3(),
        guest_cr4: l1_cr4,
        host_cr0: arch::read_cr0(),
        host_cr3: arch::read_cr3(),
        host_cr4: arch::read_cr4(),
        es: segment_state(segments.es),
        cs: segment_state(segments.cs),
        ss: segment_state(segments.ss),
        ds: segment_state(segments.ds),
        fs: segment_state(segments.fs),
        gs: segment_state(segments.gs),
        ldtr: segment_state(segments.ldtr),
        tr: segment_state(segments.tr),
        gdtr_base: segments.gdtr.base,
        gdtr_limit: segments.gdtr.limit,
        idtr_base: segments.idtr.base,
        idtr_limit: segments.idtr.limit,
        sysenter_cs: arch::ArchitecturalMsr::SysenterCs.read(),
        sysenter_esp: arch::ArchitecturalMsr::SysenterEsp.read(),
        sysenter_eip: arch::ArchitecturalMsr::SysenterEip.read(),
    }
}

#[cfg(target_os = "uefi")]
pub(crate) fn nested_vmx_capabilities(
    host_vmx_basic: u64,
    options: crate::boot::config::MatrixConfig,
) -> NestedVmxCapabilities {
    let has_true_controls = host_vmx_basic & VMX_BASIC_TRUE_CONTROLS != 0;
    let host = unsafe {
        HostVmxCapabilities {
            vmx_basic: host_vmx_basic,
            pinbased_ctls: arch::read_msr(IA32_VMX_PINBASED_CTLS_MSR),
            procbased_ctls: arch::read_msr(IA32_VMX_PROCBASED_CTLS_MSR),
            exit_ctls: arch::read_msr(IA32_VMX_EXIT_CTLS_MSR),
            entry_ctls: arch::read_msr(IA32_VMX_ENTRY_CTLS_MSR),
            misc: arch::read_msr(IA32_VMX_MISC_MSR),
            cr0_fixed0: arch::read_msr(IA32_VMX_CR0_FIXED0_MSR),
            cr0_fixed1: arch::read_msr(IA32_VMX_CR0_FIXED1_MSR),
            cr4_fixed0: arch::read_msr(IA32_VMX_CR4_FIXED0_MSR),
            cr4_fixed1: arch::read_msr(IA32_VMX_CR4_FIXED1_MSR),
            vmcs_enum: arch::read_msr(IA32_VMX_VMCS_ENUM_MSR),
            procbased_ctls2: arch::read_msr(IA32_VMX_PROCBASED_CTLS2_MSR),
            ept_vpid_cap: arch::read_msr(IA32_VMX_EPT_VPID_CAP_MSR),
            true_pinbased_ctls: if has_true_controls {
                arch::read_msr(IA32_VMX_TRUE_PINBASED_CTLS_MSR)
            } else {
                0
            },
            true_procbased_ctls: if has_true_controls {
                arch::read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR)
            } else {
                0
            },
            true_exit_ctls: if has_true_controls {
                arch::read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR)
            } else {
                0
            },
            true_entry_ctls: if has_true_controls {
                arch::read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR)
            } else {
                0
            },
        }
    };
    let mut capabilities = NestedVmxCapabilities::from_host(host);
    crate::logging::info(format_args!(
        "nested VMX host basic={:#x} misc={:#x} proc2={:#x} ept_vpid={:#x} guest misc={:#x} proc2={:#x} ept_vpid={:#x}",
        host.vmx_basic,
        host.misc,
        host.procbased_ctls2,
        host.ept_vpid_cap,
        capabilities.vmx_misc,
        capabilities.vmx_procbased_ctls2,
        capabilities.vmx_ept_vpid_cap,
    ));
    capabilities.expose_vmx = options.vt_nested;
    capabilities.vmx_procbased_ctls2 = hyperv::restrict_evmcs_secondary_capability(
        capabilities.vmx_procbased_ctls2,
        options.vt_evmcs,
    );
    debug_assert_eq!(
        capabilities.vmx_msr(IA32_VMX_BASIC_MSR),
        Some(capabilities.vmx_basic)
    );
    capabilities
}

#[cfg(target_os = "uefi")]
const _: () = assert!(
    (NESTED_GUEST_MSR_LIST_CAPACITY + RESIDENT_MSR_SWITCH_CAPACITY) * size_of::<VmxMsrEntry>()
        <= PAGE_SIZE * 3
);

#[cfg(target_os = "uefi")]
impl From<EptError> for NestedHardwareError {
    fn from(value: EptError) -> Self {
        Self::Ept(value)
    }
}
#[cfg(target_os = "uefi")]
pub(crate) struct CpuStateConfiguration {
    pub(crate) vmxon_operand: u64,
    pub(crate) vmxon_region: u64,
    pub(crate) vmcs12_operand: u64,
    pub(crate) vmcs12_region: u64,
    pub(crate) vmptrst_destination: u64,
    pub(crate) vmcs01_region: u64,
    pub(crate) vmcs02_region: u64,
    pub(crate) msr_guest_list: u64,
    pub(crate) msr_state: u64,
    pub(crate) ept12_pointer: u64,
    pub(crate) ept02_pointer: u64,
    pub(crate) ept02_alternate_pointer: u64,
    pub(crate) ept02_table_pools: [(u64, usize, usize); 2],
    pub(crate) source_gpa: u64,
    pub(crate) target_gpa: u64,
    pub(crate) second_target_gpa: u64,
    pub(crate) source_leaf: u64,
    pub(crate) source_leaf_attributes: u64,
    pub(crate) composition: super::ept::EptComposition,
    pub(crate) alternate: super::ept::EptComposition,
    pub(crate) eptp_list: u64,
    pub(crate) eptp_tables: u64,
    pub(crate) eptp_pages: u64,
    pub(crate) backing: *mut u8,
    pub(crate) backing_len: usize,
}

#[cfg(target_os = "uefi")]
pub(crate) fn prepare_cpu_state(
    configuration: CpuStateConfiguration,
    options: crate::boot::config::MatrixConfig,
    vmx_basic: u64,
    l1_cr4: u64,
    segments: arch::SegmentationState,
    vmcs_shadow: Option<(u64, u64)>,
    msr_bitmap: u64,
) -> Result<NestedVmxState, NestedHardwareError> {
    let nested_capabilities = nested_vmx_capabilities(vmx_basic, options);
    let mut nested_state = NestedVmxState::new(
        nested_capabilities,
        configuration.vmxon_operand,
        configuration.vmxon_region,
        NestedVmcs12State::new(
            nested_capabilities.revision_id,
            configuration.vmcs12_operand,
            configuration.vmcs12_region,
            configuration.vmptrst_destination,
        ),
        configuration.vmcs01_region,
        configuration.vmcs02_region,
    );
    nested_state.l1_cr4 = l1_cr4;
    if let Some((shadow_vmcs, vmread_bitmap)) = vmcs_shadow {
        nested_state.shadow_vmcs_region = shadow_vmcs;
        nested_state.shadow_vmread_bitmap = vmread_bitmap;
    }
    nested_state.evmcs_enabled = u64::from(options.vt_evmcs);
    configure_nested_msr_composition(
        &mut nested_state,
        msr_bitmap,
        configuration.msr_guest_list,
        configuration.msr_state,
    );
    nested_state.configure_ept(NestedEptConfiguration {
        ept12_pointer: configuration.ept12_pointer,
        ept02_pointer: configuration.ept02_pointer,
        source_gpa: configuration.source_gpa,
        target_gpa: configuration.target_gpa,
        composed_hpa: configuration.composition.host_physical_address,
        permissions: configuration.composition.permissions,
        alternate_ept02_pointer: configuration.ept02_alternate_pointer,
        second_target_gpa: configuration.second_target_gpa,
        source_leaf: configuration.source_leaf,
        source_leaf_attributes: configuration.source_leaf_attributes,
        alternate_composed_hpa: configuration.alternate.host_physical_address,
        alternate_permissions: configuration.alternate.permissions,
    });
    if !nested_state.configure_ept02_table_pools(configuration.ept02_table_pools) {
        return Err(NestedHardwareError::InvalidEptPoolUsage);
    }
    nested_state.eptp_shadow_list = configuration.eptp_list;
    nested_state.eptp_table_pool = configuration.eptp_tables;
    nested_state.eptp_table_pages = configuration.eptp_pages;
    nested_state.eptp_native_supported = u64::from(controls::native_eptp_switching_supported());
    nested_state.eptp_sync_apic_id = u64::from(arch::apic_id());
    nested_state
        .vmcs12
        .seed_core_state(capture_nested_vmcs12_core_state(segments, l1_cr4));
    unsafe {
        nested_state
            .vmcs12
            .seed_backing(core::slice::from_raw_parts_mut(
                configuration.backing,
                configuration.backing_len,
            ));
    }

    Ok(nested_state)
}
