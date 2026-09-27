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
pub const VMX_CR3_TARGET_COUNT: u64 = 4;
pub const VMCS12_MAX_ENUM_INDEX: u64 = 22;

pub const CPUID_VMX_BIT: u32 = 1 << 5;
pub const CPUID_OSXSAVE_BIT: u32 = 1 << 27;
pub const CPUID_HYPERVISOR_PRESENT_BIT: u32 = 1 << 31;
pub const HYPERVISOR_LEAF_START: u32 = 0x4000_0000;
pub const HYPERVISOR_LEAF_END: u32 = 0x4fff_ffff;
pub const HYPERV_FEATURES_LEAF: u32 = 0x4000_0003;
pub const MATRIXHV_STATUS_LEAF: u32 = 0x4d48_5652;
pub const MATRIXHV_STATUS_SIGNATURE_EAX: u32 = 0x4d48_5631;
pub const MATRIXHV_STATUS_SIGNATURE_EBX: u32 = u32::from_le_bytes(*b"MATR");
pub const MATRIXHV_STATUS_SIGNATURE_ECX: u32 = u32::from_le_bytes(*b"IXHV");
pub const MATRIXHV_STATUS_PROTOCOL: u32 = 6;
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
        let secondary_mbec = if host.ept_vpid_cap
            & (VMX_EPT_EXECUTE_ONLY | VMX_EPT_ADVANCED_EXIT_INFO)
            == (VMX_EPT_EXECUTE_ONLY | VMX_EPT_ADVANCED_EXIT_INFO)
        {
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
            restrict_emulated_control(host.true_exit_ctls, exit_supported, 0)
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
            restrict_control(
                host.entry_ctls,
                entry_supported,
                VMX_LEGACY_ENTRY_DEFAULT1 | VM_ENTRY_IA32E_MODE_GUEST,
            )
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
            vmx_misc: (host.misc & !(0x1ff_u64 << 16)) | (VMX_CR3_TARGET_COUNT << 16),
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

pub const VMCS12_LAUNCH_STATE_CLEAR: u64 = 0;
pub const VMCS12_LAUNCH_STATE_LAUNCHED: u64 = 1;
pub const VMCS12_LAUNCH_STATE_UNINITIALIZED: u64 = u64::MAX;

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

pub const VMCS_FIELD_VPID: u64 = 0x0000;
pub const VMCS_FIELD_GUEST_ES_SELECTOR: u64 = 0x0800;
pub const VMCS_FIELD_GUEST_CS_SELECTOR: u64 = 0x0802;
pub const VMCS_FIELD_GUEST_SS_SELECTOR: u64 = 0x0804;
pub const VMCS_FIELD_GUEST_DS_SELECTOR: u64 = 0x0806;
pub const VMCS_FIELD_GUEST_FS_SELECTOR: u64 = 0x0808;
pub const VMCS_FIELD_GUEST_GS_SELECTOR: u64 = 0x080a;
pub const VMCS_FIELD_GUEST_LDTR_SELECTOR: u64 = 0x080c;
pub const VMCS_FIELD_GUEST_TR_SELECTOR: u64 = 0x080e;
pub const VMCS_FIELD_HOST_ES_SELECTOR: u64 = 0x0c00;
pub const VMCS_FIELD_HOST_CS_SELECTOR: u64 = 0x0c02;
pub const VMCS_FIELD_HOST_SS_SELECTOR: u64 = 0x0c04;
pub const VMCS_FIELD_HOST_DS_SELECTOR: u64 = 0x0c06;
pub const VMCS_FIELD_HOST_FS_SELECTOR: u64 = 0x0c08;
pub const VMCS_FIELD_HOST_GS_SELECTOR: u64 = 0x0c0a;
pub const VMCS_FIELD_HOST_TR_SELECTOR: u64 = 0x0c0c;
pub const VMCS_FIELD_IO_BITMAP_A: u64 = 0x2000;
pub const VMCS_FIELD_IO_BITMAP_B: u64 = 0x2002;
pub const VMCS_FIELD_MSR_BITMAP: u64 = 0x2004;
pub const VMCS_FIELD_VM_EXIT_MSR_STORE_ADDR: u64 = 0x2006;
pub const VMCS_FIELD_VM_EXIT_MSR_LOAD_ADDR: u64 = 0x2008;
pub const VMCS_FIELD_VM_ENTRY_MSR_LOAD_ADDR: u64 = 0x200a;
pub const VMCS_FIELD_EXECUTIVE_VMCS_POINTER: u64 = 0x200c;
pub const VMCS_FIELD_TSC_OFFSET: u64 = 0x2010;
pub const VMCS_FIELD_VIRTUAL_APIC_PAGE_ADDR: u64 = 0x2012;
pub const VMCS_FIELD_APIC_ACCESS_ADDR: u64 = 0x2014;
pub const VMCS_FIELD_EPT_POINTER: u64 = 0x201a;
pub const VMCS_FIELD_VM_FUNCTION_CONTROL: u64 = 0x2018;
pub const VMCS_FIELD_EPTP_LIST_ADDRESS: u64 = 0x2024;
pub const VMCS_FIELD_XSS_EXITING_BITMAP: u64 = 0x202c;
pub const VMCS_FIELD_VMCS_LINK_POINTER: u64 = 0x2800;
pub const VMCS_FIELD_GUEST_PHYSICAL_ADDRESS: u64 = 0x2400;
pub const VMCS_FIELD_GUEST_IA32_DEBUGCTL: u64 = 0x2802;
pub const VMCS_FIELD_GUEST_IA32_PAT: u64 = 0x2804;
pub const VMCS_FIELD_GUEST_IA32_EFER: u64 = 0x2806;
pub const VMCS_FIELD_GUEST_PDPTR0: u64 = 0x280a;
pub const VMCS_FIELD_GUEST_PDPTR1: u64 = 0x280c;
pub const VMCS_FIELD_GUEST_PDPTR2: u64 = 0x280e;
pub const VMCS_FIELD_GUEST_PDPTR3: u64 = 0x2810;
pub const VMCS_FIELD_HOST_IA32_PAT: u64 = 0x2c00;
pub const VMCS_FIELD_HOST_IA32_EFER: u64 = 0x2c02;
pub const VMCS_FIELD_PIN_BASED_VM_EXEC_CONTROL: u64 = 0x4000;
pub const VMCS_FIELD_CPU_BASED_VM_EXEC_CONTROL: u64 = 0x4002;
pub const VMCS_FIELD_EXCEPTION_BITMAP: u64 = 0x4004;
pub const VMCS_FIELD_PAGE_FAULT_ERROR_CODE_MASK: u64 = 0x4006;
pub const VMCS_FIELD_PAGE_FAULT_ERROR_CODE_MATCH: u64 = 0x4008;
pub const VMCS_FIELD_CR3_TARGET_COUNT: u64 = 0x400a;
pub const VMCS_FIELD_VM_EXIT_CONTROLS: u64 = 0x400c;
pub const VMCS_FIELD_VM_EXIT_MSR_STORE_COUNT: u64 = 0x400e;
pub const VMCS_FIELD_VM_EXIT_MSR_LOAD_COUNT: u64 = 0x4010;
pub const VMCS_FIELD_VM_ENTRY_CONTROLS: u64 = 0x4012;
pub const VMCS_FIELD_VM_ENTRY_MSR_LOAD_COUNT: u64 = 0x4014;
pub const VMCS_FIELD_VM_ENTRY_INTR_INFO_FIELD: u64 = 0x4016;
pub const VMCS_FIELD_VM_ENTRY_EXCEPTION_ERROR_CODE: u64 = 0x4018;
pub const VMCS_FIELD_VM_ENTRY_INSTRUCTION_LEN: u64 = 0x401a;
pub const VMCS_FIELD_TPR_THRESHOLD: u64 = 0x401c;
pub const VMCS_FIELD_SECONDARY_VM_EXEC_CONTROL: u64 = 0x401e;
pub const VMCS_FIELD_VM_INSTRUCTION_ERROR: u64 = 0x4400;
pub const VMCS_FIELD_VM_EXIT_REASON: u64 = 0x4402;
pub const VMCS_FIELD_VM_EXIT_INTR_INFO: u64 = 0x4404;
pub const VMCS_FIELD_VM_EXIT_INTR_ERROR_CODE: u64 = 0x4406;
pub const VMCS_FIELD_IDT_VECTORING_INFO_FIELD: u64 = 0x4408;
pub const VMCS_FIELD_IDT_VECTORING_ERROR_CODE: u64 = 0x440a;
pub const VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN: u64 = 0x440c;
pub const VMCS_FIELD_VM_EXIT_INSTRUCTION_INFO: u64 = 0x440e;
pub const VMCS_FIELD_GUEST_ES_LIMIT: u64 = 0x4800;
pub const VMCS_FIELD_GUEST_CS_LIMIT: u64 = 0x4802;
pub const VMCS_FIELD_GUEST_SS_LIMIT: u64 = 0x4804;
pub const VMCS_FIELD_GUEST_DS_LIMIT: u64 = 0x4806;
pub const VMCS_FIELD_GUEST_FS_LIMIT: u64 = 0x4808;
pub const VMCS_FIELD_GUEST_GS_LIMIT: u64 = 0x480a;
pub const VMCS_FIELD_GUEST_LDTR_LIMIT: u64 = 0x480c;
pub const VMCS_FIELD_GUEST_TR_LIMIT: u64 = 0x480e;
pub const VMCS_FIELD_GUEST_GDTR_LIMIT: u64 = 0x4810;
pub const VMCS_FIELD_GUEST_IDTR_LIMIT: u64 = 0x4812;
pub const VMCS_FIELD_GUEST_ES_AR_BYTES: u64 = 0x4814;
pub const VMCS_FIELD_GUEST_CS_AR_BYTES: u64 = 0x4816;
pub const VMCS_FIELD_GUEST_SS_AR_BYTES: u64 = 0x4818;
pub const VMCS_FIELD_GUEST_DS_AR_BYTES: u64 = 0x481a;
pub const VMCS_FIELD_GUEST_FS_AR_BYTES: u64 = 0x481c;
pub const VMCS_FIELD_GUEST_GS_AR_BYTES: u64 = 0x481e;
pub const VMCS_FIELD_GUEST_LDTR_AR_BYTES: u64 = 0x4820;
pub const VMCS_FIELD_GUEST_TR_AR_BYTES: u64 = 0x4822;
pub const VMCS_FIELD_GUEST_INTERRUPTIBILITY_INFO: u64 = 0x4824;
pub const VMCS_FIELD_GUEST_ACTIVITY_STATE: u64 = 0x4826;
pub const VMCS_FIELD_GUEST_SYSENTER_CS: u64 = 0x482a;
pub const VMCS_FIELD_HOST_SYSENTER_CS: u64 = 0x4c00;
pub const VMCS_FIELD_CR0_GUEST_HOST_MASK: u64 = 0x6000;
pub const VMCS_FIELD_CR4_GUEST_HOST_MASK: u64 = 0x6002;
pub const VMCS_FIELD_CR0_READ_SHADOW: u64 = 0x6004;
pub const VMCS_FIELD_CR4_READ_SHADOW: u64 = 0x6006;
pub const VMCS_FIELD_CR3_TARGET_VALUE0: u64 = 0x6008;
pub const VMCS_FIELD_CR3_TARGET_VALUE1: u64 = 0x600a;
pub const VMCS_FIELD_CR3_TARGET_VALUE2: u64 = 0x600c;
pub const VMCS_FIELD_CR3_TARGET_VALUE3: u64 = 0x600e;
pub const VMCS_FIELD_EXIT_QUALIFICATION: u64 = 0x6400;
pub const VMCS_FIELD_GUEST_LINEAR_ADDRESS: u64 = 0x640a;
pub const VMCS_FIELD_GUEST_CR0: u64 = 0x6800;
pub const VMCS_FIELD_GUEST_CR3: u64 = 0x6802;
pub const VMCS_FIELD_GUEST_CR4: u64 = 0x6804;
pub const VMCS_FIELD_GUEST_ES_BASE: u64 = 0x6806;
pub const VMCS_FIELD_GUEST_CS_BASE: u64 = 0x6808;
pub const VMCS_FIELD_GUEST_SS_BASE: u64 = 0x680a;
pub const VMCS_FIELD_GUEST_DS_BASE: u64 = 0x680c;
pub const VMCS_FIELD_GUEST_FS_BASE: u64 = 0x680e;
pub const VMCS_FIELD_GUEST_GS_BASE: u64 = 0x6810;
pub const VMCS_FIELD_GUEST_LDTR_BASE: u64 = 0x6812;
pub const VMCS_FIELD_GUEST_TR_BASE: u64 = 0x6814;
pub const VMCS_FIELD_GUEST_GDTR_BASE: u64 = 0x6816;
pub const VMCS_FIELD_GUEST_IDTR_BASE: u64 = 0x6818;
pub const VMCS_FIELD_GUEST_DR7: u64 = 0x681a;
pub const VMCS_FIELD_GUEST_RSP: u64 = 0x681c;
pub const VMCS_FIELD_GUEST_RIP: u64 = 0x681e;
pub const VMCS_FIELD_GUEST_RFLAGS: u64 = 0x6820;
pub const VMCS_FIELD_GUEST_PENDING_DBG_EXCEPTIONS: u64 = 0x6822;
pub const VMCS_FIELD_GUEST_SYSENTER_ESP: u64 = 0x6824;
pub const VMCS_FIELD_GUEST_SYSENTER_EIP: u64 = 0x6826;
pub const VMCS_FIELD_HOST_CR0: u64 = 0x6c00;
pub const VMCS_FIELD_HOST_CR3: u64 = 0x6c02;
pub const VMCS_FIELD_HOST_CR4: u64 = 0x6c04;
pub const VMCS_FIELD_HOST_FS_BASE: u64 = 0x6c06;
pub const VMCS_FIELD_HOST_GS_BASE: u64 = 0x6c08;
pub const VMCS_FIELD_HOST_TR_BASE: u64 = 0x6c0a;
pub const VMCS_FIELD_HOST_GDTR_BASE: u64 = 0x6c0c;
pub const VMCS_FIELD_HOST_IDTR_BASE: u64 = 0x6c0e;
pub const VMCS_FIELD_HOST_SYSENTER_ESP: u64 = 0x6c10;
pub const VMCS_FIELD_HOST_SYSENTER_EIP: u64 = 0x6c12;
pub const VMCS_FIELD_HOST_RSP: u64 = 0x6c14;
pub const VMCS_FIELD_HOST_RIP: u64 = 0x6c16;

pub const VMCS12_EXTENDED_FIELD_COUNT: usize = 120;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmcs12ExtendedField {
    pub encoding: u64,
    pub index: usize,
}

pub const VMCS12_EXTENDED_FIELDS: [Vmcs12ExtendedField; VMCS12_EXTENDED_FIELD_COUNT] = [
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VPID,
        index: 0,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_PIN_BASED_VM_EXEC_CONTROL,
        index: 1,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CPU_BASED_VM_EXEC_CONTROL,
        index: 2,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_SECONDARY_VM_EXEC_CONTROL,
        index: 3,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_EXCEPTION_BITMAP,
        index: 4,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_PAGE_FAULT_ERROR_CODE_MASK,
        index: 5,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_PAGE_FAULT_ERROR_CODE_MATCH,
        index: 6,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR3_TARGET_COUNT,
        index: 7,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_CONTROLS,
        index: 8,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_MSR_STORE_COUNT,
        index: 9,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_MSR_LOAD_COUNT,
        index: 10,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_ENTRY_CONTROLS,
        index: 11,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_ENTRY_MSR_LOAD_COUNT,
        index: 12,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_ENTRY_INTR_INFO_FIELD,
        index: 13,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_ENTRY_EXCEPTION_ERROR_CODE,
        index: 14,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_ENTRY_INSTRUCTION_LEN,
        index: 15,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_EPT_POINTER,
        index: 16,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_TSC_OFFSET,
        index: 17,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_MSR_BITMAP,
        index: 18,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR0_GUEST_HOST_MASK,
        index: 19,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR4_GUEST_HOST_MASK,
        index: 20,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR0_READ_SHADOW,
        index: 21,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR4_READ_SHADOW,
        index: 22,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VMCS_LINK_POINTER,
        index: 23,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_IA32_DEBUGCTL,
        index: 24,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_IA32_PAT,
        index: 25,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_IA32_EFER,
        index: 26,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_IA32_PAT,
        index: 27,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_IA32_EFER,
        index: 28,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_CR0,
        index: 29,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_CR3,
        index: 30,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_CR4,
        index: 31,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_CR0,
        index: 32,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_CR3,
        index: 33,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_CR4,
        index: 34,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_ES_SELECTOR,
        index: 35,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_CS_SELECTOR,
        index: 36,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_SS_SELECTOR,
        index: 37,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_DS_SELECTOR,
        index: 38,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_FS_SELECTOR,
        index: 39,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_GS_SELECTOR,
        index: 40,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_LDTR_SELECTOR,
        index: 41,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_TR_SELECTOR,
        index: 42,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_ES_SELECTOR,
        index: 43,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_CS_SELECTOR,
        index: 44,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_SS_SELECTOR,
        index: 45,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_DS_SELECTOR,
        index: 46,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_FS_SELECTOR,
        index: 47,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_GS_SELECTOR,
        index: 48,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_TR_SELECTOR,
        index: 49,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_ES_BASE,
        index: 50,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_CS_BASE,
        index: 51,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_SS_BASE,
        index: 52,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_DS_BASE,
        index: 53,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_FS_BASE,
        index: 54,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_GS_BASE,
        index: 55,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_LDTR_BASE,
        index: 56,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_TR_BASE,
        index: 57,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_GDTR_BASE,
        index: 58,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_IDTR_BASE,
        index: 59,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_FS_BASE,
        index: 60,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_GS_BASE,
        index: 61,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_TR_BASE,
        index: 62,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_GDTR_BASE,
        index: 63,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_IDTR_BASE,
        index: 64,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_ES_LIMIT,
        index: 65,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_CS_LIMIT,
        index: 66,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_SS_LIMIT,
        index: 67,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_DS_LIMIT,
        index: 68,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_FS_LIMIT,
        index: 69,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_GS_LIMIT,
        index: 70,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_LDTR_LIMIT,
        index: 71,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_TR_LIMIT,
        index: 72,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_GDTR_LIMIT,
        index: 73,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_IDTR_LIMIT,
        index: 74,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_ES_AR_BYTES,
        index: 75,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_CS_AR_BYTES,
        index: 76,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_SS_AR_BYTES,
        index: 77,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_DS_AR_BYTES,
        index: 78,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_FS_AR_BYTES,
        index: 79,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_GS_AR_BYTES,
        index: 80,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_LDTR_AR_BYTES,
        index: 81,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_TR_AR_BYTES,
        index: 82,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_INTERRUPTIBILITY_INFO,
        index: 83,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_ACTIVITY_STATE,
        index: 84,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_SYSENTER_CS,
        index: 85,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_SYSENTER_ESP,
        index: 86,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_SYSENTER_EIP,
        index: 87,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_SYSENTER_CS,
        index: 88,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_SYSENTER_ESP,
        index: 89,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_SYSENTER_EIP,
        index: 90,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_DR7,
        index: 91,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_PENDING_DBG_EXCEPTIONS,
        index: 92,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_IO_BITMAP_A,
        index: 93,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_IO_BITMAP_B,
        index: 94,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_XSS_EXITING_BITMAP,
        index: 95,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR3_TARGET_VALUE0,
        index: 96,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR3_TARGET_VALUE1,
        index: 97,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR3_TARGET_VALUE2,
        index: 98,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR3_TARGET_VALUE3,
        index: 99,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_TPR_THRESHOLD,
        index: 100,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VIRTUAL_APIC_PAGE_ADDR,
        index: 101,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_APIC_ACCESS_ADDR,
        index: 102,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_MSR_STORE_ADDR,
        index: 103,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_MSR_LOAD_ADDR,
        index: 104,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_ENTRY_MSR_LOAD_ADDR,
        index: 105,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_INTR_INFO,
        index: 106,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_INTR_ERROR_CODE,
        index: 107,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_IDT_VECTORING_INFO_FIELD,
        index: 108,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_IDT_VECTORING_ERROR_CODE,
        index: 109,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_PHYSICAL_ADDRESS,
        index: 110,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_PDPTR0,
        index: 111,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_PDPTR1,
        index: 112,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_PDPTR2,
        index: 113,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_PDPTR3,
        index: 114,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_INSTRUCTION_INFO,
        index: 115,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_LINEAR_ADDRESS,
        index: 116,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_EXECUTIVE_VMCS_POINTER,
        index: 117,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_FUNCTION_CONTROL,
        index: 118,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_EPTP_LIST_ADDRESS,
        index: 119,
    },
];

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedVmcs12State {
    pub operand: u64,
    pub region: u64,
    pub vmptrst_destination: u64,
    pub last_stored_pointer: u64,
    pub revision_id: u64,
    pub launch_state: u64,
    pub guest_rip: u64,
    pub vmclear_count: u64,
    pub vmptrld_count: u64,
    pub vmptrst_count: u64,
    pub vmwrite_count: u64,
    pub vmread_count: u64,
    pub probe_complete: u64,
    pub vmlaunch_count: u64,
    pub vmresume_count: u64,
    pub entry_rejection_count: u64,
    pub guest_rsp: u64,
    pub guest_rflags: u64,
    pub host_rsp: u64,
    pub host_rip: u64,
    pub exit_reason: u64,
    pub exit_instruction_len: u64,
    pub exit_qualification: u64,
    pub extended_fields: [u64; VMCS12_EXTENDED_FIELD_COUNT],
    pub control_validation_count: u64,
}

impl NestedVmcs12State {
    pub fn new(revision_id: u32, operand: u64, region: u64, vmptrst_destination: u64) -> Self {
        Self {
            operand,
            region,
            vmptrst_destination,
            last_stored_pointer: 0,
            revision_id: u64::from(revision_id),
            launch_state: VMCS12_LAUNCH_STATE_UNINITIALIZED,
            guest_rip: 0,
            vmclear_count: 0,
            vmptrld_count: 0,
            vmptrst_count: 0,
            vmwrite_count: 0,
            vmread_count: 0,
            probe_complete: 0,
            vmlaunch_count: 0,
            vmresume_count: 0,
            entry_rejection_count: 0,
            guest_rsp: 0,
            guest_rflags: 0,
            host_rsp: 0,
            host_rip: 0,
            exit_reason: 0,
            exit_instruction_len: 0,
            exit_qualification: 0,
            extended_fields: [0; VMCS12_EXTENDED_FIELD_COUNT],
            control_validation_count: 0,
        }
    }
}

pub const VMCS12_BACKING_MAGIC: u64 = 0x4d48_5656_4d43_5331;
pub const VMCS12_BACKING_MAGIC_OFFSET: usize = 0x20;
pub const VMCS12_BACKING_STATE_OFFSET: usize = 0x100;
pub const VMCS12_BACKING_QWORD_COUNT: usize =
    core::mem::size_of::<NestedVmcs12State>() / core::mem::size_of::<u64>();

const _: () = assert!(VMCS12_BACKING_MAGIC_OFFSET + core::mem::size_of::<u64>() <= 0x100);
const _: () = assert!(VMCS12_BACKING_STATE_OFFSET & 7 == 0);
const _: () =
    assert!(VMCS12_BACKING_STATE_OFFSET + core::mem::size_of::<NestedVmcs12State>() <= 4096);

pub const INVALID_VMCS_POINTER: u64 = u64::MAX;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedVmxState {
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
    pub expose_vmx: u64,
    pub l1_cr4: u64,
    pub vmxon_operand: u64,
    pub vmxon_region: u64,
    pub current_vmcs: u64,
    pub last_operand: u64,
    pub last_vmcs_field: u64,
    pub instruction_error: u64,
    pub vmxon_count: u64,
    pub vmxoff_count: u64,
    pub failure_count: u64,
    pub active: u64,
    pub probe_complete: u64,
    pub vmcs12: NestedVmcs12State,
    pub vmcs01_region: u64,
    pub vmcs02_region: u64,
    pub l2_active: u64,
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
    pub ept01_pointer: u64,
    pub ept02_invalidation_count: u64,
    pub vmcs02_launched: u64,
    pub ept02_cache_initialized: u64,
    pub ept02_cached_ept12_pointer: u64,
    pub ept02_cached_pointer: u64,
    pub ept02_cached_table_pool: u64,
    pub ept02_cached_table_pool_pages: u64,
    pub ept02_cached_table_pool_used: u64,
    pub ept02_mbec: u64,
    pub vmcs02_guest_cache_valid: u64,
    pub vmcs02_control_cache_valid: [u64; 2],
    pub vmcs02_field_cache: [u64; VMCS12_EXTENDED_FIELD_COUNT],
    pub vmcs02_last_vpid: u64,
    pub ept02_cached_mbec: u64,
    pub exit_started_tsc: u64,
    pub exit_handler_cycles: [u64; 4],
    pub reflected_exit_counts: [u32; 44],
    pub vmcs02_vpid_cache: u32,
    pub physical_address_bits: u32,
    pub host_mapping_cache: [u64; 4],
    pub vmcs02_rare_state_pending: [u64; 2],
    pub ept02_recycle_count: u64,
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
            0
        };
        Self {
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
            last_operand: 0,
            last_vmcs_field: 0,
            instruction_error: 0,
            vmxon_count: 0,
            vmxoff_count: 0,
            failure_count: 0,
            active: 0,
            probe_complete: 0,
            vmcs12,
            vmcs01_region,
            vmcs02_region,
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
            vmcs02_rare_state_pending: [0; 2],
            ept02_recycle_count: 0,
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

    pub fn configure_ept02_table_pools(&mut self, pools: [(u64, usize, usize); 2]) {
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
