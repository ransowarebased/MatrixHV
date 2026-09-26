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

pub const VMX_PIN_EXTERNAL_INTERRUPT_EXITING: u32 = 1 << 0;
pub const VMX_PIN_NMI_EXITING: u32 = 1 << 3;
pub const VMX_PIN_VIRTUAL_NMIS: u32 = 1 << 5;
pub const VM_EXIT_ACK_INTERRUPT_ON_EXIT: u32 = 1 << 15;
pub const VM_EXIT_HOST_ADDRESS_SPACE_SIZE: u32 = 1 << 9;
pub const VM_EXIT_LOAD_IA32_PAT: u32 = 1 << 19;
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
pub const VMX_SECONDARY_UNRESTRICTED_GUEST: u32 = 1 << 7;
pub const VMX_SECONDARY_RDRAND_EXITING: u32 = 1 << 11;
pub const VMX_SECONDARY_ENABLE_INVPCID: u32 = 1 << 12;
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
pub const MATRIXHV_STATUS_PROTOCOL: u32 = 2;

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
            | VMX_PRIMARY_USE_MSR_BITMAPS
            | VMX_PRIMARY_PAUSE_EXITING
            | optional_primary;
        let exit_supported = VMX_LEGACY_EXIT_DEFAULT1
            | VM_EXIT_HOST_ADDRESS_SPACE_SIZE
            | VM_EXIT_ACK_INTERRUPT_ON_EXIT
            | VM_EXIT_LOAD_IA32_PAT
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
                | secondary_unrestricted
                | secondary_rdrand
                | secondary_invpcid
                | secondary_xsaves
                | secondary_mbec
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
