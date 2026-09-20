pub const IA32_FEATURE_CONTROL_LOCKED: u64 = 1 << 0;
pub const IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX: u64 = 1 << 2;
pub const VMX_MEMORY_TYPE_WRITE_BACK: u64 = 6;
pub const VMX_REGION_SIZE: u64 = 4096;
pub const VMX_BASIC_TRUE_CONTROLS: u64 = 1 << 55;

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

pub const VM_EXIT_HOST_ADDRESS_SPACE_SIZE: u32 = 1 << 9;
pub const VM_ENTRY_IA32E_MODE_GUEST: u32 = 1 << 9;
pub const VMCS12_MAX_ENUM_INDEX: u64 = 22;

pub const CPUID_VMX_BIT: u32 = 1 << 5;
pub const CPUID_OSXSAVE_BIT: u32 = 1 << 27;
pub const CPUID_HYPERVISOR_PRESENT_BIT: u32 = 1 << 31;
pub const HYPERVISOR_LEAF_START: u32 = 0x4000_0000;
pub const HYPERVISOR_LEAF_END: u32 = 0x4fff_ffff;
pub const HYPERV_FEATURES_LEAF: u32 = 0x4000_0003;

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
        let exit_ctls = restrict_control(
            host.exit_ctls,
            VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
            VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
        );
        let entry_ctls = restrict_control(
            host.entry_ctls,
            VM_ENTRY_IA32E_MODE_GUEST,
            VM_ENTRY_IA32E_MODE_GUEST,
        );
        let true_exit_ctls = if has_true_controls {
            restrict_control(
                host.true_exit_ctls,
                VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
                VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
            )
        } else {
            0
        };
        let true_entry_ctls = if has_true_controls {
            restrict_control(
                host.true_entry_ctls,
                VM_ENTRY_IA32E_MODE_GUEST,
                VM_ENTRY_IA32E_MODE_GUEST,
            )
        } else {
            0
        };

        Self {
            revision_id,
            feature_control: IA32_FEATURE_CONTROL_LOCKED | IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX,
            vmx_basic: u64::from(revision_id)
                | (VMX_REGION_SIZE << 32)
                | (VMX_MEMORY_TYPE_WRITE_BACK << 50)
                | (host.vmx_basic & VMX_BASIC_TRUE_CONTROLS),
            vmx_pinbased_ctls: restrict_control(host.pinbased_ctls, 0, 0),
            vmx_procbased_ctls: restrict_control(host.procbased_ctls, 0, 0),
            vmx_exit_ctls: exit_ctls,
            vmx_entry_ctls: entry_ctls,
            vmx_misc: 0,
            vmx_cr0_fixed0: host.cr0_fixed0,
            vmx_cr0_fixed1: host.cr0_fixed1,
            vmx_cr4_fixed0: host.cr4_fixed0,
            vmx_cr4_fixed1: host.cr4_fixed1,
            vmx_vmcs_enum: restrict_vmcs_enum(host.vmcs_enum),
            vmx_procbased_ctls2: restrict_control(host.procbased_ctls2, 0, 0),
            vmx_ept_vpid_cap: 0,
            vmx_true_pinbased_ctls: if has_true_controls {
                restrict_control(host.true_pinbased_ctls, 0, 0)
            } else {
                0
            },
            vmx_true_procbased_ctls: if has_true_controls {
                restrict_control(host.true_procbased_ctls, 0, 0)
            } else {
                0
            },
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

fn restrict_vmcs_enum(host: u64) -> u64 {
    let host_index = (host >> 1) & 0x1ff;
    host_index.min(VMCS12_MAX_ENUM_INDEX) << 1
}
