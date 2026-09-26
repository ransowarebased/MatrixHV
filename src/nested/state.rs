use core::arch::x86_64::__cpuid;

use super::capabilities::NestedVmxCapabilities;
use super::vmcs::{NestedVmcs12State, VMCS12_EXTENDED_FIELD_COUNT};

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
