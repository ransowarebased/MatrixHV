pub const CPUID_HYPERVISOR_PRESENT_BIT: u32 = 1 << 31;
pub const HYPERVISOR_LEAF_START: u32 = 0x4000_0000;
pub const HYPERVISOR_LEAF_END: u32 = 0x4fff_ffff;
pub const HYPERV_FEATURES_LEAF: u32 = 0x4000_0003;
pub const HYPERV_GUEST_IDLE_ACCESS_MASK: u32 = !(1 << 10);
pub const HYPERV_GUEST_IDLE_FEATURE_MASK: u32 = !(1 << 5);
pub const HYPERV_GUEST_OS_ID_MSR: u32 = 0x4000_0000;
pub const HYPERV_HYPERCALL_MSR: u32 = 0x4000_0001;
pub const HYPERV_VP_INDEX_MSR: u32 = 0x4000_0002;
pub const HYPERV_REFERENCE_COUNT_MSR: u32 = 0x4000_0020;
pub const HYPERV_REFERENCE_TSC_MSR: u32 = 0x4000_0021;
pub const HYPERV_APIC_FREQUENCY_MSR: u32 = 0x4000_0023;
pub const HYPERV_REFERENCE_TIME_MSR_SPAN: u32 =
    HYPERV_APIC_FREQUENCY_MSR - HYPERV_REFERENCE_TSC_MSR;
pub const HYPERV_VP_ASSIST_MSR: u32 = 0x4000_0073;
pub const HYPERV_SIMP_MSR: u32 = 0x4000_0083;
pub const HYPERV_SINT3_MSR: u32 = 0x4000_0093;
pub const HYPERV_STIMER0_CONFIG_MSR: u32 = 0x4000_00b0;
pub const HYPERV_STIMER0_COUNT_MSR: u32 = 0x4000_00b1;

pub fn hyperv_reference_tsc_scale(denominator: u32, numerator: u32, crystal_hz: u32) -> u64 {
    if denominator == 0 || numerator == 0 || crystal_hz == 0 {
        return 0;
    }
    let tsc_hz = u64::from(crystal_hz) * u64::from(numerator) / u64::from(denominator);
    if tsc_hz <= 10_000_000 {
        return 0;
    }
    ((10_000_000_u128 << 64) / u128::from(tsc_hz)) as u64
}

pub fn native_hyperv_reference_tsc() -> (u64, u64) {
    let cpuid = core::arch::x86_64::__cpuid;
    if cpuid(0).eax < 0x15
        || cpuid(1).ecx & CPUID_HYPERVISOR_PRESENT_BIT != 0
        || cpuid(0x8000_0000).eax < 0x8000_0007
        || cpuid(0x8000_0007).edx & (1 << 8) == 0
    {
        return (0, 0);
    }
    let frequency = cpuid(0x15);
    let scale = hyperv_reference_tsc_scale(frequency.eax, frequency.ebx, frequency.ecx);
    let epoch = unsafe { core::arch::x86_64::_rdtsc() };
    let offset = ((u128::from(epoch) * u128::from(scale)) >> 64) as u64;
    (scale, offset.wrapping_neg())
}

pub fn restrict_evmcs_controls(secondary_controls: u64, vt_evmcs: bool) -> u64 {
    if vt_evmcs {
        secondary_controls
            & !(u64::from(
                crate::nested::VMX_SECONDARY_ENABLE_VM_FUNCTIONS
                    | crate::nested::VMX_SECONDARY_VMCS_SHADOWING,
            ) << 32)
    } else {
        secondary_controls
    }
}

pub fn timing_supported(cpuid_presence: bool, tsc_scale: u64) -> bool {
    cpuid_presence && tsc_scale != 0
}

// Hyper-V owns the version-one enlightened VMCS and VP Assist wire layouts.
pub const EVMCS_VERSION: u32 = 1;
pub const EVMCS_PAGE_SIZE: usize = 4096;
pub const VP_ASSIST_ENLIGHTEN_VM_ENTRY_OFFSET: usize = 40;
pub const VP_ASSIST_CURRENT_NESTED_VMCS_OFFSET: usize = 48;

#[repr(C, packed)]
pub struct EnlightenedVmcs {
    pub version_number: u32,
    pub abort_indicator: u32,
    pub host_es_selector: u16,
    pub host_cs_selector: u16,
    pub host_ss_selector: u16,
    pub host_ds_selector: u16,
    pub host_fs_selector: u16,
    pub host_gs_selector: u16,
    pub host_tr_selector: u16,
    pub reserved_0: u16,
    pub host_pat: u64,
    pub host_efer: u64,
    pub host_cr0: u64,
    pub host_cr3: u64,
    pub host_cr4: u64,
    pub host_sysenter_esp: u64,
    pub host_sysenter_eip: u64,
    pub host_rip: u64,
    pub host_sysenter_cs: u32,
    pub pin_controls: u32,
    pub exit_controls: u32,
    pub secondary_processor_controls: u32,
    pub io_bitmap_a: u64,
    pub io_bitmap_b: u64,
    pub msr_bitmap: u64,
    pub guest_es_selector: u16,
    pub guest_cs_selector: u16,
    pub guest_ss_selector: u16,
    pub guest_ds_selector: u16,
    pub guest_fs_selector: u16,
    pub guest_gs_selector: u16,
    pub guest_ldtr_selector: u16,
    pub guest_tr_selector: u16,
    pub guest_es_limit: u32,
    pub guest_cs_limit: u32,
    pub guest_ss_limit: u32,
    pub guest_ds_limit: u32,
    pub guest_fs_limit: u32,
    pub guest_gs_limit: u32,
    pub guest_ldtr_limit: u32,
    pub guest_tr_limit: u32,
    pub guest_gdtr_limit: u32,
    pub guest_idtr_limit: u32,
    pub guest_es_attributes: u32,
    pub guest_cs_attributes: u32,
    pub guest_ss_attributes: u32,
    pub guest_ds_attributes: u32,
    pub guest_fs_attributes: u32,
    pub guest_gs_attributes: u32,
    pub guest_ldtr_attributes: u32,
    pub guest_tr_attributes: u32,
    pub guest_es_base: u64,
    pub guest_cs_base: u64,
    pub guest_ss_base: u64,
    pub guest_ds_base: u64,
    pub guest_fs_base: u64,
    pub guest_gs_base: u64,
    pub guest_ldtr_base: u64,
    pub guest_tr_base: u64,
    pub guest_gdtr_base: u64,
    pub guest_idtr_base: u64,
    pub reserved_1: [u64; 3],
    pub exit_msr_store_address: u64,
    pub exit_msr_load_address: u64,
    pub entry_msr_load_address: u64,
    pub cr3_target_0: u64,
    pub cr3_target_1: u64,
    pub cr3_target_2: u64,
    pub cr3_target_3: u64,
    pub pfec_mask: u32,
    pub pfec_match: u32,
    pub cr3_target_count: u32,
    pub exit_msr_store_count: u32,
    pub exit_msr_load_count: u32,
    pub entry_msr_load_count: u32,
    pub tsc_offset: u64,
    pub virtual_apic_page: u64,
    pub guest_working_vmcs_ptr: u64,
    pub guest_ia32_debugctl: u64,
    pub guest_pat: u64,
    pub guest_efer: u64,
    pub guest_pdpte_0: u64,
    pub guest_pdpte_1: u64,
    pub guest_pdpte_2: u64,
    pub guest_pdpte_3: u64,
    pub guest_pending_debug_exceptions: u64,
    pub guest_sysenter_esp: u64,
    pub guest_sysenter_eip: u64,
    pub guest_activity_state: u32,
    pub guest_sysenter_cs: u32,
    pub cr0_guest_host_mask: u64,
    pub cr4_guest_host_mask: u64,
    pub cr0_read_shadow: u64,
    pub cr4_read_shadow: u64,
    pub guest_cr0: u64,
    pub guest_cr3: u64,
    pub guest_cr4: u64,
    pub guest_dr7: u64,
    pub host_fs_base: u64,
    pub host_gs_base: u64,
    pub host_tr_base: u64,
    pub host_gdtr_base: u64,
    pub host_idtr_base: u64,
    pub host_rsp: u64,
    pub ept_root: u64,
    pub vpid: u16,
    pub reserved_2: [u16; 3],
    pub reserved_3: [u64; 4],
    pub exit_extended_instruction_info: u64,
    pub exit_ept_fault_gpa: u64,
    pub exit_instruction_error: u32,
    pub exit_reason: u32,
    pub exit_interruption_info: u32,
    pub exit_exception_error_code: u32,
    pub exit_idt_vectoring_info: u32,
    pub exit_idt_vectoring_error_code: u32,
    pub exit_instruction_length: u32,
    pub exit_instruction_info: u32,
    pub exit_qualification: u64,
    pub exit_io_instruction_ecx: u64,
    pub exit_io_instruction_esi: u64,
    pub exit_io_instruction_edi: u64,
    pub exit_io_instruction_eip: u64,
    pub guest_linear_address: u64,
    pub guest_rsp: u64,
    pub guest_rflags: u64,
    pub guest_interruptibility: u32,
    pub processor_controls: u32,
    pub exception_bitmap: u32,
    pub entry_controls: u32,
    pub entry_interrupt_info: u32,
    pub entry_exception_error_code: u32,
    pub entry_instruction_length: u32,
    pub tpr_threshold: u32,
    pub guest_rip: u64,
    pub clean_fields: u32,
    pub reserved_4: u32,
    pub synthetic_controls: u32,
    pub enlightenments_control: u32,
    pub vp_id: u32,
    pub reserved_5: u32,
    pub vm_id: u64,
    pub partition_assist_page: u64,
    pub reserved_6: [u64; 4],
    pub guest_bndcfgs: u64,
    pub guest_perf_global_ctrl: u64,
    pub guest_s_cet: u64,
    pub guest_ssp: u64,
    pub guest_interrupt_ssp_table_addr: u64,
    pub guest_lbr_ctl: u64,
    pub reserved_7: [u64; 2],
    pub xss_exiting_bitmap: u64,
    pub encls_exiting_bitmap: u64,
    pub host_perf_global_ctrl: u64,
    pub tsc_multiplier: u64,
    pub host_s_cet: u64,
    pub host_ssp: u64,
    pub host_interrupt_ssp_table_addr: u64,
    pub tertiary_processor_controls: u64,
}

const _: () = assert!(core::mem::size_of::<EnlightenedVmcs>() == 1024);
const _: () = assert!(core::mem::size_of::<EnlightenedVmcs>() <= EVMCS_PAGE_SIZE);
const _: () = assert!(core::mem::offset_of!(EnlightenedVmcs, host_pat) == 24);
const _: () = assert!(core::mem::offset_of!(EnlightenedVmcs, host_rsp) == 616);
const _: () = assert!(core::mem::offset_of!(EnlightenedVmcs, exit_reason) == 692);
const _: () = assert!(core::mem::offset_of!(EnlightenedVmcs, exit_instruction_length) == 712);
const _: () = assert!(core::mem::offset_of!(EnlightenedVmcs, exit_qualification) == 720);
const _: () = assert!(core::mem::offset_of!(EnlightenedVmcs, guest_rsp) == 768);
const _: () = assert!(core::mem::offset_of!(EnlightenedVmcs, guest_rflags) == 776);
const _: () = assert!(core::mem::offset_of!(EnlightenedVmcs, guest_rip) == 816);
const _: () = assert!(core::mem::offset_of!(EnlightenedVmcs, clean_fields) == 824);
const _: () = assert!(core::mem::offset_of!(EnlightenedVmcs, xss_exiting_bitmap) == 960);
