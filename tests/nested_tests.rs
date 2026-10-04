#[cfg(test_harness = "policy")]
#[path = "../src/protocol.rs"]
pub mod protocol;
#[cfg(test_harness = "policy")]
use vmx::hyperv;
#[cfg(test_harness = "policy")]
#[path = "../src/boot/config.rs"]
pub mod config;
#[cfg(test_harness = "policy")]
pub mod vmx {
    pub mod hyperv {
        include!("../src/vmx/hyperv.rs");
    }
    pub mod nested {
        include!("../src/vmx/nested.rs");
    }
    pub mod vmcs12 {
        include!("../src/vmx/vmcs12.rs");
    }
}
#[cfg(test_harness = "policy")]
mod policy {
    include!("hyperv_layout.rs");
    include!("hyperv_regressions.rs");
    #[cfg(matrixhv_review)]
    include!("review_hv_loader_tests.rs");

    use crate::protocol::{
        MATRIXHV_STATUS_LEAF, MATRIXHV_STATUS_PROTOCOL, MATRIXHV_STATUS_SIGNATURE_EAX,
        MATRIXHV_STATUS_SIGNATURE_EBX, MATRIXHV_STATUS_SIGNATURE_ECX,
    };
    use crate::vmx::{nested, vmcs12};

    core::arch::global_asm!(
        include_str!("../builds/evmcs-tests/handlers.S"),
        b_nested_operand_linear_address = const core::mem::offset_of!(nested::NestedVmxState, operand_linear_address),
        b_nested_current_vmcs = const core::mem::offset_of!(nested::NestedVmxState, current_vmcs),
        b_nested_current_vmcs_hpa = const core::mem::offset_of!(nested::NestedVmxState, current_vmcs_hpa),
        b_nested_current_vmcs_is_shadow = const core::mem::offset_of!(nested::NestedVmxState, current_vmcs_is_shadow),
        b_nested_evmcs_active = const core::mem::offset_of!(nested::NestedVmxState, evmcs_active),
        b_nested_evmcs_page_cache = const core::mem::offset_of!(nested::NestedVmxState, evmcs_page_cache),
        b_nested_failure_count = const core::mem::offset_of!(nested::NestedVmxState, failure_count),
        b_nested_evmcs_enabled = const core::mem::offset_of!(nested::NestedVmxState, evmcs_enabled),
        b_nested_vp_assist_msr = const core::mem::offset_of!(nested::NestedVmxState, vp_assist_msr),
        b_cache_ept_pointer = const core::mem::offset_of!(nested::NestedVmxState, ept01_pointer),
        b_nested_host_mapping_cache = const core::mem::offset_of!(nested::NestedVmxState, host_mapping_cache),
        host_page_address_mask = const 0x000f_ffff_ffff_f000_u64,
        b_nested_active = const core::mem::offset_of!(nested::NestedVmxState, active),
        b_nested_last_operand = const core::mem::offset_of!(nested::NestedVmxState, last_operand),
        b_nested_vmxon_region = const core::mem::offset_of!(nested::NestedVmxState, vmxon_region),
        b_nested_vmx_procbased_ctls2 = const core::mem::offset_of!(nested::NestedVmxState, vmx_procbased_ctls2),
        b_nested_vmx_procbased_ctls = const core::mem::offset_of!(nested::NestedVmxState, vmx_procbased_ctls),
        b_nested_vmcs12_guest_cr0 = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, extended_fields) + 29 * 8,
        b_nested_vmclear_count = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, vmclear_count),
        b_telemetry_active = const core::mem::offset_of!(nested::NestedVmxState, probe_complete),
        guest_cs_selector = const 0x0802,
        vmclear_invalid_physical_address_error = const nested::VMCLEAR_INVALID_PHYSICAL_ADDRESS_ERROR,
        vmclear_vmxon_pointer_error = const nested::VMCLEAR_VMXON_POINTER_ERROR,
        vmcs12_backing_magic = const vmcs12::VMCS12_BACKING_MAGIC,
        vmcs12_backing_magic_offset = const vmcs12::VMCS12_BACKING_MAGIC_OFFSET,
        vmcs12_backing_state_offset = const vmcs12::VMCS12_BACKING_STATE_OFFSET,
        vmcs12_backing_qword_count = const vmcs12::VMCS12_BACKING_QWORD_COUNT,
        vmcs12_revision_id_offset = const core::mem::offset_of!(vmcs12::NestedVmcs12State, revision_id),
        vmcs12_launch_state_offset = const core::mem::offset_of!(vmcs12::NestedVmcs12State, launch_state),
        vmcs12_vmclear_count_offset = const core::mem::offset_of!(vmcs12::NestedVmcs12State, vmclear_count),
        vmcs12_launch_state_clear = const vmcs12::VMCS12_LAUNCH_STATE_CLEAR,
        b_nested_shadow_vmread_bitmap = const core::mem::offset_of!(nested::NestedVmxState, shadow_vmread_bitmap),
        vmcs_shadow_read_byte_offset = const vmcs12::VMCS_SHADOW_READ_BITMAP_BYTE_OFFSET,
        vmcs_shadow_read_bypass_mask = const vmcs12::VMCS_SHADOW_READ_BYPASS_MASK,
        b_nested_vmcs02_guest_cache_valid = const core::mem::offset_of!(nested::NestedVmxState, vmcs02_guest_cache_valid),
        b_nested_vmcs02_control_cache_valid = const core::mem::offset_of!(nested::NestedVmxState, vmcs02_control_cache_valid),
        b_nested_vmcs12_extended_fields = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, extended_fields),
        b_nested_vmcs12_revision_id = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, revision_id),
        b_nested_vmcs12_operand = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, operand),
        b_nested_vmcs12_region = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, region),
        vmptrld_invalid_physical_address_error = const nested::VMPTRLD_INVALID_PHYSICAL_ADDRESS_ERROR,
        vmptrld_vmxon_pointer_error = const nested::VMPTRLD_VMXON_POINTER_ERROR,
        vmptrld_incorrect_revision_error = const nested::VMPTRLD_INCORRECT_REVISION_ERROR,
        b_nested_vmcs12_guest_rip = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, guest_rip),
        b_nested_vmcs12_guest_rsp = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, guest_rsp),
        b_nested_vmcs12_guest_rflags = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, guest_rflags),
        b_nested_vmcs12_host_rip = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, host_rip),
        b_nested_vmcs12_host_rsp = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, host_rsp),
        b_nested_vmcs12_exit_reason = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, exit_reason),
        b_nested_vmcs12_vm_entry_intr_info = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, extended_fields) + 13 * 8,
        b_nested_vmcs12_vm_entry_exception_error = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, extended_fields) + 14 * 8,
        b_nested_vmcs12_vm_entry_instruction_len = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, extended_fields) + 15 * 8,
        b_nested_vmcs12_primary_control = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, extended_fields) + 2 * 8,
        b_nested_vmcs12_tsc_offset = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, extended_fields) + 17 * 8,
        b_nested_inherited_l1_tsc_offset = const core::mem::offset_of!(nested::NestedVmxState, inherited_l1_tsc_offset),
        tsc_offset = const 0x2010,
        b_nested_vmcs12_vm_entry_controls = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, extended_fields) + 11 * 8,
        b_nested_vmcs12_vm_exit_controls = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, extended_fields) + 4 * 8,
        b_nested_l2_saved_pat = const core::mem::offset_of!(nested::NestedVmxState, l2_saved_pat),
        b_nested_l2_saved_efer = const core::mem::offset_of!(nested::NestedVmxState, l2_saved_efer),
        b_nested_vmx_misc = const core::mem::offset_of!(nested::NestedVmxState, vmx_misc),
        guest_efer = const 0x2806,
        guest_pat = const 0x2804,
        b_nested_vmcs12_launch_state = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, launch_state),
        b_nested_l2_entry_was_resume = const core::mem::offset_of!(nested::NestedVmxState, l2_entry_was_resume),
        b_nested_vmcs02_launched = const core::mem::offset_of!(nested::NestedVmxState, vmcs02_launched),
        matrixhv_status_leaf = const crate::protocol::MATRIXHV_STATUS_LEAF,
        vmcs12_launch_state_launched = const vmcs12::VMCS12_LAUNCH_STATE_LAUNCHED,
        b_nested_vmcs12_exit_instruction_len = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, exit_instruction_len),
        b_nested_vmcs12_exit_qualification = const core::mem::offset_of!(nested::NestedVmxState, vmcs12)
            + core::mem::offset_of!(vmcs12::NestedVmcs12State, exit_qualification),
        evmcs_version = const crate::hyperv::EVMCS_VERSION,
        evmcs_guest_rip = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, guest_rip),
        evmcs_guest_rsp = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, guest_rsp),
        evmcs_guest_rflags = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, guest_rflags),
        evmcs_host_rip = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, host_rip),
        evmcs_host_rsp = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, host_rsp),
        evmcs_exit_reason = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, exit_reason),
        evmcs_exit_instruction_length = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, exit_instruction_length),
        evmcs_exit_qualification = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, exit_qualification),
        evmcs_clean_fields = const core::mem::offset_of!(crate::hyperv::EnlightenedVmcs, clean_fields),
        nested_extended_field_count = const vmcs12::VMCS12_EXTENDED_FIELD_COUNT,
        vp_assist_enlighten_vm_entry = const crate::hyperv::VP_ASSIST_ENLIGHTEN_VM_ENTRY_OFFSET,
        vp_assist_current_nested_vmcs = const crate::hyperv::VP_ASSIST_CURRENT_NESTED_VMCS_OFFSET,
    );

    unsafe extern "C" {
        fn test_evmcs_cpuid(leaf: u32, result: *mut u32);
        fn test_select_evmcs(state: *mut nested::NestedVmxState) -> i32;
        fn test_store_evmcs(state: *mut nested::NestedVmxState);
        fn test_complete_evmcs_exit(state: *mut nested::NestedVmxState);
        fn test_route_l2_cpuid(state: *mut nested::NestedVmxState, leaf: u64) -> u32;
        fn test_write_vp_assist(state: *mut nested::NestedVmxState, value: u64) -> u32;
        fn test_clear_evmcs(state: *mut nested::NestedVmxState, address: u64) -> u32;
        fn test_load_vmcs(state: *mut nested::NestedVmxState, address: u64) -> u32;
        fn test_capture_evmcs_entry_mode(state: *mut nested::NestedVmxState, efer: u64);
    }

    #[test]
    fn evmcs_discovery_advertises_assist_page_and_disables_spin_hypercalls() {
        let mut features = [0_u32; 4];
        let mut recommendations = [0_u32; 4];
        let mut versions = [0_u32; 4];
        unsafe {
            test_evmcs_cpuid(0x4000_0003, features.as_mut_ptr());
            test_evmcs_cpuid(0x4000_0004, recommendations.as_mut_ptr());
            test_evmcs_cpuid(0x4000_000a, versions.as_mut_ptr());
        }
        assert_ne!(features[0] & (1 << 4), 0);
        assert_ne!(recommendations[0] & (1 << 14), 0);
        assert_eq!(recommendations[1], u32::MAX);
        assert_eq!(versions[0] & 0xffff, 0x0101);
    }

    #[test]
    fn l2_routes_only_the_private_diagnostic_cpuid_to_root() {
        for (reason, leaf, intercepted) in [
            (10, crate::protocol::MATRIXHV_STATUS_LEAF, 1),
            (10, 1, 0),
            (10, 0x4000_0000, 0),
            (10, 0x4000_000a, 0),
            (18, crate::protocol::MATRIXHV_STATUS_LEAF, 0),
            (0x8000_000a, crate::protocol::MATRIXHV_STATUS_LEAF, 0),
        ] {
            let mut state = nested_state(0);
            state.vmcs12.exit_reason = reason;
            assert_eq!(
                unsafe { test_route_l2_cpuid(&mut state, u64::from(leaf)) },
                intercepted
            );
            assert_eq!(state.vmcs02_launched, u64::from(intercepted));
        }
    }

    #[test]
    fn hyperv_exposure_requires_cpuid_and_nested_vmx_for_evmcs() {
        for cpuid in [false, true] {
            for nested in [false, true] {
                for evmcs in [false, true] {
                    let mut cpuid_presence = cpuid;
                    let mut vt_nested = nested;
                    crate::config::normalize_exposure(&mut cpuid_presence, &mut vt_nested, evmcs);
                    assert_eq!(cpuid_presence, cpuid || evmcs);
                    assert_eq!(vt_nested, nested || evmcs);
                    assert_eq!(crate::hyperv::timing_supported(cpuid_presence, 0), false);
                    assert_eq!(
                        crate::hyperv::timing_supported(cpuid_presence, 1),
                        cpuid_presence
                    );
                }
            }
        }
    }

    #[test]
    fn evmcs_controls_preserve_required_bits_and_hide_unsupported_controls() {
        let unsupported = u64::from(
            nested::VMX_SECONDARY_ENABLE_VM_FUNCTIONS | nested::VMX_SECONDARY_VMCS_SHADOWING,
        ) << 32;
        for controls in [0, unsupported, u64::MAX, 0x1234_5678_9abc_def0] {
            assert_eq!(
                crate::hyperv::restrict_evmcs_secondary_capability(controls, false),
                controls
            );
            assert_eq!(
                crate::hyperv::restrict_evmcs_secondary_capability(controls, true),
                controls & !unsupported
            );
        }
    }

    use crate::hyperv::{
        CPUID_HYPERVISOR_PRESENT_BIT, HYPERV_FEATURES_LEAF, HYPERVISOR_LEAF_END,
        HYPERVISOR_LEAF_START,
    };
    use nested::{CPUID_OSXSAVE_BIT, CPUID_VMX_BIT, HostVmxCapabilities, IA32_FEATURE_CONTROL_LOCKED, IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX, INVALID_OPERAND_TO_INVEPT_INVVPID_ERROR, INVALID_VMCS_POINTER, NestedEptConfiguration, NestedMsrComposition, NestedVmxCapabilities, NestedVmxState, VM_ENTRY_BLOCKED_BY_MOV_SS_ERROR, VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR, VM_ENTRY_INVALID_HOST_STATE_FIELD_ERROR, VMCLEAR_INVALID_PHYSICAL_ADDRESS_ERROR, VMCLEAR_VMXON_POINTER_ERROR, VMCS_UNSUPPORTED_COMPONENT_ERROR, VMFAIL_INVALID_STATUS, VMFAIL_VALID_STATUS, VMLAUNCH_NON_CLEAR_VMCS_ERROR, VMPTRLD_INCORRECT_REVISION_ERROR, VMPTRLD_INVALID_PHYSICAL_ADDRESS_ERROR, VMPTRLD_VMXON_POINTER_ERROR, VMRESUME_NON_LAUNCHED_VMCS_ERROR, VMWRITE_READ_ONLY_COMPONENT_ERROR, VMX_BASIC_TRUE_CONTROLS, VMX_MEMORY_TYPE_WRITE_BACK, VMX_REGION_SIZE, VMX_STATUS_FLAGS, VMX_STATUS_FLAGS_CLEAR_MASK, VMXON_IN_VMX_ROOT_ERROR};
    use vmcs12::{NestedVmcs12State, VMCS_FIELD_EXIT_QUALIFICATION, VMCS_FIELD_GUEST_RFLAGS, VMCS_FIELD_GUEST_RIP, VMCS_FIELD_GUEST_RSP, VMCS_FIELD_HOST_RIP, VMCS_FIELD_HOST_RSP, VMCS_FIELD_VM_EXIT_INSTRUCTION_INFO, VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN, VMCS_FIELD_VM_EXIT_REASON, VMCS_FIELD_VM_INSTRUCTION_ERROR, VMCS12_BACKING_MAGIC, VMCS12_BACKING_MAGIC_OFFSET, VMCS12_BACKING_QWORD_COUNT, VMCS12_BACKING_STATE_OFFSET, VMCS12_LAUNCH_STATE_CLEAR, VMCS12_LAUNCH_STATE_LAUNCHED, VMCS12_LAUNCH_STATE_UNINITIALIZED};

    const HOST_VMX_BASIC: u64 = 0x00da_0400_0000_1234;
    const VMXON_REGION: u64 = 0x20_0000;
    const VMXON_OPERAND: u64 = 0x21_0000;
    const VMCS12_REGION: u64 = 0x30_0000;
    const VMCS12_OPERAND: u64 = 0x31_0000;
    const VMPTRST_DESTINATION: u64 = VMCS12_OPERAND + 8;
    const VMCS01_REGION: u64 = 0x40_0000;
    const VMCS02_REGION: u64 = 0x50_0000;

    #[test]
    fn vmcs12_seed_preserves_guest_selectors_and_distinguishes_host_registers() {
        let segments: [vmcs12::NestedVmcs12SegmentState; 8] =
            core::array::from_fn(|index| vmcs12::NestedVmcs12SegmentState {
                selector: 0x27 + index as u16 * 8,
                base: 0x1000 * (index as u64 + 1),
                limit: 0xffff + index as u32,
                access_rights: 0x93 + index as u32,
            });
        let mut vmcs12 = NestedVmcs12State::new(1, 2, 3, 4);
        vmcs12.extended_fields.fill(0xfeed);
        vmcs12.guest_rip = 0x1234;
        vmcs12.seed_core_state(vmcs12::NestedVmcs12CoreState {
            guest_cr0: 0x8000_0021,
            guest_cr3: 0x1000,
            guest_cr4: 0x20,
            host_cr0: 0x8000_0031,
            host_cr3: 0x2000,
            host_cr4: 0x2020,
            es: segments[0],
            cs: segments[1],
            ss: segments[2],
            ds: segments[3],
            fs: segments[4],
            gs: segments[5],
            ldtr: segments[6],
            tr: segments[7],
            gdtr_base: 0x9000,
            gdtr_limit: 0x7f,
            idtr_base: 0xa000,
            idtr_limit: 0xfff,
            sysenter_cs: 0x10,
            sysenter_esp: 0xb000,
            sysenter_eip: 0xc000,
        });
        let field_value = |encoding| {
            let field = vmcs12::VMCS12_EXTENDED_FIELDS
                .iter()
                .find(|field| field.encoding == encoding)
                .unwrap();
            vmcs12.extended_fields[field.index]
        };
        for (encoding, expected) in [
            (0x2800, u64::MAX),
            (0x6800, 0x8000_0021),
            (0x6802, 0x1000),
            (0x6804, 0x20),
            (0x6c00, 0x8000_0031),
            (0x6c02, 0x2000),
            (0x6c04, 0x2020),
            (0x6816, 0x9000),
            (0x4810, 0x7f),
            (0x6818, 0xa000),
            (0x4812, 0xfff),
            (0x6c0c, 0x9000),
            (0x6c0e, 0xa000),
            (0x4824, 0),
            (0x4826, 0),
            (0x6822, 0),
            (0x482a, 0x10),
            (0x6824, 0xb000),
            (0x6826, 0xc000),
            (0x4c00, 0x10),
            (0x6c10, 0xb000),
            (0x6c12, 0xc000),
            (0x201a, 0xfeed),
        ] {
            assert_eq!(field_value(encoding), expected, "encoding={encoding:#x}");
        }
        for (index, segment) in segments.iter().enumerate() {
            let offset = index as u64 * 2;
            assert_eq!(field_value(0x0800 + offset), u64::from(segment.selector));
            assert_eq!(field_value(0x6806 + offset), segment.base);
            assert_eq!(field_value(0x4800 + offset), u64::from(segment.limit));
            assert_eq!(
                field_value(0x4814 + offset),
                u64::from(segment.access_rights)
            );
            if index != 6 {
                let host_index = if index == 7 { 6 } else { index };
                assert_eq!(
                    field_value(0x0c00 + host_index as u64 * 2),
                    u64::from(segment.selector & !7),
                );
            }
        }
        assert_eq!(field_value(0x6c06), segments[4].base);
        assert_eq!(field_value(0x6c08), segments[5].base);
        assert_eq!(field_value(0x6c0a), segments[7].base);
        assert_eq!(vmcs12.guest_rip, 0x1234);
        assert_eq!(vmcs12.launch_state, VMCS12_LAUNCH_STATE_UNINITIALIZED);
    }

    #[test]
    fn vmcs12_seed_backing_preserves_header_and_writes_unaligned_state() {
        let mut storage = [0xa5a5_a5a5_a5a5_a5a5_u64; 513];
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                storage.as_mut_ptr().cast::<u8>(),
                core::mem::size_of_val(&storage),
            )
        };
        let page = &mut bytes[1..4097];
        page[..4].copy_from_slice(&0x1234_u32.to_ne_bytes());
        let original = page.to_vec();
        let mut vmcs12 = NestedVmcs12State::new(0x1234, 0x1000, 0x2000, 0x3000);
        vmcs12.guest_rip = 0x4000;
        vmcs12.vmwrite_count = 7;
        vmcs12.extended_fields[vmcs12::VMCS12_EXTENDED_FIELD_COUNT - 1] = 0x5000;
        vmcs12.seed_backing(page);
        let magic_end = VMCS12_BACKING_MAGIC_OFFSET + core::mem::size_of::<u64>();
        let state_end = VMCS12_BACKING_STATE_OFFSET + core::mem::size_of::<NestedVmcs12State>();
        assert_eq!(
            &page[..VMCS12_BACKING_MAGIC_OFFSET],
            &original[..VMCS12_BACKING_MAGIC_OFFSET]
        );
        assert_eq!(
            &page[magic_end..VMCS12_BACKING_STATE_OFFSET],
            &original[magic_end..VMCS12_BACKING_STATE_OFFSET]
        );
        assert_eq!(&page[state_end..], &original[state_end..]);
        assert_eq!(
            u64::from_ne_bytes(
                page[VMCS12_BACKING_MAGIC_OFFSET..magic_end]
                    .try_into()
                    .unwrap()
            ),
            VMCS12_BACKING_MAGIC,
        );
        let backed_state = unsafe {
            page.as_ptr()
                .add(VMCS12_BACKING_STATE_OFFSET)
                .cast::<NestedVmcs12State>()
                .read_unaligned()
        };
        assert_eq!(backed_state, vmcs12);
    }

    #[test]
    #[should_panic]
    fn vmcs12_seed_backing_rejects_short_regions() {
        NestedVmcs12State::new(1, 2, 3, 4).seed_backing(&mut [0; 4095]);
    }

    fn control_capabilities(must_be_one: u32, may_be_one: u32) -> u64 {
        u64::from(must_be_one) | (u64::from(may_be_one) << 32)
    }

    fn host_vmx_capabilities() -> HostVmxCapabilities {
        HostVmxCapabilities {
            vmx_basic: HOST_VMX_BASIC,
            pinbased_ctls: control_capabilities(0x16, u32::MAX),
            procbased_ctls: control_capabilities(0x0400_6172, u32::MAX),
            exit_ctls: control_capabilities(0x0003_6dfb, u32::MAX),
            entry_ctls: control_capabilities(0x0000_11fb, u32::MAX),
            misc: u64::MAX,
            cr0_fixed0: 0x8000_0021,
            cr0_fixed1: 0xffff_ffff,
            cr4_fixed0: 0x0000_2000,
            cr4_fixed1: 0x003f_ffff,
            vmcs_enum: 31 << 1,
            procbased_ctls2: control_capabilities(0, u32::MAX),
            ept_vpid_cap: u64::MAX,
            true_pinbased_ctls: control_capabilities(0, u32::MAX),
            true_procbased_ctls: control_capabilities(0, u32::MAX),
            true_exit_ctls: control_capabilities(0, u32::MAX),
            true_entry_ctls: control_capabilities(0, u32::MAX),
        }
    }

    fn vmcs12(region_offset: u64) -> NestedVmcs12State {
        NestedVmcs12State::new(
            HOST_VMX_BASIC as u32 & 0x7fff_ffff,
            VMCS12_OPERAND + region_offset,
            VMCS12_REGION + region_offset,
            VMPTRST_DESTINATION + region_offset,
        )
    }

    fn nested_state(region_offset: u64) -> NestedVmxState {
        NestedVmxState::new(
            NestedVmxCapabilities::vmxon_vmxoff(HOST_VMX_BASIC),
            VMXON_OPERAND + region_offset,
            VMXON_REGION + region_offset,
            vmcs12(region_offset),
            VMCS01_REGION + region_offset,
            VMCS02_REGION + region_offset,
        )
    }

    #[test]
    fn nested_state_tracks_l1_cr4_independently() {
        let mut state = nested_state(0);

        assert_eq!(state.l1_cr4, 0);
        assert_eq!(state.shadow_vmcs_region, 0);
        assert_eq!(state.shadow_vmread_bitmap, 0);
        state.l1_cr4 = 0x2660;
        assert_eq!(state.l1_cr4, 0x2660);
    }

    #[test]
    fn native_vmcs_shadowing_requires_host_may_be_one_capability() {
        let bit = nested::VMX_SECONDARY_VMCS_SHADOWING;
        assert!(!nested::native_vmcs_shadowing_available(
            control_capabilities(0, nested::VMX_SECONDARY_ENABLE_EPT,)
        ));
        assert!(!nested::native_vmcs_shadowing_available(
            control_capabilities(bit, 0)
        ));
        assert!(nested::native_vmcs_shadowing_available(
            control_capabilities(0, bit)
        ));

        let guest = NestedVmxCapabilities::from_host(host_vmx_capabilities());
        assert_eq!((guest.vmx_procbased_ctls2 >> 32) as u32 & bit, bit);
        let mut host = host_vmx_capabilities();
        host.procbased_ctls2 &= !(u64::from(bit) << 32);
        let guest = NestedVmxCapabilities::from_host(host);
        assert_eq!((guest.vmx_procbased_ctls2 >> 32) as u32 & bit, 0);
        for supported in [false, true] {
            let mut host = host_vmx_capabilities();
            host.misc = (host.misc & !(1 << 29)) | (u64::from(supported) << 29);
            let guest = NestedVmxCapabilities::from_host(host);
            assert_eq!(guest.vmx_misc & (1 << 29), host.misc & (1 << 29));
        }
    }

    #[test]
    fn vmcs_shadow_read_bitmap_bypasses_only_selected_host_fields() {
        let byte = vmcs12::VMCS_SHADOW_READ_BITMAP_BYTE_OFFSET;
        let bypass = vmcs12::VMCS_SHADOW_READ_BYPASS_MASK;
        assert!(byte < 4096);
        assert_eq!(byte, (vmcs12::VMCS_FIELD_HOST_RIP >> 3) as usize);
        assert_eq!(bypass, 0x50);
        assert_eq!(vmcs12::VMCS_SHADOW_READ_TRAP_MASK, !bypass);
        let mut bitmap = [0xff_u8; 4096];
        bitmap[byte] &= vmcs12::VMCS_SHADOW_READ_TRAP_MASK;
        assert_eq!(bitmap[byte], 0xaf);
        assert_eq!(bitmap[byte - 1], 0xff);
        assert_eq!(bitmap[byte + 1], 0xff);
        bitmap[byte] |= bypass;
        assert_eq!(bitmap[byte], 0xff);
    }

    #[test]
    fn nested_state_records_msr_composition_buffers() {
        let mut state = nested_state(0);

        state.configure_msr_composition(NestedMsrComposition {
            l0_msr_bitmap: 0x60_0000,
            composed_msr_bitmap: 0x61_0000,
            l0_msr_guest_list: 0x62_0000,
            l0_msr_host_list: 0x62_0070,
            vmcs02_entry_msr_list: 0x63_0000,
            vmcs02_exit_store_msr_list: 0x65_0000,
            vmcs01_entry_msr_list: 0x67_0000,
        });

        assert_eq!(state.l0_msr_bitmap, 0x60_0000);
        assert_eq!(state.composed_msr_bitmap, 0x61_0000);
        assert_eq!(state.l0_msr_guest_list, 0x62_0000);
        assert_eq!(state.l0_msr_host_list, 0x62_0070);
        assert_eq!(state.vmcs02_entry_msr_list, 0x63_0000);
        assert_eq!(state.vmcs02_exit_store_msr_list, 0x65_0000);
        assert_eq!(state.vmcs01_entry_msr_list, 0x67_0000);
        assert_eq!(state.vmcs01_msr_entry_composed, 0);
    }

    #[test]
    fn nested_state_records_dynamic_ept02_table_pool() {
        let mut state = nested_state(0);

        assert!(state.configure_ept02_table_pools([(0x70_0000, 128, 9), (0x80_0000, 128, 6)]));

        assert_eq!(state.ept02_table_pool, 0x70_0000);
        assert_eq!(state.ept02_table_pool_pages, 128);
        assert_eq!(state.ept02_table_pool_used, 9);
        assert_eq!(state.ept02_cached_table_pool, 0x80_0000);
        assert_eq!(state.ept02_cached_table_pool_pages, 128);
        assert_eq!(state.ept02_cached_table_pool_used, 6);
        assert_eq!(state.ept02_cache_initialized, 0);
        assert_eq!(state.ept02_cached_ept12_pointer, 0);
        assert_eq!(state.ept01_pointer, 0);
        assert_eq!(state.ept02_invalidation_count, 0);
        for pools in [[(0x90_0000, 1, 2), (0xa0_0000, 2, 1)],
                      [(0x90_0000, 2, 1), (0xa0_0000, 1, 2)]] {
            assert!(!state.configure_ept02_table_pools(pools));
            assert_eq!(state.ept02_table_pool, 0x70_0000);
            assert_eq!(state.ept02_table_pool_used, 9);
            assert_eq!(state.ept02_cached_table_pool, 0x80_0000);
            assert_eq!(state.ept02_cached_table_pool_used, 6);
        }
    }

    #[test]
    fn vmcs12_backing_state_fits_in_each_vmcs_region() {
        assert_ne!(VMCS12_BACKING_MAGIC, 0);
        assert!(VMCS12_BACKING_MAGIC_OFFSET >= 8);
        assert_eq!(VMCS12_BACKING_STATE_OFFSET & 7, 0);
        assert_eq!(
            VMCS12_BACKING_QWORD_COUNT * core::mem::size_of::<u64>(),
            core::mem::size_of::<NestedVmcs12State>()
        );
        assert!(
            VMCS12_BACKING_STATE_OFFSET + core::mem::size_of::<NestedVmcs12State>()
                <= VMX_REGION_SIZE as usize
        );
    }

    #[test]
    fn capabilities_normalize_vmx_basic_and_keep_vmx_internal() {
        let capabilities = NestedVmxCapabilities::vmxon_vmxoff(HOST_VMX_BASIC);

        assert_eq!(capabilities.revision_id, 0x1234);
        assert_eq!(capabilities.vmx_basic as u32, 0x1234);
        assert_eq!((capabilities.vmx_basic >> 32) & 0x1fff, VMX_REGION_SIZE);
        assert_eq!(
            (capabilities.vmx_basic >> 50) & 0xf,
            VMX_MEMORY_TYPE_WRITE_BACK
        );
        assert_eq!(capabilities.vmx_basic & VMX_BASIC_TRUE_CONTROLS, 0);
        assert_eq!(
            capabilities.feature_control,
            IA32_FEATURE_CONTROL_LOCKED | IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX
        );
        assert_eq!(capabilities.vmx_pinbased_ctls, 0);
        assert_eq!(capabilities.vmx_procbased_ctls, 0);
        assert_eq!(capabilities.vmx_exit_ctls, 0);
        assert_eq!(capabilities.vmx_entry_ctls, 0);
        assert_eq!(capabilities.vmx_cr0_fixed0, 0);
        assert_eq!(capabilities.vmx_cr0_fixed1, 0);
        assert_eq!(capabilities.vmx_cr4_fixed0, 0);
        assert_eq!(capabilities.vmx_cr4_fixed1, 0);
        assert_eq!(capabilities.vmx_vmcs_enum, 0);
        assert_eq!(capabilities.vmx_procbased_ctls2, 0);
        assert_eq!(capabilities.vmx_ept_vpid_cap, 0);
        assert!(!capabilities.expose_vmx);
    }

    #[test]
    fn vmware_vhv_primary_intercepts_are_available() {
        let capabilities = NestedVmxCapabilities::from_host(host_vmx_capabilities());
        let required = 0xbff9_fffe;
        assert_eq!(
            (capabilities.vmx_true_procbased_ctls >> 32) as u32 & required,
            required
        );
    }

    #[test]
    fn vmware_vhv_secondary_intercepts_are_available() {
        let capabilities = NestedVmxCapabilities::from_host(host_vmx_capabilities());
        let required = 0x6e;
        assert_eq!(
            (capabilities.vmx_procbased_ctls2 >> 32) as u32 & required,
            required
        );
    }

    #[test]
    fn host_derived_capabilities_expose_only_the_current_nested_contract() {
        let host = host_vmx_capabilities();
        let capabilities = NestedVmxCapabilities::from_host(host);
        assert_eq!(capabilities.host_procbased_ctls2, host.procbased_ctls2);
        assert_eq!(capabilities.host_misc, host.misc);
        let pinbased_bits = nested::VMX_LEGACY_PINBASED_DEFAULT1
            | nested::VMX_PIN_EXTERNAL_INTERRUPT_EXITING
            | nested::VMX_PIN_NMI_EXITING
            | nested::VMX_PIN_VIRTUAL_NMIS;
        let pinbased_control =
            control_capabilities(nested::VMX_LEGACY_PINBASED_DEFAULT1, pinbased_bits);
        let true_pinbased_control = control_capabilities(0, pinbased_bits);
        let legacy_entry_bits = nested::VMX_LEGACY_ENTRY_DEFAULT1
            | nested::VM_ENTRY_IA32E_MODE_GUEST
            | nested::VM_ENTRY_LOAD_IA32_PAT
            | nested::VM_ENTRY_LOAD_IA32_EFER;
        let ia32e_control = control_capabilities(0, legacy_entry_bits);
        let legacy_entry_control =
            control_capabilities(nested::VMX_LEGACY_ENTRY_DEFAULT1, legacy_entry_bits);
        let legacy_exit_bits = nested::VMX_LEGACY_EXIT_DEFAULT1
            | nested::VM_EXIT_HOST_ADDRESS_SPACE_SIZE
            | nested::VM_EXIT_ACK_INTERRUPT_ON_EXIT
            | nested::VM_EXIT_LOAD_IA32_PAT
            | nested::VM_EXIT_SAVE_IA32_EFER
            | nested::VM_EXIT_LOAD_IA32_EFER;
        let true_exit_control =
            control_capabilities(nested::VM_EXIT_HOST_ADDRESS_SPACE_SIZE, legacy_exit_bits);
        let legacy_exit_control = control_capabilities(
            nested::VMX_LEGACY_EXIT_DEFAULT1 | nested::VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
            legacy_exit_bits,
        );
        let primary_may_be_one = nested::VMX_LEGACY_PROCBASED_DEFAULT1
            | nested::VMX_PRIMARY_KVM_EXITING_CONTROLS
            | nested::VMX_PRIMARY_RDTSC_EXITING
            | nested::VMX_PRIMARY_TPR_SHADOW
            | nested::VMX_PRIMARY_UNCONDITIONAL_IO_EXITING
            | nested::VMX_PRIMARY_USE_IO_BITMAPS
            | nested::VMX_PRIMARY_MONITOR_TRAP_FLAG
            | nested::VMX_PRIMARY_USE_MSR_BITMAPS
            | nested::VMX_PRIMARY_PAUSE_EXITING
            | nested::VMX_PRIMARY_ACTIVATE_SECONDARY_CONTROLS;
        let primary_control =
            control_capabilities(nested::VMX_LEGACY_PROCBASED_DEFAULT1, primary_may_be_one);
        let true_primary_control = control_capabilities(0, primary_may_be_one);
        let secondary_control = control_capabilities(
            0,
            nested::VMX_SECONDARY_ENABLE_EPT
                | nested::VMX_SECONDARY_DESCRIPTOR_TABLE_EXITING
                | nested::VMX_SECONDARY_ENABLE_RDTSCP
                | nested::VMX_SECONDARY_ENABLE_VPID
                | nested::VMX_SECONDARY_WBINVD_EXITING
                | nested::VMX_SECONDARY_UNRESTRICTED_GUEST
                | nested::VMX_SECONDARY_RDRAND_EXITING
                | nested::VMX_SECONDARY_ENABLE_INVPCID
                | nested::VMX_SECONDARY_ENABLE_VM_FUNCTIONS
                | nested::VMX_SECONDARY_VMCS_SHADOWING
                | nested::VMX_SECONDARY_ENABLE_XSAVES
                | nested::VMX_SECONDARY_MODE_BASED_EXECUTE,
        );

        assert_eq!(capabilities.vmx_pinbased_ctls, pinbased_control);
        assert_eq!(capabilities.vmx_procbased_ctls, primary_control);
        assert_eq!(capabilities.vmx_exit_ctls, legacy_exit_control);
        assert_eq!(capabilities.vmx_entry_ctls, legacy_entry_control);
        assert_eq!(
            capabilities.vmx_misc,
            (host.misc & (0x1ff | (1 << 29) | (1 << 30)))
                | (nested::VMX_CR3_TARGET_COUNT << 16)
        );
        assert_eq!(capabilities.vmx_cr0_fixed0, host.cr0_fixed0);
        assert_eq!(capabilities.vmx_cr0_fixed1, host.cr0_fixed1);
        assert_eq!(capabilities.vmx_cr4_fixed0, host.cr4_fixed0);
        assert_eq!(capabilities.vmx_cr4_fixed1, host.cr4_fixed1);
        assert_eq!(
            capabilities.vmx_vmcs_enum,
            vmcs12::VMCS12_MAX_ENUM_INDEX << 1
        );
        assert_eq!(capabilities.vmx_procbased_ctls2, secondary_control);
        assert_eq!((capabilities.vmx_procbased_ctls2 >> 32) as u32 & 0x26, 0x26);
        assert_eq!(
            capabilities.vmx_ept_vpid_cap,
            nested::VMX_EPT_CAPABILITIES | nested::VMX_SOFTWARE_INVALIDATION_CAPABILITIES
        );
        assert_eq!(
            capabilities.vmx_ept_vpid_cap & 0xF01_0610_4040,
            0xF01_0610_4040
        );
        assert_eq!(nested::VMX_EPT_CAPABILITIES, 0x61_4041);
        assert_ne!(
            capabilities.vmx_ept_vpid_cap & nested::VMX_EPT_INVEPT_ALL_CONTEXTS,
            0
        );
        assert_eq!(
            capabilities.vmx_ept_vpid_cap & nested::VMX_SOFTWARE_INVALIDATION_CAPABILITIES,
            nested::VMX_SOFTWARE_INVALIDATION_CAPABILITIES
        );
        assert_eq!(capabilities.vmx_true_pinbased_ctls, true_pinbased_control);
        assert_eq!(capabilities.vmx_true_procbased_ctls, true_primary_control);
        assert_eq!(
            (capabilities.vmx_true_procbased_ctls >> 32) as u32 & 0xE7F9_FFFE,
            0xE7F9_FFFE
        );
        assert_eq!(capabilities.vmx_true_exit_ctls, true_exit_control);
        assert_eq!(
            (capabilities.vmx_true_exit_ctls >> 32) as u32 & 0x003B_EFFF,
            0x003B_EFFF
        );
        assert_eq!(capabilities.vmx_true_entry_ctls, ia32e_control);
        assert_eq!(
            (capabilities.vmx_true_entry_ctls >> 32) as u32 & 0x0000_D3FF,
            0x0000_D3FF
        );
        assert!(!capabilities.expose_vmx);
    }

    #[test]
    fn host_derived_controls_never_invent_unsupported_one_settings() {
        let mut host = host_vmx_capabilities();
        let pin_supported = u32::MAX
            & !nested::VMX_PIN_EXTERNAL_INTERRUPT_EXITING
            & !nested::VMX_PIN_NMI_EXITING
            & !nested::VMX_PIN_VIRTUAL_NMIS;
        let exit_supported = u32::MAX
            & !nested::VM_EXIT_HOST_ADDRESS_SPACE_SIZE
            & !nested::VM_EXIT_ACK_INTERRUPT_ON_EXIT
            & !nested::VM_EXIT_LOAD_IA32_PAT
            & !nested::VM_EXIT_SAVE_IA32_EFER
            & !nested::VM_EXIT_LOAD_IA32_EFER;
        let entry_supported = u32::MAX
            & !nested::VM_ENTRY_IA32E_MODE_GUEST
            & !nested::VM_ENTRY_LOAD_IA32_PAT
            & !nested::VM_ENTRY_LOAD_IA32_EFER;
        host.exit_ctls = control_capabilities(0, exit_supported);
        host.entry_ctls = control_capabilities(0, entry_supported);
        host.true_exit_ctls = control_capabilities(0, exit_supported);
        host.true_entry_ctls = control_capabilities(0, entry_supported);
        host.pinbased_ctls = control_capabilities(0, pin_supported);
        host.true_pinbased_ctls = host.pinbased_ctls;
        host.procbased_ctls = control_capabilities(
            0,
            u32::MAX
                & !nested::VMX_PRIMARY_KVM_EXITING_CONTROLS
                & !nested::VMX_PRIMARY_UNCONDITIONAL_IO_EXITING
                & !nested::VMX_PRIMARY_RDTSC_EXITING
                & !nested::VMX_PRIMARY_TPR_SHADOW
                & !nested::VMX_PRIMARY_USE_IO_BITMAPS
                & !nested::VMX_PRIMARY_MONITOR_TRAP_FLAG
                & !nested::VMX_PRIMARY_USE_MSR_BITMAPS
                & !nested::VMX_PRIMARY_PAUSE_EXITING,
        );
        host.true_procbased_ctls = host.procbased_ctls;
        host.procbased_ctls2 = control_capabilities(
            0,
            u32::MAX
                & !nested::VMX_SECONDARY_DESCRIPTOR_TABLE_EXITING
                & !nested::VMX_SECONDARY_WBINVD_EXITING,
        );

        let capabilities = NestedVmxCapabilities::from_host(host);
        assert_eq!(
            (capabilities.vmx_procbased_ctls2 >> 32) as u32
                & (nested::VMX_SECONDARY_DESCRIPTOR_TABLE_EXITING
                    | nested::VMX_SECONDARY_WBINVD_EXITING),
            0
        );

        let nested_pin_controls = nested::VMX_PIN_EXTERNAL_INTERRUPT_EXITING
            | nested::VMX_PIN_NMI_EXITING
            | nested::VMX_PIN_VIRTUAL_NMIS;
        assert_eq!(
            capabilities.vmx_pinbased_ctls >> 32 & u64::from(nested_pin_controls),
            0
        );
        assert_eq!(
            capabilities.vmx_true_pinbased_ctls >> 32 & u64::from(nested_pin_controls),
            0
        );
        assert_eq!(
            capabilities.vmx_exit_ctls >> 32
                & u64::from(
                    nested::VM_EXIT_HOST_ADDRESS_SPACE_SIZE
                        | nested::VM_EXIT_ACK_INTERRUPT_ON_EXIT
                        | nested::VM_EXIT_LOAD_IA32_PAT
                        | nested::VM_EXIT_SAVE_IA32_EFER
                        | nested::VM_EXIT_LOAD_IA32_EFER,
                ),
            0
        );
        assert_eq!(
            capabilities.vmx_entry_ctls >> 32
                & u64::from(
                    nested::VM_ENTRY_IA32E_MODE_GUEST
                        | nested::VM_ENTRY_LOAD_IA32_PAT
                        | nested::VM_ENTRY_LOAD_IA32_EFER,
                ),
            0
        );
        assert_eq!(
            capabilities.vmx_true_exit_ctls >> 32
                & u64::from(
                    nested::VM_EXIT_HOST_ADDRESS_SPACE_SIZE
                        | nested::VM_EXIT_ACK_INTERRUPT_ON_EXIT
                        | nested::VM_EXIT_LOAD_IA32_PAT
                        | nested::VM_EXIT_SAVE_IA32_EFER
                        | nested::VM_EXIT_LOAD_IA32_EFER,
                ),
            0
        );
        assert_eq!(
            capabilities.vmx_true_entry_ctls >> 32
                & u64::from(
                    nested::VM_ENTRY_IA32E_MODE_GUEST
                        | nested::VM_ENTRY_LOAD_IA32_PAT
                        | nested::VM_ENTRY_LOAD_IA32_EFER,
                ),
            0
        );
        assert_eq!(
            capabilities.vmx_procbased_ctls >> 32
                & u64::from(
                    nested::VMX_PRIMARY_UNCONDITIONAL_IO_EXITING
                        | nested::VMX_PRIMARY_KVM_EXITING_CONTROLS
                        | nested::VMX_PRIMARY_RDTSC_EXITING
                        | nested::VMX_PRIMARY_TPR_SHADOW
                        | nested::VMX_PRIMARY_USE_IO_BITMAPS
                        | nested::VMX_PRIMARY_MONITOR_TRAP_FLAG
                        | nested::VMX_PRIMARY_USE_MSR_BITMAPS
                        | nested::VMX_PRIMARY_PAUSE_EXITING
                ),
            0
        );
        assert_eq!(
            capabilities.vmx_true_procbased_ctls >> 32
                & u64::from(
                    nested::VMX_PRIMARY_UNCONDITIONAL_IO_EXITING
                        | nested::VMX_PRIMARY_KVM_EXITING_CONTROLS
                        | nested::VMX_PRIMARY_RDTSC_EXITING
                        | nested::VMX_PRIMARY_TPR_SHADOW
                        | nested::VMX_PRIMARY_USE_IO_BITMAPS
                        | nested::VMX_PRIMARY_MONITOR_TRAP_FLAG
                        | nested::VMX_PRIMARY_USE_MSR_BITMAPS
                        | nested::VMX_PRIMARY_PAUSE_EXITING
                ),
            0
        );
    }

    #[test]
    fn emulated_true_controls_do_not_inherit_host_fixed_one_settings() {
        let mut host = host_vmx_capabilities();
        host.true_pinbased_ctls = control_capabilities(u32::MAX, u32::MAX);
        host.true_procbased_ctls = control_capabilities(u32::MAX, u32::MAX);
        host.true_exit_ctls = control_capabilities(u32::MAX, u32::MAX);
        host.true_entry_ctls = control_capabilities(u32::MAX, u32::MAX);

        let capabilities = NestedVmxCapabilities::from_host(host);

        assert_eq!(capabilities.vmx_true_pinbased_ctls as u32, 0);
        assert_eq!(capabilities.vmx_true_procbased_ctls as u32, 0);
        assert_eq!(
            capabilities.vmx_true_exit_ctls as u32,
            nested::VM_EXIT_HOST_ADDRESS_SPACE_SIZE
        );
        assert_eq!(capabilities.vmx_true_entry_ctls as u32, 0);
    }

    #[test]
    fn nested_ept_is_hidden_when_the_host_contract_is_incomplete() {
        let mut host = host_vmx_capabilities();
        host.ept_vpid_cap &= !nested::VMX_EPT_MEMORY_TYPE_WB;

        let capabilities = NestedVmxCapabilities::from_host(host);

        assert_eq!(
            capabilities.vmx_procbased_ctls >> 32
                & u64::from(nested::VMX_PRIMARY_ACTIVATE_SECONDARY_CONTROLS),
            0
        );
        assert_eq!(capabilities.vmx_procbased_ctls2, 0);
        assert_eq!(capabilities.vmx_ept_vpid_cap, 0);
        assert_eq!(
            capabilities.vmx_true_procbased_ctls >> 32
                & u64::from(nested::VMX_PRIMARY_ACTIVATE_SECONDARY_CONTROLS),
            0
        );
    }

    #[test]
    fn software_invalidations_do_not_require_host_invept_or_invvpid() {
        let mut host = host_vmx_capabilities();
        host.ept_vpid_cap = nested::VMX_EPT_CAPABILITIES;
        host.procbased_ctls2 = control_capabilities(0, nested::VMX_SECONDARY_ENABLE_EPT);

        let capabilities = NestedVmxCapabilities::from_host(host);

        assert_eq!(
            capabilities.vmx_procbased_ctls2,
            control_capabilities(
                0,
                nested::VMX_SECONDARY_ENABLE_EPT | nested::VMX_SECONDARY_ENABLE_VPID
            )
        );
        assert_eq!(
            capabilities.vmx_ept_vpid_cap,
            nested::VMX_EPT_CAPABILITIES | nested::VMX_SOFTWARE_INVALIDATION_CAPABILITIES
        );
    }

    #[test]
    fn true_control_msrs_follow_vmx_basic_availability() {
        let mut host = host_vmx_capabilities();
        host.vmx_basic &= !VMX_BASIC_TRUE_CONTROLS;
        let capabilities = NestedVmxCapabilities::from_host(host);

        assert_eq!(capabilities.vmx_basic & VMX_BASIC_TRUE_CONTROLS, 0);
        assert_eq!(capabilities.vmx_true_pinbased_ctls, 0);
        assert_eq!(capabilities.vmx_true_procbased_ctls, 0);
        assert_eq!(capabilities.vmx_true_exit_ctls, 0);
        assert_eq!(capabilities.vmx_true_entry_ctls, 0);
        assert_eq!(
            capabilities.vmx_msr(nested::IA32_VMX_TRUE_PINBASED_CTLS_MSR),
            None
        );
        assert_eq!(
            capabilities.vmx_msr(nested::IA32_VMX_TRUE_ENTRY_CTLS_MSR),
            None
        );
    }

    #[test]
    fn virtual_vmx_msr_map_covers_the_supported_capability_range() {
        let capabilities = NestedVmxCapabilities::from_host(host_vmx_capabilities());
        let expected = [
            (nested::IA32_VMX_BASIC_MSR, capabilities.vmx_basic),
            (
                nested::IA32_VMX_PINBASED_CTLS_MSR,
                capabilities.vmx_pinbased_ctls,
            ),
            (
                nested::IA32_VMX_PROCBASED_CTLS_MSR,
                capabilities.vmx_procbased_ctls,
            ),
            (nested::IA32_VMX_EXIT_CTLS_MSR, capabilities.vmx_exit_ctls),
            (nested::IA32_VMX_ENTRY_CTLS_MSR, capabilities.vmx_entry_ctls),
            (nested::IA32_VMX_MISC_MSR, capabilities.vmx_misc),
            (nested::IA32_VMX_CR0_FIXED0_MSR, capabilities.vmx_cr0_fixed0),
            (nested::IA32_VMX_CR0_FIXED1_MSR, capabilities.vmx_cr0_fixed1),
            (nested::IA32_VMX_CR4_FIXED0_MSR, capabilities.vmx_cr4_fixed0),
            (nested::IA32_VMX_CR4_FIXED1_MSR, capabilities.vmx_cr4_fixed1),
            (nested::IA32_VMX_VMCS_ENUM_MSR, capabilities.vmx_vmcs_enum),
            (
                nested::IA32_VMX_PROCBASED_CTLS2_MSR,
                capabilities.vmx_procbased_ctls2,
            ),
            (
                nested::IA32_VMX_EPT_VPID_CAP_MSR,
                capabilities.vmx_ept_vpid_cap,
            ),
            (
                nested::IA32_VMX_TRUE_PINBASED_CTLS_MSR,
                capabilities.vmx_true_pinbased_ctls,
            ),
            (
                nested::IA32_VMX_TRUE_PROCBASED_CTLS_MSR,
                capabilities.vmx_true_procbased_ctls,
            ),
            (
                nested::IA32_VMX_TRUE_EXIT_CTLS_MSR,
                capabilities.vmx_true_exit_ctls,
            ),
            (
                nested::IA32_VMX_TRUE_ENTRY_CTLS_MSR,
                capabilities.vmx_true_entry_ctls,
            ),
        ];

        for (msr, value) in expected {
            assert_eq!(capabilities.vmx_msr(msr), Some(value));
        }
        assert_eq!(capabilities.vmx_msr(nested::IA32_VMX_VMFUNC_MSR), Some(1));
    }

    #[test]
    fn vmcs_enum_is_bounded_by_host_and_vmcs12_field_indices() {
        let max_vmcs12_index = vmcs12::VMCS12_EXTENDED_FIELDS
            .iter()
            .map(|field| (field.encoding >> 1) & 0x1ff)
            .max()
            .unwrap();
        assert_eq!(max_vmcs12_index, vmcs12::VMCS12_MAX_ENUM_INDEX);

        let mut host = host_vmx_capabilities();
        host.vmcs_enum = 9 << 1;
        let capabilities = NestedVmxCapabilities::from_host(host);
        assert_eq!(capabilities.vmx_vmcs_enum, 9 << 1);
    }

    #[test]
    fn vmfunc_requires_host_instruction_support_and_virtual_ept() {
        let mut host = host_vmx_capabilities();
        assert_eq!(
            NestedVmxCapabilities::from_host(host).vmx_msr(0x491),
            Some(1)
        );
        host.procbased_ctls2 &= !(u64::from(nested::VMX_SECONDARY_ENABLE_VM_FUNCTIONS) << 32);
        assert_eq!(NestedVmxCapabilities::from_host(host).vmx_msr(0x491), None);
        host = host_vmx_capabilities();
        host.ept_vpid_cap = 0;
        let capabilities = NestedVmxCapabilities::from_host(host);
        assert_eq!(capabilities.vmx_msr(0x491), None);
        assert_eq!(capabilities.vmx_procbased_ctls2, 0);
        assert_eq!(nested::VMFUNC_EXIT_REASON, 59);
    }

    #[test]
    fn cpuid_contract_uses_architectural_bits_and_hypervisor_namespace() {
        assert_eq!(CPUID_VMX_BIT, 1 << 5);
        assert_eq!(CPUID_OSXSAVE_BIT, 1 << 27);
        assert_eq!(CPUID_HYPERVISOR_PRESENT_BIT, 1 << 31);
        assert!((0x4000_0000..=0x4fff_ffff).contains(&MATRIXHV_STATUS_LEAF));
        assert_eq!(MATRIXHV_STATUS_SIGNATURE_EAX, 0x4d48_5631);
        assert_eq!(MATRIXHV_STATUS_SIGNATURE_EBX.to_le_bytes(), *b"MATR");
        assert_eq!(MATRIXHV_STATUS_SIGNATURE_ECX.to_le_bytes(), *b"IXHV");
        assert_eq!(MATRIXHV_STATUS_PROTOCOL, 7);
        assert_eq!(HYPERVISOR_LEAF_START, 0x4000_0000);
        assert_eq!(HYPERV_FEATURES_LEAF, 0x4000_0003);
        assert_eq!(HYPERVISOR_LEAF_END, 0x4fff_ffff);
    }

    #[test]
    fn per_cpu_nested_state_starts_independent_and_inactive() {
        let bsp = nested_state(0);
        let ap = nested_state(0x10_0000);

        assert_ne!(bsp.vmxon_operand, ap.vmxon_operand);
        assert_ne!(bsp.vmxon_region, ap.vmxon_region);
        assert_ne!(bsp.vmcs12.operand, ap.vmcs12.operand);
        assert_ne!(bsp.vmcs12.region, ap.vmcs12.region);
        assert_eq!(bsp.current_vmcs, INVALID_VMCS_POINTER);
        assert_eq!(ap.current_vmcs, INVALID_VMCS_POINTER);
        assert_eq!(bsp.expose_vmx, 0);
        assert_eq!(ap.expose_vmx, 0);
        assert_eq!(bsp.active, 0);
        assert_eq!(ap.active, 0);
        assert_eq!(bsp.vmxon_count, 0);
        assert_eq!(bsp.vmxoff_count, 0);
        assert_eq!(bsp.failure_count, 0);
        assert_eq!(bsp.probe_complete, 0);
        assert_eq!(bsp.vmcs01_region, VMCS01_REGION);
        assert_eq!(bsp.vmcs02_region, VMCS02_REGION);
        assert_eq!(bsp.l2_active, 0);
        assert_eq!(bsp.l2_entry_count, 0);
        assert_eq!(bsp.l2_exit_count, 0);
        assert_eq!(bsp.l2_last_exit_rsp, 0);
        assert_eq!(bsp.l1_reflection_count, 0);
        assert_eq!(bsp.l2_resume_count, 0);
        assert_eq!(bsp.l2_resume_exit_count, 0);
        assert_eq!(bsp.ept12_pointer, 0);
        assert_eq!(bsp.ept02_pointer, 0);
        assert_eq!(bsp.ept_source_gpa, 0);
        assert_eq!(bsp.ept_target_gpa, 0);
        assert_eq!(bsp.ept_composed_hpa, 0);
        assert_eq!(bsp.ept_permissions, 0);
        assert_eq!(bsp.ept_composition_count, 0);
        assert_eq!(bsp.ept_probe_count, 0);
        assert_eq!(bsp.ept_observed_value, 0);
        assert_eq!(bsp.ept02_alternate_pointer, 0);
        assert_eq!(bsp.ept_second_target_gpa, 0);
        assert_eq!(bsp.ept12_source_leaf, 0);
        assert_eq!(bsp.ept_alternate_composed_hpa, 0);
        assert_eq!(bsp.ept_alternate_permissions, 0);
        assert_eq!(bsp.invept_count, 0);
        assert_eq!(bsp.invept_software_count, 0);
        assert_eq!(bsp.invvpid_count, 0);
        assert_eq!(bsp.invvpid_software_count, 0);
        assert_eq!(bsp.ept_observed_value_after_invept, 0);
        assert_eq!(bsp.ept02_initial_pointer, 0);
        assert_eq!(bsp.ept12_source_leaf_attributes, 0);
        assert_eq!(bsp.ept_observed_value_before_invept, 0);
        assert_eq!(bsp.control_merge_count, 0);
        assert_eq!(bsp.guest_state_sync_count, 0);
        assert_eq!(bsp.l1_host_restore_count, 0);
        assert_eq!(bsp.last_synced_guest_cr0, 0);
        assert_eq!(bsp.last_synced_guest_cr3, 0);
        assert_eq!(bsp.last_synced_guest_cr4, 0);
        assert_eq!(bsp.last_restored_host_cr0, 0);
        assert_eq!(bsp.last_restored_host_cr3, 0);
        assert_eq!(bsp.last_restored_host_cr4, 0);
        assert_eq!(bsp.last_synced_guest_sysenter_eip, 0);
        assert_eq!(bsp.last_restored_host_sysenter_eip, 0);
        assert_eq!(bsp.inherited_l1_pat, 0);
        assert_eq!(bsp.inherited_l1_efer, 0);
        assert_eq!(bsp.inherited_l1_tsc_offset, 0);
        assert_eq!(bsp.l2_saved_pat, 0);
        assert_eq!(bsp.l2_saved_efer, 0);
        assert_eq!(bsp.last_merged_secondary_controls, 0);
        assert_eq!(bsp.last_synced_guest_gs_base, 0);
        assert_eq!(bsp.last_captured_guest_gs_base, 0);
        assert_eq!(bsp.last_restored_host_gs_base, 0);
        assert_eq!(bsp.last_restored_host_cs_ar, 0);
    }

    #[test]
    fn nested_state_records_ept_composition() {
        let mut state = nested_state(0);

        state.configure_ept(NestedEptConfiguration {
            ept12_pointer: 0x60_001e,
            ept02_pointer: 0x70_001e,
            source_gpa: 0x80_0000,
            target_gpa: 0x90_0000,
            composed_hpa: 0x90_0000,
            permissions: 0x5,
            alternate_ept02_pointer: 0x71_001e,
            second_target_gpa: 0xa0_0000,
            source_leaf: 0xb0_0128,
            source_leaf_attributes: 0x7,
            alternate_composed_hpa: 0xa0_0000,
            alternate_permissions: 0x3,
        });

        assert_eq!(state.ept12_pointer, 0x60_001e);
        assert_eq!(state.ept02_pointer, 0x70_001e);
        assert_eq!(state.ept_source_gpa, 0x80_0000);
        assert_eq!(state.ept_target_gpa, 0x90_0000);
        assert_eq!(state.ept_composed_hpa, 0x90_0000);
        assert_eq!(state.ept_permissions, 0x5);
        assert_eq!(state.ept_composition_count, 2);
        assert_eq!(state.ept02_initial_pointer, 0x70_001e);
        assert_eq!(state.ept02_alternate_pointer, 0x71_001e);
        assert_eq!(state.ept_second_target_gpa, 0xa0_0000);
        assert_eq!(state.ept12_source_leaf, 0xb0_0128);
        assert_eq!(state.ept12_source_leaf_attributes, 0x7);
        assert_eq!(state.ept_alternate_composed_hpa, 0xa0_0000);
        assert_eq!(state.ept_alternate_permissions, 0x3);
    }

    #[test]
    fn vmcs12_state_starts_uninitialized_with_zero_observability() {
        let vmcs12 = vmcs12(0);

        assert_eq!(vmcs12.operand, VMCS12_OPERAND);
        assert_eq!(vmcs12.region, VMCS12_REGION);
        assert_eq!(vmcs12.vmptrst_destination, VMPTRST_DESTINATION);
        assert_eq!(vmcs12.last_stored_pointer, 0);
        assert_eq!(vmcs12.revision_id, 0x1234);
        assert_eq!(vmcs12.launch_state, VMCS12_LAUNCH_STATE_UNINITIALIZED);
        assert_ne!(VMCS12_LAUNCH_STATE_CLEAR, VMCS12_LAUNCH_STATE_UNINITIALIZED);
        assert_eq!(vmcs12.guest_rip, 0);
        assert_eq!(vmcs12.vmclear_count, 0);
        assert_eq!(vmcs12.vmptrld_count, 0);
        assert_eq!(vmcs12.vmptrst_count, 0);
        assert_eq!(vmcs12.vmwrite_count, 0);
        assert_eq!(vmcs12.vmread_count, 0);
        assert_eq!(vmcs12.probe_complete, 0);
        assert_eq!(vmcs12.vmlaunch_count, 0);
        assert_eq!(vmcs12.vmresume_count, 0);
        assert_eq!(vmcs12.entry_rejection_count, 0);
        assert_eq!(vmcs12.guest_rsp, 0);
        assert_eq!(vmcs12.guest_rflags, 0);
        assert_eq!(vmcs12.host_rsp, 0);
        assert_eq!(vmcs12.host_rip, 0);
        assert_eq!(vmcs12.exit_reason, 0);
        assert_eq!(vmcs12.exit_instruction_len, 0);
        assert_eq!(vmcs12.exit_qualification, 0);
        assert_eq!(vmcs12.control_validation_count, 0);
    }

    #[test]
    fn nested_exit_reasons_match_intel_basic_exit_reasons() {
        assert_eq!(nested::VMCLEAR_EXIT_REASON, 19);
        assert_eq!(nested::VMLAUNCH_EXIT_REASON, 20);
        assert_eq!(nested::VMPTRLD_EXIT_REASON, 21);
        assert_eq!(nested::VMPTRST_EXIT_REASON, 22);
        assert_eq!(nested::VMREAD_EXIT_REASON, 23);
        assert_eq!(nested::VMRESUME_EXIT_REASON, 24);
        assert_eq!(nested::VMWRITE_EXIT_REASON, 25);
        assert_eq!(nested::VMXOFF_EXIT_REASON, 26);
        assert_eq!(nested::VMXON_EXIT_REASON, 27);
        assert_eq!(nested::INVEPT_EXIT_REASON, 50);
        assert_eq!(nested::INVVPID_EXIT_REASON, 53);
    }

    #[test]
    fn vm_instruction_errors_and_status_flags_match_architecture() {
        assert_eq!(VMCLEAR_INVALID_PHYSICAL_ADDRESS_ERROR, 2);
        assert_eq!(VMCLEAR_VMXON_POINTER_ERROR, 3);
        assert_eq!(VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR, 7);
        assert_eq!(VM_ENTRY_INVALID_HOST_STATE_FIELD_ERROR, 8);
        assert_eq!(VM_ENTRY_BLOCKED_BY_MOV_SS_ERROR, 26);
        assert_eq!(INVALID_OPERAND_TO_INVEPT_INVVPID_ERROR, 28);
        assert_eq!(VMXON_IN_VMX_ROOT_ERROR, 15);
        assert_eq!(VMLAUNCH_NON_CLEAR_VMCS_ERROR, 4);
        assert_eq!(VMRESUME_NON_LAUNCHED_VMCS_ERROR, 5);
        assert_eq!(VMPTRLD_INVALID_PHYSICAL_ADDRESS_ERROR, 9);
        assert_eq!(VMPTRLD_VMXON_POINTER_ERROR, 10);
        assert_eq!(VMPTRLD_INCORRECT_REVISION_ERROR, 11);
        assert_eq!(VMCS_UNSUPPORTED_COMPONENT_ERROR, 12);
        assert_eq!(VMWRITE_READ_ONLY_COMPONENT_ERROR, 13);
        assert_eq!(VMX_STATUS_FLAGS, 0x8d5);
        assert_eq!(VMX_STATUS_FLAGS_CLEAR_MASK, -2262);
        assert_eq!(VMFAIL_INVALID_STATUS, 1);
        assert_eq!(VMFAIL_VALID_STATUS, 1 << 6);
    }

    #[test]
    fn supported_vmcs12_fields_match_intel_encodings() {
        assert_eq!(VMCS_FIELD_VM_INSTRUCTION_ERROR, 0x4400);
        assert_eq!(VMCS_FIELD_VM_EXIT_REASON, 0x4402);
        assert_eq!(VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN, 0x440c);
        assert_eq!(VMCS_FIELD_VM_EXIT_INSTRUCTION_INFO, 0x440e);
        assert_eq!(VMCS_FIELD_EXIT_QUALIFICATION, 0x6400);
        assert_eq!(vmcs12::VMCS_FIELD_GUEST_PHYSICAL_ADDRESS, 0x2400);
        assert_eq!(vmcs12::VMCS_FIELD_GUEST_LINEAR_ADDRESS, 0x640a);
        assert_eq!(VMCS_FIELD_GUEST_RSP, 0x681c);
        assert_eq!(VMCS_FIELD_GUEST_RIP, 0x681e);
        assert_eq!(VMCS_FIELD_GUEST_RFLAGS, 0x6820);
        assert_eq!(vmcs12::VMCS_FIELD_GUEST_PDPTR0, 0x280a);
        assert_eq!(vmcs12::VMCS_FIELD_GUEST_PDPTR1, 0x280c);
        assert_eq!(vmcs12::VMCS_FIELD_GUEST_PDPTR2, 0x280e);
        assert_eq!(vmcs12::VMCS_FIELD_GUEST_PDPTR3, 0x2810);
        assert_eq!(VMCS_FIELD_HOST_RSP, 0x6c14);
        assert_eq!(VMCS_FIELD_HOST_RIP, 0x6c16);
        assert_eq!(VMCS12_LAUNCH_STATE_CLEAR, 0);
        assert_eq!(VMCS12_LAUNCH_STATE_LAUNCHED, 1);
    }

    #[test]
    fn resident_vmcs12_lookup_matches_the_canonical_field_table() {
        let source = include_str!("../src/vmx/asm/nested.S");
        let table = source
            .split(".Lresident_vmcs12_field_index_table:")
            .nth(1)
            .unwrap()
            .split(".balign 8")
            .next()
            .unwrap();
        let indices: Vec<u8> = table
            .lines()
            .filter_map(|line| line.split(".byte ").nth(1))
            .flat_map(|line| line.trim().split(", "))
            .map(|value| value.parse().unwrap())
            .collect();
        assert_eq!(indices.len(), 1024);
        assert_eq!(
            indices.iter().filter(|index| **index != 255).count(),
            vmcs12::VMCS12_EXTENDED_FIELD_COUNT
        );
        for field in vmcs12::VMCS12_EXTENDED_FIELDS {
            let key = ((field.encoding & 0x6c00) >> 5) | ((field.encoding & 0x3e) >> 1);
            assert_eq!(usize::from(indices[key as usize]), field.index);
        }
    }

    #[test]
    fn extended_vmcs12_fields_are_dense_unique_and_cover_entry_state() {
        assert_eq!(
            vmcs12::VMCS12_EXTENDED_FIELDS.len(),
            vmcs12::VMCS12_EXTENDED_FIELD_COUNT
        );
        for (index, field) in vmcs12::VMCS12_EXTENDED_FIELDS.iter().enumerate() {
            assert_eq!(field.index, index);
            assert_eq!(
                vmcs12::VMCS12_EXTENDED_FIELDS
                    .iter()
                    .filter(|candidate| candidate.encoding == field.encoding)
                    .count(),
                1
            );
        }
        assert_eq!(
            vmcs12::VMCS12_EXTENDED_FIELDS[115].encoding,
            VMCS_FIELD_VM_EXIT_INSTRUCTION_INFO
        );
        assert_eq!(
            vmcs12::VMCS12_EXTENDED_FIELDS[116].encoding,
            vmcs12::VMCS_FIELD_GUEST_LINEAR_ADDRESS
        );
        assert_eq!(
            vmcs12::VMCS12_EXTENDED_FIELDS[117].encoding,
            vmcs12::VMCS_FIELD_EXECUTIVE_VMCS_POINTER
        );
        assert!(
            vmcs12::VMCS12_EXTENDED_FIELDS
                .iter()
                .any(|field| field.encoding == vmcs12::VMCS_FIELD_EXCEPTION_BITMAP)
        );
        assert!(
            vmcs12::VMCS12_EXTENDED_FIELDS
                .iter()
                .any(|field| field.encoding == vmcs12::VMCS_FIELD_GUEST_CR3)
        );
        assert!(
            vmcs12::VMCS12_EXTENDED_FIELDS
                .iter()
                .any(|field| field.encoding == vmcs12::VMCS_FIELD_HOST_CR3)
        );
        assert!(
            vmcs12::VMCS12_EXTENDED_FIELDS
                .iter()
                .any(|field| field.encoding == vmcs12::VMCS_FIELD_GUEST_PHYSICAL_ADDRESS)
        );
        for encoding in [
            vmcs12::VMCS_FIELD_GUEST_PDPTR0,
            vmcs12::VMCS_FIELD_GUEST_PDPTR1,
            vmcs12::VMCS_FIELD_GUEST_PDPTR2,
            vmcs12::VMCS_FIELD_GUEST_PDPTR3,
        ] {
            assert!(
                vmcs12::VMCS12_EXTENDED_FIELDS
                    .iter()
                    .any(|field| field.encoding == encoding)
            );
        }
    }

    #[test]
    fn mbec_requires_host_execution_control_and_exit_information() {
        let mut host = host_vmx_capabilities();
        let mbec = u64::from(nested::VMX_SECONDARY_MODE_BASED_EXECUTE) << 32;
        assert_ne!(
            nested::NestedVmxCapabilities::from_host(host).vmx_procbased_ctls2 & mbec,
            0
        );
        let mut missing = host;
        missing.ept_vpid_cap &= !nested::VMX_EPT_EXECUTE_ONLY;
        assert_ne!(
            nested::NestedVmxCapabilities::from_host(missing).vmx_procbased_ctls2 & mbec,
            0
        );
        missing.ept_vpid_cap &= !nested::VMX_EPT_ADVANCED_EXIT_INFO;
        assert_eq!(
            nested::NestedVmxCapabilities::from_host(missing).vmx_procbased_ctls2 & mbec,
            0
        );
        host.procbased_ctls2 &= !mbec;
        assert_eq!(
            nested::NestedVmxCapabilities::from_host(host).vmx_procbased_ctls2 & mbec,
            0
        );
    }
    use crate::hyperv::EnlightenedVmcs;
    use core::mem::{offset_of, size_of};

    fn field_map() -> Vec<(usize, u16)> {
        let assembly = include_str!("../src/vmx/asm/hyperv.S");
        let start = assembly.find(".Lresident_evmcs_field_map:").unwrap();
        let end = assembly[start..].find(".endm").unwrap() + start;
        assembly[start..end]
            .lines()
            .filter_map(|line| line.trim().strip_prefix(".short "))
            .map(|line| {
                let (offset, flags) = line.split_once(',').unwrap();
                (
                    offset.trim().parse().unwrap(),
                    flags.trim().parse().unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn version_one_layout_and_field_map_match() {
        let fields = field_map();
        assert_eq!(crate::hyperv::EVMCS_VERSION, 1);
        assert_eq!(crate::hyperv::VP_ASSIST_ENLIGHTEN_VM_ENTRY_OFFSET, 40);
        assert_eq!(crate::hyperv::VP_ASSIST_CURRENT_NESTED_VMCS_OFFSET, 48);
        assert_eq!(size_of::<EnlightenedVmcs>(), 1024);
        assert_eq!(fields.len(), vmcs12::VMCS12_EXTENDED_FIELD_COUNT);
        for (offset, flags) in fields.iter().copied() {
            if flags != 0 {
                assert!([2, 4, 8].contains(&(flags & 15)));
                assert!(offset + usize::from(flags & 15) <= 1024);
            }
        }
        assert_eq!(fields[0], (offset_of!(EnlightenedVmcs, vpid), 2));
        assert_eq!(fields[16], (offset_of!(EnlightenedVmcs, ept_root), 8));
        assert_eq!(fields[18], (offset_of!(EnlightenedVmcs, msr_bitmap), 8));
        assert_eq!(
            fields[11],
            (offset_of!(EnlightenedVmcs, entry_controls), 0x84)
        );
        assert_eq!(fields[25], (offset_of!(EnlightenedVmcs, guest_pat), 0x88));
        assert_eq!(fields[29], (offset_of!(EnlightenedVmcs, guest_cr0), 0x88));
        assert_eq!(
            fields[35],
            (offset_of!(EnlightenedVmcs, guest_es_selector), 0x82)
        );
        assert_eq!(
            fields[43],
            (offset_of!(EnlightenedVmcs, host_es_selector), 2)
        );
        assert_eq!(
            fields[50],
            (offset_of!(EnlightenedVmcs, guest_es_base), 0x88)
        );
        assert_eq!(
            fields[65],
            (offset_of!(EnlightenedVmcs, guest_es_limit), 0x84)
        );
        assert_eq!(
            fields[75],
            (offset_of!(EnlightenedVmcs, guest_es_attributes), 0x84)
        );
        assert_eq!(
            fields[83],
            (offset_of!(EnlightenedVmcs, guest_interruptibility), 0x84)
        );
        assert_eq!(
            fields[95],
            (offset_of!(EnlightenedVmcs, xss_exiting_bitmap), 8)
        );
        assert_eq!(fields[102], (0, 0));
        assert_eq!(
            fields[106],
            (offset_of!(EnlightenedVmcs, exit_interruption_info), 0x44)
        );
        assert_eq!(
            fields[110],
            (offset_of!(EnlightenedVmcs, exit_ept_fault_gpa), 0x48)
        );
        assert_eq!(
            fields[111],
            (offset_of!(EnlightenedVmcs, guest_pdpte_0), 0x88)
        );
        assert_eq!(
            fields[116],
            (offset_of!(EnlightenedVmcs, guest_linear_address), 0x48)
        );
        assert_eq!(fields[117], (0, 0));
        assert_eq!(fields[118], (0, 0));
        assert_eq!(fields[119], (0, 0));
    }

    #[repr(align(4096))]
    struct EvmcsTestPage([u8; 4096]);

    fn page_u64(page: &EvmcsTestPage, offset: usize) -> u64 {
        u64::from_le_bytes(page.0[offset..offset + 8].try_into().unwrap())
    }

    fn write_page_u64(page: &mut EvmcsTestPage, offset: usize, value: u64) {
        page.0[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    struct EvmcsTestEpt {
        tables: Vec<Box<EvmcsTestPage>>,
    }

    impl EvmcsTestEpt {
        fn new(state: &mut NestedVmxState) -> Self {
            let tables = vec![Box::new(EvmcsTestPage([0; 4096]))];
            state.ept01_pointer = tables[0].0.as_ptr() as u64;
            Self { tables }
        }

        fn map(&mut self, guest_address: u64, host_address: u64, permissions: u64) {
            self.set_entry(guest_address, 12, host_address | permissions);
        }

        fn set_entry(&mut self, guest_address: u64, leaf_shift: u32, value: u64) {
            let mut table_index = 0;
            for shift in [39, 30, 21, 12] {
                let offset = ((guest_address >> shift) & 511) as usize * 8;
                if shift == leaf_shift {
                    write_page_u64(&mut self.tables[table_index], offset, value);
                    return;
                }
                let entry = page_u64(&self.tables[table_index], offset);
                table_index = if entry == 0 {
                    let next = Box::new(EvmcsTestPage([0; 4096]));
                    let address = next.0.as_ptr() as u64;
                    write_page_u64(&mut self.tables[table_index], offset, address | 7);
                    self.tables.push(next);
                    self.tables.len() - 1
                } else {
                    self.tables
                        .iter()
                        .position(|page| page.0.as_ptr() as u64 == entry & !4095)
                        .unwrap()
                };
            }
            panic!("invalid EPT leaf shift {leaf_shift}");
        }

        fn entry(&self, guest_address: u64, leaf_shift: u32) -> u64 {
            let mut table_index = 0;
            for shift in [39, 30, 21, 12] {
                let offset = ((guest_address >> shift) & 511) as usize * 8;
                let entry = page_u64(&self.tables[table_index], offset);
                if shift == leaf_shift {
                    return entry;
                }
                table_index = self
                    .tables
                    .iter()
                    .position(|page| page.0.as_ptr() as u64 == entry & !4095)
                    .unwrap();
            }
            panic!("invalid EPT leaf shift {leaf_shift}");
        }
    }

    #[test]
    fn vp_assist_rejects_ept_denials_without_writing_root_memory() {
        for (shift, permissions) in [
            (12, 0),
            (12, 1),
            (12, 2),
            (12, 5),
            (39, 1),
            (30, 1),
            (21, 1),
        ] {
            let page = Box::new(EvmcsTestPage([0xa5; 4096]));
            let address = page.0.as_ptr() as u64;
            let mut state = nested_state(0);
            state.evmcs_enabled = 1;
            let mut ept = EvmcsTestEpt::new(&mut state);
            ept.map(address, address, 7);
            let entry = ept.entry(address, shift);
            ept.set_entry(address, shift, entry & !7 | permissions);
            assert_eq!(unsafe { test_write_vp_assist(&mut state, address | 1) }, 0);
            assert_eq!(state.vp_assist_msr, 0);
            assert_eq!(page.0, [0xa5; 4096]);
        }
    }

    #[test]
    fn vp_assist_writes_the_translated_page_and_preserves_nested_fields() {
        let decoy = Box::new(EvmcsTestPage([0x5a; 4096]));
        let page = Box::new(EvmcsTestPage([0xa5; 4096]));
        let guest_address = decoy.0.as_ptr() as u64;
        let host_address = page.0.as_ptr() as u64;
        let mut state = nested_state(0);
        state.evmcs_enabled = 1;
        let mut ept = EvmcsTestEpt::new(&mut state);
        ept.map(guest_address, host_address, 7);
        for _ in 0..2 {
            assert_eq!(
                unsafe { test_write_vp_assist(&mut state, guest_address | 1) },
                1
            );
            assert_eq!(state.vp_assist_msr, guest_address | 1);
            assert_eq!(&page.0[..4], &[0; 4]);
            assert!(page.0[4..].iter().all(|byte| *byte == 0xa5));
            assert_eq!(decoy.0, [0x5a; 4096]);
        }
    }

    #[test]
    fn evmcs_selection_checks_assist_read_access_and_state_write_access() {
        for (assist_permissions, vmcs_permissions) in
            [(0, 7), (2, 7), (4, 7), (7, 0), (7, 1), (7, 2), (7, 5)]
        {
            let mut assist = Box::new(EvmcsTestPage([0; 4096]));
            let mut evmcs = Box::new(EvmcsTestPage([0; 4096]));
            let mut state = nested_state(0);
            state.evmcs_enabled = 1;
            state.vp_assist_msr = assist.0.as_ptr() as u64 | 1;
            let address = evmcs.0.as_ptr() as u64;
            write_page_u64(
                &mut assist,
                crate::hyperv::VP_ASSIST_ENLIGHTEN_VM_ENTRY_OFFSET,
                1,
            );
            write_page_u64(
                &mut assist,
                crate::hyperv::VP_ASSIST_CURRENT_NESTED_VMCS_OFFSET,
                address,
            );
            evmcs.0[..4].copy_from_slice(&crate::hyperv::EVMCS_VERSION.to_le_bytes());
            let mut ept = EvmcsTestEpt::new(&mut state);
            ept.map(
                state.vp_assist_msr & !4095,
                state.vp_assist_msr & !4095,
                assist_permissions,
            );
            ept.map(address, address, vmcs_permissions);
            assert_eq!(unsafe { test_select_evmcs(&mut state) }, -1);
            assert_eq!(state.current_vmcs, INVALID_VMCS_POINTER);
            assert_eq!(state.evmcs_active, 0);
            assert_eq!(
                page_u64(&evmcs, offset_of!(EnlightenedVmcs, clean_fields)),
                0
            );
        }
    }

    #[test]
    fn evmcs_selection_and_writeback_follow_non_identity_ept01_mappings() {
        let assist_decoy = Box::new(EvmcsTestPage([0x5a; 4096]));
        let vmcs_decoy = Box::new(EvmcsTestPage([0xa5; 4096]));
        let mut assist = Box::new(EvmcsTestPage([0; 4096]));
        let mut evmcs = Box::new(EvmcsTestPage([0; 4096]));
        let mut state = nested_state(0);
        let guest_address = vmcs_decoy.0.as_ptr() as u64;
        state.evmcs_enabled = 1;
        state.vp_assist_msr = assist_decoy.0.as_ptr() as u64 | 1;
        write_page_u64(
            &mut assist,
            crate::hyperv::VP_ASSIST_ENLIGHTEN_VM_ENTRY_OFFSET,
            1,
        );
        write_page_u64(
            &mut assist,
            crate::hyperv::VP_ASSIST_CURRENT_NESTED_VMCS_OFFSET,
            guest_address,
        );
        evmcs.0[..4].copy_from_slice(&crate::hyperv::EVMCS_VERSION.to_le_bytes());
        write_page_u64(&mut evmcs, offset_of!(EnlightenedVmcs, guest_rip), 0x1234);
        let mut ept = EvmcsTestEpt::new(&mut state);
        ept.map(state.vp_assist_msr & !4095, assist.0.as_ptr() as u64, 1);
        ept.map(guest_address, evmcs.0.as_ptr() as u64, 7);
        assert_eq!(unsafe { test_select_evmcs(&mut state) }, 1);
        assert_eq!(state.current_vmcs, guest_address);
        assert_eq!(state.vmcs12.guest_rip, 0x1234);
        state.vmcs12.guest_rip = 0x5678;
        unsafe { test_store_evmcs(&mut state) };
        assert_eq!(
            page_u64(&evmcs, offset_of!(EnlightenedVmcs, guest_rip)),
            0x5678
        );
        assert_eq!(assist_decoy.0, [0x5a; 4096]);
        assert_eq!(vmcs_decoy.0, [0xa5; 4096]);
        let before = evmcs.0;
        ept.map(guest_address, evmcs.0.as_ptr() as u64, 1);
        state.vmcs12.guest_rip = 0xabcd;
        unsafe { test_store_evmcs(&mut state) };
        assert_eq!(evmcs.0, before);
        assert_eq!(state.failure_count, 1);
        assert_eq!(unsafe { test_select_evmcs(&mut state) }, -1);
        ept.map(guest_address, evmcs.0.as_ptr() as u64, 7);
        state.host_mapping_cache[0] = evmcs.0.as_ptr() as u64;
        assert_eq!(unsafe { test_select_evmcs(&mut state) }, -1);
    }

    #[test]
    fn vmclear_preserves_non_current_evmcs_pages_and_the_current_selection() {
        for (use_revision, shared_revision) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let mut assist = Box::new(EvmcsTestPage([0; 4096]));
            let mut first = Box::new(EvmcsTestPage([0xa5; 4096]));
            let mut second = Box::new(EvmcsTestPage([0; 4096]));
            let first_address = first.0.as_ptr() as u64;
            let second_address = second.0.as_ptr() as u64;
            let mut state = nested_state(0);
            state.active = 1;
            state.evmcs_enabled = 1;
            if shared_revision {
                state.vmcs12.revision_id = u64::from(crate::hyperv::EVMCS_VERSION);
            }
            state.vp_assist_msr = assist.0.as_ptr() as u64 | 1;
            let version = if use_revision {
                state.vmcs12.revision_id as u32
            } else {
                crate::hyperv::EVMCS_VERSION
            };
            first.0[..4].copy_from_slice(&version.to_le_bytes());
            second.0[..4].copy_from_slice(&crate::hyperv::EVMCS_VERSION.to_le_bytes());
            write_page_u64(
                &mut assist,
                crate::hyperv::VP_ASSIST_ENLIGHTEN_VM_ENTRY_OFFSET,
                1,
            );
            write_page_u64(
                &mut assist,
                crate::hyperv::VP_ASSIST_CURRENT_NESTED_VMCS_OFFSET,
                second_address,
            );
            let mut ept = EvmcsTestEpt::new(&mut state);
            ept.map(state.vp_assist_msr & !4095, state.vp_assist_msr & !4095, 7);
            ept.map(first_address, first_address, 7);
            ept.map(second_address, second_address, 7);
            assert_eq!(unsafe { test_select_evmcs(&mut state) }, 1);
            state.vmcs02_launched = 1;
            state.vmcs02_guest_cache_valid = 1;
            state.vmcs02_control_cache_valid = [1, 1];
            let before = first.0;
            assert_eq!(unsafe { test_clear_evmcs(&mut state, first_address) }, 1);
            assert_eq!(first.0, before);
            assert_eq!(state.current_vmcs, second_address);
            assert_eq!(state.evmcs_active, 1);
            assert_eq!(state.vmcs02_launched, 1);
            assert_eq!(state.vmcs02_guest_cache_valid, 1);
            assert_eq!(state.vmcs02_control_cache_valid, [1, 1]);
            if !use_revision {
                state.vp_assist_msr = 0;
                assert_eq!(unsafe { test_clear_evmcs(&mut state, first_address) }, 1);
                assert_eq!(first.0, before);
            }
            assert_eq!(unsafe { test_clear_evmcs(&mut state, second_address) }, 1);
            assert_eq!(state.current_vmcs, INVALID_VMCS_POINTER);
            assert_eq!(state.evmcs_active, 0);
            assert_eq!(state.vmcs02_launched, 0);
            assert_eq!(state.vmcs02_guest_cache_valid, 0);
            assert_eq!(state.vmcs02_control_cache_valid, [0, 0]);
        }
    }

    #[test]
    fn ordinary_vmclear_requires_ept_write_access_at_every_level() {
        for deny_shift in [39, 30, 21, 12] {
            let mut page = Box::new(EvmcsTestPage([0x5a; 4096]));
            let address = page.0.as_mut_ptr() as u64;
            let before = page.0;
            let mut state = nested_state(0);
            state.active = 1;
            state.current_vmcs = address;
            state.vmcs02_launched = 1;
            let mut ept = EvmcsTestEpt::new(&mut state);
            ept.map(address, address, 7);
            let entry = ept.entry(address, deny_shift);
            ept.set_entry(address, deny_shift, entry & !2);
            assert_eq!(unsafe { test_clear_evmcs(&mut state, address) }, 0);
            assert_eq!(page.0, before);
            assert_eq!(state.current_vmcs, address);
            assert_eq!(state.vmcs02_launched, 1);
        }
    }

    #[test]
    fn ordinary_vmclear_writes_the_hpa_and_compares_the_current_gpa() {
        for current in [false, true] {
            let mut page = Box::new(EvmcsTestPage([0; 4096]));
            let address = page.0.as_mut_ptr() as u64;
            let guest_address = 0x1234_0000;
            let mut state = nested_state(0);
            state.active = 1;
            if current {
                state.current_vmcs = guest_address;
            }
            let mut ept = EvmcsTestEpt::new(&mut state);
            ept.map(guest_address, address, 7);
            assert_eq!(unsafe { test_clear_evmcs(&mut state, guest_address) }, 1);
            assert_eq!(
                page_u64(&page, VMCS12_BACKING_MAGIC_OFFSET),
                VMCS12_BACKING_MAGIC
            );
            assert_eq!(
                page_u64(
                    &page,
                    VMCS12_BACKING_STATE_OFFSET + offset_of!(NestedVmcs12State, launch_state)
                ),
                VMCS12_LAUNCH_STATE_CLEAR
            );
            assert_eq!(state.current_vmcs, INVALID_VMCS_POINTER);
        }
    }

    #[test]
    fn nested_misc_advertises_exactly_512_msr_entries_for_every_host_limit() {
        for limit in 0..8 {
            let mut host = host_vmx_capabilities();
            host.misc = (host.misc & !(7 << 25)) | (limit << 25);
            let guest = NestedVmxCapabilities::from_host(host);
            assert_eq!(512 * (((guest.vmx_misc >> 25) & 7) + 1), 512);
            assert_eq!(guest.host_misc, host.misc);
        }
    }

    #[test]
    fn vmclear_keeps_the_ordinary_backing_layout_outside_enlightened_mode() {
        let mut page = Box::new(EvmcsTestPage([0; 4096]));
        let address = page.0.as_ptr() as u64;
        let mut state = nested_state(0);
        state.active = 1;
        state.evmcs_enabled = 1;
        page.0[..4].copy_from_slice(&(state.vmcs12.revision_id as u32).to_le_bytes());
        let mut ept = EvmcsTestEpt::new(&mut state);
        ept.map(address, address, 7);
        assert_eq!(unsafe { test_clear_evmcs(&mut state, address) }, 1);
        assert_eq!(
            page_u64(&page, VMCS12_BACKING_MAGIC_OFFSET),
            VMCS12_BACKING_MAGIC
        );
    }

    #[test]
    fn vmclear_clears_ordinary_backing_while_another_evmcs_is_selected() {
        for assist_enabled in [false, true] {
            let mut assist = Box::new(EvmcsTestPage([0; 4096]));
            let mut selected = Box::new(EvmcsTestPage([0; 4096]));
            let mut ordinary = Box::new(EvmcsTestPage([0; 4096]));
            let ordinary_address = ordinary.0.as_mut_ptr() as u64;
            let selected_address = selected.0.as_mut_ptr() as u64;
            let mut state = nested_state(0);
            state.active = 1;
            state.evmcs_enabled = 1;
            state.vmcs12.revision_id = u64::from(crate::hyperv::EVMCS_VERSION);
            ordinary.0[..4].copy_from_slice(&crate::hyperv::EVMCS_VERSION.to_le_bytes());
            selected.0[..4].copy_from_slice(&crate::hyperv::EVMCS_VERSION.to_le_bytes());
            let mut ept = EvmcsTestEpt::new(&mut state);
            ept.map(ordinary_address, ordinary_address, 7);
            ept.map(selected_address, selected_address, 7);
            assert_eq!(unsafe { test_clear_evmcs(&mut state, ordinary_address) }, 1);
            let launch_offset =
                VMCS12_BACKING_STATE_OFFSET + offset_of!(NestedVmcs12State, launch_state);
            write_page_u64(&mut ordinary, launch_offset, 1);
            state.evmcs_active = 1;
            state.current_vmcs = selected_address;
            if assist_enabled {
                state.vp_assist_msr = assist.0.as_mut_ptr() as u64 | 1;
                write_page_u64(
                    &mut assist,
                    crate::hyperv::VP_ASSIST_ENLIGHTEN_VM_ENTRY_OFFSET,
                    1,
                );
                write_page_u64(
                    &mut assist,
                    crate::hyperv::VP_ASSIST_CURRENT_NESTED_VMCS_OFFSET,
                    selected_address,
                );
                ept.map(state.vp_assist_msr & !4095, state.vp_assist_msr & !4095, 7);
            }
            let before = selected.0;
            assert_eq!(unsafe { test_clear_evmcs(&mut state, ordinary_address) }, 1);
            assert_eq!(
                page_u64(&ordinary, launch_offset),
                VMCS12_LAUNCH_STATE_CLEAR
            );
            assert_eq!(state.current_vmcs, selected_address);
            assert_eq!(state.evmcs_active, 1);
            assert_eq!(selected.0, before);
        }
    }

    #[test]
    fn vmclear_initializes_ordinary_vmcs_when_native_revision_matches_evmcs_version() {
        for assist_enabled in [false, true] {
            for current in [false, true] {
                let mut assist = Box::new(EvmcsTestPage([0; 4096]));
                let mut page = Box::new(EvmcsTestPage([0; 4096]));
                let address = page.0.as_ptr() as u64;
                let mut state = nested_state(0);
                state.active = 1;
                state.evmcs_enabled = 1;
                state.vmcs12.revision_id = u64::from(crate::hyperv::EVMCS_VERSION);
                if current {
                    state.current_vmcs = address;
                }
                if assist_enabled {
                    state.vp_assist_msr = assist.0.as_mut_ptr() as u64 | 1;
                }
                page.0[..4].copy_from_slice(&crate::hyperv::EVMCS_VERSION.to_le_bytes());
                let mut ept = EvmcsTestEpt::new(&mut state);
                ept.map(address, address, 7);
                if assist_enabled {
                    ept.map(state.vp_assist_msr & !4095, state.vp_assist_msr & !4095, 1);
                }
                assert_eq!(unsafe { test_clear_evmcs(&mut state, address) }, 1);
                assert_eq!(
                    page_u64(&page, VMCS12_BACKING_MAGIC_OFFSET),
                    VMCS12_BACKING_MAGIC
                );
                assert_eq!(
                    page_u64(
                        &page,
                        VMCS12_BACKING_STATE_OFFSET + offset_of!(NestedVmcs12State, launch_state)
                    ),
                    VMCS12_LAUNCH_STATE_CLEAR
                );
                assert_eq!(state.current_vmcs, INVALID_VMCS_POINTER);
                assert_eq!(state.evmcs_active, 0);
                if current {
                    assert_eq!(state.vmcs12.launch_state, VMCS12_LAUNCH_STATE_CLEAR);
                }
            }
        }
    }

    #[test]
    fn evmcs_writeback_preserves_ia32e_entry_mode_across_selection() {
        let mut assist = Box::new(EvmcsTestPage([0; 4096]));
        let mut evmcs = Box::new(EvmcsTestPage([0; 4096]));
        let address = evmcs.0.as_ptr() as u64;
        let mut state = nested_state(0);
        state.evmcs_enabled = 1;
        state.vp_assist_msr = assist.0.as_ptr() as u64 | 1;
        write_page_u64(
            &mut assist,
            crate::hyperv::VP_ASSIST_ENLIGHTEN_VM_ENTRY_OFFSET,
            1,
        );
        write_page_u64(
            &mut assist,
            crate::hyperv::VP_ASSIST_CURRENT_NESTED_VMCS_OFFSET,
            address,
        );
        evmcs.0[..4].copy_from_slice(&crate::hyperv::EVMCS_VERSION.to_le_bytes());
        let mut ept = EvmcsTestEpt::new(&mut state);
        ept.map(state.vp_assist_msr & !4095, state.vp_assist_msr & !4095, 7);
        ept.map(address, address, 7);
        assert_eq!(unsafe { test_select_evmcs(&mut state) }, 1);
        state.vmcs12.extended_fields[11] = 0x4004;
        state.vmx_misc |= 1 << 5;
        for (efer, expected) in [(0x500, 0x4204), (0x100, 0x4004), (0x500, 0x4204)] {
            unsafe { test_capture_evmcs_entry_mode(&mut state, efer) };
            assert_eq!(state.vmcs12.extended_fields[11], expected);
            unsafe { test_store_evmcs(&mut state) };
            assert_eq!(
                page_u64(&evmcs, offset_of!(EnlightenedVmcs, entry_controls)) as u32,
                expected as u32
            );
            assert_eq!(unsafe { test_select_evmcs(&mut state) }, 1);
            assert_eq!(state.vmcs12.extended_fields[11], expected);
        }
    }

    #[test]
    fn resident_evmcs_handlers_transfer_entry_and_exit_state() {
        let mut assist = Box::new(EvmcsTestPage([0; 4096]));
        let mut evmcs = Box::new(EvmcsTestPage([0; 4096]));
        let mut vmread_bitmap = Box::new(EvmcsTestPage([0xff; 4096]));
        let mut state = nested_state(0);
        let evmcs_address = evmcs.0.as_ptr() as u64;
        let shadow_byte = vmcs12::VMCS_SHADOW_READ_BITMAP_BYTE_OFFSET;
        vmread_bitmap.0[shadow_byte] = vmcs12::VMCS_SHADOW_READ_TRAP_MASK;
        state.shadow_vmread_bitmap = vmread_bitmap.0.as_ptr() as u64;
        state.evmcs_enabled = 1;
        state.vp_assist_msr = assist.0.as_ptr() as u64 | 1;
        let mut ept = EvmcsTestEpt::new(&mut state);
        ept.map(state.vp_assist_msr & !4095, state.vp_assist_msr & !4095, 7);
        ept.map(evmcs_address, evmcs_address, 7);
        state.vmcs02_guest_cache_valid = 1;
        state.vmcs02_control_cache_valid = [1, 1];
        assist.0[crate::hyperv::VP_ASSIST_ENLIGHTEN_VM_ENTRY_OFFSET..][..4]
            .copy_from_slice(&1u32.to_le_bytes());
        write_page_u64(
            &mut assist,
            crate::hyperv::VP_ASSIST_CURRENT_NESTED_VMCS_OFFSET,
            evmcs_address,
        );
        evmcs.0[..4].copy_from_slice(&crate::hyperv::EVMCS_VERSION.to_le_bytes());
        write_page_u64(
            &mut evmcs,
            offset_of!(EnlightenedVmcs, ept_root),
            0x4560_001e,
        );
        write_page_u64(
            &mut evmcs,
            offset_of!(EnlightenedVmcs, guest_cr0),
            0x8000_0031,
        );
        write_page_u64(
            &mut evmcs,
            offset_of!(EnlightenedVmcs, guest_rip),
            0x1234_5678,
        );
        write_page_u64(
            &mut evmcs,
            offset_of!(EnlightenedVmcs, guest_rsp),
            0x1234_f000,
        );
        write_page_u64(&mut evmcs, offset_of!(EnlightenedVmcs, guest_rflags), 0x202);
        write_page_u64(
            &mut evmcs,
            offset_of!(EnlightenedVmcs, host_rip),
            0xabcd_1000,
        );
        write_page_u64(
            &mut evmcs,
            offset_of!(EnlightenedVmcs, host_rsp),
            0xabcd_f000,
        );
        evmcs.0[offset_of!(EnlightenedVmcs, guest_es_selector)..][..2]
            .copy_from_slice(&0x28u16.to_le_bytes());

        assert_eq!(unsafe { test_select_evmcs(&mut state) }, 1);
        assert_eq!(vmread_bitmap.0[shadow_byte], 0xff);
        assert_eq!(state.evmcs_active, 1);
        assert_eq!(state.current_vmcs, evmcs_address);
        assert_eq!(state.vmcs12.extended_fields[16], 0x4560_001e);
        assert_eq!(state.vmcs12.extended_fields[29], 0x8000_0031);
        assert_eq!(state.vmcs12.extended_fields[35], 0x28);
        assert_eq!(state.vmcs12.guest_rip, 0x1234_5678);
        assert_eq!(state.vmcs12.guest_rsp, 0x1234_f000);
        assert_eq!(state.vmcs12.guest_rflags, 0x202);
        assert_eq!(state.vmcs12.host_rip, 0xabcd_1000);
        assert_eq!(state.vmcs12.host_rsp, 0xabcd_f000);
        assert_eq!(state.vmcs02_guest_cache_valid, 0);
        assert_eq!(state.vmcs02_control_cache_valid, [0, 0]);

        state.vmcs12.guest_rip = 0x1234_5680;
        state.vmcs12.extended_fields[29] = 0x8000_0033;
        state.vmcs12.extended_fields[106] = 0x8000_0202;
        state.vmcs12.exit_reason = 18;
        state.vmcs12.exit_instruction_len = 3;
        state.vmcs12.exit_qualification = 0x42;
        evmcs.0[offset_of!(EnlightenedVmcs, clean_fields)..][..4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        unsafe { test_store_evmcs(&mut state) };
        assert_eq!(
            page_u64(&evmcs, offset_of!(EnlightenedVmcs, guest_rip)),
            0x1234_5680
        );
        assert_eq!(
            page_u64(&evmcs, offset_of!(EnlightenedVmcs, guest_cr0)),
            0x8000_0033
        );
        assert_eq!(
            u32::from_le_bytes(
                evmcs.0[offset_of!(EnlightenedVmcs, exit_interruption_info)..][..4]
                    .try_into()
                    .unwrap()
            ),
            0x8000_0202
        );
        assert_eq!(
            u32::from_le_bytes(
                evmcs.0[offset_of!(EnlightenedVmcs, exit_reason)..][..4]
                    .try_into()
                    .unwrap()
            ),
            18
        );
        assert_eq!(
            page_u64(&evmcs, offset_of!(EnlightenedVmcs, exit_qualification)),
            0x42
        );
        assert_eq!(
            u32::from_le_bytes(
                evmcs.0[offset_of!(EnlightenedVmcs, clean_fields)..][..4]
                    .try_into()
                    .unwrap()
            ),
            0x7fff
        );

        evmcs.0[..4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(unsafe { test_select_evmcs(&mut state) }, -1);
        evmcs.0[..4].copy_from_slice(&(state.vmcs12.revision_id as u32).to_le_bytes());
        assert_eq!(unsafe { test_select_evmcs(&mut state) }, -1);
        assist.0[crate::hyperv::VP_ASSIST_ENLIGHTEN_VM_ENTRY_OFFSET..][..4]
            .copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(unsafe { test_select_evmcs(&mut state) }, 0);
        assert_eq!(state.evmcs_active, 0);
        assert_eq!(state.current_vmcs, nested::INVALID_VMCS_POINTER);
    }

    #[test]
    fn evmcs_exit_consumes_delivered_event_but_preserves_failed_entry() {
        for (exit_reason, expected) in [(18, 0x40), (0x8000_0021, 0x8000_0040)] {
            let mut evmcs = Box::new(EvmcsTestPage([0; 4096]));
            let mut assist = Box::new(EvmcsTestPage([0; 4096]));
            let mut state = nested_state(0);
            state.evmcs_enabled = 1;
            state.evmcs_active = 1;
            state.current_vmcs = evmcs.0.as_ptr() as u64;
            state.vp_assist_msr = assist.0.as_ptr() as u64 | 1;
            let mut ept = EvmcsTestEpt::new(&mut state);
            ept.map(state.vp_assist_msr & !4095, state.vp_assist_msr & !4095, 7);
            ept.map(state.current_vmcs, state.current_vmcs, 7);
            assist.0[crate::hyperv::VP_ASSIST_ENLIGHTEN_VM_ENTRY_OFFSET..][..4]
                .copy_from_slice(&1u32.to_le_bytes());
            write_page_u64(
                &mut assist,
                crate::hyperv::VP_ASSIST_CURRENT_NESTED_VMCS_OFFSET,
                state.current_vmcs,
            );
            evmcs.0[..4].copy_from_slice(&crate::hyperv::EVMCS_VERSION.to_le_bytes());
            state.vmcs12.exit_reason = exit_reason;
            state.vmcs12.extended_fields[13] = 0x8000_0040;
            state.vmcs12.guest_rflags = 0x46;
            unsafe { test_complete_evmcs_exit(&mut state) };
            assert_eq!(state.vmcs12.extended_fields[13], expected);
            assert_eq!(unsafe { test_select_evmcs(&mut state) }, 1);
            assert_eq!(state.vmcs12.extended_fields[13], expected);
            assert_eq!(state.vmcs12.guest_rflags, 0x46);
        }
    }
}

#[cfg(test_harness = "ept")]
mod ept {
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::collections::HashMap;

    #[repr(C)]
    struct InterceptContext {
        l0_primary: u64,
        l1_primary: u64,
        l0_secondary: u64,
        l1_secondary: u64,
        vpid: u64,
        merged_secondary: u64,
        xss_bitmap: u64,
        hardware: [u64; 5],
        extended_fields: [u64; 122],
    }

    core::arch::global_asm!(
        ".text",
        ".globl merge_test_intercepts",
        "merge_test_intercepts:",
        "push r12", "mov r12, rcx",
        "call .Ltest_merge_intercepts",
        "pop r12", "ret",
        ".Ltest_merge_intercepts:",
        include_str!("../builds/nested-ept-tests/resident-intercepts.S"),
        cpu_based_vm_exec_control = const 0,
        secondary_vm_exec_control = const 1,
        xss_exiting_bitmap = const 2,
        b_nested_vmcs12_xss_exiting_bitmap = const std::mem::offset_of!(InterceptContext, xss_bitmap),
        b_nested_vmcs01_primary_controls = const std::mem::offset_of!(InterceptContext, l0_primary),
        b_nested_vmcs12_primary_control = const std::mem::offset_of!(InterceptContext, l1_primary),
        b_nested_vmcs01_secondary_controls = const std::mem::offset_of!(InterceptContext, l0_secondary),
        b_nested_vmcs12_secondary_control = const std::mem::offset_of!(InterceptContext, l1_secondary),
        b_nested_vmcs02_last_vpid = const std::mem::offset_of!(InterceptContext, vpid),
        b_nested_last_merged_secondary_controls = const std::mem::offset_of!(InterceptContext, merged_secondary),
        test_hardware = const std::mem::offset_of!(InterceptContext, hardware),
        b_nested_vmcs12_extended_fields = const std::mem::offset_of!(InterceptContext, extended_fields),
    );

    unsafe extern "win64" {
        #[link_name = "merge_test_intercepts"]
        fn merge_test_intercepts_raw(context: *mut InterceptContext);
    }

    fn merge_test_intercepts(context: &mut InterceptContext) {
        // The trampoline only reads and writes fields of the exclusively borrowed context.
        unsafe { merge_test_intercepts_raw(context) }
    }

    #[test]
    fn l1_monitor_trap_and_wbinvd_controls_reach_vmcs02_and_can_be_cleared() {
        let mut context = InterceptContext {
            l0_primary: 1 << 28,
            l1_primary: (1 << 31) | (1 << 27),
            l0_secondary: 1 << 1,
            l1_secondary: 1 << 6,
            vpid: 0,
            merged_secondary: 0,
            xss_bitmap: 0,
            hardware: [0; 5],
            extended_fields: [0; 122],
        };
        merge_test_intercepts(&mut context);
        assert_eq!(
            context.hardware[..3],
            [(1 << 31) | (1 << 28) | (1 << 27), (1 << 1) | (1 << 6), 0]
        );
        assert_eq!(context.merged_secondary, context.hardware[1]);
        context.l1_primary = 0;
        context.l1_secondary = 0;
        merge_test_intercepts(&mut context);
        assert_eq!(context.hardware[..3], [1 << 28, 1 << 1, 0]);
    }

    #[test]
    fn instruction_enables_follow_l1_and_intercepts_keep_l0_requirements() {
        let enables = (1 << 3) | (1 << 12) | (1 << 20);
        let intercepts = (1 << 2) | (1 << 6) | (1 << 11);
        let mut context = InterceptContext {
            l0_primary: 1 << 31,
            l1_primary: 1 << 31,
            l0_secondary: 2 | enables | intercepts,
            l1_secondary: 0,
            vpid: 0,
            merged_secondary: 0,
            xss_bitmap: 0,
            hardware: [0; 5],
            extended_fields: [0; 122],
        };
        for requested in [0, 1 << 3, 1 << 12, 1 << 20, enables] {
            context.l1_secondary = requested;
            merge_test_intercepts(&mut context);
            assert_eq!(context.hardware[1] & enables, requested);
            assert_eq!(context.hardware[1] & intercepts, intercepts);
            assert_ne!(context.hardware[1] & 2, 0);
        }
        context.l1_primary = 0;
        merge_test_intercepts(&mut context);
        assert_eq!(context.hardware[1] & enables, 0);
    }

    #[test]
    fn l0_vmcs_shadowing_does_not_reach_vmcs02() {
        let mut context = InterceptContext {
            l0_primary: 1 << 31,
            l1_primary: 1 << 31,
            l0_secondary: (1 << 1) | (1 << 14),
            l1_secondary: 0,
            vpid: 0,
            merged_secondary: 0,
            xss_bitmap: 0,
            hardware: [0; 5],
            extended_fields: [0; 122],
        };
        merge_test_intercepts(&mut context);
        assert_eq!(context.hardware[1], 1 << 1);
        assert_eq!(context.merged_secondary, 1 << 1);
        context.l1_secondary = 1 << 14;
        context.extended_fields[120] = 0x1234_0000;
        context.extended_fields[121] = 0x5678_0000;
        merge_test_intercepts(&mut context);
        assert_eq!(context.hardware[1], (1 << 1) | (1 << 14));
        assert_eq!(context.hardware[3..], [0x1234_0000, 0x5678_0000]);
        context.l1_primary = 0;
        merge_test_intercepts(&mut context);
        assert_eq!(context.hardware[1], 1 << 1);
        context.l1_primary = 1 << 31;
        context.l1_secondary = 0;
        merge_test_intercepts(&mut context);
        assert_eq!(context.hardware[1], 1 << 1);
    }

    #[test]
    fn vmfunc_trapping_follows_l1_secondary_control_activation() {
        let mut context = InterceptContext {
            l0_primary: 1 << 31,
            l1_primary: 1 << 31,
            l0_secondary: 2,
            l1_secondary: 0x2002,
            vpid: 0,
            merged_secondary: 0,
            xss_bitmap: 0,
            hardware: [0; 5],
            extended_fields: [0; 122],
        };
        merge_test_intercepts(&mut context);
        assert_eq!(context.hardware[1], 0x2002);
        context.l1_primary = 0;
        merge_test_intercepts(&mut context);
        assert_eq!(context.hardware[1], 2);
        context.l1_primary = 1 << 31;
        context.l1_secondary = 2;
        merge_test_intercepts(&mut context);
        assert_eq!(context.hardware[1], 2);
    }

    #[test]
    fn inactive_secondary_controls_do_not_add_l2_intercepts_or_mbec() {
        let mut context = InterceptContext {
            l0_primary: (1 << 31) | (1 << 28),
            l1_primary: 0,
            l0_secondary: 2,
            l1_secondary: 0x5038ce,
            vpid: 0,
            merged_secondary: 0,
            xss_bitmap: u64::MAX,
            hardware: [0; 5],
            extended_fields: [0; 122],
        };
        merge_test_intercepts(&mut context);
        assert_eq!(context.hardware[1], 2);
        assert_eq!(context.hardware[2], 0);
        context.l1_primary = 1 << 31;
        merge_test_intercepts(&mut context);
        assert_eq!(context.hardware[1], 0x5038ce);
        assert_eq!(context.hardware[2], u64::MAX);
        context.l1_primary = 0;
        merge_test_intercepts(&mut context);
        assert_eq!(context.hardware[1], 2);
        assert_eq!(context.hardware[2], 0);
    }

    #[repr(C)]
    struct MsrPolicyContext {
        primary: u64,
        l0: *const u8,
        l1: *const u8,
        composed: *mut u8,
        mapped: u64,
        selected: *const u8,
        translated: *const u8,
    }

    core::arch::global_asm!(
        ".text",
        ".globl select_test_msr_bitmap",
        "select_test_msr_bitmap:",
        "push r12", "push rsi", "push rdi", "mov r12, rcx",
        "call .Ltest_msr_policy_entry",
        "pop rdi", "pop rsi", "pop r12", "ret",
        ".Ltest_msr_policy_entry:",
        include_str!("../builds/nested-ept-tests/resident-msr-policy.S"),
        b_nested_vmcs12_primary_control = const std::mem::offset_of!(MsrPolicyContext, primary),
        b_nested_l0_msr_bitmap = const std::mem::offset_of!(MsrPolicyContext, l0),
        b_nested_vmcs12_msr_bitmap = const std::mem::offset_of!(MsrPolicyContext, l1),
        b_nested_composed_msr_bitmap = const std::mem::offset_of!(MsrPolicyContext, composed),
        nested_msr_bitmap_qword_count = const 512,
        msr_bitmap = const 0,
        test_mapped = const std::mem::offset_of!(MsrPolicyContext, mapped),
        test_selected = const std::mem::offset_of!(MsrPolicyContext, selected),
        test_translated = const std::mem::offset_of!(MsrPolicyContext, translated),
    );

    unsafe extern "win64" {
        fn select_test_msr_bitmap(context: *mut MsrPolicyContext);
    }

    #[test]
    fn disabled_l1_msr_bitmap_intercepts_every_msr_and_tracks_reactivation() {
        let mut l0 = [0_u8; 4096];
        let mut l1 = [0_u8; 4096];
        let mut composed = [0_u8; 4096];
        l0[16] = 0x12;
        l1[2048 + 17] = 0x34;
        let mut context = MsrPolicyContext {
            primary: 0,
            l0: l0.as_ptr(),
            l1: 0x800000 as *const u8,
            composed: composed.as_mut_ptr(),
            mapped: 1,
            selected: std::ptr::null(),
            translated: l1.as_ptr(),
        };
        for primary in [0, 1 << 28, 0] {
            context.primary = primary;
            // The production routine accesses only these live arrays and the context.
            unsafe { select_test_msr_bitmap(&mut context) };
            assert_eq!(context.selected, composed.as_ptr());
            for offset in 0..4096 {
                let expected = if primary == 0 {
                    0xff
                } else {
                    l0[offset] | l1[offset]
                };
                assert_eq!(composed[offset], expected);
            }
        }
    }

    #[repr(C)]
    struct SuccessContext {
        rflags: u64,
        writes: u64,
        advances: u64,
    }

    core::arch::global_asm!(
        ".text",
        ".globl complete_test_vmx_success",
        "complete_test_vmx_success:",
        "push r12", "mov r12, rcx",
        "call .Ltest_nested_success",
        "pop r12", "ret",
        include_str!("../builds/nested-ept-tests/resident-success.S"),
        guest_rflags = const 0,
        vmx_status_flags_clear_mask = const !0x8d5_i32,
        test_rflags = const std::mem::offset_of!(SuccessContext, rflags),
        test_writes = const std::mem::offset_of!(SuccessContext, writes),
        test_advances = const std::mem::offset_of!(SuccessContext, advances),
    );

    unsafe extern "win64" {
        #[link_name = "complete_test_vmx_success"]
        fn complete_test_vmx_success_raw(context: *mut SuccessContext);
    }

    fn complete_test_vmx_success(context: &mut SuccessContext) {
        // All simulated VMCS accesses stay inside the borrowed context.
        unsafe { complete_test_vmx_success_raw(context) }
    }

    #[test]
    fn vmx_success_clears_status_flags_and_preserves_other_guest_flags() {
        for combination in 0..64 {
            let status = [0, 2, 4, 6, 7, 11]
                .iter()
                .enumerate()
                .fold(0, |flags, (index, bit)| {
                    flags | (((combination >> index) & 1) << bit)
                });
            for preserved in [2, 0x247702] {
                let mut state = SuccessContext {
                    rflags: preserved | status,
                    writes: 0,
                    advances: 0,
                };
                complete_test_vmx_success(&mut state);
                assert_eq!(state.rflags, preserved);
                assert_eq!(state.writes, u64::from(status != 0));
                assert_eq!(state.advances, 1);
            }
        }
    }

    core::arch::global_asm!(
        ".text",
        ".globl compose_test_msr_bitmap",
        "compose_test_msr_bitmap:",
        "push rsi",
        "push rdi",
        "mov rsi, rcx",
        "mov rdi, r8",
        "mov ecx, 512",
        "call .Lresident_nested_merge_msr_bitmap_loop",
        "pop rdi",
        "pop rsi",
        "ret",
        include_str!("../builds/nested-ept-tests/resident-msr-bitmap.S"),
    );

    unsafe extern "win64" {
        #[link_name = "compose_test_msr_bitmap"]
        fn compose_test_msr_bitmap_raw(l0: *const u8, l1: *const u8, output: *mut u8);
    }

    fn compose_test_msr_bitmap(l0: &[u8; 4096], l1: &[u8; 4096], output: &mut [u8; 4096]) {
        // Array sizes cover all 512 qword accesses; the output borrow excludes aliasing.
        unsafe { compose_test_msr_bitmap_raw(l0.as_ptr(), l1.as_ptr(), output.as_mut_ptr()) }
    }

    #[test]
    fn apic_passthrough_keeps_l1_intercepts_and_tracks_bitmap_changes() {
        let mut l0 = [0xff_u8; 4096];
        let mut l1 = [0_u8; 4096];
        let mut output = [0_u8; 4096];
        for base in [0, 2048] {
            for msr in 0x800..=0x8ff {
                l0[base + msr / 8] &= !(1 << (msr % 8));
            }
            for msr in [0x80b, 0x830] {
                l1[base + msr / 8] |= 1 << (msr % 8);
            }
        }
        for revision in 0..3 {
            if revision == 1 {
                l1[2048 + 0x80b / 8] &= !(1 << (0x80b % 8));
            } else if revision == 2 {
                l1[2048 + 0x808 / 8] |= 1 << (0x808 % 8);
            }
            compose_test_msr_bitmap(&l0, &l1, &mut output);
            for offset in 0..4096 {
                assert_eq!(output[offset], l0[offset] | l1[offset]);
            }
        }
    }

    #[repr(C)]
    struct SnapshotContext {
        values: [u64; 9],
        hardware: [u64; 9],
        reads: u64,
    }

    core::arch::global_asm!(
        ".text",
        ".globl snapshot_test_vmcs01",
        "snapshot_test_vmcs01:",
        "push r12", "mov r12, rcx",
        "call .Lresident_nested_snapshot_vmcs01_effective_state",
        "pop r12", "ret",
        include_str!("../builds/nested-ept-tests/resident-snapshot.S"),
        guest_pat = const 0,
        guest_efer = const 1,
        tsc_offset = const 2,
        vm_entry_controls = const 3,
        pin_based_vm_exec_control = const 4,
        cpu_based_vm_exec_control = const 5,
        secondary_vm_exec_control = const 6,
        vm_exit_controls = const 7,
        ept_pointer = const 8,
        b_nested_inherited_l1_pat = const 0,
        b_nested_inherited_l1_efer = const 8,
        b_nested_inherited_l1_tsc_offset = const 16,
        b_nested_vmcs01_entry_controls = const 24,
        b_nested_vmcs01_pin_based_controls = const 32,
        b_nested_vmcs01_primary_controls = const 40,
        b_nested_vmcs01_secondary_controls = const 48,
        b_nested_vmcs01_exit_controls = const 56,
        b_nested_ept01_pointer = const 64,
        test_hardware = const std::mem::offset_of!(SnapshotContext, hardware),
        test_reads = const std::mem::offset_of!(SnapshotContext, reads),
    );

    unsafe extern "win64" {
        #[link_name = "snapshot_test_vmcs01"]
        fn snapshot_test_vmcs01_raw(context: *mut SnapshotContext);
    }

    fn snapshot_test_vmcs01(context: &mut SnapshotContext) {
        // The nine fixed VMCS selectors index the two inline arrays.
        unsafe { snapshot_test_vmcs01_raw(context) }
    }

    #[test]
    fn vmcs01_snapshot_retains_controls_and_refreshes_live_l1_state() {
        let mut state = SnapshotContext {
            values: [0; 9],
            hardware: [
                0x7040600070406,
                0xd01,
                0,
                0x93fb,
                0x1e,
                0x92006172,
                0xa2,
                0x36ffb,
                0x1234501e,
            ],
            reads: 0,
        };
        snapshot_test_vmcs01(&mut state);
        assert_eq!(state.values, state.hardware);
        assert_eq!(state.reads, 9);
        let controls = state.values[4..].to_vec();
        // Mode changes and TSC adjustment must propagate despite the fixed controls.
        state.hardware[0] = 0x606060606060606;
        state.hardware[1] = 0;
        state.hardware[2] = u64::MAX - 100;
        state.hardware[3] &= !0x200;
        snapshot_test_vmcs01(&mut state);
        assert_eq!(state.values[..4], state.hardware[..4]);
        assert_eq!(state.values[4..], controls);
        assert_eq!(state.reads, 13);
    }

    core::arch::global_asm!(
        ".text",
        ".globl validate_test_address",
        "validate_test_address:",
        "push r12", "mov r12, rcx", "mov r11, rdx",
        "test r8, r8", "jz .Ltest_unaligned_address",
        "call .Lresident_nested_physical_address_is_valid",
        "pop r12", "ret",
        ".Ltest_unaligned_address:",
        "call .Lresident_nested_address_width_is_valid",
        "pop r12", "ret",
        include_str!("../builds/nested-ept-tests/resident-address.S"),
        b_nested_physical_address_bits = const 0,
    );

    unsafe extern "win64" {
        #[link_name = "validate_test_address"]
        fn validate_test_address_raw(width: *const u32, address: u64, aligned: u64) -> u64;
    }

    fn validate_test_address(width: &u32, address: u64, aligned: u64) -> u64 {
        // The address is validated as an integer, never dereferenced.
        unsafe { validate_test_address_raw(width, address, aligned) }
    }

    #[test]
    fn physical_address_validation_honors_cached_width_and_alignment() {
        for width in [36, 39, 48, 52] {
            let last_byte = (1_u64 << width) - 1;
            for (address, aligned, valid) in [
                (last_byte, 0, 1),
                (last_byte, 1, 0),
                (last_byte & !4095, 1, 1),
                (last_byte + 1, 0, 0),
                (last_byte + 1, 1, 0),
                (u64::MAX, 0, 0),
            ] {
                assert_eq!(validate_test_address(&width, address, aligned), valid);
            }
        }
        assert_eq!(validate_test_address(&0, 0, 1), 0);
        assert_eq!(validate_test_address(&64, u64::MAX, 0), 1);
    }

    #[repr(C)]
    struct MsrContext {
        host_cr3: u64,
        host_mapping_cache: [u64; 4],
        exit_store: u64,
        root_guest: u64,
        l1_store: u64,
        l1_store_count: u64,
        captured_count: u64,
        l1_load: u64,
        l1_load_count: u64,
        l1_entry: u64,
        composed: u64,
        hardware: [u64; 2],
        writes: u64,
    }

    core::arch::global_asm!(
        ".text",
        ".globl complete_test_msr_exit",
        "complete_test_msr_exit:",
        "push rbx", "push rbp", "push rdi", "push rsi",
        "push r12", "push r13", "push r14", "push r15",
        "mov r12, rcx", "mov r10, rdx",
        "call .Lresident_nested_complete_vmcs02_msr_exit",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop rsi", "pop rdi", "pop rbp", "pop rbx", "ret",
        ".globl activate_test_msr_entry",
        "activate_test_msr_entry:",
        "push r12", "mov r12, rcx",
        "call .Lresident_nested_activate_vmcs01_msr_entry",
        "pop r12", "ret",
        include_str!("../builds/nested-ept-tests/resident-msr-exit.S"),
        b_nested_vmcs02_exit_store_msr_list = const std::mem::offset_of!(MsrContext, exit_store),
        b_nested_l0_msr_guest_list = const std::mem::offset_of!(MsrContext, root_guest),
        b_nested_vmcs12_vm_exit_msr_store_addr = const std::mem::offset_of!(MsrContext, l1_store),
        b_nested_vmcs12_vm_exit_msr_store_count = const std::mem::offset_of!(MsrContext, l1_store_count),
        b_nested_captured_msr_store_count = const std::mem::offset_of!(MsrContext, captured_count),
        b_nested_current_vmcs = const std::mem::offset_of!(MsrContext, l1_store),
        nested_guest_msr_list_capacity = const 512,
        b_nested_vmcs12_vm_exit_msr_load_addr = const std::mem::offset_of!(MsrContext, l1_load),
        b_nested_vmcs12_vm_exit_msr_load_count = const std::mem::offset_of!(MsrContext, l1_load_count),
        b_nested_vmcs01_entry_msr_list = const std::mem::offset_of!(MsrContext, l1_entry),
        b_nested_vmcs01_msr_entry_composed = const std::mem::offset_of!(MsrContext, composed),
        test_hardware = const std::mem::offset_of!(MsrContext, hardware),
        test_writes = const std::mem::offset_of!(MsrContext, writes),
        vm_entry_msr_load_addr = const 0,
        vm_entry_msr_load_count = const 1,
    );

    unsafe extern "win64" {
        fn complete_test_msr_exit(context: *mut MsrContext, exit_reason: u64);
        fn activate_test_msr_entry(context: *mut MsrContext);
    }

    #[test]
    fn nested_msr_exit_preserves_l1_lists_and_root_speculation_state() {
        let mut arena = Arena::new();
        let buffers = arena.pages(1);
        let mut state = MsrContext {
            host_cr3: arena.host_map(),
            host_mapping_cache: [0; 4],
            exit_store: buffers,
            root_guest: buffers + 0x100,
            l1_store: buffers + 0x200,
            l1_store_count: 3,
            captured_count: 4,
            l1_load: buffers + 0x300,
            l1_load_count: 2,
            l1_entry: buffers + 0x400,
            composed: 0,
            hardware: [buffers + 0x100, 1],
            writes: 0,
        };
        unsafe {
            let source = std::slice::from_raw_parts_mut(state.exit_store as *mut u64, 8);
            source.copy_from_slice(&[0x48, 7, 0xc0000102, 0x1234, 0x48, 7, 0xc0000103, 3]);
            let target = std::slice::from_raw_parts_mut(state.l1_store as *mut u64, 6);
            target.copy_from_slice(&[0xc0000102, 0, 0x48, 0, 0xc0000103, 0]);
            let load = std::slice::from_raw_parts_mut(state.l1_load as *mut u64, 4);
            load.copy_from_slice(&[0x48, 9, 0xc0000102, 0x5678]);
            (state.root_guest as *mut u64).write(0x48);
            complete_test_msr_exit(&mut state, 18);
            assert_eq!(target, &[0xc0000102, 0x1234, 0x48, 7, 0xc0000103, 3]);
            let entry = std::slice::from_raw_parts(state.l1_entry as *const u64, 6);
            assert_eq!(entry, &[0x48, 7, 0x48, 9, 0xc0000102, 0x5678]);
            source[1] = 11;
            complete_test_msr_exit(&mut state, 0x80000021);
            assert_eq!(entry, &[0x48, 7, 0x48, 9, 0xc0000102, 0x5678]);
            activate_test_msr_entry(&mut state);
            assert_eq!(state.hardware, [state.l1_entry, 3]);
            assert_eq!(state.composed, 1);
            assert_eq!(state.writes, 2);
            // The first L1 exit restores this base list before its next nested entry.
            state.hardware = [state.root_guest, 1];
            state.composed = 0;
            state.l1_load_count = 0;
            complete_test_msr_exit(&mut state, 18);
            activate_test_msr_entry(&mut state);
            assert_eq!(state.hardware, [state.root_guest, 1]);
            assert_eq!(state.composed, 0);
            assert_eq!(state.writes, 2);
            assert_eq!((state.root_guest as *const u64).add(1).read(), 11);
        }
    }

    #[repr(C)]
    #[derive(Default)]
    struct VpidContext {
        primary: u64,
        secondary: u64,
        hardware_controls: u64,
        virtual_tag: u64,
        last_tag: u64,
        flushes: u64,
        kind: u64,
        hardware_tag: u64,
        cache: u64,
        selected_tag: u64,
    }

    core::arch::global_asm!(
        ".text",
        ".globl prepare_test_vpid",
        "prepare_test_vpid:",
        "push r12", "mov r12, rcx",
        "call .Lresident_nested_prepare_vpid02",
        "pop r12", "ret",
        ".globl invalidate_test_vpid",
        "invalidate_test_vpid:",
        "push r12", "mov r12, rcx", "mov r9, rdx", "mov r10, r8",
        "call .Lresident_nested_invvpid_validate",
        "pop r12", "ret",
        include_str!("../builds/nested-ept-tests/resident-vpid.S"),
        b_nested_vmcs12_primary_control = const std::mem::offset_of!(VpidContext, primary),
        b_nested_vmcs12_secondary_control = const std::mem::offset_of!(VpidContext, secondary),
        b_nested_vmcs01_secondary_controls = const std::mem::offset_of!(VpidContext, hardware_controls),
        b_nested_vmcs12_vpid = const std::mem::offset_of!(VpidContext, virtual_tag),
        b_nested_vmcs02_last_vpid = const std::mem::offset_of!(VpidContext, last_tag),
        b_nested_vmcs02_vpid_cache = const std::mem::offset_of!(VpidContext, cache),
        virtual_processor_id = const 0,
        test_flushes = const std::mem::offset_of!(VpidContext, flushes),
        test_kind = const std::mem::offset_of!(VpidContext, kind),
        test_tag = const std::mem::offset_of!(VpidContext, hardware_tag),
        test_selected_tag = const std::mem::offset_of!(VpidContext, selected_tag),
    );

    unsafe extern "win64" {
        #[link_name = "prepare_test_vpid"]
        fn prepare_test_vpid_raw(context: *mut VpidContext);
        #[link_name = "invalidate_test_vpid"]
        fn invalidate_test_vpid_raw(
            context: *mut VpidContext,
            kind: u64,
            descriptor: *const u64,
        ) -> u64;
    }

    fn invalidate_test_vpid(context: &mut VpidContext, kind: u64, descriptor: &[u64; 2]) -> u64 {
        // The descriptor contains both qwords consumed by the validation routine.
        unsafe { invalidate_test_vpid_raw(context, kind, descriptor.as_ptr()) }
    }

    fn prepare_test_vpid(context: &mut VpidContext) {
        // VPID tags and the packed cache are integers; hardware operations are mocked.
        unsafe { prepare_test_vpid_raw(context) }
    }

    #[test]
    fn vpid_cache_retains_virtual_tags_and_invalidates_each_l2_entry() {
        let mut state = VpidContext {
            primary: 1 << 31,
            secondary: 1 << 5,
            hardware_controls: 1 << 5,
            virtual_tag: 1,
            cache: 48 << 32,
            ..Default::default()
        };
        for (tag, selected, expected_flushes) in [
            (1, 2, 1),
            (1, 2, 2),
            (2, 3, 3),
            (2, 3, 4),
            (1, 2, 5),
            (3, 3, 6),
            (1, 2, 7),
            (2, 3, 8),
        ] {
            state.virtual_tag = tag;
            prepare_test_vpid(&mut state);
            assert_eq!(state.flushes, expected_flushes);
            assert_eq!(state.selected_tag, selected);
            assert_eq!(state.kind, 1);
            assert_ne!(state.hardware_tag, 1);
        }
        state.secondary = 0;
        prepare_test_vpid(&mut state);
        assert_eq!(state.last_tag, 0);
        assert_eq!(state.flushes, 10);
        assert_eq!(state.cache, 48 << 32);
        state.secondary = 1 << 5;
        prepare_test_vpid(&mut state);
        assert_eq!(state.flushes, 11);
        state.hardware_controls = 0;
        state.virtual_tag = 3;
        prepare_test_vpid(&mut state);
        assert_eq!(state.flushes, 11);
    }

    #[test]
    fn invvpid_preserves_l1_and_validates_only_architectural_operand_bits() {
        let mut state = VpidContext {
            hardware_controls: 1 << 5,
            last_tag: 5,
            cache: 5 | (6 << 16),
            ..Default::default()
        };
        for kind in 0..4 {
            let linear = if kind == 0 {
                0xffff_8000_0000_0000
            } else {
                u64::MAX
            };
            let descriptor = [5, linear];
            assert_eq!(invalidate_test_vpid(&mut state, kind, &descriptor), 0);
            assert_eq!(
                (state.kind, state.hardware_tag),
                (1, if kind == 2 { 3 } else { 2 })
            );
        }
        assert_eq!(state.flushes, 5);
        for (kind, descriptor) in [
            (0, [5, 0x0001_0000_0000_0000]),
            (1, [0, 0]),
            (2, [1 << 16, 0]),
            (3, [0, 0]),
        ] {
            assert_eq!(invalidate_test_vpid(&mut state, kind, &descriptor), 1);
        }
        assert_eq!(state.flushes, 5);
        assert_eq!(invalidate_test_vpid(&mut state, 1, &[7, 0]), 0);
        assert_eq!(state.flushes, 5);
        assert_eq!(invalidate_test_vpid(&mut state, 1, &[6, 0]), 0);
        assert_eq!((state.flushes, state.hardware_tag), (6, 3));
        assert_eq!(invalidate_test_vpid(&mut state, 2, &[0, u64::MAX]), 0);
        assert_eq!(state.flushes, 8);
    }

    #[repr(C)]
    #[derive(Default)]
    struct Context {
        host_cr3: u64,
        host_mapping_cache: [u64; 4],
        gpa: u64,
        qualification: u64,
        exit_reason: u64,
        ept01: u64,
        invalidations: u64,
        native_invept: u64,
        recycles: u64,
        eviction_cursor: u64,
        table_evictions: u64,
        ept02: u64,
        pool: u64,
        pool_pages: u64,
        pool_used: u64,
        compositions: u64,
        ept12: u64,
        secondary_control: u64,
        cache_initialized: u64,
        cached_ept12: u64,
        mbec: u64,
        primary_control: u64,
        initial_ept02: u64,
        alternate_ept12: u64,
        alternate_ept02: u64,
        alternate_pool: u64,
        alternate_pool_pages: u64,
        alternate_pool_used: u64,
        alternate_mbec: u64,
        telemetry_active: u64,
        vm_function_control: u64,
        eptp_list_address: u64,
        physical_address_bits: u64,
        ept_capabilities: u64,
        shadow_list: u64,
        native_supported: u64,
        native_enabled: u64,
        native_vmcs: [u64; 3],
        admission: u64,
        write_retry: u64,
        sync_result: u64,
        sync_requests: u64,
        sync_releases: u64,
        eptp_pool: u64,
        eptp_pages: u64,
        eptp_used: u64,
        event_context: u64,
        lists_live: u64,
    }

    core::arch::global_asm!(
        ".text",
        ".globl resolve_test_ept",
        "resolve_test_ept:",
        "push rbx", "push rbp", "push rdi", "push rsi",
        "push r12", "push r13", "push r14", "push r15",
        "mov r12, rcx",
        "call .Lresident_nested_resolve_ept02_violation",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop rsi", "pop rdi", "pop rbp", "pop rbx",
        "ret",
        ".globl check_test_host_mapping",
        "check_test_host_mapping:",
        "push r12", "mov r12, rcx", "mov r11, rdx",
        "call .Lresident_ept01_host_page_is_mapped",
        "pop r12", "ret",
        ".globl discard_test_ept",
        "discard_test_ept:",
        "push rbx", "push rbp", "push rdi", "push rsi",
        "push r12", "push r13", "push r14", "push r15",
        "mov r12, rcx",
        "call .Lresident_nested_invalidate_ept02",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop rsi", "pop rdi", "pop rbp", "pop rbx",
        "ret",
        ".globl revalidate_test_ept",
        "revalidate_test_ept:",
        "push rbx", "push rbp", "push rdi", "push rsi",
        "push r12", "push r13", "push r14", "push r15",
        "mov r12, rcx",
        "call .Lresident_nested_revalidate_ept02",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop rsi", "pop rdi", "pop rbp", "pop rbx",
        "ret",
        ".globl prepare_test_ept",
        "prepare_test_ept:",
        "push rbx", "push rbp", "push rdi", "push rsi",
        "push r12", "push r13", "push r14", "push r15",
        "mov r12, rcx",
        "call .Lresident_nested_prepare_ept02",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop rsi", "pop rdi", "pop rbp", "pop rbx",
        "ret",
        ".globl invalidate_test_ept_context",
        "invalidate_test_ept_context:",
        "push rbx", "push rbp", "push rdi", "push rsi",
        "push r12", "push r13", "push r14", "push r15",
        "mov r12, rcx", "mov r14, rdx",
        "call .Lresident_nested_invalidate_ept12_context",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop rsi", "pop rdi", "pop rbp", "pop rbx",
        "ret",
        ".globl switch_test_eptp",
        "switch_test_eptp:",
        "push rbx", "push rbp", "push rdi", "push rsi",
        "push r12", "push r13", "push r14", "push r15",
        "mov r12, rcx", "mov eax, edx", "mov ecx, r8d",
        "call .Lresident_nested_switch_eptp",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop rsi", "pop rdi", "pop rbp", "pop rbx", "ret",
        ".globl invalidate_test_all_ept_contexts",
        "invalidate_test_all_ept_contexts:",
        "push rbx", "push rbp", "push rdi", "push rsi",
        "push r12", "push r13", "push r14", "push r15",
        "mov r12, rcx", "mov r10, rdx",
        "call .Lresident_dispatch_invept_all_contexts",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop rsi", "pop rdi", "pop rbp", "pop rbx", "ret",
        ".globl validate_test_vm_functions",
        "validate_test_vm_functions:",
        "push r12", "mov r12, rcx",
        "call .Lresident_nested_validate_vm_functions",
        "pop r12", "ret",
        ".globl refresh_test_eptp_list",
        "refresh_test_eptp_list:",
        "push rbx", "push rbp", "push rdi", "push rsi",
        "push r12", "push r13", "push r14", "push r15",
        "mov r12, rcx", "call .Lresident_nested_refresh_eptp_list",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop rsi", "pop rdi", "pop rbp", "pop rbx", "ret",
        ".globl capture_test_native_eptp",
        "capture_test_native_eptp:",
        "push r12", "mov r12, rcx", "call .Lresident_nested_capture_native_eptp",
        "pop r12", "ret",
        ".globl release_test_eptp_sources",
        "release_test_eptp_sources:",
        "push rbx", "push rbp", "push rdi", "push rsi",
        "push r12", "push r13", "push r14", "push r15",
        "mov r12, rcx", "call .Lresident_nested_eptp_release_sources",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop rsi", "pop rdi", "pop rbp", "pop rbx", "ret",
        ".globl root_write_test_eptp",
        "root_write_test_eptp:",
        "push r12", "mov r12, rcx",
        "call .Lresident_nested_eptp_before_root_write",
        "pop r12", "ret",
        include_str!("../builds/nested-ept-tests/resident-ept.S"),
        b_event_context = const std::mem::offset_of!(Context, event_context),
        event_cpu_contexts = const 0,
        test_lists_live = const std::mem::offset_of!(Context, lists_live),
        b_nested_eptp_shadow_list = const std::mem::offset_of!(Context, shadow_list),
        b_nested_eptp_native_supported = const std::mem::offset_of!(Context, native_supported),
        b_nested_eptp_native_enabled = const std::mem::offset_of!(Context, native_enabled),
        b_nested_eptp_admission = const std::mem::offset_of!(Context, admission),
        b_nested_eptp_write_retry = const std::mem::offset_of!(Context, write_retry),
        test_sync_result = const std::mem::offset_of!(Context, sync_result),
        test_sync_requests = const std::mem::offset_of!(Context, sync_requests),
        test_sync_releases = const std::mem::offset_of!(Context, sync_releases),
        b_nested_eptp_table_pool = const std::mem::offset_of!(Context, eptp_pool),
        b_nested_eptp_table_pages = const std::mem::offset_of!(Context, eptp_pages),
        b_nested_eptp_table_used = const std::mem::offset_of!(Context, eptp_used),
        test_native_vmcs = const std::mem::offset_of!(Context, native_vmcs),
        vm_function_control = const 0,
        eptp_list_address = const 1,
        ept_pointer = const 2,
        b_nested_vmcs12_vm_function_control = const std::mem::offset_of!(Context, vm_function_control),
        b_nested_vmcs12_eptp_list_address = const std::mem::offset_of!(Context, eptp_list_address),
        b_nested_physical_address_bits = const std::mem::offset_of!(Context, physical_address_bits),
        b_nested_vmx_ept_vpid_cap = const std::mem::offset_of!(Context, ept_capabilities),
        b_expected_host_cr3 = const std::mem::offset_of!(Context, host_cr3),
        b_telemetry_active = const std::mem::offset_of!(Context, telemetry_active),
        b_nested_host_mapping_cache = const std::mem::offset_of!(Context, host_mapping_cache),
        b_last_guest_physical_address = const std::mem::offset_of!(Context, gpa),
        b_last_qualification = const std::mem::offset_of!(Context, qualification),
        b_last_reason = const std::mem::offset_of!(Context, exit_reason),
        ept_misconfiguration_reason = const 49,
        b_nested_ept01_pointer = const std::mem::offset_of!(Context, ept01),
        b_cache_ept_pointer = const std::mem::offset_of!(Context, ept01),
        b_nested_ept02_invalidation_count = const std::mem::offset_of!(Context, invalidations),
        b_invept_exits = const std::mem::offset_of!(Context, native_invept),
        b_nested_ept02_recycle_count = const std::mem::offset_of!(Context, recycles),
        b_nested_ept02_pointer = const std::mem::offset_of!(Context, ept02),
        b_nested_ept02_table_pool = const std::mem::offset_of!(Context, pool),
        b_nested_ept02_table_pool_pages = const std::mem::offset_of!(Context, pool_pages),
        b_nested_ept02_table_pool_used = const std::mem::offset_of!(Context, pool_used),
        b_nested_ept02_eviction_cursor = const std::mem::offset_of!(Context, eviction_cursor),
        b_nested_ept02_table_eviction_count = const std::mem::offset_of!(Context, table_evictions),
        b_nested_ept_composition_count = const std::mem::offset_of!(Context, compositions),
        b_nested_vmcs12_ept_pointer = const std::mem::offset_of!(Context, ept12),
        b_nested_vmcs12_secondary_control = const std::mem::offset_of!(Context, secondary_control),
        b_nested_ept02_cache_initialized = const std::mem::offset_of!(Context, cache_initialized),
        b_nested_ept12_pointer = const std::mem::offset_of!(Context, cached_ept12),
        b_nested_ept02_mbec = const std::mem::offset_of!(Context, mbec),
        b_nested_vmcs12_primary_control = const std::mem::offset_of!(Context, primary_control),
        b_nested_ept02_initial_pointer = const std::mem::offset_of!(Context, initial_ept02),
        b_nested_ept02_cached_ept12_pointer = const std::mem::offset_of!(Context, alternate_ept12),
        b_nested_ept02_cached_pointer = const std::mem::offset_of!(Context, alternate_ept02),
        b_nested_ept02_cached_table_pool = const std::mem::offset_of!(Context, alternate_pool),
        b_nested_ept02_cached_table_pool_pages = const std::mem::offset_of!(Context, alternate_pool_pages),
        b_nested_ept02_cached_table_pool_used = const std::mem::offset_of!(Context, alternate_pool_used),
        b_nested_ept02_cached_mbec = const std::mem::offset_of!(Context, alternate_mbec),
        guest_physical_address = const 0x2400,
        host_page_address_mask = const 0x000f_ffff_ffff_f000u64,
    );

    unsafe extern "win64" {
        fn check_test_host_mapping(context: *mut Context, address: u64) -> u64;
        fn resolve_test_ept(context: *mut Context) -> u64;
        fn discard_test_ept(context: *mut Context);
        fn revalidate_test_ept(context: *mut Context);
        fn prepare_test_ept(context: *mut Context);
        fn invalidate_test_ept_context(context: *mut Context, ept_pointer: u64);
        fn invalidate_test_all_ept_contexts(context: *mut Context, descriptor: *const u64) -> u64;
        fn switch_test_eptp(context: *mut Context, function: u64, index: u64) -> u64;
        fn validate_test_vm_functions(context: *mut Context) -> u64;
        fn refresh_test_eptp_list(context: *mut Context);
        fn capture_test_native_eptp(context: *mut Context);
        fn release_test_eptp_sources(context: *mut Context) -> u64;
        fn root_write_test_eptp(context: *mut Context);
    }

    const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
    struct Arena {
        allocations: Vec<(*mut u8, Layout)>,
        ept12_mappings: HashMap<u64, u64>,
    }
    impl Arena {
        fn new() -> Self {
            Self {
                allocations: Vec::new(),
                ept12_mappings: HashMap::new(),
            }
        }
        fn pages(&mut self, count: usize) -> u64 {
            let layout = Layout::from_size_align(count * 4096, 4096).unwrap();
            let pointer = unsafe { alloc_zeroed(layout) };
            assert!(!pointer.is_null());
            self.allocations.push((pointer, layout));
            pointer as u64
        }
        fn map(&mut self, root: u64, address: u64, target: u64, shift: u32, attributes: u64) {
            let mut table = root;
            for level in [39, 30, 21, 12] {
                let slot = table + ((address >> level) & 511) * 8;
                if level == shift {
                    unsafe {
                        (slot as *mut u64).write(target | attributes);
                    }
                    if let Some(&ept01) = self.ept12_mappings.get(&root) {
                        self.map_ept12_tables(root, ept01, 39);
                    }
                    return;
                }
                let entry = unsafe { (slot as *const u64).read() };
                if entry & 7 == 0 {
                    let child = self.pages(1);
                    unsafe {
                        (slot as *mut u64).write(child | 0x407);
                    }
                    table = child;
                } else {
                    assert_eq!(entry & 128, 0);
                    table = entry & ADDRESS_MASK;
                }
            }
            panic!("Invalid leaf size");
        }
        fn expose_ept12(&mut self, root: u64, ept01: u64) {
            self.ept12_mappings.insert(root, ept01);
            self.map_ept12_tables(root, ept01, 39);
        }
        fn map_ept12_tables(&mut self, table: u64, ept01: u64, shift: u32) {
            self.map(ept01, table, table, 12, 0x37);
            if shift == 12 {
                return;
            }
            for index in 0..512 {
                let entry = unsafe { (table as *const u64).add(index).read() };
                if entry & 0x407 != 0 && entry & 0x80 == 0 {
                    self.map_ept12_tables(entry & ADDRESS_MASK, ept01, shift - 9);
                }
            }
        }
        fn host_map(&mut self) -> u64 {
            let root = self.pages(1);
            let addresses: Vec<_> = self.allocations.iter().map(|(p, _)| *p as u64).collect();
            let mut ranges = HashMap::new();
            for address in addresses.into_iter().chain([0, 0x4000_0000]) {
                let index = (address >> 39) & 511;
                let pdpt = *ranges.entry(index).or_insert_with(|| self.pages(1));
                unsafe {
                    ((root + index * 8) as *mut u64).write(pdpt | 3);
                }
                for j in 0..512 {
                    unsafe {
                        ((pdpt + j * 8) as *mut u64).write((index << 39) | (j << 30) | 0x83);
                    }
                }
            }
            root
        }
    }
    impl Drop for Arena {
        fn drop(&mut self) {
            for &(pointer, layout) in &self.allocations {
                unsafe {
                    dealloc(pointer, layout);
                }
            }
        }
    }
    fn leaf(root: u64, address: u64) -> (u32, u64) {
        let mut table = root & ADDRESS_MASK;
        for shift in [39, 30, 21, 12] {
            let entry = unsafe { ((table + ((address >> shift) & 511) * 8) as *const u64).read() };
            if entry & 7 == 0 || shift == 12 || entry & 128 != 0 {
                return (shift, entry);
            }
            table = entry & ADDRESS_MASK;
        }
        unreachable!()
    }
    fn entry_addresses(root: u64, address: u64) -> Vec<u64> {
        let mut table = root & ADDRESS_MASK;
        let mut addresses = Vec::new();
        for shift in [39, 30, 21, 12] {
            let slot = table + ((address >> shift) & 511) * 8;
            addresses.push(slot);
            let entry = unsafe { (slot as *const u64).read() };
            if shift == 12 || entry & 128 != 0 {
                break;
            }
            table = entry & ADDRESS_MASK;
        }
        addresses
    }

    #[test]
    fn accessed_dirty_tracks_first_access_and_write_without_discarding_other_leaves() {
        for shift in [12, 21] {
            let mut arena = Arena::new();
            let ept12 = arena.pages(1);
            let ept01 = arena.pages(1);
            let large = if shift == 21 { 0x80 } else { 0 };
            arena.map(ept12, 0x200000, 0x400000, shift, 0x37 | large);
            arena.map(ept12, 0x600000, 0x800000, 21, 0xb7);
            arena.map(ept01, 0x400000, 0x400000, 21, 0xb7);
            arena.map(ept01, 0x800000, 0x800000, 21, 0xb7);
            let mut state = context(&mut arena, ept12 | 0x40, ept01);
            state.cached_ept12 = state.ept12;
            state.gpa = 0x600000;
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
            let other_leaf = leaf(state.ept02, state.gpa);
            state.gpa = 0x200000;
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
            let entries = entry_addresses(ept12, state.gpa);
            for address in &entries {
                assert_eq!(unsafe { (*address as *const u64).read() } & 0x300, 0x100);
            }
            assert_eq!(leaf(state.ept02, state.gpa).1 & 0x302, 0x300);
            let used = state.pool_used;
            state.qualification = 2;
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
            assert_eq!(leaf(ept12, state.gpa).1 & 0x300, 0x300);
            assert_eq!(leaf(state.ept02, state.gpa).1 & 0x302, 0x302);
            assert_eq!(leaf(state.ept02, 0x600000), other_leaf);
            assert_eq!(state.pool_used, used);
            for address in &entries[..entries.len() - 1] {
                assert_eq!(unsafe { (*address as *const u64).read() } & 0x200, 0);
            }
        }
    }

    #[test]
    fn accessed_dirty_invalidation_preserves_cleared_flags_until_real_access() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
        arena.map(ept01, 0x400000, 0x400000, 21, 0xb7);
        let mut state = context(&mut arena, ept12 | 0x40, ept01);
        state.cached_ept12 = state.ept12;
        state.qualification = 2;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        let entries = entry_addresses(ept12, state.gpa);
        let last = *entries.last().unwrap() as *mut u64;
        unsafe { *last &= !0x200 };
        unsafe { discard_test_ept(&mut state) };
        assert_eq!(unsafe { *last } & 0x300, 0x100);
        assert_eq!(leaf(state.ept02, state.gpa).1 & 2, 0);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(unsafe { *last } & 0x300, 0x300);
        for address in entries {
            unsafe { *(address as *mut u64) &= !0x100 };
            unsafe { discard_test_ept(&mut state) };
            assert_eq!(leaf(state.ept02, state.gpa).1, 0);
            assert_eq!(unsafe { *(address as *const u64) } & 0x100, 0);
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
            assert_ne!(unsafe { *(address as *const u64) } & 0x100, 0);
        }
    }

    #[test]
    fn accessed_dirty_does_not_mark_denied_writes_or_change_disabled_flags() {
        for (ad, l1, l0) in [(true, 0xb5, 0xb7), (true, 0xb7, 0xb5), (false, 0xb7, 0xb7)] {
            let mut arena = Arena::new();
            let ept12 = arena.pages(1);
            let ept01 = arena.pages(1);
            arena.map(ept12, 0x200000, 0x400000, 21, l1);
            arena.map(ept01, 0x400000, 0x400000, 21, l0);
            let mut state = context(&mut arena, ept12 | if ad { 0x40 } else { 0 }, ept01);
            state.qualification = 2;
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, u64::from(!ad));
            for address in entry_addresses(ept12, state.gpa) {
                let entry = unsafe { (address as *const u64).read() };
                assert_eq!(entry & 0x200, 0);
                assert_eq!(entry & 0x100, if ad { 0x100 } else { 0 });
            }
        }
    }

    fn context(arena: &mut Arena, ept12: u64, ept01: u64) -> Context {
        if ept12 & ADDRESS_MASK != 0 && ept01 != 0 {
            arena.expose_ept12(ept12 & ADDRESS_MASK, ept01);
        }
        let ept02 = arena.pages(1);
        let pool = arena.pages(16);
        let alternate_ept02 = arena.pages(1);
        let alternate_pool = arena.pages(16);
        let eptp_pool = arena.pages(4);
        Context {
            eptp_pool,
            eptp_pages: 4,
            lists_live: 1,
            telemetry_active: 1,
            host_cr3: arena.host_map(),
            gpa: 0x203000,
            qualification: 1,
            exit_reason: 48,
            ept01,
            ept12,
            ept02,
            physical_address_bits: 52,
            ept_capabilities: 1 | (1 << 16) | (1 << 17),
            pool,
            pool_pages: 16,
            secondary_control: 2,
            cache_initialized: 1,
            cached_ept12: ept12,
            primary_control: 1 << 31,
            initial_ept02: ept02,
            alternate_ept02,
            alternate_pool,
            alternate_pool_pages: 16,
            ..Default::default()
        }
    }

    #[test]
    fn inactive_l1_ept_does_not_resolve_an_exit_using_stale_tables() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        state.primary_control = 0;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
        assert_eq!(state.pool_used, 0);
        assert_eq!(state.compositions, 0);
        state.primary_control = 1 << 31;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert!(state.pool_used > 0);
    }

    #[test]
    fn disabled_telemetry_keeps_ept_composition_and_invalidation_operational() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        state.telemetry_active = 0;
        unsafe {
            assert_eq!(resolve_test_ept(&mut state), 1);
            discard_test_ept(&mut state);
            assert_eq!(resolve_test_ept(&mut state), 1);
        }
        assert_eq!(state.compositions, 0);
        assert_eq!(state.invalidations, 0);
        assert_eq!(state.native_invept, 0);
        assert!(state.pool_used > 0);
    }

    #[test]
    fn vmfunc_switches_remapped_list_entries_and_retains_both_cached_roots() {
        let mut arena = Arena::new();
        let first = arena.pages(1) | 0x1e;
        let second = arena.pages(1) | 0x1e;
        let ept01 = arena.pages(1);
        let list = arena.pages(1);
        arena.map(ept01, 0x9000, list, 12, 0x31);
        arena.map(first & ADDRESS_MASK, 0x200000, 0x400000, 21, 0xb7);
        arena.map(second & ADDRESS_MASK, 0x200000, 0x600000, 21, 0xb7);
        arena.expose_ept12(second & ADDRESS_MASK, ept01);
        arena.map(ept01, 0x400000, 0x800000, 21, 0xb7);
        arena.map(ept01, 0x600000, 0xa00000, 21, 0xb7);
        unsafe {
            (list as *mut u64).write(first);
            (list as *mut u64).add(511).write(second);
        }
        let mut state = context(&mut arena, first, ept01);
        state.secondary_control |= 1 << 13;
        state.vm_function_control = 1;
        state.eptp_list_address = 0x9000;
        state.physical_address_bits = 52;
        let first_root = state.ept02;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        let first_leaf = leaf(state.ept02, state.gpa);
        assert_eq!(first_leaf.1 & ADDRESS_MASK, 0x800000);
        assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 511) }, 1);
        assert_eq!(state.ept12, second);
        assert_ne!(state.ept02, first_root);
        assert_eq!(state.invalidations, 1);
        let second_root = state.ept02;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        let second_leaf = leaf(state.ept02, state.gpa);
        assert_eq!(second_leaf.1 & ADDRESS_MASK, 0xa00000);
        for _ in 0..8 {
            assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 0) }, 1);
            assert_eq!(state.ept02, first_root);
            assert_eq!(leaf(state.ept02, state.gpa), first_leaf);
            assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 511) }, 1);
            assert_eq!(state.ept02, second_root);
            assert_eq!(leaf(state.ept02, state.gpa), second_leaf);
        }
        assert_eq!(state.invalidations, 1);
        assert_eq!(state.compositions, 2);
        assert_eq!(unsafe { switch_test_eptp(&mut state, 1 << 32, 1 << 32) }, 1);
        assert_eq!(state.ept12, first);
    }

    #[test]
    fn vmfunc_invalid_requests_preserve_the_active_ept() {
        let mut arena = Arena::new();
        let first = arena.pages(1) | 0x1e;
        let ept01 = arena.pages(1);
        let list = arena.pages(1);
        arena.map(ept01, 0x9000, list, 12, 0x31);
        let mut state = context(&mut arena, first, ept01);
        state.secondary_control |= 1 << 13;
        state.vm_function_control = 1;
        state.eptp_list_address = 0x9000;
        state.physical_address_bits = 48;
        let root = state.ept02;
        for entry in [0, first | 0x80, first | (1 << 48), first ^ 1, first | 0x40] {
            unsafe { (list as *mut u64).write(entry) };
            assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 0) }, 0);
            assert_eq!(state.ept12, first);
            assert_eq!(state.ept02, root);
            assert_eq!(state.invalidations, 0);
        }
        unsafe { (list as *mut u64).write(first) };
        for (function, index) in [(1, 0), (63, 0), (0, 512), (0, u32::MAX as u64)] {
            assert_eq!(unsafe { switch_test_eptp(&mut state, function, index) }, 0);
        }
        state.vm_function_control = 0;
        assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 0) }, 0);
        state.vm_function_control = 1;
        state.primary_control = 0;
        assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 0) }, 0);
        state.primary_control = 1 << 31;
        state.secondary_control = 2;
        assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 0) }, 0);
        state.secondary_control = 0x2002;
        arena.map(ept01, 0x9000, list, 12, 0x34);
        assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 0) }, 0);
        assert_eq!(state.ept12, first);
        assert_eq!(state.ept02, root);
        assert_eq!(state.invalidations, 0);
    }

    #[test]
    fn native_eptp_list_publishes_composed_roots_and_recovers_hardware_selection() {
        let mut arena = Arena::new();
        let first = arena.pages(1) | 0x1e;
        let second = arena.pages(1) | 0x1e;
        let cold = arena.pages(1) | 0x1e;
        let list = arena.pages(1);
        let shadow = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept01, 0x9000, list, 12, 0x31);
        unsafe {
            (list as *mut u64).write(first);
            (list as *mut u64).add(1).write(second);
            (list as *mut u64).add(2).write(cold);
            (list as *mut u64).add(3).write(u64::MAX);
            (list as *mut u64).add(511).write(second);
        }
        let mut state = context(&mut arena, first, ept01);
        state.secondary_control = 0x2002;
        state.vm_function_control = 1;
        state.eptp_list_address = 0x9000;
        state.physical_address_bits = 52;
        state.shadow_list = shadow;
        state.native_supported = 1;
        assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 1) }, 1);
        let second_root = state.ept02;
        let first_root = state.alternate_ept02;
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_enabled, 1);
        assert_eq!(state.native_vmcs[..2], [1, shadow]);
        let published = unsafe { std::slice::from_raw_parts(shadow as *const u64, 512) };
        assert_eq!(published[0], first_root);
        assert_eq!(published[1], second_root);
        assert_eq!(published[511], second_root);
        assert!(published[2..511].iter().all(|entry| *entry == 0));

        let old_pool = state.pool;
        let old_alternate_pool = state.alternate_pool;
        state.native_vmcs[2] = published[0];
        unsafe { capture_test_native_eptp(&mut state) };
        assert_eq!(state.ept12, first);
        assert_eq!(state.ept02, first_root);
        assert_eq!(state.pool, old_alternate_pool);
        assert_eq!(state.alternate_pool, old_pool);
        state.native_vmcs[2] = published[511];
        unsafe { capture_test_native_eptp(&mut state) };
        assert_eq!(state.ept12, second);
        assert_eq!(state.ept02, second_root);
        assert_eq!(state.pool, old_pool);
        assert_eq!(state.invalidations, 1);

        assert_eq!(unsafe { switch_test_eptp(&mut state, 0, 2) }, 1);
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(
            published[0], 0,
            "A recycled root must lose its old list aliases"
        );
        assert_eq!(published[1], second_root);
        assert_eq!(published[2], state.ept02);
        state.vm_function_control = 0;
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_enabled, 0);
        assert_eq!(state.native_vmcs[0], 0);
    }

    #[test]
    fn native_eptp_list_requires_stable_source_and_matching_execution_mode() {
        let mut arena = Arena::new();
        let first = arena.pages(1) | 0x5e;
        let list = arena.pages(1);
        let shadow = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept01, 0x9000, list, 12, 0x33);
        unsafe { (list as *mut u64).write(first) };
        let mut state = context(&mut arena, first, ept01);
        state.ept02 |= 0x1e;
        state.secondary_control = 0x2002;
        state.vm_function_control = 1;
        state.eptp_list_address = 0x9000;
        state.physical_address_bits = 52;
        state.ept_capabilities = 1 << 21;
        state.shadow_list = shadow;
        state.native_supported = 1;
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_enabled, 0);
        arena.map(ept01, 0x9000, list, 12, 0x31);
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_enabled, 1);
        assert_eq!(unsafe { (shadow as *const u64).read() }, state.ept02 | 0x40);
        state.native_vmcs[2] = state.ept02 | 0x40;
        unsafe { capture_test_native_eptp(&mut state) };
        assert_eq!(state.ept12, first);
        state.secondary_control |= 1 << 22;
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(unsafe { (shadow as *const u64).read() }, 0);
        state.native_supported = 0;
        state.native_vmcs = [0xfeed; 3];
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_vmcs, [0xfeed; 3]);
    }

    #[test]
    fn native_eptp_list_rejects_writable_physical_aliases_at_every_leaf_size() {
        for shift in [12, 21, 30] {
            let mut arena = Arena::new();
            let first = arena.pages(1) | 0x1e;
            let list = arena.pages(1);
            let shadow = arena.pages(1);
            let ept01 = arena.pages(1);
            let alias = (1_u64 << 39) + (5_u64 << 30);
            let size = 1_u64 << shift;
            let target = list & !(size - 1);
            let large = if shift == 12 { 0 } else { 0x80 };
            arena.map(ept01, 0x9000, list, 12, 0x31);
            arena.map(ept01, alias, target, shift, 0x31 | large);
            unsafe { (list as *mut u64).write(first) };
            let mut state = context(&mut arena, first, ept01);
            state.ept02 |= 0x1e;
            state.secondary_control = 0x2002;
            state.vm_function_control = 1;
            state.eptp_list_address = 0x9000;
            state.physical_address_bits = 52;
            state.shadow_list = shadow;
            state.native_supported = 1;
            unsafe { refresh_test_eptp_list(&mut state) };
            assert_eq!(state.native_enabled, 1);

            arena.map(ept01, alias, target, shift, 0x33 | large);
            unsafe { refresh_test_eptp_list(&mut state) };
            assert_eq!(state.native_enabled, 0, "Writable alias with shift {shift}");
            assert_eq!(state.native_vmcs[0], 0);

            // A denial at any ancestor removes effective write access to the alias.
            let entries = entry_addresses(ept01, alias);
            for &address in &entries[..entries.len() - 1] {
                unsafe { *(address as *mut u64) &= !2 };
                unsafe { refresh_test_eptp_list(&mut state) };
                assert_eq!(state.native_enabled, 1);
                unsafe { *(address as *mut u64) |= 2 };
            }

            arena.map(ept01, alias, target ^ size, shift, 0x33 | large);
            unsafe { refresh_test_eptp_list(&mut state) };
            assert_eq!(
                state.native_enabled, 1,
                "Unrelated writable leaf with shift {shift}"
            );
            assert_eq!(unsafe { (shadow as *const u64).read() }, state.ept02);
        }
    }

    #[test]
    fn writable_lists_are_protected_before_publication_and_deoptimized_before_a_write() {
        const TRACKED: u64 = 1 << 55;
        for shift in [12, 21, 30] {
            let mut arena = Arena::new();
            let first = arena.pages(1) | 0x1e;
            let list = arena.pages(1);
            let shadow = arena.pages(1);
            let ept01 = arena.pages(1);
            let alias = 1_u64 << 39;
            let size = 1_u64 << shift;
            let alias_page = alias + (list & (size - 1));
            let large = if shift == 12 { 0 } else { 0x80 };
            arena.map(ept01, 0x9000, list, 12, 0x37);
            arena.map(ept01, alias, list & !(size - 1), shift, 0x33 | large);
            arena.map(ept01, 0xa000, list, 12, 0x31);
            arena.map(first & ADDRESS_MASK, 0x200000, 0x9000, 12, 0x37);
            unsafe { (list as *mut u64).write(first) };
            let mut state = context(&mut arena, first, ept01);
            state.ept02 |= 0x1e;
            state.secondary_control = 0x2002;
            state.vm_function_control = 1;
            state.eptp_list_address = 0x9000;
            state.physical_address_bits = 52;
            state.shadow_list = shadow;
            state.native_supported = 1;
            state.admission = 1;
            let original = [leaf(ept01, 0x9000), leaf(ept01, alias), leaf(ept01, 0xa000)];

            // Failed quiescence preserves EPT permissions and keeps native VMFUNC disabled.
            unsafe { refresh_test_eptp_list(&mut state) };
            assert_eq!(state.native_enabled, 0);
            assert_eq!(leaf(ept01, 0x9000), original[0]);
            assert_eq!(state.sync_releases, 0);
            state.admission = 1;
            state.sync_result = 1;
            unsafe { refresh_test_eptp_list(&mut state) };
            assert_eq!(state.native_enabled, 1);
            assert_eq!(state.admission, 0);
            assert_eq!(state.sync_releases, 1);
            assert_eq!(leaf(ept01, 0x9000).1, (original[0].1 & !2) | TRACKED);
            assert_eq!(leaf(ept01, alias_page), (12, list | 0x31 | TRACKED));
            if shift != 12 {
                let neighbor = alias_page ^ 4096;
                let neighbor_leaf = leaf(ept01, neighbor);
                assert_eq!(neighbor_leaf, (12, (list ^ 4096) | 0x33));
            }
            assert_eq!(state.eptp_used, u64::from((shift - 12) / 9));
            assert_eq!(leaf(ept01, 0xa000), original[2]);
            assert_eq!(unsafe { (shadow as *const u64).read() }, state.ept02);
            state.gpa = 0x200000;
            state.qualification = 2;
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
            assert_eq!(state.write_retry, 1);

            state.sync_result = 0;
            assert_eq!(unsafe { release_test_eptp_sources(&mut state) }, 0);
            assert_ne!(leaf(ept01, 0x9000).1 & TRACKED, 0);
            state.sync_result = 1;
            assert_eq!(unsafe { release_test_eptp_sources(&mut state) }, 1);
            assert_eq!(state.native_enabled, 0);
            assert_eq!(leaf(ept01, 0x9000), original[0]);
            assert_eq!(leaf(ept01, alias_page), (12, list | 0x33));
            assert_eq!(leaf(ept01, 0xa000), original[2]);
            assert!(
                unsafe { std::slice::from_raw_parts(shadow as *const u64, 512) }
                    .iter()
                    .all(|entry| *entry == 0)
            );
            unsafe { refresh_test_eptp_list(&mut state) };
            assert_eq!(
                state.native_enabled, 0,
                "Internal retry must not reprotect the pending store"
            );
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
            assert_eq!(state.write_retry, 0);
            assert_eq!(leaf(state.ept02, state.gpa).1 & 2, 2);
            let used = state.eptp_used;
            state.admission = 1;
            unsafe { refresh_test_eptp_list(&mut state) };
            assert_eq!(state.native_enabled, 1);
            assert_eq!(
                state.eptp_used, used,
                "Readmission reuses permanent split tables"
            );
        }
    }

    #[test]
    fn protection_pool_exhaustion_restores_earlier_aliases_without_publishing() {
        for pages in [0, 1] {
            let mut arena = Arena::new();
            let first = arena.pages(1) | 0x1e;
            let list = arena.pages(1);
            let shadow = arena.pages(1);
            let ept01 = arena.pages(1);
            let alias = 1_u64 << 39;
            let attributes = (1_u64 << 63) | (3 << 52) | 0x3b7;
            arena.map(ept01, 0x9000, list, 12, 0x37);
            arena.map(ept01, alias, list & !((1 << 30) - 1), 30, attributes);
            unsafe { (list as *mut u64).write(first) };
            let mut state = context(&mut arena, first, ept01);
            state.ept02 |= 0x1e;
            state.secondary_control = 0x2002;
            state.vm_function_control = 1;
            state.eptp_list_address = 0x9000;
            state.physical_address_bits = 52;
            state.shadow_list = shadow;
            state.native_supported = 1;
            state.admission = 1;
            state.sync_result = 1;
            state.eptp_pages = pages;
            unsafe { refresh_test_eptp_list(&mut state) };
            assert_eq!(state.native_enabled, 0);
            assert_eq!(state.lists_live, 0);
            assert_eq!(state.eptp_used, pages);
            assert_eq!(state.sync_releases, 1);
            assert_eq!(leaf(ept01, 0x9000), (12, list | 0x37));
            let address = alias + (list & ((1 << 30) - 1));
            let (shift, entry) = leaf(ept01, address);
            let mask = (1_u64 << shift) - 1;
            assert_eq!(entry, (list & !mask) | attributes);
            assert!(
                unsafe { std::slice::from_raw_parts(shadow as *const u64, 512) }
                    .iter()
                    .all(|entry| *entry == 0)
            );
        }
    }

    #[test]
    fn root_writes_retire_readonly_sources_and_tpr_shadow_prevents_publication() {
        let mut arena = Arena::new();
        let first = arena.pages(1) | 0x1e;
        let list = arena.pages(1);
        let shadow = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept01, 0x9000, list, 12, 0x31);
        unsafe { (list as *mut u64).write(first) };
        let mut state = context(&mut arena, first, ept01);
        state.ept02 |= 0x1e;
        state.secondary_control = 0x2002;
        state.vm_function_control = 1;
        state.eptp_list_address = 0x9000;
        state.physical_address_bits = 52;
        state.shadow_list = shadow;
        state.native_supported = 1;
        state.lists_live = 0;
        unsafe { root_write_test_eptp(&mut state) };
        assert_eq!(state.sync_requests, 0);
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(
            state.native_enabled, 0,
            "Initial publication requires quiescence"
        );
        state.sync_result = 1;
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_enabled, 1);
        assert_eq!(state.lists_live, 1);
        unsafe { root_write_test_eptp(&mut state) };
        assert_eq!(state.lists_live, 0);
        assert_eq!(state.native_enabled, 0);
        assert_eq!(leaf(ept01, 0x9000), (12, list | 0x31));
        assert_eq!(unsafe { (shadow as *const u64).read() }, 0);
        let requests = state.sync_requests;
        unsafe { root_write_test_eptp(&mut state) };
        assert_eq!(state.sync_requests, requests);

        let peer = Context {
            primary_control: 1 << 21,
            ..Default::default()
        };
        let mut peers = [0_u64; 64];
        peers[63] = &peer as *const Context as u64;
        state.event_context = peers.as_ptr() as u64;
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_enabled, 0);
        unsafe { peers.as_mut_ptr().add(63).write_volatile(0) };
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_enabled, 1);
        state.primary_control |= 1 << 21;
        unsafe { refresh_test_eptp_list(&mut state) };
        assert_eq!(state.native_enabled, 0);
    }

    #[test]
    fn vm_function_entry_validation_checks_reserved_bits_ept_and_list_alignment() {
        let mut arena = Arena::new();
        let mut state = context(&mut arena, 0, 0);
        state.secondary_control = 0x2002;
        state.physical_address_bits = 48;
        state.vm_function_control = 1;
        state.eptp_list_address = 0x9000;
        assert_eq!(unsafe { validate_test_vm_functions(&mut state) }, 1);
        for list in [0x9001, 1 << 48, u64::MAX] {
            state.eptp_list_address = list;
            assert_eq!(unsafe { validate_test_vm_functions(&mut state) }, 0);
        }
        state.eptp_list_address = 0x9000;
        for function_mask in [2, 3, 1 << 63] {
            state.vm_function_control = function_mask;
            assert_eq!(unsafe { validate_test_vm_functions(&mut state) }, 0);
        }
        state.vm_function_control = 1;
        state.secondary_control = 1 << 13;
        assert_eq!(unsafe { validate_test_vm_functions(&mut state) }, 0);
        state.vm_function_control = 0;
        assert_eq!(unsafe { validate_test_vm_functions(&mut state) }, 1);
        state.vm_function_control = u64::MAX;
        state.secondary_control = 2;
        assert_eq!(unsafe { validate_test_vm_functions(&mut state) }, 1);
        state.primary_control = 0;
        state.secondary_control = 0x2002;
        assert_eq!(unsafe { validate_test_vm_functions(&mut state) }, 1);
    }

    #[test]
    fn host_mapping_cache_respects_large_page_boundaries_and_small_page_holes() {
        let mut arena = Arena::new();
        let root = arena.pages(1);
        let pdpt = arena.pages(1);
        let directory = arena.pages(1);
        let small_pages = arena.pages(1);
        unsafe {
            (root as *mut u64).write(pdpt | 3);
            (pdpt as *mut u64).write(directory | 3);
            (pdpt as *mut u64).add(1).write(0x40000083);
            (directory as *mut u64).write(0x83);
            (directory as *mut u64).add(1).write(small_pages | 3);
            (directory as *mut u64).add(4).write(0x800083);
            (small_pages as *mut u64).write(0x200003);
            (small_pages as *mut u64).add(511).write(0x3ff003);
        }
        let mut state = Context {
            host_cr3: root,
            ..Default::default()
        };
        for (address, expected) in [
            (0, 1),
            (0x1fffff, 1),
            (0x200000, 1),
            (0x201000, 0),
            (0x3ff000, 1),
            (0x400000, 0),
            (0x800000, 1),
            (0, 1),
            (0x40000000, 1),
            (0x7fffffff, 1),
            (0x80000000, 0),
        ] {
            assert_eq!(
                unsafe { check_test_host_mapping(&mut state, address) },
                expected,
                "{address:#x}"
            );
        }
        assert_eq!(state.host_mapping_cache[1], 0);
    }

    #[test]
    fn ept_cache_retains_each_execution_mode_and_invalidates_both_by_root() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0x4b7);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12 | 0x1e, ept01);
        let supervisor_root = state.ept02;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        state.secondary_control |= 1 << 22;
        unsafe { prepare_test_ept(&mut state) };
        let mbec_root = state.ept02;
        assert_ne!(supervisor_root, mbec_root);
        assert_eq!(state.mbec, 1);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(supervisor_root, state.gpa).1 & 0x407, 7);
        assert_eq!(leaf(mbec_root, state.gpa).1 & 0x407, 0x407);
        let invalidations = state.invalidations;
        for mode in [0, 1, 0, 1] {
            state.secondary_control = 2 | (mode << 22);
            unsafe { prepare_test_ept(&mut state) };
            assert_eq!(state.mbec, mode);
            assert_eq!(state.invalidations, invalidations);
            assert_eq!(
                state.ept02,
                if mode == 0 {
                    supervisor_root
                } else {
                    mbec_root
                }
            );
        }
        arena.map(ept12, 0x200000, 0x400000, 21, 0x4b3);
        unsafe { invalidate_test_ept_context(&mut state, ept12 | 0x5e) };
        assert_eq!(state.ept02, mbec_root);
        assert_eq!(state.mbec, 1);
        assert_eq!(state.invalidations, invalidations + 2);
        assert_eq!(leaf(supervisor_root, state.gpa).1 & 0x407, 3);
        assert_eq!(leaf(mbec_root, state.gpa).1 & 0x407, 0x403);
        state.secondary_control = 2;
        unsafe { prepare_test_ept(&mut state) };
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(supervisor_root, state.gpa).1 & 0x407, 3);
        assert_eq!(leaf(mbec_root, state.gpa).1 & 0x407, 0x403);
        arena.map(ept12, 0x200000, 0, 21, 0);
        unsafe { invalidate_test_ept_context(&mut state, ept12 | 0x1e) };
        assert_eq!(leaf(supervisor_root, state.gpa).1, 0);
        assert_eq!(leaf(mbec_root, state.gpa).1, 0);
    }
    #[test]
    fn global_invept_ignores_eptp_and_revokes_both_cached_contexts() {
        for descriptor_eptp in [0, 0x1234, u64::MAX] {
            let mut arena = Arena::new();
            let ept12 = arena.pages(1);
            let ept01 = arena.pages(1);
            arena.map(ept12, 0x200000, 0x400000, 21, 0x4b7);
            arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
            let mut state = context(&mut arena, ept12 | 0x1e, ept01);
            let supervisor_root = state.ept02;
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
            state.secondary_control |= 1 << 22;
            unsafe { prepare_test_ept(&mut state) };
            let mbec_root = state.ept02;
            assert_ne!(supervisor_root, mbec_root);
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
            arena.map(ept12, 0x200000, 0, 21, 0);
            let invalidations = state.invalidations;
            let descriptor = [descriptor_eptp, 0];
            assert_eq!(
                unsafe { invalidate_test_all_ept_contexts(&mut state, descriptor.as_ptr()) },
                0,
                "Global INVEPT rejected ignored EPTP {descriptor_eptp:#x}"
            );
            assert_eq!(state.invalidations, invalidations + 2);
            assert_eq!(state.ept02, mbec_root);
            assert_eq!(leaf(supervisor_root, state.gpa).1, 0);
            assert_eq!(leaf(mbec_root, state.gpa).1, 0);
        }
    }

    #[test]
    fn composition_translates_every_ept12_table_and_honors_table_write_protection() {
        let mut arena = Arena::new();
        let tables = [
            arena.pages(1),
            arena.pages(1),
            arena.pages(1),
            arena.pages(1),
        ];
        let table_gpas = [0, 0x101000, 0x102000, 0x103000];
        let slots = [tables[0], tables[1], tables[2] + 8, tables[3] + 3 * 8];
        let entries = [
            table_gpas[1] | 7,
            table_gpas[2] | 7,
            table_gpas[3] | 7,
            0x403037,
        ];
        let ept01 = arena.pages(1);
        for (gpa, hpa) in table_gpas.into_iter().zip(tables) {
            arena.map(ept01, gpa, hpa, 12, 0x37);
        }
        arena.map(ept01, 0x403000, 0x803000, 12, 0x37);
        for (slot, entry) in slots.into_iter().zip(entries) {
            unsafe { (slot as *mut u64).write(entry) };
        }
        let mut state = context(&mut arena, 0, ept01);
        state.ept12 = table_gpas[0] | 0x1e;
        state.cached_ept12 = state.ept12;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(state.ept02, state.gpa), (12, 0x803037));

        arena.map(ept01, 0x405000, 0xa05000, 12, 0x37);
        unsafe { (slots[3] as *mut u64).write(0x405031) };
        let eptp = state.ept12;
        unsafe { invalidate_test_ept_context(&mut state, eptp) };
        assert_eq!(leaf(state.ept02, state.gpa), (12, 0xa05031));
        unsafe { (slots[3] as *mut u64).write(entries[3]) };

        for index in 0..4 {
            // Deny reads through EPT01 even though all host backing pages are mapped.
            arena.map(ept01, table_gpas[index], tables[index], 12, 0x34);
            unsafe { discard_test_ept(&mut state) };
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
            assert_eq!(leaf(state.ept02, state.gpa).1, 0);
            arena.map(ept01, table_gpas[index], tables[index], 12, 0x37);
        }

        state.ept12 |= 0x40;
        state.cached_ept12 = state.ept12;
        for index in 0..4 {
            for (slot, entry) in slots.into_iter().zip(entries) {
                unsafe { (slot as *mut u64).write(entry) };
            }
            arena.map(ept01, table_gpas[index], tables[index], 12, 0x35);
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
            assert_eq!(
                unsafe { (slots[index] as *const u64).read() },
                entries[index]
            );
            arena.map(ept01, table_gpas[index], tables[index], 12, 0x37);
        }
        for (slot, entry) in slots.into_iter().zip(entries) {
            unsafe { (slot as *mut u64).write(entry | 0x100) };
        }
        arena.map(ept01, table_gpas[3], tables[3], 12, 0x35);
        // Already-accessed, read-only table pages can be walked without any update.
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        state.qualification = 2;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
        assert_eq!(unsafe { (slots[3] as *const u64).read() } & 0x200, 0);
        arena.map(ept01, table_gpas[3], tables[3], 12, 0x37);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(unsafe { (slots[3] as *const u64).read() } & 0x300, 0x300);

        // L0's software A/D writes must take the same deoptimization path as a
        // guest store when an EPT12 table shares the protected list page/range.
        state.sync_result = 1;
        for index in 0..4 {
            for (slot, entry) in slots.into_iter().zip(entries) {
                unsafe { (slot as *mut u64).write(entry) };
            }
            arena.map(
                ept01,
                table_gpas[index],
                tables[index],
                12,
                (1 << 55) | 0x35,
            );
            state.qualification = 1;
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
            assert_eq!(state.write_retry, 1);
            assert_eq!(
                unsafe { (slots[index] as *const u64).read() },
                entries[index]
            );
            assert_eq!(unsafe { release_test_eptp_sources(&mut state) }, 1);
            assert_eq!(leaf(ept01, table_gpas[index]).1 & ((1 << 55) | 2), 2);
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
            assert_eq!(state.write_retry, 0);
        }
    }

    #[test]
    fn composes_large_leaves_with_remapping_and_restricted_permissions() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0xb5);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(state.ept02, state.gpa), (21, 0x6000b5));
        assert_eq!(state.pool_used, 2);
    }

    #[test]
    fn vmware_shadow_markers_raise_misconfiguration_at_every_ept_level() {
        for mbec in [false, true] {
            for ad in [false, true] {
                for level in 0..4 {
                    let mut arena = Arena::new();
                    let ept12 = arena.pages(1);
                    let ept01 = arena.pages(1);
                    let zero_page = arena.pages(1);
                    arena.map(ept12, 0x203000, 0x403000, 12, 0x37);
                    arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
                    arena.map(ept01, 0, zero_page, 12, 0x37);
                    let mut state = context(&mut arena, ept12 | if ad { 0x40 } else { 0 }, ept01);
                    state.mbec = u64::from(mbec);
                    state.qualification = 0x681;
                    let slot = entry_addresses(ept12, state.gpa)[level] as *mut u64;
                    // VMware VNPTClearShadowEntry uses W=1/R=0 to request exit 49.
                    let marker = if mbec { 0x476 } else { 0x76 };
                    unsafe { slot.write(marker) };
                    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
                    assert_eq!(state.exit_reason, 49, "level={level}, mbec={mbec}, ad={ad}");
                    assert_eq!(state.gpa, 0x203000);
                    assert_eq!(state.compositions, 0);
                    assert_eq!(unsafe { slot.read() }, marker);
                    assert_eq!(leaf(state.ept02, state.gpa).1, 0);
                }
            }
        }
    }

    #[test]
    fn write_without_read_is_invalid_even_for_writes_and_instruction_fetches() {
        for access in [1, 2, 4] {
            for permissions in [2, 6] {
                let mut arena = Arena::new();
                let ept12 = arena.pages(1);
                let ept01 = arena.pages(1);
                arena.map(ept12, 0x200000, 0x400000, 21, 0xb0 | permissions);
                arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
                let mut state = context(&mut arena, ept12, ept01);
                state.qualification = access;
                assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
                assert_eq!(state.exit_reason, 49);
                assert_eq!(state.compositions, 0);
            }
        }
    }

    #[test]
    fn misconfiguration_precedes_accumulated_permission_denial() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x203000, 0x403000, 12, 0x36);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        let slots = entry_addresses(ept12, state.gpa);
        unsafe {
            *(slots[0] as *mut u64) &= !3;
            *(slots[1] as *mut u64) &= !6;
        }
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
        assert_eq!(state.exit_reason, 49);
        assert_eq!(state.compositions, 0);

        // A nonpresent entry ends the walk before a malformed descendant.
        state.exit_reason = 48;
        state.qualification = 1;
        unsafe { *(slots[0] as *mut u64) &= !0x407 };
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
        assert_eq!(state.exit_reason, 48);
    }

    #[test]
    fn invept_removes_misconfigured_leaves_without_synthesizing_an_exit() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        let slots = entry_addresses(ept12, state.gpa);
        unsafe { *(*slots.last().unwrap() as *mut u64) &= !1 };
        state.exit_reason = 50;
        unsafe { revalidate_test_ept(&mut state) };
        assert_eq!(state.exit_reason, 50);
        assert_eq!(leaf(state.ept02, state.gpa).1, 0);
    }
    #[test]
    fn preserves_four_kib_l0_remaps_inside_a_large_l1_leaf() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
        arena.map(ept01, 0x403000, 0xa00000, 12, 0x31);
        let mut state = context(&mut arena, ept12, ept01);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(state.ept02, state.gpa), (12, 0xa00031));
        assert_eq!(leaf(state.ept02, state.gpa + 4096), (12, 0));
    }
    #[test]
    fn keeps_four_kib_l1_permissions_and_uncacheable_memory() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x203000, 0x403000, 12, 3);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(state.ept02, state.gpa), (12, 0x603003));
        assert_eq!(leaf(state.ept02, state.gpa + 4096), (12, 0));
    }
    #[test]
    fn rejects_writes_denied_by_either_level() {
        for (l1, l0) in [(0xb5, 0xb7), (0xb7, 0xb5)] {
            let mut arena = Arena::new();
            let ept12 = arena.pages(1);
            let ept01 = arena.pages(1);
            arena.map(ept12, 0x200000, 0x400000, 21, l1);
            arena.map(ept01, 0x400000, 0x600000, 21, l0);
            let mut state = context(&mut arena, ept12, ept01);
            state.qualification = 2;
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
            assert_eq!(state.compositions, 0);
        }
    }
    #[test]
    fn recycles_exhausted_tables_without_reflecting_a_false_violation() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x203000, 0x403000, 12, 0x37);
        arena.map(ept12, 0x40003000, 0x405000, 12, 0x37);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        state.pool_pages = 3;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        state.gpa = 0x40003000;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(state.invalidations, 1);
        assert_eq!(state.recycles, 1);
        assert_eq!(leaf(state.ept02, state.gpa), (12, 0x605037));
        assert_eq!(leaf(state.ept02, 0x203000).1, 0);
    }

    #[test]
    fn full_pool_recycles_one_leaf_table_and_retains_other_translations() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        for region in 1..=12 {
            for offset in [0x3000, 0x4000] {
                let address = region * 0x200000 + offset;
                arena.map(ept12, address, address, 12, 0x37);
            }
            arena.map(ept01, region * 0x200000, region * 0x200000, 21, 0xb7);
        }
        let mut state = context(&mut arena, ept12, ept01);
        state.pool_pages = 6;
        for region in 1..=4 {
            for offset in [0x3000, 0x4000] {
                state.gpa = region * 0x200000 + offset;
                assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
            }
        }
        assert_eq!(state.pool_used, 6);
        state.gpa = 0xa03000;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(state.ept02, state.gpa), (12, state.gpa | 0x37));
        let retained = (1..=4)
            .flat_map(|region| [0x3000, 0x4000].map(move |offset| region * 0x200000 + offset))
            .filter(|address| leaf(state.ept02, *address).1 != 0)
            .count();
        assert_eq!(retained, 6);
        assert_eq!(state.recycles, 0);
        assert_eq!(state.table_evictions, 1);
        assert_eq!(state.pool_used, 6);
        assert_eq!(leaf(state.ept02, 0xa04000).1, 0);
        state.telemetry_active = 0;
        for region in 6..=12 {
            state.gpa = region * 0x200000 + 0x3000;
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
            assert_eq!(leaf(state.ept02, state.gpa), (12, state.gpa | 0x37));
            assert_eq!(leaf(state.ept02, state.gpa + 4096).1, 0);
            assert_eq!(leaf(state.ept02, (region - 4) * 0x200000 + 0x3000).1, 0);
            for retained_region in region - 3..region {
                let address = retained_region * 0x200000 + 0x3000;
                assert_eq!(leaf(state.ept02, address), (12, address | 0x37));
            }
        }
        assert_eq!(state.pool_used, 6);
        assert_eq!(state.table_evictions, 1);
        assert_eq!(state.recycles, 0);
    }

    #[test]
    fn replaces_a_cached_large_leaf_after_l1_relaxes_permissions() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0xb5);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
        state.qualification = 2;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(state.ept02, state.gpa), (21, 0x6000b7));
        assert_eq!(state.invalidations, 1);
    }

    #[test]
    fn invalidation_rebuilds_remaps_permissions_and_memory_type_on_demand() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
        arena.map(ept12, 0x400000, 0x800000, 21, 0xb7);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        arena.map(ept01, 0x800000, 0xa00000, 21, 0xb7);
        arena.map(ept01, 0xc00000, 0xe00000, 21, 0xb1);
        let mut state = context(&mut arena, ept12, ept01);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        state.gpa = 0x403000;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        let pool_before = unsafe {
            std::slice::from_raw_parts(state.pool as *const u64, state.pool_used as usize * 512)
                .to_vec()
        };
        arena.map(ept12, 0x200000, 0xc00000, 21, 0x87);
        unsafe {
            discard_test_ept(&mut state);
        }
        assert_eq!(leaf(state.ept02, 0x203000).1, 0);
        assert_eq!(leaf(state.ept02, 0x403000).1, 0);
        assert_eq!(state.pool_used, 0);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(state.pool as *const u64, pool_before.len()) },
            pool_before
        );
        state.gpa = 0x203000;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(state.ept02, state.gpa), (21, 0xe00081));
        // Reused pages must not make an old sibling mapping reachable again.
        assert_eq!(leaf(state.ept02, 0x403000).1, 0);
        state.gpa = 0x403000;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(state.ept02, 0x403000), (21, 0xa000b7));
        arena.map(ept12, 0x200000, 0, 21, 0);
        unsafe {
            discard_test_ept(&mut state);
        }
        assert_eq!(leaf(state.ept02, 0x203000).1, 0);
        state.gpa = 0x203000;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
        state.gpa = 0x403000;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(state.ept02, 0x403000), (21, 0xa000b7));
    }
    #[test]
    fn invalidation_removes_a_large_mapping_when_l1_splits_it() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        arena.map(ept12, 0x200000, 0, 21, 0);
        arena.map(ept12, 0x203000, 0x403000, 12, 0x31);
        unsafe {
            discard_test_ept(&mut state);
        }
        assert_eq!(leaf(state.ept02, state.gpa).1, 0);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(state.ept02, state.gpa), (12, 0x603031));
        assert_eq!(leaf(state.ept02, 0x204000), (12, 0));
    }
    #[test]
    fn invalidation_applies_four_kib_remaps_and_upper_level_revocations() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x203000, 0x403000, 12, 0x37);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        arena.map(ept12, 0x203000, 0x405000, 12, 0x31);
        unsafe {
            discard_test_ept(&mut state);
        }
        assert_eq!(leaf(state.ept02, state.gpa).1, 0);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(state.ept02, state.gpa), (12, 0x605031));
        unsafe {
            (ept12 as *mut u64).write(0);
            discard_test_ept(&mut state);
        }
        assert_eq!(leaf(state.ept02, state.gpa).1, 0);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
    }

    #[test]
    fn revalidation_updates_remaps_permissions_and_memory_type() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
        arena.map(ept12, 0x400000, 0x800000, 21, 0xb7);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        arena.map(ept01, 0x800000, 0xa00000, 21, 0xb7);
        arena.map(ept01, 0xc00000, 0xe00000, 21, 0xb1);
        let mut state = context(&mut arena, ept12, ept01);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        state.gpa = 0x403000;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        let used = state.pool_used;
        arena.map(ept12, 0x200000, 0xc00000, 21, 0x87);
        unsafe {
            revalidate_test_ept(&mut state);
        }
        assert_eq!(leaf(state.ept02, 0x203000), (21, 0xe00081));
        assert_eq!(leaf(state.ept02, 0x403000), (21, 0xa000b7));
        assert_eq!(state.pool_used, used);
        arena.map(ept12, 0x200000, 0, 21, 0);
        unsafe {
            revalidate_test_ept(&mut state);
        }
        assert_eq!(leaf(state.ept02, 0x203000), (21, 0));
        assert_eq!(leaf(state.ept02, 0x403000), (21, 0xa000b7));
    }
    #[test]
    fn revalidation_removes_a_large_mapping_when_l1_splits_it() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0xb7);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        arena.map(ept12, 0x200000, 0, 21, 0);
        arena.map(ept12, 0x203000, 0x403000, 12, 0x31);
        unsafe {
            revalidate_test_ept(&mut state);
        }
        assert_eq!(leaf(state.ept02, state.gpa), (21, 0));
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        assert_eq!(leaf(state.ept02, state.gpa), (12, 0x603031));
        assert_eq!(leaf(state.ept02, 0x204000), (12, 0));
    }
    #[test]
    fn revalidation_visits_four_kib_leaves_and_upper_level_revocations() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x203000, 0x403000, 12, 0x37);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        arena.map(ept12, 0x203000, 0x405000, 12, 0x31);
        unsafe {
            revalidate_test_ept(&mut state);
        }
        assert_eq!(leaf(state.ept02, state.gpa), (12, 0x605031));
        unsafe {
            (ept12 as *mut u64).write(0);
            revalidate_test_ept(&mut state);
        }
        assert_eq!(leaf(state.ept02, state.gpa), (12, 0));
    }

    #[test]
    fn revalidation_checks_sparse_boundary_slots_and_mbec_only_entries() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        let slots = [0, 1, 7, 8, 63, 64, 255, 256, 510, 511];
        for slot in slots {
            let address = 0x200000 + slot * 4096;
            arena.map(ept12, address, address + 0x200000, 12, 0x37);
        }
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        for slot in slots {
            state.gpa = 0x200000 + slot * 4096;
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
            let entry = *entry_addresses(state.ept02, state.gpa).last().unwrap();
            // A user-execute-only MBEC entry must still be visited, even without R/W/X.
            unsafe { (entry as *mut u64).write(0x400) };
            arena.map(ept12, state.gpa, 0, 12, 0);
        }
        unsafe { revalidate_test_ept(&mut state) };
        for slot in slots {
            let entry = *entry_addresses(state.ept02, 0x200000 + slot * 4096)
                .last()
                .unwrap();
            assert_eq!(unsafe { (entry as *const u64).read() }, 0);
        }
    }

    #[test]
    fn dense_revalidation_updates_stale_translations_and_retains_unchanged_mappings() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept01, 0, 0, 30, 0xb7);
        for index in 0..24 {
            let address = 0x200000 + index * 0x200000;
            arena.map(ept12, address, address + 0x200000, 12, 0x37);
        }
        let mut state = context(&mut arena, ept12, ept01);
        state.pool = arena.pages(32);
        state.pool_pages = 32;
        for index in 0..24 {
            state.gpa = 0x200000 + index * 0x200000;
            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        }
        assert!(state.pool_used >= 24);
        let pool_used = state.pool_used;
        let address = state.gpa;
        arena.map(ept12, address, address + 0x400000, 12, 0x31);
        unsafe { revalidate_test_ept(&mut state) };
        assert_eq!(leaf(state.ept02, address), (12, address + 0x400000 + 0x31));
        for index in 0..23 {
            let unchanged_address = 0x200000 + index * 0x200000;
            assert_eq!(
                leaf(state.ept02, unchanged_address),
                (12, unchanged_address + 0x200000 + 0x37)
            );
        }
        assert_eq!(state.pool_used, pool_used);
        assert_eq!(state.native_invept, 1);
        arena.map(ept12, address, 0, 12, 0);
        unsafe { revalidate_test_ept(&mut state) };
        assert_eq!(leaf(state.ept02, address).1, 0);
    }

    #[test]
    #[ignore = "Run explicitly to measure the production EPT revalidation assembly"]
    fn benchmark_ept_revalidation() {
        for leaves_per_table in [1_u64, 16, 512] {
            let mut arena = Arena::new();
            let ept12 = arena.pages(1);
            let ept01 = arena.pages(1);
            for table in 1..=16 {
                for slot in 0..leaves_per_table {
                    let address = table * 0x200000 + slot * 4096;
                    arena.map(ept12, address, address + 0x4000000, 12, 0x37);
                }
                arena.map(
                    ept01,
                    table * 0x200000 + 0x4000000,
                    table * 0x200000 + 0x8000000,
                    21,
                    0xb7,
                );
            }
            let mut state = context(&mut arena, ept12, ept01);
            state.pool = arena.pages(32);
            state.pool_pages = 32;
            state.host_cr3 = arena.host_map();
            for table in 1..=16 {
                for slot in 0..leaves_per_table {
                    state.gpa = table * 0x200000 + slot * 4096;
                    assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
                }
            }
            let mut timings = Vec::new();
            for _ in 0..7 {
                let start = std::time::Instant::now();
                for _ in 0..1000 {
                    unsafe { revalidate_test_ept(std::hint::black_box(&mut state)) };
                }
                timings.push(start.elapsed().as_nanos() / 1000);
            }
            timings.sort_unstable();
            println!(
                "leaves_per_table={leaves_per_table} table_pages={} median_ns={}",
                state.pool_used, timings[3]
            );
        }
    }

    #[test]
    #[ignore = "Run explicitly to measure INVEPT together with working-set refill"]
    fn benchmark_ept_invalidation_and_refill() {
        for leaves_per_table in [1_u64, 16, 512] {
            let mut arena = Arena::new();
            let ept12 = arena.pages(1);
            let ept01 = arena.pages(1);
            arena.map(ept01, 0, 0, 30, 0xb7);
            let mut addresses = Vec::new();
            for table in 1..=32 {
                for slot in 0..leaves_per_table {
                    let address = table * 0x200000 + slot * 4096;
                    arena.map(ept12, address, address + 0x8000000, 12, 0x37);
                    addresses.push(address);
                }
            }
            let mut state = context(&mut arena, ept12, ept01);
            state.pool = arena.pages(64);
            state.pool_pages = 64;
            state.host_cr3 = arena.host_map();
            for &address in &addresses {
                state.gpa = address;
                assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
            }
            let mut timings = Vec::new();
            let mut refill_faults = 0;
            for _ in 0..5 {
                let start = std::time::Instant::now();
                for _ in 0..30 {
                    unsafe { revalidate_test_ept(std::hint::black_box(&mut state)) };
                    for &address in &addresses {
                        if std::hint::black_box(leaf(state.ept02, address).1) & 7 == 0 {
                            state.gpa = address;
                            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
                            refill_faults += 1;
                        }
                    }
                }
                timings.push(start.elapsed().as_nanos() / 30);
            }
            timings.sort_unstable();
            println!(
                "leaves_per_table={leaves_per_table} median_ns={} refill_faults_per_invept={}",
                timings[2],
                refill_faults / 150
            );
        }
    }

    #[test]
    #[ignore = "Run explicitly to measure full-cache recycling with a reused working set"]
    fn benchmark_ept_pool_recycling() {
        for leaves_per_table in [1_u64, 16, 512] {
            let mut arena = Arena::new();
            let ept12 = arena.pages(1);
            let ept01 = arena.pages(1);
            arena.map(ept01, 0, 0, 30, 0xb7);
            let mut hot = Vec::new();
            for table in 1..=64 {
                for slot in 0..if table <= 8 { leaves_per_table } else { 1 } {
                    let address = table * 0x200000 + slot * 4096;
                    arena.map(ept12, address, address, 12, 0x37);
                    if table <= 8 {
                        hot.push(address);
                    }
                }
            }
            let mut state = context(&mut arena, ept12, ept01);
            state.pool = arena.pages(18);
            state.pool_pages = 18;
            state.host_cr3 = arena.host_map();
            let start = std::time::Instant::now();
            let mut faults = 0_u64;
            for _ in 0..10 {
                for table in 9..=64 {
                    for address in std::iter::once(table * 0x200000).chain(hot.iter().copied()) {
                        if leaf(state.ept02, address).1 & 7 == 0 {
                            state.gpa = address;
                            assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
                            faults += 1;
                        }
                    }
                }
            }
            println!(
                "leaves_per_table={leaves_per_table} faults={faults} full_resets={} table_evictions={} elapsed_ns={}",
                state.recycles,
                state.table_evictions,
                start.elapsed().as_nanos()
            );
        }
    }

    #[repr(C)]
    struct ExitMsrContext {
        values: [u64; 117],
        hardware: [u64; 117],
        saved_pat: u64,
        saved_efer: u64,
        exit_reason: u64,
        exit_controls: u64,
        vmx_misc: u64,
        entry_controls: u64,
    }
    core::arch::global_asm!(
        ".text",
        ".globl capture_test_exit_msrs",
        "capture_test_exit_msrs:",
        "push r12", "mov r12, rcx",
        "call .Lresident_nested_capture_vmcs02_guest_state",
        "pop r12", "ret",
        include_str!("../builds/nested-ept-tests/resident-exit-msrs.S"),
        guest_pat = const 25,
        guest_efer = const 26,
        test_hardware = const std::mem::offset_of!(ExitMsrContext, hardware),
        b_nested_l2_saved_pat = const std::mem::offset_of!(ExitMsrContext, saved_pat),
        b_nested_l2_saved_efer = const std::mem::offset_of!(ExitMsrContext, saved_efer),
        b_nested_vmcs12_exit_reason = const std::mem::offset_of!(ExitMsrContext, exit_reason),
        b_nested_vmcs12_vm_exit_controls = const std::mem::offset_of!(ExitMsrContext, exit_controls),
        b_nested_vmcs12_extended_fields = const std::mem::offset_of!(ExitMsrContext, values),
        b_nested_vmx_misc = const std::mem::offset_of!(ExitMsrContext, vmx_misc),
        b_nested_vmcs12_vm_entry_controls = const std::mem::offset_of!(ExitMsrContext, entry_controls),
    );
    unsafe extern "win64" {
        #[link_name = "capture_test_exit_msrs"]
        fn capture_test_exit_msrs_raw(context: *mut ExitMsrContext);
    }

    fn capture_test_exit_msrs(context: &mut ExitMsrContext) {
        // Fixed PAT and EFER indices are within both inline arrays.
        unsafe { capture_test_exit_msrs_raw(context) }
    }
    #[test]
    fn exit_saves_efer_only_when_requested_after_successful_entry() {
        for save_efer in [false, true] {
            for entry_failed in [false, true] {
                for update_entry_mode in [false, true] {
                    let mut state = ExitMsrContext {
                        values: [0xfeed; 117],
                        hardware: [0; 117],
                        saved_pat: 0,
                        saved_efer: 0,
                        exit_reason: if entry_failed { 0x80000021 } else { 10 },
                        exit_controls: if save_efer { 1 << 20 } else { 0 },
                        vmx_misc: if update_entry_mode { 1 << 5 } else { 0 },
                        entry_controls: 0,
                    };
                    state.hardware[25] = 0x0007040600070406;
                    state.hardware[26] = 0x500;
                    capture_test_exit_msrs(&mut state);
                    assert_eq!(state.saved_efer, 0x500);
                    assert_eq!(state.saved_pat, state.hardware[25]);
                    assert_eq!(state.values[25], 0xfeed);
                    assert_eq!(
                        state.values[26],
                        if save_efer && !entry_failed {
                            0x500
                        } else {
                            0xfeed
                        }
                    );
                    assert_eq!(
                        state.entry_controls,
                        if update_entry_mode && !entry_failed {
                            1 << 9
                        } else {
                            0
                        }
                    );
                }
            }
        }
    }

    #[repr(C)]
    struct GuestContext {
        valid: u64,
        control_valid: [u64; 2],
        values: [u64; 117],
        cache: [u64; 117],
        hardware: [u64; 117],
        writes: u64,
        rare_pending: [u64; 2],
        vmcs01: u64,
        vmcs02: u64,
        selected_vmcs: u64,
        switches: u64,
        reads: u64,
    }
    core::arch::global_asm!(
        ".text",
        ".globl sync_test_guest",
        "sync_test_guest:",
        "push r12", "push rsi",
        "mov r12, rcx",
        "call .Lresident_nested_sync_vmcs02_guest_fields",
        "pop rsi", "pop r12", "ret",
        ".globl capture_test_guest",
        "capture_test_guest:",
        "push r12", "push rsi", "mov r12, rcx",
        "lea rsi, [rip + .Lresident_nested_guest_state_table]", "mov ecx, 50",
        "call .Lresident_nested_capture_vmcs02_guest_state_loop",
        "pop rsi", "pop r12", "ret",
        ".globl materialize_test_guest",
        "materialize_test_guest:",
        "push r12", "mov r12, rcx", "mov rax, rdx",
        "mov r11, r8", "mov r10, r9",
        "push rdx", "mov rdx, r9",
        "call .Lresident_nested_materialize_guest_field",
        "cmp rax, qword ptr [rsp]", "jne .Lresident_dispatch_halt",
        "cmp rdx, r9", "jne .Lresident_dispatch_halt", "pop rdx",
        "cmp r11, r8", "jne .Lresident_dispatch_halt",
        "cmp r10, r9", "jne .Lresident_dispatch_halt",
        "pop r12", "ret",
        ".globl materialize_test_all_guest",
        "materialize_test_all_guest:",
        "push r12", "mov r12, rcx",
        "call .Lresident_nested_materialize_vmcs02_rare_state",
        "pop r12", "ret",
        include_str!("../builds/nested-ept-tests/resident-guest.S"),
        b_nested_vmcs02_guest_cache_valid = const std::mem::offset_of!(GuestContext,valid),
        b_nested_vmcs02_field_cache = const std::mem::offset_of!(GuestContext,cache),
        b_nested_vmcs12_extended_fields = const std::mem::offset_of!(GuestContext,values),
        test_hardware = const std::mem::offset_of!(GuestContext,hardware),
        test_writes = const std::mem::offset_of!(GuestContext,writes),
        test_reads = const std::mem::offset_of!(GuestContext,reads),
        test_selected_vmcs = const std::mem::offset_of!(GuestContext,selected_vmcs),
        test_switches = const std::mem::offset_of!(GuestContext,switches),
        b_nested_vmcs01_region = const std::mem::offset_of!(GuestContext,vmcs01),
        b_nested_vmcs02_region = const std::mem::offset_of!(GuestContext,vmcs02),
        b_nested_vmcs02_rare_state_pending = const std::mem::offset_of!(GuestContext,rare_pending),
        nested_rare_guest_fields_low = const (0xff_u64 << 35) | (0x3ff_u64 << 50),
        nested_rare_guest_fields_high = const (0xffff_u64 << 1) | (1_u64 << 28),
        nested_guest_state_table_count = const 50,
    );
    unsafe extern "win64" {
        #[link_name = "sync_test_guest"]
        fn sync_test_guest_raw(context: *mut GuestContext);
        #[link_name = "capture_test_guest"]
        fn capture_test_guest_raw(context: *mut GuestContext);
        #[link_name = "materialize_test_guest"]
        fn materialize_test_guest_raw(
            context: *mut GuestContext,
            field: u64,
            value: u64,
            encoding: u64,
        );
        #[link_name = "materialize_test_all_guest"]
        fn materialize_test_all_guest_raw(context: *mut GuestContext);
    }

    fn materialize_test_all_guest(context: &mut GuestContext) {
        assert_eq!(context.vmcs01, 1);
        assert_eq!(context.vmcs02, 2);
        // Deferred fields come from the bounded static table; VMCS identifiers are mocked.
        unsafe { materialize_test_all_guest_raw(context) }
    }

    fn materialize_test_guest(context: &mut GuestContext, field: u64, value: u64, encoding: u64) {
        assert!(
            field < context.values.len() as u64,
            "guest field index is out of bounds"
        );
        assert_eq!(context.vmcs01, 1);
        assert_eq!(context.vmcs02, 2);
        // The checked field bounds the bitmap and array accesses; VMCS identifiers are mocked.
        unsafe { materialize_test_guest_raw(context, field, value, encoding) }
    }

    fn capture_test_guest(context: &mut GuestContext) {
        assert_eq!(context.selected_vmcs, 2);
        // The static guest-field table indexes only the inline context arrays.
        unsafe { capture_test_guest_raw(context) }
    }

    fn sync_test_guest(context: &mut GuestContext) {
        // The static guest-field table indexes only the inline context arrays.
        unsafe { sync_test_guest_raw(context) }
    }
    #[test]
    fn guest_sync_retains_hardware_state_and_applies_l1_changes() {
        let mut state = GuestContext {
            valid: 0,
            control_valid: [0; 2],
            values: [0; 117],
            cache: [0; 117],
            hardware: [u64::MAX; 117],
            writes: 0,
            rare_pending: [0; 2],
            vmcs01: 1,
            vmcs02: 2,
            selected_vmcs: 2,
            switches: 0,
            reads: 0,
        };
        sync_test_guest(&mut state);
        assert_eq!(state.writes, 50);
        state.values[30] = 0x12345000;
        sync_test_guest(&mut state);
        assert_eq!(state.writes, 55);
        assert_eq!(state.hardware[30], 0x12345000);
        state.hardware[30] = 0x87654000;
        state.cache[30] = state.hardware[30];
        state.values[30] = state.hardware[30];
        sync_test_guest(&mut state);
        assert_eq!(state.writes, 59);
        assert_eq!(state.hardware[30], 0x87654000);
        state.valid = 0;
        sync_test_guest(&mut state);
        assert_eq!(state.writes, 109);
    }

    #[test]
    fn deferred_guest_state_survives_resume_and_materializes_before_l1_access() {
        let mut state = GuestContext {
            valid: 0,
            control_valid: [0; 2],
            values: [0; 117],
            cache: [0; 117],
            hardware: [u64::MAX; 117],
            writes: 0,
            rare_pending: [0; 2],
            vmcs01: 1,
            vmcs02: 2,
            selected_vmcs: 2,
            switches: 0,
            reads: 0,
        };
        let rare = |index| {
            (35..=42).contains(&index)
                || (50..=59).contains(&index)
                || (65..=80).contains(&index)
                || index == 92
        };
        sync_test_guest(&mut state);
        let fields: Vec<usize> = state
            .hardware
            .iter()
            .enumerate()
            .filter_map(|(index, value)| (*value != u64::MAX).then_some(index))
            .collect();
        assert_eq!(fields.len(), 50);
        for &index in &fields {
            state.hardware[index] = 0x10000 + index as u64;
        }
        capture_test_guest(&mut state);
        assert_eq!(state.reads, 15);
        let pending = [
            (0xff_u64 << 35) | (0x3ff_u64 << 50),
            (0xffff_u64 << 1) | (1_u64 << 28),
        ];
        assert_eq!(state.rare_pending, pending);
        for &index in &fields {
            assert_eq!(
                state.values[index],
                if rare(index) {
                    0
                } else {
                    state.hardware[index]
                }
            );
        }
        state.selected_vmcs = 1;
        materialize_test_guest(&mut state, 30, u64::MAX, 0x6802);
        assert_eq!(state.switches, 0);
        assert_eq!(state.rare_pending, pending);
        state.selected_vmcs = 2;
        sync_test_guest(&mut state);
        assert_eq!(state.writes, 54);
        for &index in &fields {
            assert_eq!(state.hardware[index], 0x10000 + index as u64);
        }
        state.selected_vmcs = 1;
        materialize_test_guest(&mut state, 50, 0xfeed_dead_beef, 0x6806);
        assert_eq!(state.reads, 16);
        assert_eq!(state.switches, 2);
        assert_eq!(state.selected_vmcs, 1);
        assert_eq!(state.rare_pending, [pending[0] & !(1 << 50), pending[1]]);
        for &index in &fields {
            let expected = if rare(index) && index != 50 {
                0
            } else {
                state.hardware[index]
            };
            assert_eq!(state.values[index], expected);
            assert_eq!(state.cache[index], expected);
        }
        materialize_test_guest(&mut state, 50, 0, 0x6806);
        assert_eq!(state.reads, 16);
        assert_eq!(state.switches, 2);
        state.values[50] = 0x87654000;
        state.selected_vmcs = 2;
        sync_test_guest(&mut state);
        assert_eq!(state.hardware[50], 0x87654000);
        assert_eq!(state.writes, 59);
        // A VMCS switch or clear must save even fields L1 has not read.
        for &index in &fields {
            state.hardware[index] = 0x20000 + index as u64;
        }
        capture_test_guest(&mut state);
        state.selected_vmcs = 1;
        materialize_test_all_guest(&mut state);
        materialize_test_all_guest(&mut state);
        assert_eq!(state.reads, 66);
        assert_eq!(state.switches, 4);
        assert_eq!(state.selected_vmcs, 1);
        assert_eq!(state.rare_pending, [0; 2]);
        for &index in &fields {
            assert_eq!(state.values[index], state.hardware[index]);
        }
    }

    core::arch::global_asm!(
        ".text",
        ".globl sync_test_control",
        "sync_test_control:",
        "push r12",
        "mov r12, rcx",
        "mov rax, rdx",
        "mov r11, r8",
        "call .Lresident_nested_write_vmcs02_control",
        "pop r12", "ret",
        ".globl lookup_test_field",
        "lookup_test_field:",
        "push rsi", "mov rdx, rcx",
        "call .Lresident_vmcs12_field_index",
        "pop rsi", "ret",
        include_str!("../builds/nested-ept-tests/resident-controls.S"),
        b_nested_vmcs02_control_cache_valid = const std::mem::offset_of!(GuestContext,control_valid),
        b_nested_vmcs02_field_cache = const std::mem::offset_of!(GuestContext,cache),
        test_hardware = const std::mem::offset_of!(GuestContext,hardware),
        test_writes = const std::mem::offset_of!(GuestContext,writes),
        vmcs12_extended_field_count = const 117,
    );
    unsafe extern "win64" {
        #[link_name = "sync_test_control"]
        fn sync_test_control_raw(context: *mut GuestContext, field: u64, value: u64);
        #[link_name = "lookup_test_field"]
        fn lookup_test_field_raw(encoding: u64) -> u64;
    }

    fn lookup_test_field(encoding: u64) -> u64 {
        // The assembly rejects reserved bits before indexing its static lookup table.
        unsafe { lookup_test_field_raw(encoding) }
    }

    fn sync_test_control(context: &mut GuestContext, field: u64, value: u64) {
        assert!(
            lookup_test_field(field) < context.cache.len() as u64,
            "unknown VMCS field"
        );
        // The validated encoding maps to an in-bounds context array index.
        unsafe { sync_test_control_raw(context, field, value) }
    }

    #[test]
    fn guest_wrappers_reject_invalid_indices_before_entering_assembly() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let mut context = GuestContext {
            valid: 0,
            control_valid: [0; 2],
            values: [0; 117],
            cache: [0; 117],
            hardware: [0; 117],
            writes: 0,
            rare_pending: [u64::MAX; 2],
            vmcs01: 1,
            vmcs02: 2,
            selected_vmcs: 2,
            switches: 0,
            reads: 0,
        };
        for field in [117, 128, u64::MAX] {
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    materialize_test_guest(&mut context, field, 0, 0x6806);
                }))
                .is_err()
            );
        }
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                sync_test_control(&mut context, u64::MAX, 0);
            }))
            .is_err()
        );
        assert_eq!((context.reads, context.writes, context.switches), (0, 0, 0));
    }
    #[test]
    fn vmcs_lookup_rejects_reserved_bits_and_resolves_every_index() {
        let source = include_str!("../src/vmx/asm/nested.S");
        let table = source
            .split(".Lresident_vmcs12_field_index_table:")
            .nth(1)
            .unwrap()
            .split(".balign 8")
            .next()
            .unwrap();
        let indices: Vec<u64> = table
            .lines()
            .filter_map(|line| line.split(".byte ").nth(1))
            .flat_map(|line| line.trim().split(", "))
            .map(|value| value.parse().unwrap())
            .collect();
        for encoding in 0_u64..0x10000 {
            let expected = if encoding & !0x6c3e == 0 {
                indices[(((encoding & 0x6c00) >> 5) | ((encoding & 0x3e) >> 1)) as usize]
            } else {
                255
            };
            assert_eq!(lookup_test_field(encoding), expected, "{encoding:#x}");
        }
        for encoding in [0x1_0000_6802, u64::MAX, 0x8000_0000_0000_0000] {
            assert_eq!(lookup_test_field(encoding), 255);
        }
    }
    #[test]
    fn control_cache_writes_zero_initially_and_tracks_high_indices() {
        let mut state = GuestContext {
            valid: 0,
            control_valid: [0; 2],
            values: [0; 117],
            cache: [0; 117],
            hardware: [u64::MAX; 117],
            writes: 0,
            rare_pending: [0; 2],
            vmcs01: 1,
            vmcs02: 2,
            selected_vmcs: 2,
            switches: 0,
            reads: 0,
        };
        sync_test_control(&mut state, 0x4000, 0);
        assert_eq!(state.hardware[1], 0);
        assert_eq!(state.writes, 1);
        sync_test_control(&mut state, 0x4000, 0);
        assert_eq!(state.writes, 1);
        sync_test_control(&mut state, 0x2012, 0x100000000);
        assert_eq!(state.hardware[101], 0x100000000);
        assert_eq!(state.writes, 2);
        sync_test_control(&mut state, 0x2012, 0x100000000);
        assert_eq!(state.writes, 2);
        sync_test_control(&mut state, 0x2012, 0x200000000);
        assert_eq!(state.hardware[101], 0x200000000);
        assert_eq!(state.writes, 3);
        state.control_valid = [0; 2];
        sync_test_control(&mut state, 0x2012, 0x200000000);
        assert_eq!(state.writes, 4);
    }

    #[test]
    fn mbec_enforces_distinct_user_and_supervisor_execute_permissions() {
        for (attributes, user_allowed, supervisor_allowed) in [
            (0x4b3, true, false),
            (0xb7, false, true),
            (0x4b7, true, true),
            (0x4b0, true, false),
        ] {
            let mut arena = Arena::new();
            let ept12 = arena.pages(1);
            let ept01 = arena.pages(1);
            arena.map(ept12, 0x200000, 0x400000, 21, attributes);
            arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
            let mut state = context(&mut arena, ept12, ept01);
            state.mbec = 1;
            state.qualification = 0x384;
            assert_eq!(
                unsafe { resolve_test_ept(&mut state) },
                u64::from(user_allowed)
            );
            if user_allowed {
                assert_eq!(leaf(state.ept02, state.gpa), (21, 0x600000 | attributes));
            }
            state.qualification = 0x184;
            assert_eq!(
                unsafe { resolve_test_ept(&mut state) },
                u64::from(supervisor_allowed)
            );
            if !supervisor_allowed {
                assert_eq!(state.qualification & 0x60, 0x40);
                assert_eq!(state.qualification & !0xfff, 0);
            }
        }
    }
    #[test]
    fn mbec_respects_l0_execute_denials_after_user_only_leaf_invalidation() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0x4b0);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        state.mbec = 1;
        state.qualification = 0x384;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 1);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb3);
        unsafe {
            discard_test_ept(&mut state);
        }
        assert_eq!(leaf(state.ept02, state.gpa).1 & 0x407, 0);
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
        assert_eq!(state.qualification & 0x60, 0);
    }
    #[test]
    fn disabled_mbec_ignores_the_user_execute_bit() {
        let mut arena = Arena::new();
        let ept12 = arena.pages(1);
        let ept01 = arena.pages(1);
        arena.map(ept12, 0x200000, 0x400000, 21, 0x4b3);
        arena.map(ept01, 0x400000, 0x600000, 21, 0xb7);
        let mut state = context(&mut arena, ept12, ept01);
        state.qualification = 0x384;
        assert_eq!(unsafe { resolve_test_ept(&mut state) }, 0);
        assert_eq!(state.qualification & 0x60, 0);
    }

    include!("review_hv_ept_tests.rs");
    include!("review_hv_edge_tests.rs");
}

#[cfg(test_harness = "native_shadow")]
mod native_shadow {
    include!("../builds/native-shadow-tests/offsets.rs");
    core::arch::global_asm!(include_str!("../builds/native-shadow-tests/handlers.S"));

    unsafe extern "win64" {
        fn test_native_shadow_read(context: *mut u64, field: u64, value: u64) -> u64;
        fn test_native_shadow_write(context: *mut u64, field: u64, value: u64) -> u64;
        fn test_native_shadow_validate(context: *mut u64, field: u64, value: u64) -> u64;
        fn test_native_shadow_load(context: *mut u64, field: u64, value: u64) -> u64;
        fn test_native_shadow_clear(context: *mut u64, field: u64, value: u64) -> u64;
        fn test_native_shadow_flush(context: *mut u64, field: u64, value: u64) -> u64;
        fn test_native_shadow_link(context: *mut u64, field: u64, value: u64) -> u64;
        fn test_native_shadow_launch(context: *mut u64, field: u64, value: u64) -> u64;
        fn test_native_shadow_resume(context: *mut u64, field: u64, value: u64) -> u64;
        fn test_native_shadow_field(context: *mut u64, field: u64, value: u64) -> u64;
        fn test_native_shadow_software_write(context: *mut u64, field: u64, value: u64) -> u64;
        fn test_native_shadow_entry(context: *mut u64, field: u64, value: u64) -> u64;
    }

    type Handler = unsafe extern "win64" fn(*mut u64, u64, u64) -> u64;
    fn run(context: &mut [u64], handler: Handler, field: u64, value: u64) -> u64 {
        unsafe { handler(context.as_mut_ptr(), field, value) }
    }

    fn context() -> Vec<u64> {
        let mut state = vec![0; CONTEXT_QWORDS];
        for (name, value) in [
            ("b_nested_active", 1),
            ("b_nested_physical_address_bits", 48),
            ("b_nested_vmcs12_revision_id", 0x42),
            ("b_nested_vmx_procbased_ctls2", 1 << 46),
            ("b_nested_vmcs01_region", 0x1000),
            ("b_nested_current_vmcs", u64::MAX),
            ("test_mapped", 1),
            ("test_native_flags", 2),
        ] {
            state[offset(name)] = value;
        }
        state
    }

    #[repr(C, align(4096))]
    struct Page([u8; 4096]);

    #[test]
    fn shadow_pointer_lifecycle_preserves_native_backing_and_rejects_entry() {
        let mut page = Box::new(Page([0; 4096]));
        page.0[..4].copy_from_slice(&0x8000_0042_u32.to_le_bytes());
        let address = page.0.as_mut_ptr() as u64;
        let mut bitmap = Box::new(Page([0; 4096]));
        let mut state = context();
        state[offset("b_nested_shadow_vmread_bitmap")] = bitmap.0.as_mut_ptr() as u64;
        state[offset("test_operand")] = address;
        assert_eq!(run(&mut state, test_native_shadow_load, 0, 0), 0);
        assert_eq!(state[offset("b_nested_current_vmcs")], address);
        assert_eq!(state[offset("b_nested_current_vmcs_is_shadow")], 1);
        assert_eq!(bitmap.0[0xd82], 0x50);
        assert_eq!(run(&mut state, test_native_shadow_launch, 0, 0), u64::MAX);
        assert_eq!(run(&mut state, test_native_shadow_resume, 0, 0), u64::MAX);
        assert_eq!(run(&mut state, test_native_shadow_clear, 0, address), 0);
        assert_eq!(state[offset("test_cleared")], address);
        assert_eq!(state[offset("b_nested_current_vmcs")], u64::MAX);
        assert_eq!(state[offset("b_nested_current_vmcs_is_shadow")], 0);
        assert!(page.0[4..].iter().all(|byte| *byte == 0));
        state[offset("b_nested_vmx_procbased_ctls2")] = 0;
        assert_eq!(run(&mut state, test_native_shadow_load, 0, 0), 11);
        state[offset("b_nested_vmx_procbased_ctls2")] = 1 << 46;
        page.0[0] = 0x43;
        assert_eq!(run(&mut state, test_native_shadow_load, 0, 0), 11);
        page.0[0] = 0x42;
        state[offset("test_mapped")] = 0;
        assert_eq!(run(&mut state, test_native_shadow_load, 0, 0), 9);
    }

    #[test]
    fn native_access_flushes_shadow_and_restores_vmcs01_on_success_and_failure() {
        let mut state = context();
        state[offset("b_nested_current_vmcs")] = 0x2000;
        state[offset("b_last_reason")] = 25;
        assert_eq!(run(&mut state, test_native_shadow_write, 0x681e, 0x1234), 0);
        assert_eq!(state[offset("test_shadow_value")], 0x1234);
        assert_eq!(state[offset("test_selected")], 0x1000);
        assert_eq!(state[offset("test_cleared")], 0x2000);
        state[offset("b_last_reason")] = 23;
        assert_eq!(run(&mut state, test_native_shadow_read, 0x681e, 0), 0);
        assert_eq!(state[offset("test_read_value")], 0x1234);
        assert_eq!(state[offset("test_clear_count")], 2);
        assert_eq!(state[offset("test_root_writes")], 2);
        for flags in [3, 0x42] {
            state[offset("test_native_flags")] = flags;
            state[offset("test_rflags")] = 0xad7;
            run(&mut state, test_native_shadow_read, 0x7fff, 0);
            assert_eq!(
                state[offset("test_rflags")],
                (0xad7 & !0x8d5) | (flags & 0x41)
            );
            assert_eq!(state[offset("test_selected")], 0x1000);
        }
        state[offset("b_nested_vmx_misc")] = 1 << 29;
        state[offset("test_native_flags")] = 2;
        state[offset("b_last_reason")] = 25;
        assert_eq!(run(&mut state, test_native_shadow_write, 0x4402, 0x1234), 0);
        assert_eq!(state[offset("test_shadow_value")], 0x1234);
    }

    #[test]
    fn software_vmwrite_discards_upper_bits_of_sixteen_bit_fields() {
        let mut state = context();
        let fields = offset("b_nested_vmcs12_extended_fields");
        let cases = core::iter::once((0_u64, 0_usize))
            .chain((0..8).map(|index| (0x800 + index as u64 * 2, 35 + index)))
            .chain((0..7).map(|index| (0xc00 + index as u64 * 2, 43 + index)));
        for (field, index) in cases {
            assert_eq!(
                run(&mut state, test_native_shadow_software_write, field, 0x1234_5678_8765_4321),
                0
            );
            assert_eq!(state[fields + index], 0x4321, "field {field:#x}");
        }
    }

    #[test]
    fn software_exit_field_writes_match_native_misc_capability_and_field_width() {
        let mut state = context();
        let fields = offset("b_nested_vmcs12_extended_fields");
        let value = 0x1234_5678_8765_4321;
        let cases = [
            (0x4400, offset("b_nested_instruction_error"), 0x8765_4321),
            (0x4402, offset("b_nested_vmcs12_exit_reason"), 0x8765_4321),
            (
                0x440c,
                offset("b_nested_vmcs12_exit_instruction_len"),
                0x8765_4321,
            ),
            (0x6400, offset("b_nested_vmcs12_exit_qualification"), value),
            (0x440e, fields + 115, 0x8765_4321),
            (0x2400, fields + 110, value),
            (0x640a, fields + 116, value),
        ];
        for (field, destination, expected) in cases {
            state[offset("b_nested_vmx_misc")] = 0;
            assert_eq!(
                run(&mut state, test_native_shadow_software_write, field, value),
                13
            );
            assert_eq!(state[destination], 0);
            state[offset("b_nested_vmx_misc")] = 1 << 29;
            assert_eq!(
                run(&mut state, test_native_shadow_software_write, field, value),
                0
            );
            assert_eq!(state[destination], expected);
        }
        state[offset("b_nested_vmx_misc")] = 0;
        assert_eq!(
            run(&mut state, test_native_shadow_software_write, 0x2401, value),
            13
        );
        state[offset("b_nested_vmx_misc")] = 1 << 29;
        assert_eq!(
            run(&mut state, test_native_shadow_software_write, 0x2401, value),
            0
        );
        assert_eq!(state[fields + 110], 0x8765_4321_8765_4321);
        assert_eq!(
            run(&mut state, test_native_shadow_software_write, 0x7fff, value),
            12
        );
        for (field, index) in [(0x2026, 120), (0x2028, 121)] {
            assert_eq!(
                run(&mut state, test_native_shadow_software_write, field, value),
                0
            );
            assert_eq!(state[fields + index], value);
            assert_eq!(
                run(
                    &mut state,
                    test_native_shadow_software_write,
                    field + 1,
                    0xabcd
                ),
                0
            );
            assert_eq!(state[fields + index], 0xabcd_8765_4321);
        }
    }

    #[test]
    fn shadow_controls_require_valid_mapped_bitmaps_only_when_enabled() {
        let mut state = context();
        let fields = offset("b_nested_vmcs12_extended_fields");
        state[offset("b_nested_vmcs12_primary_control")] = 1 << 31;
        state[offset("b_nested_vmcs12_secondary_control")] = 1 << 14;
        state[fields + 120] = 0x2000;
        state[fields + 121] = 0x3000;
        state[fields + 23] = u64::MAX;
        assert_eq!(run(&mut state, test_native_shadow_validate, 0, 0), 1);
        for index in [120, 121] {
            for invalid in [0x2001, 1 << 48, u64::MAX] {
                state[fields + index] = invalid;
                assert_eq!(run(&mut state, test_native_shadow_validate, 0, 0), 0);
            }
            state[fields + index] = 0x2000;
        }
        state[offset("test_mapped")] = 0;
        assert_eq!(run(&mut state, test_native_shadow_validate, 0, 0), 0);
        state[offset("b_nested_vmcs12_primary_control")] = 0;
        assert_eq!(run(&mut state, test_native_shadow_validate, 0, 0), 1);
        state[offset("b_nested_vmcs12_primary_control")] = 1 << 31;
        state[offset("b_nested_vmcs12_secondary_control")] = 0;
        assert_eq!(run(&mut state, test_native_shadow_validate, 0, 0), 1);
    }

    #[test]
    fn entry_rejects_unsupported_host_mode_and_control_dependencies() {
        for true_controls in [false, true] {
            let mut state = context();
            for name in [
                "b_nested_vmx_pinbased_ctls",
                "b_nested_vmx_procbased_ctls",
                "b_nested_vmx_exit_ctls",
                "b_nested_vmx_entry_ctls",
                "b_nested_vmx_true_pinbased_ctls",
                "b_nested_vmx_true_procbased_ctls",
                "b_nested_vmx_true_exit_ctls",
                "b_nested_vmx_true_entry_ctls",
                "b_nested_vmx_procbased_ctls2",
            ] {
                state[offset(name)] = 0xffff_ffff_0000_0000;
            }
            state[offset("b_nested_vmx_basic")] = u64::from(true_controls) << 55;
            state[offset("b_nested_vmx_cr0_fixed1")] = u64::MAX;
            state[offset("b_nested_vmx_cr4_fixed1")] = u64::MAX;
            state[offset("b_nested_vmcs12_host_cr4")] = 0x2020;
            state[offset("b_nested_vmcs12_ept_pointer")] = 0x101e;
            let fields = offset("b_nested_vmcs12_extended_fields");
            state[fields + 44] = 8;
            state[fields + 49] = 16;
            for (pin, primary, secondary, exit, expected) in [
                (0, 0, 0, 1 << 9, 0),
                (1 << 5, 0, 0, 1 << 9, 7),
                (0, 1 << 22, 0, 1 << 9, 7),
                (1 << 3, 1 << 22, 0, 1 << 9, 7),
                ((1 << 3) | (1 << 5), 1 << 22, 0, 1 << 9, 0),
                (0, 1 << 31, 1 << 7, 1 << 9, 7),
                (0, 1 << 31, (1 << 7) | 2, 1 << 9, 0),
                (0, 0, 1 << 7, 1 << 9, 0),
                (0, 0, 0, 0, 7),
            ] {
                state[offset("b_nested_vmcs12_pin_based_control")] = pin;
                state[offset("b_nested_vmcs12_primary_control")] = primary;
                state[offset("b_nested_vmcs12_secondary_control")] = secondary;
                state[offset("b_nested_vmcs12_vm_exit_controls")] = exit;
                assert_eq!(
                    run(&mut state, test_native_shadow_entry, 0, 0),
                    expected,
                    "true={true_controls} pin={pin:#x} primary={primary:#x} secondary={secondary:#x}"
                );
            }
        }
    }

    #[test]
    fn bitmap_field_availability_includes_high_halves_and_tracks_capability() {
        let mut state = context();
        for supported in [false, true] {
            state[offset("b_nested_vmx_procbased_ctls2")] = u64::from(supported) << 46;
            for field in 0x2026..=0x2029 {
                assert_eq!(
                    run(&mut state, test_native_shadow_field, field, 0),
                    u64::from(supported)
                );
            }
            assert_eq!(run(&mut state, test_native_shadow_field, 0x681e, 0), 1);
        }
    }

    #[test]
    fn l2_link_and_flush_follow_effective_controls_and_entry_success() {
        let mut state = context();
        let fields = offset("b_nested_vmcs12_extended_fields");
        state[fields + 23] = 0x3000;
        run(&mut state, test_native_shadow_link, 0, 0);
        assert_eq!(state[offset("test_link")], u64::MAX);
        state[offset("b_nested_last_merged_secondary_controls")] = 1 << 14;
        state[offset("test_translation_delta")] = 0x5000;
        run(&mut state, test_native_shadow_link, 0, 0);
        assert_eq!(state[offset("test_link")], 0x8000);
        run(&mut state, test_native_shadow_flush, 0, 0);
        assert_eq!(state[offset("test_cleared")], 0x8000);
        assert_eq!(state[fields + 23], 0x3000);
        state[offset("b_last_reason")] = 0x8000_0021;
        run(&mut state, test_native_shadow_flush, 0, 0);
        assert_eq!(state[offset("test_clear_count")], 1);
        state[offset("b_last_reason")] = 10;
        state[fields + 23] = u64::MAX;
        run(&mut state, test_native_shadow_flush, 0, 0);
        assert_eq!(state[offset("test_clear_count")], 1);
        state[fields + 23] = 0x3000;
        state[offset("b_nested_last_merged_secondary_controls")] = 0;
        run(&mut state, test_native_shadow_flush, 0, 0);
        assert_eq!(state[offset("test_clear_count")], 1);
    }
}

#[cfg(test_harness = "shadow")]
mod shadow {
    const HOST_RSP: u64 = 0x6c14;
    const HOST_RIP: u64 = 0x6c16;
    const READ_BITMAP_BYTE: usize = (HOST_RSP >> 3) as usize;
    const READ_BYPASS_MASK: u8 = 0x50;
    const READ_TRAP_MASK: u8 = !READ_BYPASS_MASK;

    #[repr(C)]
    struct Context {
        shadow_vmcs_region: u64,
        shadow_vmread_bitmap: u64,
        probe_complete: u64,
        vmcs12_host_rip: u64,
        vmcs12_host_rsp: u64,
        telemetry_probe_active: u64,
        current_vmcs: u64,
        shadow_rip: u64,
        shadow_rsp: u64,
    }

    core::arch::global_asm!(
        include_str!("../builds/vmcs-shadow-tests/handlers.S"),
        b_nested_shadow_vmcs_region = const core::mem::offset_of!(Context, shadow_vmcs_region),
        b_nested_shadow_vmread_bitmap = const core::mem::offset_of!(Context, shadow_vmread_bitmap),
        b_nested_probe_complete = const core::mem::offset_of!(Context, probe_complete),
        b_nested_vmcs12_host_rip = const core::mem::offset_of!(Context, vmcs12_host_rip),
        b_nested_vmcs12_host_rsp = const core::mem::offset_of!(Context, vmcs12_host_rsp),
        b_telemetry_probe_active = const core::mem::offset_of!(Context, telemetry_probe_active),
        test_current_vmcs = const core::mem::offset_of!(Context, current_vmcs),
        test_shadow_rip = const core::mem::offset_of!(Context, shadow_rip),
        test_shadow_rsp = const core::mem::offset_of!(Context, shadow_rsp),
        host_rip = const HOST_RIP,
        host_rsp = const HOST_RSP,
        vmcs_shadow_read_byte_offset = const READ_BITMAP_BYTE,
        vmcs_shadow_read_bypass_mask = const READ_BYPASS_MASK,
        vmcs_shadow_read_trap_mask = const READ_TRAP_MASK,
    );

    unsafe extern "win64" {
        fn test_shadow_sync(context: *mut Context);
        fn test_shadow_write(context: *mut Context, field: u64, value: u64);
        fn test_shadow_intercept(context: *mut Context);
    }

    #[test]
    fn shadow_vmcs_sync_respects_capability_probe_and_lifecycle() {
        let mut bitmap = vec![0xff_u8; 4096];
        let byte = READ_BITMAP_BYTE;
        let mut context = Context {
            shadow_vmcs_region: 0,
            shadow_vmread_bitmap: bitmap.as_mut_ptr() as u64,
            probe_complete: 0,
            vmcs12_host_rip: 0x1234_5678,
            vmcs12_host_rsp: 0x1234_f000,
            telemetry_probe_active: 0,
            current_vmcs: 0,
            shadow_rip: 0,
            shadow_rsp: 0,
        };
        unsafe { test_shadow_sync(&mut context) };
        assert_eq!(bitmap[byte], 0xff);
        assert_eq!((context.shadow_rip, context.shadow_rsp), (0, 0));

        context.shadow_vmcs_region = 0x6000;
        bitmap[byte] = READ_TRAP_MASK;
        unsafe { test_shadow_sync(&mut context) };
        assert_eq!(bitmap[byte], 0xff);
        assert_eq!((context.shadow_rip, context.shadow_rsp), (0, 0));

        context.probe_complete = 1;
        context.telemetry_probe_active = 1;
        bitmap[byte] = READ_TRAP_MASK;
        unsafe { test_shadow_sync(&mut context) };
        assert_eq!(bitmap[byte], 0xff);
        assert_eq!((context.shadow_rip, context.shadow_rsp), (0, 0));

        context.telemetry_probe_active = 0;
        unsafe { test_shadow_sync(&mut context) };
        assert_eq!(bitmap[byte], READ_TRAP_MASK);
        assert_eq!(context.current_vmcs, 0);
        assert_eq!(context.shadow_rip, context.vmcs12_host_rip);
        assert_eq!(context.shadow_rsp, context.vmcs12_host_rsp);

        unsafe { test_shadow_write(&mut context, HOST_RIP, 0x9876_5432) };
        assert_eq!(context.shadow_rip, 0x9876_5432);
        assert_eq!(context.current_vmcs, 0);
        unsafe { test_shadow_intercept(&mut context) };
        assert_eq!(bitmap[byte], 0xff);
    }
}

#[cfg(test_harness = "logging")]
core::arch::global_asm!(include_str!("../builds/nested-logging-tests/lifecycle.S"));
#[cfg(test_harness = "logging")]
core::arch::global_asm!(include_str!("../builds/nested-logging-tests/display.S"));
#[cfg(test_harness = "logging")]
include!("../builds/nested-logging-tests/offsets.rs");

#[cfg(test_harness = "logging")]
unsafe extern "win64" {
    fn test_vmx_lifecycle(context: *mut u64, vmxoff: u32) -> u32;
    fn test_update_retire_nested(context: *mut u64) -> u32;
    fn test_resident_display(event: *const u64, hexadecimal: u32);
}

#[cfg(test_harness = "logging")]
fn lifecycle(probe_active: bool, telemetry_active: bool) -> u64 {
    let revision = 1_u64;
    let mut context = [0_u64; 64];
    let mut vmread_bitmap = vec![0xff_u8; 4096];
    let shadow_byte = 0xd82;
    vmread_bitmap[shadow_byte] = 0xaf;
    context[offset("b_nested_shadow_vmread_bitmap")] = vmread_bitmap.as_mut_ptr() as u64;
    context[offset("b_nested_l1_cr4")] = 1 << 13;
    context[offset("b_nested_vmx_cr0_fixed1")] = u64::MAX;
    context[offset("b_nested_vmx_cr4_fixed1")] = u64::MAX;
    context[offset("b_nested_feature_control")] = 5;
    context[offset("b_nested_vmx_basic")] = revision;
    context[offset("b_test_operand")] = &revision as *const u64 as u64;
    context[offset("b_test_rflags")] = 0x202 | 0x8d5;
    context[offset("b_test_rip")] = 0x1000;
    context[offset("b_telemetry_probe_active")] = u64::from(probe_active);
    context[offset("b_telemetry_active")] = u64::from(telemetry_active);

    assert_eq!(unsafe { test_vmx_lifecycle(context.as_mut_ptr(), 0) }, 0);
    assert_eq!(context[offset("b_nested_active")], 1);
    assert_eq!(context[offset("b_nested_current_vmcs")], u64::MAX);
    assert_eq!(context[offset("b_nested_instruction_error")], 0);
    assert_eq!(context[offset("b_test_rflags")], 0x202);
    assert_eq!(context[offset("b_test_rip")], 0x1003);
    assert_eq!(vmread_bitmap[shadow_byte], 0xff);

    context[offset("b_test_rflags")] |= 0x8d5;
    vmread_bitmap[shadow_byte] = 0xaf;
    assert_eq!(unsafe { test_vmx_lifecycle(context.as_mut_ptr(), 1) }, 0);
    assert_eq!(context[offset("b_nested_active")], 0);
    assert_eq!(context[offset("b_nested_current_vmcs")], u64::MAX);
    assert_eq!(context[offset("b_test_stores")], 1);
    assert_eq!(context[offset("b_test_rflags")], 0x202);
    assert_eq!(context[offset("b_test_rip")], 0x1006);
    assert_eq!(vmread_bitmap[shadow_byte], 0xff);
    for name in ["b_nested_vmxon_count", "b_nested_vmxoff_count"] {
        assert_eq!(context[offset(name)], u64::from(telemetry_active));
    }
    context[offset("b_test_serial_bytes")]
}

#[cfg(test_harness = "logging")]
#[test]
fn vmxon_checks_virtual_cr0_cr4_fixed_masks_before_reading_the_operand() {
    for (cr0, cr4, expected) in [
        (0x80000021, 0x2020, 0),
        (0x21, 0x2020, 13),
        (0x80000001, 0x2020, 13),
        (0x80000021 | (1 << 63), 0x2020, 13),
        (0x80000021, 0x2000, 13),
        (0x80000021, 0x2020 | (1 << 63), 13),
        (0x80000021, 0x20, 6),
    ] {
        let revision = 1_u64;
        let mut state = [0_u64; 64];
        state[offset("b_test_cr0")] = cr0;
        state[offset("b_test_cr4")] = cr4 | (1 << 13);
        state[offset("b_nested_l1_cr4")] = cr4 & (1 << 13);
        state[offset("b_nested_vmx_cr0_fixed0")] = 0x80000021;
        state[offset("b_nested_vmx_cr0_fixed1")] = 0xffff_ffff;
        state[offset("b_nested_vmx_cr4_fixed0")] = 0x2020;
        state[offset("b_nested_vmx_cr4_fixed1")] = 0xffff_ffff;
        state[offset("b_nested_feature_control")] = 5;
        state[offset("b_nested_vmx_basic")] = revision;
        state[offset("b_test_operand")] = &revision as *const u64 as u64;
        state[offset("b_test_rip")] = 0x1000;
        assert_eq!(
            unsafe { test_vmx_lifecycle(state.as_mut_ptr(), 0) },
            u32::from(expected != 0)
        );
        assert_eq!(state[offset("b_test_exception")], expected);
        assert_eq!(state[offset("b_nested_active")], u64::from(expected == 0));
        assert_eq!(
            state[offset("b_test_rip")],
            if expected == 0 { 0x1003 } else { 0x1000 }
        );
    }
    let mut state = [0_u64; 64];
    state[offset("b_nested_l1_cr4")] = 0x2000;
    state[offset("b_nested_feature_control")] = 5;
    state[offset("b_test_cr0")] = 1 << 31;
    state[offset("b_test_cr0_mask")] = 1 << 31;
    state[offset("b_nested_vmx_cr0_fixed0")] = 1 << 31;
    assert_eq!(unsafe { test_vmx_lifecycle(state.as_mut_ptr(), 0) }, 1);
    assert_eq!(state[offset("b_test_exception")], 13);
    state[offset("b_test_exception")] = 0;
    state[offset("b_nested_active")] = 1;
    state[offset("b_nested_feature_control")] = 0;
    assert_eq!(unsafe { test_vmx_lifecycle(state.as_mut_ptr(), 0) }, 1);
    assert_eq!(state[offset("b_test_exception")], 0);
    assert_eq!(state[offset("b_test_vmx_error")], 15);
}

#[cfg(test_harness = "logging")]
#[test]
fn update_withdraws_a_native_nested_session_and_retires_hardware_and_cached_state() {
    let mut state = [0_u64; 64];
    state[offset("b_nested_active")] = 1;
    state[offset("b_nested_current_vmcs")] = 0x2000;
    state[offset("b_nested_vmxon_region")] = 0x1000;
    state[offset("b_nested_vmcs02_region")] = 0x3000;
    state[offset("b_nested_shadow_vmcs_region")] = 0x4000;
    state[offset("b_nested_vmcs02_launched")] = 1;
    state[offset("b_nested_l1_cr4")] = 1 << 13;
    state[offset("b_test_cr4_shadow")] = 1 << 13;
    state[offset("b_test_page_writable")] = 1;
    for name in ["b_nested_vmcs02_rare_state_pending", "b_nested_vmcs02_guest_cache_valid",
                 "b_nested_vmcs02_control_cache_valid", "b_nested_vmcs02_vpid_cache",
                 "b_nested_vmcs02_last_vpid"] {
        state[offset(name)] = u64::MAX;
    }
    state[offset("b_nested_vmcs02_vpid_cache")] = u64::from(u32::MAX);
    assert_eq!(unsafe { test_update_retire_nested(state.as_mut_ptr()) }, 1);
    assert_eq!(state[offset("b_test_stores")], 1);
    assert_eq!(state[offset("b_test_clear_count")], 2);
    assert_eq!(state[offset("b_test_clear_first")], 0x3000);
    assert_eq!(state[offset("b_test_clear_second")], 0x4000);
    assert_eq!(state[offset("b_nested_current_vmcs")], u64::MAX);
    for name in ["b_nested_active", "b_nested_vmxon_region", "b_nested_vmcs02_launched",
                 "b_nested_l1_cr4", "b_test_cr4_shadow", "b_nested_vmcs02_rare_state_pending",
                 "b_nested_vmcs02_guest_cache_valid", "b_nested_vmcs02_control_cache_valid",
                 "b_nested_vmcs02_vpid_cache", "b_nested_vmcs02_last_vpid"] {
        assert_eq!(state[offset(name)], 0, "{name}");
    }
}

#[cfg(test_harness = "logging")]
#[test]
fn unsupported_nested_handoffs_and_unwritable_vmcs12_fail_before_retirement() {
    for blocker in ["b_nested_l2_active", "b_nested_evmcs_active", "b_test_guest_os_id", "b_test_page_writable"] {
        let mut state = [0_u64; 64];
        state[offset("b_nested_active")] = 1;
        state[offset("b_nested_current_vmcs")] = 0x2000;
        state[offset("b_test_page_writable")] = 1;
        state[offset(blocker)] = u64::from(blocker != "b_test_page_writable");
        assert_eq!(unsafe { test_update_retire_nested(state.as_mut_ptr()) }, 0, "{blocker}");
        assert_eq!(state[offset("b_test_stores")], 0, "{blocker}");
        assert_eq!(state[offset("b_test_clear_count")], 0, "{blocker}");
        assert_eq!(state[offset("b_nested_active")], 1, "{blocker}");
    }
    let mut state = [0_u64; 64];
    state[offset("b_nested_current_vmcs")] = u64::MAX;
    state[offset("b_test_clear_failure")] = 1;
    state[offset("b_nested_vmcs02_launched")] = 1;
    assert_eq!(unsafe { test_update_retire_nested(state.as_mut_ptr()) }, 0);
    assert_eq!(state[offset("b_nested_vmcs02_launched")], 1);
}

#[cfg(test_harness = "logging")]
#[test]
fn runtime_update_freezes_new_nested_sessions_until_completion_or_cancellation() {
    for phase in 0_u32..=9 {
        let revision = 1_u64;
        let mut state = [0_u64; 64];
        state[offset("b_test_update_context")] = &phase as *const u32 as u64;
        state[offset("b_nested_l1_cr4")] = 1 << 13;
        state[offset("b_nested_feature_control")] = 5;
        state[offset("b_nested_vmx_basic")] = revision;
        state[offset("b_nested_vmx_cr0_fixed1")] = u64::MAX;
        state[offset("b_nested_vmx_cr4_fixed1")] = u64::MAX;
        state[offset("b_test_operand")] = &revision as *const u64 as u64;
        state[offset("b_test_rflags")] = 0x202;
        state[offset("b_test_rip")] = 0x1000;
        let frozen = matches!(phase, 2..=4 | 6);
        assert_eq!(unsafe { test_vmx_lifecycle(state.as_mut_ptr(), 0) }, 0);
        assert_eq!(state[offset("b_nested_active")], u64::from(!frozen));
        assert_eq!(state[offset("b_test_rflags")] & 0x8d5, u64::from(frozen));
        assert_eq!(state[offset("b_test_rip")], 0x1003);
    }
}

#[cfg(test_harness = "logging")]
#[test]
fn runtime_vmx_lifecycle_never_waits_for_uart_even_with_telemetry_enabled() {
    for telemetry_active in [false, true] {
        assert_eq!(lifecycle(false, telemetry_active), 0);
    }
}

#[cfg(test_harness = "logging")]
#[test]
fn explicit_startup_probe_retains_serial_lifecycle_evidence() {
    assert!(lifecycle(true, true) > 0);
}

#[cfg(test_harness = "logging")]
#[test]
fn firmware_display_is_writable_only_during_the_post_ebs_window() {
    for hexadecimal in [0, 1] {
        for (ebs_seen, deadline, writable) in
            [(0, u64::MAX, false), (1, 1001, true), (1, 1000, false)]
        {
            let mut framebuffer = vec![0x55aa55aa_u32; 512 * 128];
            let event = [ebs_seen, framebuffer.as_mut_ptr() as u64, 512 * 4, deadline];
            unsafe { test_resident_display(event.as_ptr(), hexadecimal) };
            assert_eq!(
                framebuffer.iter().any(|&pixel| pixel != 0x55aa55aa),
                writable
            );
        }
    }
}

#[cfg(test_harness = "regressions")]
mod regressions {
    include!("../builds/nested-regression-tests/offsets.rs");
    core::arch::global_asm!(include_str!("../builds/nested-regression-tests/handlers.S"));

    unsafe extern "win64" {
        fn test_nested_regression(
            state: *mut u64,
            operation: u32,
            value: u64,
            root_count: u64,
        ) -> u32;
    }

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[repr(C, align(4096))]
    struct Page([u64; 512]);

    struct Arena(Vec<Box<Page>>);

    impl Arena {
        fn new() -> Self {
            Self(Vec::new())
        }

        fn page(&mut self) -> u64 {
            let mut page = Box::new(Page([0; 512]));
            let address = page.0.as_mut_ptr() as u64;
            self.0.push(page);
            address
        }

        fn map(&mut self, root: u64, address: u64, target: u64, permissions: u64) {
            let mut table = root;
            for shift in [39, 30, 21, 12] {
                let slot = unsafe { (table as *mut u64).add(((address >> shift) & 511) as usize) };
                if shift == 12 {
                    unsafe { slot.write(target | permissions) };
                    return;
                }
                let mut entry = unsafe { slot.read() };
                if entry == 0 {
                    entry = self.page() | 7;
                    unsafe { slot.write(entry) };
                }
                table = entry & !4095;
            }
        }
    }

    fn run(state: &mut [u64], operation: u32, value: u64, root_count: u64) -> u32 {
        unsafe { test_nested_regression(state.as_mut_ptr(), operation, value, root_count) }
    }

    fn paging_state(arena: &mut Arena, first: u64, second: u64) -> (Vec<u64>, u64, u64) {
        let mut state = vec![0; CONTEXT_QWORDS];
        let root = arena.page();
        let ept = arena.page();
        arena.map(root, 0x400000, 0x1000000, 7);
        arena.map(root, 0x401000, 0x3000000, 7);
        arena.map(ept, 0x1000000, first, 7);
        arena.map(ept, 0x3000000, second, 7);
        let table_addresses: Vec<_> = arena.0.iter().map(|page| page.0.as_ptr() as u64).collect();
        for address in table_addresses {
            arena.map(ept, address, address, 7);
        }
        state[offset("b_cache_ept_pointer")] = ept;
        let vmcs = offset("test_vmcs");
        state[vmcs] = 1 << 31;
        state[vmcs + 2] = root;
        state[vmcs + 3] = 1 << 9;
        state[vmcs + 4] = 1 << 13;
        (state, root, ept)
    }

    #[test]
    fn review_vmx_operand_write_honors_guest_page_write_protection() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut arena = Arena::new();
        let first = arena.page();
        let second = arena.page();
        let (mut state, root, _) = paging_state(&mut arena, first, second);
        arena.map(root, 0x400000, 0x1000000, 1);
        state[offset("test_vmcs")] |= 1 << 16;
        state[offset("b_nested_operand_linear_address")] = 0x400000;
        state[offset("b_nested_operand_data")] = u64::MAX;
        let result = run(&mut state, 1, 8, 0);
        let written = unsafe { (first as *const u64).read() };
        assert_eq!((result, written), (0, 0));
    }

    #[test]
    fn review_vmx_operand_walk_translates_guest_page_table_addresses() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut arena = Arena::new();
        let first = arena.page();
        let second = arena.page();
        let (mut state, root, ept) = paging_state(&mut arena, first, second);
        let root_gpa = arena.page();
        let table_addresses: Vec<_> = arena.0.iter().map(|page| page.0.as_ptr() as u64).collect();
        for address in table_addresses {
            arena.map(ept, address, address, 7);
        }
        arena.map(ept, root_gpa, root, 7);
        state[offset("test_vmcs") + 2] = root_gpa;
        state[offset("b_nested_operand_linear_address")] = 0x400000;
        unsafe { (first as *mut u64).write(0x123456789abcdef0) };
        let result = run(&mut state, 0, 8, 0);
        assert_eq!(
            (result, state[offset("b_nested_operand_data")]),
            (1, 0x123456789abcdef0)
        );
    }

    #[test]
    fn operand_walk_permissions_and_remapping_cover_all_paging_modes() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        for (mode, levels) in [
            (0, vec![22, 12]),
            (1, vec![30, 21, 12]),
            (2, vec![39, 30, 21, 12]),
            (3, vec![48, 39, 30, 21, 12]),
        ] {
            for leaf_shift in [12, 21, 22, 30] {
                if !levels.contains(&leaf_shift) || (mode == 1 && leaf_shift == 30) {
                    continue;
                }
                let leaf_level = levels
                    .iter()
                    .position(|&shift| shift == leaf_shift)
                    .unwrap();
                for denied_level in 0..=leaf_level + 1 {
                    for wp in [false, true] {
                        let mut arena = Arena::new();
                        let ept = arena.page();
                        let data = arena.page();
                        let mut state = vec![0; CONTEXT_QWORDS];
                        let linear = 0x401238_u64;
                        let root_gpa = 0x900000 + if mode == 1 { 32 } else { 0 };
                        for (level, &shift) in levels.iter().enumerate().take(leaf_level + 1) {
                            let table = arena.page();
                            let table_gpa = 0x900000 + level as u64 * 4096;
                            arena.map(ept, table_gpa, table, 1);
                            let index = (linear >> shift) & if mode == 0 { 1023 } else { 511 };
                            let target = if level == leaf_level {
                                0x40000000
                            } else {
                                table_gpa + 4096
                            };
                            let permissions = if level == denied_level || (mode == 1 && level == 0)
                            {
                                1
                            } else {
                                3
                            };
                            let entry = target
                                | permissions
                                | if level == leaf_level && shift > 12 {
                                    0x80
                                } else {
                                    0
                                };
                            let base = table + if mode == 1 && level == 0 { 32 } else { 0 };
                            unsafe {
                                if mode == 0 {
                                    ((base + index * 4) as *mut u32).write(entry as u32);
                                } else {
                                    ((base + index * 8) as *mut u64).write(entry);
                                }
                            }
                        }
                        let physical = 0x40000000 | (linear & ((1 << leaf_shift) - 1));
                        arena.map(ept, physical & !4095, data, 7);
                        state[offset("b_cache_ept_pointer")] = ept;
                        let vmcs = offset("test_vmcs");
                        state[vmcs] = (1 << 31) | if wp { 1 << 16 } else { 0 };
                        state[vmcs + 1] = match mode {
                            0 => 1 << 4,
                            1 => 1 << 5,
                            3 => 1 << 12,
                            _ => 0,
                        };
                        state[vmcs + 2] = root_gpa;
                        state[vmcs + 3] = if mode >= 2 { 1 << 9 } else { 0 };
                        state[offset("b_nested_operand_linear_address")] = linear;
                        assert_eq!(run(&mut state, 0, 8, 0), 1);
                        state[offset("b_nested_operand_data")] = u64::MAX;
                        let denied =
                            wp && denied_level <= leaf_level && !(mode == 1 && denied_level == 0);
                        assert_eq!(
                            run(&mut state, 1, 8, 0),
                            u32::from(!denied),
                            "mode={mode} leaf={leaf_shift} level={denied_level} wp={wp}"
                        );
                        assert_eq!(
                            unsafe { ((data + (linear & 4095)) as *const u64).read() },
                            if denied { 0 } else { u64::MAX }
                        );
                        if denied {
                            assert_eq!(state[offset("test_controls") + 14], 3);
                            assert_eq!(state[offset("test_controls") + 13], 0x80000b0e);
                            assert_eq!(state[offset("test_fault_address")], linear);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn legacy_large_pages_preserve_pse36_physical_address_bits() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        for high_bits in [1_u64, 15, 128, 255] {
            for pat in [0, 1 << 12] {
                let mut arena = Arena::new();
                let ept = arena.page();
                let directory = arena.page();
                let low_data = arena.page();
                let high_data = arena.page();
                let linear = 0x401238_u64;
                let low_physical = 0x4000_0000 | (linear & 0x3f_ffff);
                let high_physical = low_physical | (high_bits << 32);
                arena.map(ept, 0x90_0000, directory, 7);
                arena.map(ept, low_physical & !4095, low_data, 7);
                arena.map(ept, high_physical & !4095, high_data, 7);
                let value = 0x1234_5678_9abc_def0;
                unsafe {
                    (directory as *mut u32).add(1).write(
                        (0x4000_0083 | (high_bits << 13) | pat) as u32,
                    );
                    ((high_data + (linear & 4095)) as *mut u64).write(value);
                }
                let mut state = vec![0; CONTEXT_QWORDS];
                state[offset("b_cache_ept_pointer")] = ept;
                let vmcs = offset("test_vmcs");
                state[vmcs] = (1 << 31) | (1 << 16);
                state[vmcs + 1] = 1 << 4;
                state[vmcs + 2] = 0x90_0000;
                state[offset("b_nested_operand_linear_address")] = linear;
                assert_eq!(run(&mut state, 0, 8, 0), 1);
                assert_eq!(state[offset("b_nested_operand_data")], value);
                state[offset("b_nested_operand_data")] = u64::MAX;
                assert_eq!(run(&mut state, 1, 8, 0), 1);
                unsafe {
                    assert_eq!(((high_data + (linear & 4095)) as *const u64).read(), u64::MAX);
                    assert_eq!(((low_data + (linear & 4095)) as *const u64).read(), 0);
                }
            }
        }
    }

    #[test]
    fn inaccessible_guest_paging_structure_is_rejected_at_every_level() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        for denied_level in 0..4 {
            let mut arena = Arena::new();
            let first = arena.page();
            let second = arena.page();
            let (mut state, root, ept) = paging_state(&mut arena, first, second);
            let mut table = root;
            for shift in [39, 30, 21].into_iter().take(denied_level) {
                table =
                    unsafe { (table as *const u64).add((0x400000 >> shift) & 511).read() } & !4095;
            }
            arena.map(ept, table, 0, 0);
            state[offset("b_nested_operand_linear_address")] = 0x400000;
            state[offset("b_nested_operand_data")] = u64::MAX;
            assert_eq!(run(&mut state, 0, 8, 0), 0);
            assert_eq!(state[offset("b_nested_operand_data")], u64::MAX);
            assert_eq!(state[offset("test_fault_address")], 0x400000);
            assert_eq!(state[offset("test_controls") + 14], 0);
        }
    }

    #[test]
    fn guest_write_protection_on_second_page_is_atomic_and_reports_protection_fault() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut arena = Arena::new();
        let first = arena.page();
        let second = arena.page();
        let (mut state, root, _) = paging_state(&mut arena, first, second);
        arena.map(root, 0x401000, 0x3000000, 1);
        state[offset("test_vmcs")] |= 1 << 16;
        state[offset("b_nested_operand_linear_address")] = 0x400ffc;
        state[offset("b_nested_operand_data")] = u64::MAX;
        assert_eq!(run(&mut state, 1, 8, 0), 0);
        assert_eq!(state[offset("test_fault_address")], 0x401000);
        assert_eq!(state[offset("test_controls") + 14], 3);
        unsafe {
            assert_eq!((first as *const u64).add(511).read(), 0);
            assert_eq!((second as *const u64).read(), 0);
        }
    }

    #[test]
    fn operands_read_and_write_every_cross_page_split_through_both_translations() {
        let _guard = TEST_LOCK.lock().unwrap();
        for width in [4, 8, 16] {
            for first_length in 1..width {
                let mut arena = Arena::new();
                let first = arena.page();
                let second = arena.page();
                let (mut state, _, _) = paging_state(&mut arena, first, second);
                state[offset("b_nested_operand_linear_address")] = 0x401000 - first_length;
                let expected: Vec<u8> = (0..width).map(|index| (index * 13 + 7) as u8).collect();
                unsafe {
                    let first_bytes = std::slice::from_raw_parts_mut(first as *mut u8, 4096);
                    let second_bytes = std::slice::from_raw_parts_mut(second as *mut u8, 4096);
                    first_bytes.fill(0xa5);
                    second_bytes.fill(0x5a);
                    first_bytes[4096 - first_length as usize..]
                        .copy_from_slice(&expected[..first_length as usize]);
                    second_bytes[..(width - first_length) as usize]
                        .copy_from_slice(&expected[first_length as usize..]);
                    assert_eq!(run(&mut state, 0, width, 0), 1);
                    let scratch = state.as_ptr().add(offset("b_nested_operand_data")) as *const u8;
                    assert_eq!(
                        std::slice::from_raw_parts(scratch, width as usize),
                        expected
                    );
                    let replacement: Vec<u8> = expected.iter().map(|value| value ^ 0xff).collect();
                    let scratch =
                        state.as_mut_ptr().add(offset("b_nested_operand_data")) as *mut u8;
                    std::ptr::copy_nonoverlapping(replacement.as_ptr(), scratch, width as usize);
                    assert_eq!(run(&mut state, 1, width, 0), 1);
                    assert_eq!(
                        &first_bytes[4096 - first_length as usize..],
                        &replacement[..first_length as usize]
                    );
                    assert_eq!(
                        &second_bytes[..(width - first_length) as usize],
                        &replacement[first_length as usize..]
                    );
                    assert!(
                        first_bytes[..4096 - first_length as usize]
                            .iter()
                            .all(|value| *value == 0xa5)
                    );
                    assert!(
                        second_bytes[(width - first_length) as usize..]
                            .iter()
                            .all(|value| *value == 0x5a)
                    );
                }
            }
        }
    }

    #[test]
    fn missing_or_readonly_second_page_never_partially_writes_a_vmx_operand() {
        let _guard = TEST_LOCK.lock().unwrap();
        for missing_pte in [false, true] {
            let mut arena = Arena::new();
            let first = arena.page();
            let second = arena.page();
            let (mut state, root, ept) = paging_state(&mut arena, first, second);
            state[offset("b_nested_operand_linear_address")] = 0x400ffc;
            state[offset("b_nested_operand_data")] = u64::MAX;
            if missing_pte {
                arena.map(root, 0x401000, 0, 0);
            } else {
                arena.map(ept, 0x3000000, second, 5);
                assert_eq!(run(&mut state, 0, 8, 0), 1);
                state[offset("b_nested_operand_data")] = u64::MAX;
            }
            assert_eq!(run(&mut state, 1, 8, 0), 0);
            assert_eq!(state[offset("test_fault_address")], 0x401000);
            unsafe {
                assert_eq!((first as *const u64).add(511).read(), 0);
                assert_eq!((second as *const u64).read(), 0);
            }
        }
    }

    #[test]
    fn l1_msr_bitmap_checks_read_write_low_high_boundaries_and_unconditional_exits() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut arena = Arena::new();
        let bitmap = arena.page();
        let ept = arena.page();
        arena.map(ept, 0x800000, bitmap, 7);
        let mut state = vec![0; CONTEXT_QWORDS];
        state[offset("b_cache_ept_pointer")] = ept;
        state[offset("b_nested_vmcs12_msr_bitmap")] = 0x800000;
        state[offset("b_nested_vmcs12_primary_control")] = 1 << 28;
        for msr in [0, 0x1fff, 0xc0000000, 0xc0000080, 0xc0001fff] {
            for write in [0, 1] {
                state[offset("test_write")] = write;
                let byte_offset = (if msr >= 0xc0000000 { 1024 } else { 0 })
                    + write as usize * 2048
                    + (msr as usize & 0x1fff) / 8;
                let bit = 1 << (msr & 7);
                unsafe { (bitmap as *mut u8).add(byte_offset).write(0) };
                assert_eq!(run(&mut state, 2, msr, 0), 0);
                unsafe { (bitmap as *mut u8).add(byte_offset).write(bit) };
                assert_eq!(run(&mut state, 2, msr, 0), 1);
                state[offset("test_write")] = write ^ 1;
                assert_eq!(run(&mut state, 2, msr, 0), 0);
                unsafe { (bitmap as *mut u8).add(byte_offset).write(0) };
            }
        }
        for msr in [0x2000, 0xbfffffff, 0xc0002000, u32::MAX as u64] {
            assert_eq!(run(&mut state, 2, msr, 0), 1);
        }
        state[offset("b_nested_vmcs12_primary_control")] = 0;
        assert_eq!(run(&mut state, 2, 0xc0000080, 0), 1);
        state[offset("b_nested_vmcs12_primary_control")] = 1 << 28;
        arena.map(ept, 0x800000, bitmap, 0);
        assert_eq!(run(&mut state, 2, 0xc0000080, 0), 1);
    }

    fn msr_state(
        root_count: u64,
        requested: &[[u64; 2]],
    ) -> (
        Vec<u64>,
        Vec<[u64; 2]>,
        Vec<[u64; 2]>,
        Vec<[u64; 2]>,
        Vec<[u64; 2]>,
        Arena,
    ) {
        let mut state = vec![0; CONTEXT_QWORDS];
        let mut root = vec![[0x48, 0x11]];
        let mut entry = vec![[0xdead, 0xbeef]; 514];
        let mut captured = vec![[0xdead, 0xbeef]; 514];
        let mut l1 = requested.to_vec();
        state[offset("b_nested_l0_msr_guest_list")] = root.as_mut_ptr() as u64;
        state[offset("b_nested_l0_msr_host_list")] = root.as_ptr() as u64;
        state[offset("b_nested_vmcs02_entry_msr_list")] = entry.as_mut_ptr() as u64;
        state[offset("b_nested_vmcs01_entry_msr_list")] = entry.as_mut_ptr() as u64;
        state[offset("b_nested_vmcs02_exit_store_msr_list")] = captured.as_mut_ptr() as u64;
        state[offset("b_nested_vmcs12_vm_exit_msr_store_addr")] = l1.as_mut_ptr() as u64;
        state[offset("b_nested_vmcs12_vm_exit_msr_store_count")] = l1.len() as u64;
        let mut arena = Arena::new();
        let ept = arena.page();
        state[offset("b_cache_ept_pointer")] = ept;
        if !l1.is_empty() {
            let start = l1.as_ptr() as u64 & !4095;
            let end = (l1.as_ptr() as u64 + l1.len() as u64 * 16 - 1) & !4095;
            for page in (start..=end).step_by(4096) {
                arena.map(ept, page, page, 7);
            }
        }
        run(&mut state, 3, 0, root_count);
        (state, root, entry, captured, l1, arena)
    }

    #[test]
    fn mixed_and_repeated_msr_stores_publish_captured_guest_values_and_saved_vmcs_fields() {
        let _guard = TEST_LOCK.lock().unwrap();
        for root_count in [0, 1] {
            let requested = [
                [0x277, 0xdead],
                [0xc0000102, 0xbeef],
                [0x48, 0x1234],
                [0x123, 0x5678],
                [0x277, 0xabcd],
                [0xc0000102, 0xef],
            ];
            let (mut state, root, _entry, mut captured, l1, _arena) =
                msr_state(root_count, &requested);
            assert_eq!(
                state[offset("b_nested_vmcs12_vm_exit_msr_store_count")],
                requested.len() as u64
            );
            assert_eq!(state[offset("b_nested_captured_msr_store_count")], 2);
            assert_eq!(state[offset("test_controls") + 3], 2);
            for slot in captured.iter_mut().take(2) {
                slot[1] = match slot[0] {
                    0x48 => 0x55,
                    0xc0000102 => 0x6677,
                    _ => panic!("unexpected captured MSR"),
                };
            }
            state[offset("test_vmcs") + 5] = 0x0007040600070406;
            state[offset("test_software_msr")] = 0x9876543210;
            assert_eq!(run(&mut state, 4, 10, root_count), 1);
            let values: Vec<u64> = l1.iter().map(|slot| slot[1]).collect();
            assert_eq!(
                values,
                [
                    0x0007040600070406,
                    0x6677,
                    0x55,
                    0x9876543210,
                    0x0007040600070406,
                    0x6677
                ]
            );
            assert_eq!(root[0][1], if root_count == 1 { 0x55 } else { 0x11 });
            assert_eq!(captured[2], [0xdead, 0xbeef]);
        }
    }

    #[test]
    fn msr_lists_translate_each_page_for_entry_exit_load_and_exit_store() {
        let _guard = TEST_LOCK.lock().unwrap();
        let (mut state, _root, entry, mut captured, _l1, mut arena) = msr_state(0, &[]);
        let first = arena.page();
        let second = arena.page();
        let ept = state[offset("b_cache_ept_pointer")];
        arena.map(ept, 0x700000, first, 7);
        arena.map(ept, 0x701000, second, 7);
        let records = [(first + 4080) as *mut u64, second as *mut u64];
        for (index, address) in records.iter().enumerate() {
            unsafe {
                address.write([0x48, 0xc0000102][index]);
                address.add(1).write(0x100 + index as u64);
            }
        }
        for name in [
            "b_nested_vmcs12_vm_entry_msr_load_addr",
            "b_nested_vmcs12_vm_exit_msr_load_addr",
            "b_nested_vmcs12_vm_exit_msr_store_addr",
        ] {
            state[offset(name)] = 0x700ff0;
        }
        for name in [
            "b_nested_vmcs12_vm_entry_msr_load_count",
            "b_nested_vmcs12_vm_exit_msr_load_count",
            "b_nested_vmcs12_vm_exit_msr_store_count",
        ] {
            state[offset(name)] = 2;
        }
        assert_eq!(run(&mut state, 3, 0, 0), 1);
        assert_eq!(&entry[..2], &[[0x48, 0x100], [0xc0000102, 0x101]]);
        assert_eq!(state[offset("b_nested_captured_msr_store_count")], 2);
        captured[0][1] = 0x200;
        captured[1][1] = 0x201;
        assert_eq!(run(&mut state, 4, 10, 0), 1);
        assert_eq!(unsafe { records[0].add(1).read() }, 0x200);
        assert_eq!(unsafe { records[1].add(1).read() }, 0x201);
        assert_eq!(&entry[..2], &[[0x48, 0x200], [0xc0000102, 0x201]]);
        assert_eq!(
            state[offset("b_nested_vmcs12_vm_exit_msr_store_addr")],
            0x700ff0
        );
        arena.map(ept, 0x701000, second, 0);
        assert_eq!(run(&mut state, 3, 0, 0), 1);
        assert_eq!(state[offset("test_controls") + 1], 0);
        assert_eq!(state[offset("b_nested_captured_msr_store_count")], 0);
    }

    #[test]
    fn pat_only_list_does_not_read_stale_hardware_slots_and_failed_entry_does_not_publish() {
        let _guard = TEST_LOCK.lock().unwrap();
        for root_count in [0, 1] {
            let (mut state, _root, _entry, captured, l1, _arena) =
                msr_state(root_count, &[[0x277, 0xdeadbeef]]);
            assert_eq!(
                state[offset("b_nested_captured_msr_store_count")],
                root_count
            );
            state[offset("test_vmcs") + 5] = 0x0606060606060606;
            assert_eq!(run(&mut state, 4, 0x80000021, root_count), 1);
            assert_eq!(l1[0][1], 0xdeadbeef);
            assert_eq!(run(&mut state, 4, 10, root_count), 1);
            assert_eq!(l1[0][1], 0x0606060606060606);
            assert_eq!(captured[root_count as usize], [0xdead, 0xbeef]);
        }
    }

    #[test]
    fn invalid_store_entry_aborts_with_architectural_indicator_without_publishing_stale_data() {
        let _guard = TEST_LOCK.lock().unwrap();
        for requested in [
            [[0xdead, 0x55]],
            [[(1 << 32) | 0x277, 0x55]],
            [[0x802, 0x55]],
        ] {
            let (mut state, _root, _entry, _captured, l1, _arena) = msr_state(0, &requested);
            let mut arena = Arena::new();
            let vmcs = arena.page();
            let ept = state[offset("b_cache_ept_pointer")];
            arena.map(ept, 0x100000, vmcs, 7);
            state[offset("b_cache_ept_pointer")] = ept;
            state[offset("b_nested_current_vmcs")] = 0x100000;
            assert_eq!(run(&mut state, 4, 10, 0), 0);
            assert_eq!(state[offset("test_aborted")], 1);
            assert_eq!(l1[0][1], 0x55);
            assert_eq!(unsafe { (vmcs as *const u32).add(1).read() }, 1);
        }
    }

    #[test]
    fn full_list_software_switch_and_internal_resume_preserve_the_current_spec_ctrl() {
        let _guard = TEST_LOCK.lock().unwrap();
        for root_count in [0, 1] {
            let (mut state, mut root, _entry, mut captured, _l1, _arena) =
                msr_state(root_count, &[]);
            let host = [0x48_u64, 0x99];
            state[offset("b_nested_l0_msr_host_list")] = host.as_ptr() as u64;
            state[offset("test_vmcs") + 1] = 512;
            assert_eq!(run(&mut state, 7, 0, root_count), 1);
            assert_eq!(state[offset("test_spec_ctrl_writes")], root_count);
            if root_count == 1 {
                assert_eq!(state[offset("test_spec_ctrl")], root[0][1]);
            }
            assert_eq!(run(&mut state, 8, 0, root_count), 1);
            assert_eq!(state[offset("test_spec_ctrl_writes")], root_count * 2);
            if root_count == 1 {
                assert_eq!(state[offset("test_spec_ctrl")], 0x99);
            }
            state[offset("test_vmcs") + 1] = 1;
            assert_eq!(run(&mut state, 7, 0, root_count), 1);
            assert_eq!(state[offset("test_spec_ctrl_writes")], root_count * 2);
            captured[0] = [0x48, 0x77];
            root[0][1] = 0x33;
            assert_eq!(run(&mut state, 10, 0, root_count), 1);
            assert_eq!(state[offset("test_controls")], captured.as_ptr() as u64);
            assert_eq!(state[offset("test_controls") + 1], root_count);
            assert_eq!(captured[0][1], 0x77);
            assert_eq!(root[0][1], 0x33);
        }
    }

    #[test]
    fn l0_only_efer_exits_emulate_and_resume_l2_while_l1_requests_are_reflected() {
        let _guard = TEST_LOCK.lock().unwrap();
        for (write, intercepted, fault, exception_intercepted) in [
            (false, false, false, false),
            (true, false, false, false),
            (true, false, true, false),
            (true, false, true, true),
            (false, true, false, false),
            (true, true, false, false),
        ] {
            let (mut state, _root, _entry, captured, _l1, _arena) = msr_state(1, &[]);
            let mut arena = Arena::new();
            let bitmap = arena.page();
            let ept = arena.page();
            arena.map(ept, 0x800000, bitmap, 7);
            state[offset("b_cache_ept_pointer")] = ept;
            state[offset("b_nested_vmcs12_msr_bitmap")] = 0x800000;
            state[offset("b_nested_vmcs12_primary_control")] = 1 << 28;
            if intercepted {
                let byte_offset = 1024 + u64::from(write) * 2048 + 0x80 / 8;
                unsafe { (bitmap as *mut u8).add(byte_offset as usize).write(1) };
            }
            state[offset("b_nested_l2_active")] = 1;
            state[offset("b_nested_vmcs12_exception_bitmap")] =
                if exception_intercepted { 1 << 13 } else { 0 };
            state[offset("b_last_reason")] = if write { 32 } else { 31 };
            state[offset("b_last_instruction_len")] = 2;
            state[offset("b_last_qualification")] = 0x777;
            state[offset("test_guest_rcx")] = 0xc0000080;
            state[offset("test_guest_rax")] = 0xd01;
            state[offset("test_guest_rdx")] = 0;
            state[offset("test_vmcs") + 6] = 0x501;
            state[offset("test_vmcs")] = (1 << 31) | 1;
            state[offset("test_msr_fault")] = u64::from(fault);
            state[offset("test_controls") + 13] = 0x80000320;
            assert_eq!(run(&mut state, 9, 0, 1), 1);
            assert_eq!(
                state[offset("test_reflected")],
                u64::from(intercepted || exception_intercepted)
            );
            assert_eq!(
                state[offset("test_advances")],
                u64::from(!intercepted && !fault)
            );
            if intercepted {
                assert_eq!(state[offset("test_guest_rax")], 0xd01);
                assert_eq!(state[offset("test_controls") + 13], 0x80000320);
            } else if exception_intercepted {
                assert_eq!(state[offset("b_last_reason")], 0);
                assert_eq!(state[offset("b_last_qualification")], 0);
                assert_eq!(state[offset("b_last_instruction_len")], 0);
                assert_eq!(state[offset("b_nested_l2_msr_gp_pending")], 0);
                assert_eq!(
                    state[offset("b_nested_vmcs12_vm_exit_intr_info")],
                    0x80000b0d
                );
                assert_eq!(state[offset("b_nested_vmcs12_vm_exit_intr_error")], 0);
                assert_eq!(state[offset("test_controls") + 13], 0);
                assert_eq!(state[offset("test_guest_rax")], 0xd01);
            } else {
                assert_eq!(state[offset("test_controls")], captured.as_ptr() as u64);
                assert_eq!(state[offset("test_controls") + 1], 1);
                assert_eq!(
                    state[offset("test_controls") + 13],
                    if fault { 0x80000b0d } else { 0 }
                );
                if !write {
                    assert_eq!(state[offset("test_guest_rax")], 0x501);
                    assert_eq!(state[offset("test_guest_rdx")], 0);
                } else if !fault {
                    assert_eq!(state[offset("test_controls") + 6], 0xd01);
                }
            }
        }
    }

    #[test]
    fn l0_only_efer_fault_omits_error_code_delivery_in_real_mode() {
        let _guard = TEST_LOCK.lock().unwrap();
        let (mut state, _root, _entry, _captured, _l1, _arena) = msr_state(1, &[]);
        let mut arena = Arena::new();
        let bitmap = arena.page();
        let ept = arena.page();
        arena.map(ept, 0x800000, bitmap, 7);
        state[offset("b_cache_ept_pointer")] = ept;
        state[offset("b_nested_vmcs12_msr_bitmap")] = 0x800000;
        state[offset("b_nested_vmcs12_primary_control")] = 1 << 28;
        state[offset("b_nested_l2_active")] = 1;
        state[offset("b_last_reason")] = 32;
        state[offset("test_guest_rcx")] = 0xc0000080;
        state[offset("test_guest_rax")] = 0xd01;
        state[offset("test_vmcs")] = 0;
        state[offset("test_msr_fault")] = 1;
        assert_eq!(run(&mut state, 9, 0, 1), 1);
        assert_eq!(state[offset("test_reflected")], 0);
        assert_eq!(state[offset("test_advances")], 0);
        assert_eq!(state[offset("test_controls") + 13], 0x8000030d);
        assert_eq!(state[offset("test_controls") + 14], 0);
        state[offset("b_nested_vmcs12_exception_bitmap")] = 1 << 13;
        assert_eq!(run(&mut state, 9, 0, 1), 1);
        assert_eq!(state[offset("test_reflected")], 1);
        assert_eq!(state[offset("b_nested_vmcs12_vm_exit_intr_info")], 0x8000030d);
        assert_eq!(state[offset("b_nested_vmcs12_vm_exit_intr_error")], 0);
    }

    #[test]
    fn l0_only_debugctl_exits_use_guest_state_and_preserve_root_state() {
        let _guard = TEST_LOCK.lock().unwrap();
        for (write, fault) in [(false, false), (true, false), (true, true)] {
            let (mut state, _root, _entry, captured, _l1, _arena) = msr_state(1, &[]);
            let mut arena = Arena::new();
            let bitmap = arena.page();
            let ept = arena.page();
            arena.map(ept, 0x800000, bitmap, 7);
            state[offset("b_cache_ept_pointer")] = ept;
            state[offset("b_nested_vmcs12_msr_bitmap")] = 0x800000;
            state[offset("b_nested_vmcs12_primary_control")] = 1 << 28;
            state[offset("b_nested_l2_active")] = 1;
            state[offset("b_last_reason")] = if write { 32 } else { 31 };
            state[offset("test_guest_rcx")] = 0x1d9;
            state[offset("test_guest_rax")] = 2;
            state[offset("test_vmcs")] = 1;
            state[offset("test_vmcs") + 7] = 1;
            state[offset("test_host_debugctl")] = 0;
            state[offset("test_msr_fault")] = u64::from(fault);
            assert_eq!(run(&mut state, 9, 0, 1), 1);
            assert_eq!(state[offset("test_reflected")], 0);
            assert_eq!(state[offset("test_advances")], u64::from(!fault));
            assert_eq!(state[offset("test_host_debugctl")], 0);
            assert_eq!(state[offset("test_controls")], captured.as_ptr() as u64);
            assert_eq!(state[offset("test_controls") + 1], 1);
            assert_eq!(
                state[offset("test_controls") + 13],
                if fault { 0x80000b0d } else { 0 }
            );
            if !write {
                assert_eq!(state[offset("test_guest_rax")], 1);
                assert_eq!(state[offset("test_guest_rdx")], 0);
            } else if !fault {
                assert_eq!(state[offset("test_controls") + 7], 2);
            } else {
                assert_eq!(state[offset("test_controls") + 7], 0);
            }
        }
    }

    #[test]
    fn full_512_entry_load_and_store_lists_fit_without_exceeding_host_hardware_capacity() {
        let _guard = TEST_LOCK.lock().unwrap();
        for root_count in [0, 1] {
            for count in [511, 512] {
                let requested = vec![[0x277, 0x1234]; count];
                let (mut state, _root, entry, _captured, l1, _arena) =
                    msr_state(root_count, &requested);
                state[offset("b_nested_vmcs12_vm_entry_msr_load_addr")] = l1.as_ptr() as u64;
                state[offset("b_nested_vmcs12_vm_entry_msr_load_count")] = count as u64;
                state[offset("b_nested_vmcs12_vm_exit_msr_load_addr")] = l1.as_ptr() as u64;
                state[offset("b_nested_vmcs12_vm_exit_msr_load_count")] = count as u64;
                assert_eq!(run(&mut state, 3, 0, root_count), 1);
                let prefix = if count == 512 { 0 } else { root_count };
                let selected = entry.as_ptr() as u64 + if prefix != root_count { 16 } else { 0 };
                assert_eq!(state[offset("test_controls")], selected);
                assert_eq!(state[offset("test_controls") + 1], count as u64 + prefix);
                assert_eq!(state[offset("b_nested_entry_msr_prefix_count")], prefix);
                assert_eq!(
                    &entry[root_count as usize..root_count as usize + count],
                    requested
                );
                assert_eq!(run(&mut state, 5, 0, root_count), 1);
                assert_eq!(state[offset("test_controls")], selected);
                assert_eq!(state[offset("test_controls") + 1], count as u64 + prefix);
                state[offset("b_nested_vmcs12_vm_exit_msr_load_count")] = 0;
                state[offset("test_vmcs") + 5] = 0x777;
                assert_eq!(run(&mut state, 4, 10, root_count), 1);
                assert!(l1.iter().all(|slot| slot[1] == 0x777));
                assert_eq!(entry[count + root_count as usize], [0xdead, 0xbeef]);
            }
        }
        let mut state = vec![0; CONTEXT_QWORDS];
        state[offset("b_nested_physical_address_bits")] = 48;
        state[offset("test_list_address")] = 0x10000;
        assert_eq!(run(&mut state, 6, 512, 0), 1);
        assert_eq!(run(&mut state, 6, 513, 0), 0);
    }
}
