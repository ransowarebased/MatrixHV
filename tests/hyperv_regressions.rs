include!("../builds/evmcs-tests/physical-width.rs");

unsafe extern "win64" {
    fn test_entry_event(state: *mut NestedVmxState) -> u32;
    fn test_tsc_composition(state: *mut NestedVmxState) -> u64;
}

#[test]
fn vp_assist_register_preserves_reserved_bits_and_nested_fields() {
    let page = Box::new(EvmcsTestPage([0xa5; 4096]));
    let address = page.0.as_ptr() as u64;
    let mut state = nested_state(0);
    state.evmcs_enabled = 1;
    let mut ept = EvmcsTestEpt::new(&mut state);
    ept.map(address, address, 7);
    for reserved in [2, 0x800, 0xffe] {
        let value = address | reserved | 1;
        assert_eq!(unsafe { test_write_vp_assist(&mut state, value) }, 1);
        assert_eq!(state.vp_assist_msr, value);
        assert_eq!(&page.0[..4], &[0; 4]);
        assert!(page.0[4..].iter().all(|byte| *byte == 0xa5));
        assert_eq!(unsafe { test_write_vp_assist(&mut state, value & !1) }, 1);
        assert_eq!(state.vp_assist_msr, value & !1);
    }
}

#[test]
fn vp_assist_page_zero_uses_ept_translation_without_touching_the_null_host_address() {
    let page = Box::new(EvmcsTestPage([0xa5; 4096]));
    let mut state = nested_state(0);
    state.evmcs_enabled = 1;
    let mut ept = EvmcsTestEpt::new(&mut state);
    ept.map(0, page.0.as_ptr() as u64, 7);
    assert_eq!(unsafe { test_write_vp_assist(&mut state, 1) }, 1);
    assert_eq!(state.vp_assist_msr, 1);
    assert_eq!(&page.0[..4], &[0; 4]);
    assert!(page.0[4..].iter().all(|byte| *byte == 0xa5));
}

#[test]
fn physical_width_falls_back_without_querying_an_absent_extended_leaf() {
    for (maximum, width, expected) in [
        (0x8000_0007, 0, 36),
        (0x8000_0008, 48, 48),
        (0x8000_0008, 52, 52),
    ] {
        assert_eq!(
            test_physical_width(|leaf| {
                assert!(leaf <= maximum);
                core::arch::x86_64::CpuidResult {
                    eax: if leaf == 0x8000_0000 {
                        maximum
                    } else {
                        width | 48 << 8
                    },
                    ebx: 0,
                    ecx: 0,
                    edx: 0,
                }
            }),
            expected
        );
    }
}

#[test]
fn event_instruction_length_follows_the_advertised_misc_capability() {
    let mut state = nested_state(0);
    for supported in [false, true] {
        state.vmx_misc = u64::from(supported) << 30;
        for kind in [4, 5, 6] {
            state.vmcs12.extended_fields[13] = 0x8000_0003 | kind << 8;
            for length in [0, 1, 15, 16] {
                state.vmcs12.extended_fields[15] = length;
                assert_eq!(
                    unsafe { test_entry_event(&mut state) },
                    u32::from(length <= 15 && (length != 0 || supported))
                );
            }
        }
    }
}

#[test]
fn event_error_codes_follow_the_guest_protection_mode() {
    let mut state = nested_state(0);
    for protected_mode in [false, true] {
        state.vmcs12.extended_fields[29] = u64::from(protected_mode);
        for vector in 0..32 {
            let requires_error = protected_mode && matches!(vector, 8 | 10..=14 | 17);
            for deliver_error in [false, true] {
                state.vmcs12.extended_fields[13] =
                    0x8000_0300 | vector | (u64::from(deliver_error) << 11);
                assert_eq!(
                    unsafe { test_entry_event(&mut state) },
                    u32::from(deliver_error == requires_error),
                    "protected_mode={protected_mode} vector={vector} deliver_error={deliver_error}"
                );
            }
        }
    }
}

#[test]
fn pending_mtf_injection_requires_the_advertised_execution_capability() {
    let mut state = nested_state(0);
    state.vmcs12.extended_fields[13] = 0x8000_0700;
    for supported in [false, true] {
        state.vmx_procbased_ctls = u64::from(supported) << (32 + 27);
        assert_eq!(
            unsafe { test_entry_event(&mut state) },
            u32::from(supported)
        );
    }
}

#[test]
fn nested_tsc_offsets_compose_with_wrapping_and_ignore_disabled_l2_offsetting() {
    let mut state = nested_state(0);
    for l1_offset in [0, 123456789, u64::MAX - 100] {
        for l2_offset in [0, 987654321, u64::MAX - 200] {
            for enabled in [false, true] {
                state.inherited_l1_tsc_offset = l1_offset;
                state.vmcs12.extended_fields[2] = u64::from(enabled) << 3;
                state.vmcs12.extended_fields[17] = l2_offset;
                let offset = unsafe { test_tsc_composition(&mut state) };
                assert_eq!(
                    offset,
                    l1_offset.wrapping_add(if enabled { l2_offset } else { 0 })
                );
                assert_eq!(
                    456_u64.wrapping_add(offset),
                    456_u64.wrapping_add(l1_offset).wrapping_add(if enabled {
                        l2_offset
                    } else {
                        0
                    })
                );
            }
        }
    }
}

struct EnlightenedScenario {
    state: NestedVmxState,
    assist: Box<EvmcsTestPage>,
    page: Box<EvmcsTestPage>,
    ept: EvmcsTestEpt,
}

impl EnlightenedScenario {
    fn new() -> Self {
        let mut state = nested_state(0);
        state.active = 1;
        state.evmcs_enabled = 1;
        let mut assist = Box::new(EvmcsTestPage([0; 4096]));
        let mut page = Box::new(EvmcsTestPage([0; 4096]));
        page.0[..4].copy_from_slice(&1_u32.to_le_bytes());
        state.vp_assist_msr = assist.0.as_ptr() as u64 | 1;
        write_page_u64(&mut assist, 40, 1);
        write_page_u64(&mut assist, 48, 0x1234_0000);
        let mut ept = EvmcsTestEpt::new(&mut state);
        ept.map(state.vp_assist_msr & !4095, assist.0.as_ptr() as u64, 7);
        ept.map(0x1234_0000, page.0.as_ptr() as u64, 7);
        Self {
            state,
            assist,
            page,
            ept,
        }
    }

    fn select(&mut self) -> i32 {
        unsafe { test_select_evmcs(&mut self.state) }
    }
}

#[test]
fn enlightened_vmcs_accepts_page_zero_when_distinct_from_vmxon_and_assist_pages() {
    let mut scenario = EnlightenedScenario::new();
    scenario.state.vmxon_region = 0x4000;
    write_page_u64(&mut scenario.assist, 48, 0);
    scenario.ept.map(0, scenario.page.0.as_ptr() as u64, 7);
    assert_eq!(scenario.select(), 1);
    assert_eq!(scenario.state.current_vmcs, 0);
    assert_eq!(scenario.state.current_vmcs_hpa, scenario.page.0.as_ptr() as u64);
    scenario.state.vmcs12.guest_rip = 0x1234;
    unsafe { test_store_evmcs(&mut scenario.state) };
    assert_eq!(page_u64(&scenario.page, offset_of!(EnlightenedVmcs, guest_rip)), 0x1234);
}

#[test]
fn evmcs_rejects_native_revisions_and_overlapping_roles_without_publishing() {
    for version in [0_u32, 0x42, 0x8000_0001] {
        let mut scenario = EnlightenedScenario::new();
        scenario.state.vmcs12.revision_id = 0x42;
        scenario.page.0[..4].copy_from_slice(&version.to_le_bytes());
        let before = scenario.page.0;
        assert_eq!(scenario.select(), -1);
        assert_eq!(scenario.state.current_vmcs, INVALID_VMCS_POINTER);
        assert_eq!(scenario.page.0, before);
    }
    for assist_overlap in [false, true] {
        let mut scenario = EnlightenedScenario::new();
        if assist_overlap {
            let address = scenario.state.vp_assist_msr & !4095;
            write_page_u64(&mut scenario.assist, 48, address);
            scenario.assist.0[..4].copy_from_slice(&1_u32.to_le_bytes());
        } else {
            scenario.state.vmxon_region = 0x1234_0000;
        }
        assert_eq!(scenario.select(), -1);
        assert_eq!(scenario.state.evmcs_active, 0);
    }
}

#[test]
fn vmptrld_cannot_reinterpret_the_active_enlightened_backing() {
    for revision in [1_u32, 0x42, 0x8000_0042] {
        let mut scenario = EnlightenedScenario::new();
        assert_eq!(scenario.select(), 1);
        scenario.state.vmcs12.revision_id = u64::from(revision & 0x7fff_ffff);
        scenario.page.0[..4].copy_from_slice(&revision.to_le_bytes());
        let before = scenario.page.0;
        assert_eq!(
            unsafe { test_load_vmcs(&mut scenario.state, 0x1234_0000) },
            0
        );
        assert_eq!(scenario.state.evmcs_active, 1);
        assert_eq!(scenario.state.current_vmcs, 0x1234_0000);
        assert_eq!(scenario.page.0, before);
    }
}

#[test]
fn clean_fields_reuse_state_until_dirty_or_a_different_backing_is_selected() {
    let mut scenario = EnlightenedScenario::new();
    let field = offset_of!(EnlightenedVmcs, ept_root);
    write_page_u64(&mut scenario.page, field, 0x10001e);
    assert_eq!(scenario.select(), 1);
    assert_eq!(scenario.state.vmcs12.extended_fields[16], 0x10001e);
    unsafe { test_store_evmcs(&mut scenario.state) };
    scenario.state.vmcs02_guest_cache_valid = 1;
    scenario.state.vmcs02_control_cache_valid = [u64::MAX; 2];
    write_page_u64(&mut scenario.page, field, 0x20001e);
    assert_eq!(scenario.select(), 1);
    assert_eq!(scenario.state.vmcs12.extended_fields[16], 0x10001e);
    assert_eq!(scenario.state.vmcs02_guest_cache_valid, 1);
    assert_eq!(scenario.state.vmcs02_control_cache_valid, [u64::MAX; 2]);
    scenario.page.0[offset_of!(EnlightenedVmcs, clean_fields)..][..4].fill(0);
    assert_eq!(scenario.select(), 1);
    assert_eq!(scenario.state.vmcs12.extended_fields[16], 0x20001e);
    let mut replacement = Box::new(EvmcsTestPage(scenario.page.0));
    write_page_u64(&mut replacement, field, 0x30001e);
    replacement.0[offset_of!(EnlightenedVmcs, clean_fields)..][..4]
        .copy_from_slice(&0x7fff_u32.to_le_bytes());
    scenario
        .ept
        .map(0x1234_0000, replacement.0.as_ptr() as u64, 7);
    assert_eq!(scenario.select(), 1);
    assert_eq!(scenario.state.vmcs12.extended_fields[16], 0x30001e);
    assert_eq!(
        scenario.state.current_vmcs_hpa,
        replacement.0.as_ptr() as u64
    );
    assert_eq!(scenario.state.vmcs02_guest_cache_valid, 0);
    assert_eq!(scenario.state.vmcs02_control_cache_valid, [0; 2]);
    assert_eq!(
        unsafe { test_clear_evmcs(&mut scenario.state, 0x1234_0000) },
        1
    );
    write_page_u64(&mut replacement, field, 0x40001e);
    assert_eq!(scenario.select(), 1);
    assert_eq!(scenario.state.vmcs12.extended_fields[16], 0x40001e);
}

#[test]
fn cached_ept_paths_recheck_permissions_at_every_level_and_eptp_identity() {
    for shift in [39, 30, 21, 12] {
        let mut scenario = EnlightenedScenario::new();
        assert_eq!(scenario.select(), 1);
        assert_eq!(scenario.select(), 1);
        let before = scenario.page.0;
        let entry = scenario.ept.entry(0x1234_0000, shift);
        scenario.ept.set_entry(0x1234_0000, shift, entry & !2);
        assert_eq!(scenario.select(), -1);
        unsafe { test_store_evmcs(&mut scenario.state) };
        assert_eq!(scenario.state.failure_count, 1);
        assert_eq!(scenario.page.0, before);
        scenario.ept.set_entry(0x1234_0000, shift, entry);
        assert_eq!(scenario.select(), 1);
    }
    let mut scenario = EnlightenedScenario::new();
    assert_eq!(scenario.select(), 1);
    let empty = EvmcsTestEpt::new(&mut scenario.state);
    assert_eq!(scenario.select(), -1);
    drop(empty);
}

#[test]
fn misc_keeps_implemented_native_semantics_and_hides_pt_and_dual_monitor_smm() {
    let mut host = host_vmx_capabilities();
    host.misc = u64::MAX;
    let guest = NestedVmxCapabilities::from_host(host);
    assert_eq!(guest.vmx_misc, 0x1ff | (4 << 16) | (1 << 29) | (1 << 30));
    assert_eq!(guest.host_misc, u64::MAX);
}

#[test]
fn legacy_entry_controls_allow_non_ia32e_guests_and_scaling_stays_unadvertised() {
    let mut host = host_vmx_capabilities();
    host.vmx_basic &= !(1 << 55);
    let guest = NestedVmxCapabilities::from_host(host);
    assert_eq!(guest.vmx_entry_ctls as u32 & (1 << 9), 0);
    assert_ne!(guest.vmx_entry_ctls >> 32 & (1 << 9), 0);
    assert_eq!(guest.vmx_procbased_ctls2 >> 32 & (1 << 25), 0);
}

#[test]
fn frequent_nested_fields_fit_in_the_first_two_cache_lines() {
    for offset in [
        offset_of!(NestedVmxState, current_vmcs),
        offset_of!(NestedVmxState, evmcs_active),
        offset_of!(NestedVmxState, l2_active),
        offset_of!(NestedVmxState, vmcs02_guest_cache_valid),
        offset_of!(NestedVmxState, vmcs02_control_cache_valid),
        offset_of!(NestedVmxState, ept01_pointer),
    ] {
        assert!(offset < 128);
    }
}
