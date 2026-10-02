#[cfg(test_harness = "control")]
mod control {
    use std::sync::Mutex;

    core::arch::global_asm!(include_str!(
        "../builds/resident-control-tests/resident-control.S"
    ));
    include!("../builds/resident-control-tests/offsets.rs");

    static ASSEMBLY_LOCK: Mutex<()> = Mutex::new(());
    const DEVICE_ERROR: u64 = 0x8000000000000007;
    const UNSUPPORTED: u64 = 0x8000000000000003;

    #[repr(C, align(4096))]
    struct Page([u64; 512]);

    #[repr(C, align(4096))]
    struct NativeStorage {
        stack: [u64; 512],
        pml4: [u64; 512],
    }

    unsafe extern "win64" {
        fn test_control_runtime_base() -> u64;
        fn test_control_restore_address() -> u64;
        fn test_control_off(shared: *mut u64, model: *mut Model, processor: u64) -> u64;
        fn test_control_cleanup(shared: *mut u64, model: *mut Model, processor: u64) -> u64;
        fn test_control_dispatch(
            boot: *mut u64,
            shared: *mut u64,
            model: *mut Model,
            processor: u64,
        ) -> u64;
    }

    struct Scenario {
        boot: Vec<u64>,
        shared: Vec<u64>,
        storage: Box<NativeStorage>,
        root: Box<Page>,
        native_root: Box<Page>,
        gdt: Box<[u8; 128]>,
        model: Model,
        processor: usize,
    }

    impl Scenario {
        fn new(processor: usize) -> Self {
            let mut scenario = Self {
                boot: vec![0; BOOT_WORDS],
                shared: vec![0; EVENT_WORDS],
                storage: Box::new(NativeStorage {
                    stack: [0; 512],
                    pml4: [0; 512],
                }),
                root: Box::new(Page([0; 512])),
                native_root: Box::new(Page([0; 512])),
                gdt: Box::new([0; 128]),
                model: Model {
                    vmcs_active: 1,
                    dirty_vmcs: 0x123456789abcdef0,
                    ..Model::default()
                },
                processor,
            };
            for index in 0..512 {
                scenario.root.0[index] = (index as u64 + 1) * 4096 + 3;
                scenario.native_root.0[index] = (index as u64 + 513) * 4096 + 3;
            }
            scenario.boot[offset("b_canary_start")] = 0x12345678;
            scenario.boot[offset("b_canary_end")] = 0x87654321;
            scenario.boot[offset("b_processor_number")] = processor as u64;
            scenario.boot[offset("b_event_context")] = scenario.shared.as_ptr() as u64;
            scenario.boot[offset("b_expected_host_cr3")] = scenario.root.0.as_ptr() as u64;
            scenario.event_set("event_runtime_context", scenario.shared.as_ptr() as u64);
            scenario.event_set("event_runtime_set_variable", unsafe {
                test_control_runtime_base()
            });
            scenario.event_set("event_control_stopped_mask", scenario.bit() | 1);
            scenario.event_set("event_control_active_mask", 1);
            scenario.event_set("event_control_rearm_mask", scenario.bit() | 1);
            scenario.state_set("control_cpu_phase", 3);
            scenario.state_set("control_cpu_sequence", 0x987654321);
            scenario.state_set(
                "control_cpu_native_storage_physical",
                scenario.storage.stack.as_ptr() as u64,
            );
            scenario.state_set(
                "control_cpu_native_storage_runtime",
                scenario.storage.stack.as_ptr() as u64,
            );
            scenario.state_set(
                "control_cpu_on_native_cr3",
                scenario.native_root.0.as_ptr() as u64 | 0x345,
            );
            scenario.state_set("control_cpu_on_native_cr0", 0x80050033);
            scenario.state_set("control_cpu_on_original_cr4", 0x3206f8);
            scenario.state_set("control_cpu_native_cr4", 0x3206f8);
            scenario.state_set("control_cpu_on_native_dr7", 0x400);
            scenario.state_set("control_cpu_guest_dr7", 0x400);
            scenario.state_set("control_cpu_guest_gdtr_limit", 127);
            scenario.state_set("control_cpu_guest_idtr_limit", 4095);
            scenario.state_set("control_cpu_exit_msr_load_count", 1);
            let msrs = scenario.state_index("control_cpu_on_native_msrs");
            for index in 0..9 {
                scenario.shared[msrs + index] = 0xabcdef0123456700 + index as u64;
            }
            scenario.probe_set("probe_guest_gdtr_base", scenario.gdt.as_ptr() as u64);
            scenario.probe_set("probe_guest_gdtr_limit", 127);
            scenario.probe_set("probe_guest_idtr_base", 0xffff800012340000);
            scenario.probe_set("probe_guest_idtr_limit", 4095);
            for (name, value) in [
                ("probe_guest_cs_selector", 16),
                ("probe_guest_ss_selector", 24),
                ("probe_guest_es_selector", 0),
                ("probe_guest_ds_selector", 0),
                ("probe_guest_fs_selector", 48),
                ("probe_guest_gs_selector", 0),
                ("probe_guest_tr_selector", 40),
            ] {
                scenario.probe_set(name, value);
            }
            scenario.gdt[45] = 0x8b;
            scenario
        }

        fn bit(&self) -> u64 {
            1 << self.processor
        }
        fn event_set(&mut self, name: &str, value: u64) {
            self.shared[offset(name)] = value;
        }
        fn event(&self, name: &str) -> u64 {
            self.shared[offset(name)]
        }
        fn state_index(&self, name: &str) -> usize {
            offset("event_control_cpu_states") + self.processor * STATE_WORDS + offset(name)
        }
        fn state_set(&mut self, name: &str, value: u64) {
            let index = self.state_index(name);
            self.shared[index] = value;
        }
        fn state(&self, name: &str) -> u64 {
            self.shared[self.state_index(name)]
        }
        fn probe_set(&mut self, name: &str, value: u64) {
            let index =
                offset("event_control_probe_states") + self.processor * PROBE_WORDS + offset(name);
            self.shared[index] = value;
        }
        fn dispatch(&mut self) -> u64 {
            unsafe {
                test_control_dispatch(
                    self.boot.as_mut_ptr(),
                    self.shared.as_mut_ptr(),
                    &mut self.model,
                    self.processor as u64,
                )
            }
        }
        fn preserved(&self) {
            assert_eq!(self.model.history & 0xff, 0x12);
            assert_eq!(self.model.clear_count, 1);
            assert_eq!(self.model.off_count, 1);
            assert_eq!(self.model.backing_vmcs, self.model.dirty_vmcs);
            assert_eq!(self.model.vmcs_active, 0);
        }
    }

    #[test]
    fn off_preserves_the_vmcs_before_vmxoff_and_publishes_completion() {
        let _guard = ASSEMBLY_LOCK.lock().unwrap();
        let mut scenario = Scenario::new(2);
        scenario.state_set("control_cpu_phase", 1);
        scenario.event_set("event_control_active_mask", scenario.bit() | 1);
        scenario.event_set("event_control_stopped_mask", 1);
        let status =
            unsafe { test_control_off(scenario.shared.as_mut_ptr(), &mut scenario.model, 2) };
        assert_eq!(status, 0);
        scenario.preserved();
        assert_eq!(scenario.state("control_cpu_phase"), 2);
        assert_eq!(scenario.state("control_cpu_stage"), 0);
        assert_eq!(scenario.event("event_control_active_mask"), 1);
        assert_eq!(
            scenario.event("event_control_stopped_mask"),
            scenario.bit() | 1
        );
        assert_eq!(
            scenario.shared[offset("event_control_completion_sequences") + 2],
            0x987654321
        );
    }

    #[test]
    fn immediate_activation_cleanup_preserves_the_vmcs_and_clears_only_its_rearm_bit() {
        let _guard = ASSEMBLY_LOCK.lock().unwrap();
        let mut scenario = Scenario::new(3);
        let status =
            unsafe { test_control_cleanup(scenario.shared.as_mut_ptr(), &mut scenario.model, 3) };
        assert_eq!(status, DEVICE_ERROR);
        scenario.preserved();
        assert_eq!(scenario.event("event_control_rearm_mask"), 1);
        assert_eq!(scenario.state("control_cpu_phase"), 2);
        assert_eq!(
            scenario.model.cr4,
            scenario.state("control_cpu_on_original_cr4")
        );
    }

    #[test]
    fn vmclear_failures_block_reuse_and_return_device_error_for_both_native_cleanup_paths() {
        let _guard = ASSEMBLY_LOCK.lock().unwrap();
        for clear_fail in [1, 2] {
            for off in [false, true] {
                let mut scenario = Scenario::new(4);
                scenario.model.clear_fail = clear_fail;
                let status = unsafe {
                    if off {
                        test_control_off(scenario.shared.as_mut_ptr(), &mut scenario.model, 4)
                    } else {
                        test_control_cleanup(scenario.shared.as_mut_ptr(), &mut scenario.model, 4)
                    }
                };
                assert_eq!(status, DEVICE_ERROR);
                assert_eq!(scenario.state("control_cpu_phase"), 2);
                assert_eq!(scenario.state("control_cpu_stage"), 134);
                assert_eq!(scenario.event("event_control_failed_mask"), scenario.bit());
                assert_eq!(scenario.model.history, 0x12);
            }
        }
    }

    #[test]
    fn late_entry_failures_restore_native_state_and_return_with_the_original_cause() {
        let _guard = ASSEMBLY_LOCK.lock().unwrap();
        for (reason, qualification) in [(33, 4), (34, 1), (41, 0)] {
            let mut scenario = Scenario::new(5);
            scenario.model.reason = 0x80000000 | reason;
            scenario.model.qualification = qualification;
            assert_eq!(scenario.dispatch(), DEVICE_ERROR);
            assert_eq!(
                scenario.state("control_cpu_on_failure_reason"),
                0x80000000 | reason
            );
            assert_eq!(
                scenario.state("control_cpu_on_failure_qualification"),
                qualification
            );
            assert_eq!(scenario.boot[offset("b_last_qualification")], qualification);
            assert_eq!(scenario.state("control_cpu_phase"), 2);
            assert_eq!(scenario.state("control_cpu_stage"), 133);
            assert_eq!(scenario.state("control_cpu_native_snapshot_count"), 1);
            assert_eq!(scenario.event("event_control_rearm_mask"), 1);
            assert_eq!(scenario.event("event_control_active_mask"), 1);
            assert_eq!(
                scenario.event("event_control_stopped_mask"),
                scenario.bit() | 1
            );
            assert_eq!(scenario.event("event_control_failed_mask"), 0);
            assert_eq!(scenario.model.history, 0x1234);
            assert_eq!(scenario.model.backing_vmcs, scenario.model.dirty_vmcs);
            assert_eq!(
                scenario.model.cr3_values[0],
                scenario.storage.pml4.as_ptr() as u64
            );
            assert_eq!(
                scenario.model.cr3_values[1],
                scenario.state("control_cpu_on_native_cr3")
            );
            assert_eq!(
                scenario.model.cr0,
                scenario.state("control_cpu_on_native_cr0")
            );
            assert_eq!(
                scenario.model.cr4,
                scenario.state("control_cpu_on_original_cr4")
            );
            assert_eq!(
                scenario.model.dr7,
                scenario.state("control_cpu_on_native_dr7")
            );
            assert_eq!(scenario.model.gdt_base, scenario.gdt.as_ptr() as u64);
            assert_eq!(scenario.model.gdt_limit, 127);
            assert_eq!(scenario.model.idt_base, 0xffff800012340000);
            assert_eq!(scenario.model.idt_limit, 4095);
            assert_eq!(scenario.model.selectors, [16, 24, 0, 0, 48, 0, 0, 40]);
            assert_eq!(scenario.gdt[45], 0x8b);
            let msrs = scenario.state_index("control_cpu_on_native_msrs");
            assert_eq!(scenario.model.msrs, scenario.shared[msrs..msrs + 9]);
            assert_eq!(scenario.model.msr_mask, 0x1ff);
            assert_eq!(scenario.model.msr_rearm_count, 0);
            let code_slot = (unsafe { test_control_restore_address() } >> 39 & 0x1ff) as usize;
            for index in 0..512 {
                let expected = if index == code_slot {
                    scenario.native_root.0[index]
                } else {
                    scenario.root.0[index]
                };
                assert_eq!(scenario.storage.pml4[index], expected);
            }
        }
    }

    #[test]
    fn successful_first_exit_rearms_msr_loading_without_native_cleanup() {
        let _guard = ASSEMBLY_LOCK.lock().unwrap();
        let mut scenario = Scenario::new(2);
        scenario.model.reason = 10;
        assert_eq!(scenario.dispatch(), 0);
        assert_eq!(scenario.event("event_control_rearm_mask"), 1);
        assert_eq!(scenario.model.msr_rearm_count, 1);
        assert_eq!(scenario.model.entry_msr_count, 1);
        assert_eq!(scenario.model.off_count, 0);
    }

    #[test]
    fn late_failure_recovery_requires_an_armed_activation_in_phase_three() {
        let _guard = ASSEMBLY_LOCK.lock().unwrap();
        for (armed, phase) in [(false, 3), (true, 0), (true, 2)] {
            let mut scenario = Scenario::new(2);
            scenario.model.reason = 0x80000021;
            scenario.state_set("control_cpu_phase", phase);
            if !armed {
                scenario.event_set("event_control_rearm_mask", 1);
            }
            assert_eq!(scenario.dispatch(), UNSUPPORTED);
            assert_eq!(scenario.model.off_count, 0);
            assert_eq!(scenario.model.cr3_count, 0);
        }
    }

    #[test]
    fn late_failure_with_failed_preservation_still_restores_the_native_caller() {
        let _guard = ASSEMBLY_LOCK.lock().unwrap();
        let mut scenario = Scenario::new(2);
        scenario.model.clear_fail = 1;
        scenario.model.reason = 0x80000021;
        scenario.model.qualification = 4;
        assert_eq!(scenario.dispatch(), DEVICE_ERROR);
        assert_eq!(scenario.state("control_cpu_stage"), 134);
        assert_eq!(scenario.state("control_cpu_on_failure_reason"), 0x80000021);
        assert_eq!(scenario.state("control_cpu_on_failure_qualification"), 4);
        assert_eq!(scenario.event("event_control_failed_mask"), scenario.bit());
        assert_eq!(scenario.model.history, 0x1234);
        assert_eq!(scenario.state("control_cpu_phase"), 2);
    }
}

#[cfg(test_harness = "hyperv_time")]
mod hyperv_time {
    include!("hyperv_time_regressions.rs");
    include!("../builds/hyperv-time-tests/definitions.rs");
    core::arch::global_asm!(include_str!("../builds/hyperv-time-tests/handlers.S"));

    #[repr(C, align(4096))]
    #[derive(Clone, Copy)]
    struct Page([u64; 512]);

    unsafe extern "win64" {
        fn test_time_msr(context: *mut u64, registers: *mut u64, operation: u32) -> u32;
        fn test_time_cpuid(context: *mut u64, registers: *mut u32, leaf: u32);
    }

    struct Scenario {
        context: [u64; 11],
        shared: Box<[u64; 10]>,
        page: Box<Page>,
        tables: Box<[Page; 4]>,
    }

    impl Scenario {
        fn new() -> Self {
            let mut shared = Box::new([
                hyperv_reference_tsc_scale(2, 208, 24_000_000),
                0_u64.wrapping_sub(1_000_000),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]);
            let page = Box::new(Page([u64::MAX; 512]));
            let mut tables = Box::new([Page([0; 512]); 4]);
            let address = page.0.as_ptr() as u64;
            for (level, shift) in [39, 30, 21].into_iter().enumerate() {
                tables[level].0[((address >> shift) & 511) as usize] =
                    tables[level + 1].0.as_ptr() as u64 | 7;
            }
            tables[3].0[((address >> 12) & 511) as usize] = address | 7;
            let context = [
                shared.as_mut_ptr() as u64,
                1,
                2_496_000_000,
                tables[0].0.as_ptr() as u64,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
            ];
            Self {
                context,
                shared,
                page,
                tables,
            }
        }

        fn msr(&mut self, operation: u32, value: u64) -> (u32, u64) {
            let mut registers = [value & u64::from(u32::MAX), value >> 32];
            let result = unsafe {
                test_time_msr(self.context.as_mut_ptr(), registers.as_mut_ptr(), operation)
            };
            (result, registers[0] | registers[1] << 32)
        }

        fn features(&mut self, leaf: u32) -> [u32; 4] {
            let mut registers = [0; 4];
            unsafe { test_time_cpuid(self.context.as_mut_ptr(), registers.as_mut_ptr(), leaf) };
            registers
        }
    }

    #[test]
    fn reference_scale_requires_a_complete_frequency_above_the_reference_rate() {
        for (denominator, numerator, crystal) in [
            (0, 208, 24_000_000),
            (2, 0, 24_000_000),
            (2, 208, 0),
            (1, 1, 10_000_000),
            (2, 1, 10_000_000),
        ] {
            assert_eq!(
                hyperv_reference_tsc_scale(denominator, numerator, crystal),
                0
            );
        }
        let scale = hyperv_reference_tsc_scale(2, 208, 24_000_000);
        assert_eq!((2_496_000_000_u128 * u128::from(scale)) >> 64, 9_999_999);
    }

    #[test]
    fn cpuid_exposes_reference_time_only_when_supported_and_keeps_evmcs_optional() {
        let mut scenario = Scenario::new();
        assert_eq!(scenario.features(0x4000_0003), [0x272, 0, 0, 0]);
        scenario.context[1] = 0;
        assert_eq!(scenario.features(0x4000_0003), [0x70, 0, 0, 0]);
        scenario.context[1] = 1;
        scenario.context[4] = 0;
        assert_eq!(scenario.features(0x4000_0003), [0x262, 0, 0, 0]);
        assert_eq!(scenario.features(0x4000_0004), [0, u32::MAX, 0, 0]);
        assert_eq!(scenario.features(0x4000_000a), [0; 4]);
    }

    #[test]
    fn invariant_tsc_control_remains_available_under_an_outer_hypervisor() {
        let cpuid = |leaf| {
            let mut result = core::arch::x86_64::CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            };
            match leaf {
                0 => result.eax = 0x16,
                1 => result.ecx = CPUID_HYPERVISOR_PRESENT_BIT,
                0x15 => {
                    result.eax = 2;
                    result.ebx = 208;
                    result.ecx = 24_000_000;
                }
                0x8000_0000 => result.eax = 0x8000_0007,
                0x8000_0007 => result.edx = 1 << 8,
                _ => {}
            }
            result
        };
        let mut scenario = Scenario::new();
        scenario.context[1] = 0;
        scenario.shared[8] = u64::from(native_hyperv_invariant_tsc(cpuid));
        assert_eq!(scenario.shared[8], 1);
        assert_ne!(native_hyperv_reference_tsc(cpuid, 12345, || 0).0, 0);
        assert_eq!(scenario.msr(9, 1), (1, 1));
        assert_eq!(scenario.msr(8, 0), (1, 1));
    }

    #[test]
    fn invariant_tsc_support_requires_the_advertised_extended_leaf_and_bit() {
        for (maximum, features, expected) in [
            (0x8000_0006, 1 << 8, false),
            (0x8000_0007, 0, false),
            (0x8000_0007, 1 << 8, true),
        ] {
            let cpuid = |leaf| core::arch::x86_64::CpuidResult {
                eax: if leaf == 0x8000_0000 { maximum } else { 0 },
                ebx: 0,
                ecx: CPUID_HYPERVISOR_PRESENT_BIT,
                edx: if leaf == 0x8000_0007 { features } else { 0 },
            };
            assert_eq!(native_hyperv_invariant_tsc(cpuid), expected);
        }
    }

    #[test]
    fn invariant_tsc_access_and_advertisement_follow_native_support() {
        let mut scenario = Scenario::new();
        for (timing, evmcs, features) in [(1, 1, 0x272), (1, 0, 0x262), (0, 1, 0x70)] {
            scenario.context[1] = timing;
            scenario.context[4] = evmcs;
            scenario.shared[8] = 0;
            assert_eq!(scenario.features(0x4000_0003), [features, 0, 0, 0]);
            assert_eq!(scenario.msr(8, 0).0, 0);
            assert_eq!(scenario.msr(9, 1).0, 0);
            scenario.shared[8] = 1;
            assert_eq!(scenario.features(0x4000_0003), [features | (1 << 15), 0, 0, 0]);
            assert_eq!(scenario.msr(8, 0), (1, 0));
            assert_eq!(scenario.msr(9, 0).0, 1);
        }
        assert_eq!(scenario.shared[9], 0);
    }

    #[test]
    fn invariant_tsc_enable_is_shared_and_cannot_be_cleared_by_another_processor() {
        let mut scenario = Scenario::new();
        scenario.shared[8] = 1;
        assert_eq!(scenario.msr(8, 0), (1, 0));
        assert_eq!(scenario.msr(9, 1).0, 1);
        let mut other = scenario.context;
        let mut registers = [0; 2];
        assert_eq!(
            unsafe { test_time_msr(other.as_mut_ptr(), registers.as_mut_ptr(), 8) },
            1
        );
        assert_eq!(registers, [1, 0]);
        registers = [0; 2];
        assert_eq!(
            unsafe { test_time_msr(other.as_mut_ptr(), registers.as_mut_ptr(), 9) },
            0
        );
        assert_eq!(scenario.msr(9, 1).0, 1);
        assert_eq!(scenario.msr(8, 0), (1, 1));
    }

    #[test]
    fn invariant_tsc_rejects_reserved_bits_without_modifying_partition_state() {
        let mut scenario = Scenario::new();
        scenario.shared[8] = 1;
        for enabled in [0, 1] {
            assert_eq!(scenario.msr(9, enabled).0, 1);
            for value in [2, 3, 1 << 31, 1 << 32, 1 << 63, u64::MAX] {
                assert_eq!(scenario.msr(9, value).0, 0);
                assert_eq!(scenario.msr(8, 0), (1, enabled));
            }
        }
    }

    #[test]
    fn invariant_tsc_defers_to_the_parent_when_matrixhv_does_not_own_the_interface() {
        let mut scenario = Scenario::new();
        scenario.context[1] = 0;
        scenario.context[4] = 0;
        for supported in [0, 1] {
            scenario.shared[8] = supported;
            assert_eq!(scenario.msr(8, 0).0, 2);
            assert_eq!(scenario.msr(9, 1).0, 2);
        }
        assert_eq!(scenario.shared[9], 0);
    }

    #[test]
    fn page_enable_matches_reference_counter_and_is_visible_across_processors() {
        let mut scenario = Scenario::new();
        let address = scenario.page.0.as_ptr() as u64;
        let register = address | 0x7ff;
        assert_eq!(scenario.msr(2, register).0, 1);
        assert_eq!(scenario.shared[2], register);
        assert_eq!(scenario.shared[3], 0);
        assert_eq!(scenario.page.0[0], 1);
        assert_eq!(scenario.page.0[1], scenario.shared[0]);
        assert_eq!(scenario.page.0[2], scenario.shared[1]);
        assert!(scenario.page.0[3..].iter().all(|value| *value == 0));
        let expected = (((u128::from(scenario.context[2]) * u128::from(scenario.page.0[1])) >> 64)
            as u64)
            .wrapping_add(scenario.page.0[2]);
        assert_eq!(scenario.msr(0, 0), (1, expected));
        let before = expected;
        scenario.context[2] += 2496;
        assert!(scenario.msr(0, 0).1 > before);
        let mut second_context = scenario.context;
        let mut registers = [0_u64; 2];
        assert_eq!(
            unsafe { test_time_msr(second_context.as_mut_ptr(), registers.as_mut_ptr(), 1) },
            1
        );
        assert_eq!(registers[0] | registers[1] << 32, register);
    }

    #[test]
    fn disabled_reference_page_invalidates_the_sequence_and_preserves_reserved_bits() {
        let mut scenario = Scenario::new();
        let address = scenario.page.0.as_ptr() as u64;
        assert_eq!(scenario.msr(2, address | 1).0, 1);
        let disabled = address | 0x7fe;
        assert_eq!(scenario.msr(2, disabled).0, 1);
        assert_eq!(scenario.page.0[0], 0);
        assert_eq!(scenario.msr(1, 0), (1, disabled));
        assert_eq!(scenario.msr(3, 0).0, 0);
    }

    #[test]
    fn republishing_reference_tsc_rejects_a_reader_spanning_cleared_fields() {
        let mut scenario = Scenario::new();
        let address = scenario.page.0.as_ptr() as u64;
        assert_eq!(scenario.msr(2, address | 1).0, 1);
        let before = scenario.page.0[0] as u32;
        assert_eq!(scenario.msr(2, address | 1).0, 1);
        // The assembly harness samples exactly between clearing and publication.
        let observed_scale = scenario.context[6];
        let observed_offset = scenario.context[7];
        let after = scenario.page.0[0] as u32;
        assert_eq!((observed_scale, observed_offset), (0, 0));
        assert_ne!(before, after, "a spanning reader must retry publication");
        assert_ne!(after, 0);
        assert_eq!(scenario.page.0[1], scenario.shared[0]);
        assert_eq!(scenario.page.0[2], scenario.shared[1]);
        assert_eq!(scenario.shared[3], 0);
    }

    #[test]
    fn reference_tsc_generations_survive_disable_and_skip_zero_on_wrap() {
        let mut scenario = Scenario::new();
        let address = scenario.page.0.as_ptr() as u64;
        assert_eq!(scenario.msr(2, address | 1).0, 1);
        let before = scenario.page.0[0];
        assert_eq!(scenario.msr(2, 0).0, 1);
        assert_eq!(scenario.page.0[0], 0);
        assert_eq!(scenario.msr(2, address | 1).0, 1);
        assert_ne!(scenario.page.0[0], before);
        scenario.shared[7] = u64::from(u32::MAX);
        assert_eq!(scenario.msr(2, address | 1).0, 1);
        assert_eq!(scenario.page.0[0], 1);
        assert_eq!(scenario.shared[7], 1);
    }

    #[test]
    fn hyperv_shared_pages_use_the_ept01_translation_for_setup_and_invalidation() {
        for operation in [2, 7] {
            let mut scenario = Scenario::new();
            let translated = Box::new(Page([u64::MAX; 512]));
            let guest_address = scenario.page.0.as_ptr() as u64;
            let host_address = translated.0.as_ptr() as u64;
            scenario.tables[3].0[((guest_address >> 12) & 511) as usize] = host_address | 7;
            assert_eq!(scenario.msr(6, 1).0, 1);
            assert_eq!(scenario.msr(operation, guest_address | 1).0, 1);
            assert!(scenario.page.0.iter().all(|value| *value == u64::MAX));
            if operation == 2 {
                assert_eq!(translated.0[0], 1);
                assert_eq!(translated.0[1], scenario.shared[0]);
                assert_eq!(translated.0[2], scenario.shared[1]);
                assert_eq!(scenario.msr(2, 0).0, 1);
                assert_eq!(translated.0[0], 0);
            } else {
                assert_eq!(translated.0[0] as u32, 0xc3c1010f);
            }
        }
    }

    #[test]
    fn reference_tsc_does_not_invalidate_a_page_after_ept_write_access_is_removed() {
        let mut scenario = Scenario::new();
        let address = scenario.page.0.as_ptr() as u64;
        assert_eq!(scenario.msr(2, address | 1).0, 1);
        scenario.tables[3].0[((address >> 12) & 511) as usize] &= !2;
        let before = scenario.page.0;
        assert_eq!(scenario.msr(2, 0).0, 0);
        assert_eq!(scenario.page.0, before);
        assert_eq!(scenario.msr(1, 0), (1, address | 1));
        assert_eq!(scenario.shared[3], 0);
    }

    #[test]
    fn unmapped_or_guest_read_only_pages_are_rejected_before_any_root_write() {
        let mut scenario = Scenario::new();
        assert_eq!(scenario.msr(2, 1).0, 0);
        let address = scenario.page.0.as_ptr() as u64;
        scenario.context[5] = address;
        assert_eq!(scenario.msr(2, address | 1).0, 0);
        scenario.context[5] = 0;
        scenario.tables[3].0[((address >> 12) & 511) as usize] &= !2;
        assert_eq!(scenario.msr(2, address | 1).0, 0);
        assert_eq!(scenario.shared[2], 0);
        assert_eq!(scenario.shared[3], 0);
        assert!(scenario.page.0.iter().all(|value| *value == u64::MAX));
    }

    #[test]
    fn unsupported_reference_time_defers_to_the_parent_hypervisor() {
        let mut scenario = Scenario::new();
        scenario.context[1] = 0;
        scenario.context[4] = 0;
        for operation in 0..4 {
            assert_eq!(scenario.msr(operation, 1).0, 2);
        }
        assert_eq!(scenario.shared[2], 0);
    }

    #[test]
    fn reference_pages_accept_large_ept_leaves_and_honor_parent_write_denials() {
        for (level, shift) in [(1, 30), (2, 21)] {
            let mut scenario = Scenario::new();
            let address = scenario.page.0.as_ptr() as u64;
            let index = ((address >> shift) & 511) as usize;
            scenario.tables[level].0[index] = (address & !((1 << shift) - 1)) | 0x87;
            assert_eq!(scenario.msr(2, address | 1).0, 1);
            assert_eq!(scenario.msr(2, 0).0, 1);
            scenario.tables[0].0[((address >> 39) & 511) as usize] &= !2;
            assert_eq!(scenario.msr(2, address | 1).0, 0);
            assert_eq!(scenario.page.0[0], 0);
        }
    }

    #[test]
    fn partition_msr_writes_are_visible_from_another_virtual_processor() {
        let mut scenario = Scenario::new();
        scenario.context[1] = 0;
        let identity = 0x1040a00e465f4;
        let address = scenario.page.0.as_ptr() as u64;
        assert_eq!(scenario.msr(6, identity).0, 1);
        let mut other = scenario.context;
        let mut registers = [0; 2];
        assert_eq!(
            unsafe { test_time_msr(other.as_mut_ptr(), registers.as_mut_ptr(), 4) },
            1
        );
        assert_eq!(registers[0] | registers[1] << 32, identity);
        registers = [address as u32 as u64 | 1, address >> 32];
        assert_eq!(
            unsafe { test_time_msr(other.as_mut_ptr(), registers.as_mut_ptr(), 7) },
            1
        );
        assert_eq!(scenario.msr(5, 0), (1, address | 1));
        assert_eq!(scenario.page.0[0] as u32, 0xc3c1010f);
        assert_eq!(scenario.shared[6], 0);
        assert_eq!(scenario.msr(6, 0).0, 1);
        registers = [0; 2];
        assert_eq!(
            unsafe { test_time_msr(other.as_mut_ptr(), registers.as_mut_ptr(), 5) },
            1
        );
        assert_eq!(registers[0] | registers[1] << 32, address);
    }

    #[test]
    fn hypercall_enable_without_identity_clears_enable_and_does_not_write_the_page() {
        let mut scenario = Scenario::new();
        let address = scenario.page.0.as_ptr() as u64;
        assert_eq!(scenario.msr(7, address | 1).0, 1);
        assert_eq!(scenario.msr(5, 0), (1, address));
        assert!(scenario.page.0.iter().all(|value| *value == u64::MAX));
        assert_eq!(scenario.shared[6], 0);
    }

    #[test]
    fn hypercall_page_setup_requires_guest_write_access() {
        let mut scenario = Scenario::new();
        assert_eq!(scenario.msr(6, 1).0, 1);
        let address = scenario.page.0.as_ptr() as u64;
        scenario.tables[3].0[((address >> 12) & 511) as usize] &= !2;
        assert_eq!(scenario.msr(7, address | 1).0, 0);
        assert_eq!(scenario.msr(5, 0), (1, 0));
        assert!(scenario.page.0.iter().all(|value| *value == u64::MAX));
        assert_eq!(scenario.shared[6], 0);
    }

    #[test]
    fn hypercall_locked_bit_makes_the_partition_msr_immutable_on_every_processor() {
        let mut scenario = Scenario::new();
        let address = scenario.page.0.as_ptr() as u64;
        assert_eq!(scenario.msr(6, 1).0, 1);
        assert_eq!(scenario.msr(7, address | 3).0, 1);
        assert_eq!(scenario.msr(5, 0), (1, address | 3));
        let before = scenario.page.0;
        let mut other = scenario.context;
        for value in [
            0,
            address | 1,
            address | 2,
            (address + 4096) | 3,
            0xffc,
            u64::MAX,
        ] {
            let mut registers = [value as u32 as u64, value >> 32];
            assert_eq!(
                unsafe { test_time_msr(other.as_mut_ptr(), registers.as_mut_ptr(), 7) },
                1
            );
            assert_eq!(scenario.msr(5, 0), (1, address | 3));
            assert_eq!(scenario.page.0, before);
            assert_eq!(scenario.shared[6], 0);
        }
        assert_eq!(scenario.msr(6, 0).0, 1);
        assert_eq!(scenario.msr(5, 0), (1, address | 2));
        assert_eq!(scenario.msr(6, 1).0, 1);
        assert_eq!(scenario.msr(7, address | 3).0, 1);
        assert_eq!(scenario.msr(5, 0), (1, address | 2));
    }

    #[test]
    fn disabled_hypercall_pages_can_be_locked_without_initializing_memory() {
        let mut scenario = Scenario::new();
        let address = scenario.page.0.as_ptr() as u64;
        assert_eq!(scenario.msr(7, address | 3).0, 1);
        assert_eq!(scenario.msr(5, 0), (1, address | 2));
        assert!(scenario.page.0.iter().all(|value| *value == u64::MAX));
        assert_eq!(scenario.msr(6, 1).0, 1);
        assert_eq!(scenario.msr(7, address | 1).0, 1);
        assert_eq!(scenario.msr(5, 0), (1, address | 2));
        assert!(scenario.page.0.iter().all(|value| *value == u64::MAX));
    }

    #[test]
    fn invalid_hypercall_configuration_does_not_latch_the_locked_bit() {
        let mut scenario = Scenario::new();
        let address = scenario.page.0.as_ptr() as u64;
        assert_eq!(scenario.msr(6, 1).0, 1);
        assert_eq!(scenario.msr(7, (address + 4096) | 3).0, 0);
        assert_eq!(scenario.shared[6], 0);
        scenario.tables[3].0[((address >> 12) & 511) as usize] &= !2;
        assert_eq!(scenario.msr(7, address | 3).0, 0);
        assert_eq!(scenario.msr(5, 0), (1, 0));
        assert_eq!(scenario.shared[6], 0);
        assert!(scenario.page.0.iter().all(|value| *value == u64::MAX));
    }

    #[test]
    fn concurrent_identity_clear_cannot_leave_the_hypercall_page_enabled() {
        let mut scenario = Scenario::new();
        let address = scenario.page.0.as_ptr() as u64;
        let context = scenario.context;
        assert_eq!(scenario.msr(6, 1).0, 1);
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let mut context = context;
                for _ in 0..1000 {
                    let mut registers = [address as u32 as u64 | 1, address >> 32];
                    assert_eq!(
                        unsafe { test_time_msr(context.as_mut_ptr(), registers.as_mut_ptr(), 7) },
                        1
                    );
                }
            });
            scope.spawn(move || {
                let mut context = context;
                let mut registers = [0; 2];
                assert_eq!(
                    unsafe { test_time_msr(context.as_mut_ptr(), registers.as_mut_ptr(), 6) },
                    1
                );
            });
        });
        assert_eq!(scenario.msr(4, 0), (1, 0));
        assert_eq!(scenario.msr(5, 0), (1, address));
        assert_eq!(scenario.shared[6], 0);
    }
}

#[cfg(test_harness = "msr")]
mod cr_access {
    include!("resident_cr_tests.rs");
}

#[cfg(test_harness = "msr")]
mod msr {
    include!("../builds/resident-msr-tests/definitions.rs");

    use core::arch::global_asm;

    global_asm!(include_str!(
        "../builds/resident-msr-tests/resident-hyperv-apic.S"
    ));
    global_asm!(include_str!(
        "../builds/resident-msr-tests/resident-hyperv-parent.S"
    ));
    global_asm!(include_str!(
        "../builds/resident-msr-tests/resident-private-vmcall.S"
    ));

    unsafe extern "C" {
        fn test_hyperv_apic(context: *mut u64, registers: *mut u64, write: u32) -> u32;
        fn test_parent_msr_access(context: *const u64, index: u32) -> u32;
        fn test_private_vmcall(context: *const u64, code: u64) -> u32;
    }

    #[test]
    fn synthetic_msr_passthrough_requires_the_parent_to_own_the_interface() {
        for timing in [false, true] {
            for evmcs in [false, true] {
                let context = [u64::from(timing), u64::from(evmcs)];
                for index in [0x4000_0000, 0x4000_0002, 0x4000_0083, 0x4000_0fff] {
                    assert_eq!(
                        unsafe { test_parent_msr_access(context.as_ptr(), index) },
                        u32::from(!timing && !evmcs),
                        "timing={timing} evmcs={evmcs} index={index:#x}"
                    );
                }
                for index in [0, 0x808, 0x3fff_ffff, 0x4000_1000, 0xc000_0080, u32::MAX] {
                    assert_eq!(unsafe { test_parent_msr_access(context.as_ptr(), index) }, 1);
                }
            }
        }
    }

    #[test]
    fn private_lifecycle_vmcalls_reject_unprivileged_callers_before_dispatch() {
        for denied in [false, true] {
            let context = [u64::from(denied), 1];
            for code in [
                0x4856_4150_5245_4144,
                0x4856_5354_4152_5421,
                0x4d41_5452_4958_5042,
                0x4d41_5452_4958_4f50,
                0x4d41_5452_4958_4f43,
                0x4856_5354_4f50_2121,
                0x4856_4e56_4d46_4149,
            ] {
                assert_eq!(
                    unsafe { test_private_vmcall(context.as_ptr(), code) },
                    u32::from(!denied),
                    "denied={denied} code={code:#x}"
                );
            }
            for code in [0, 8, u64::MAX] {
                assert_eq!(unsafe { test_private_vmcall(context.as_ptr(), code) }, 2);
            }
            assert_eq!(unsafe { test_private_vmcall(context.as_ptr(), 0x564d_5868) }, 3);
        }
    }

    #[test]
    fn probe_failure_vmcall_is_disabled_outside_the_startup_probe() {
        for denied in [false, true] {
            let context = [u64::from(denied), 0];
            assert_eq!(
                unsafe { test_private_vmcall(context.as_ptr(), 0x4856_4e56_4d46_4149) },
                0
            );
        }
    }

    #[test]
    fn hyperv_apic_routes_x2apic_access_and_rejects_reserved_writes() {
        for (synthetic_msr, native_msr) in [
            (0x4000_0070, 0x80b),
            (0x4000_0071, 0x830),
            (0x4000_0072, 0x808),
        ] {
            let mut context = [1, 0xfee0_0c00, 0, 0, 0];
            let mut registers = [0, synthetic_msr, 0];
            assert_eq!(
                unsafe { test_hyperv_apic(context.as_mut_ptr(), registers.as_mut_ptr(), 1) },
                1
            );
            assert_eq!(context[2], native_msr);
            if synthetic_msr == 0x4000_0070 {
                assert_eq!(
                    unsafe { test_hyperv_apic(context.as_mut_ptr(), registers.as_mut_ptr(), 0) },
                    0
                );
            } else {
                context[3] = if synthetic_msr == 0x4000_0071 {
                    0x0000_0012_0000_0034
                } else {
                    0x34
                };
                assert_eq!(
                    unsafe { test_hyperv_apic(context.as_mut_ptr(), registers.as_mut_ptr(), 0) },
                    1
                );
                let expected = if synthetic_msr == 0x4000_0071 {
                    0x0000_0012_0000_0034
                } else {
                    0x34
                };
                assert_eq!((registers[2] << 32) | registers[0], expected);
            }
        }
        for (msr, low, high) in [
            (0x4000_0070, 0, 1),
            (0x4000_0072, 0x100, 0),
            (0x4000_0072, 0, 1),
        ] {
            let mut context = [1, 0xfee0_0c00, 0, 0, 0];
            let mut registers = [low, msr, high];
            assert_eq!(
                unsafe { test_hyperv_apic(context.as_mut_ptr(), registers.as_mut_ptr(), 1) },
                0
            );
            assert_eq!(context[2], 0);
        }
    }

    #[test]
    fn hyperv_apic_preserves_xapic_destination_and_tpr() {
        #[repr(C, align(4096))]
        struct ApicPage([u32; 1024]);
        let mut page = ApicPage([0; 1024]);
        let mut context = [1, page.0.as_mut_ptr() as u64 | 0x800, 0, 0, 0];
        let mut registers = [0x45, 0x4000_0071, 0x1200_0000];
        assert_eq!(
            unsafe { test_hyperv_apic(context.as_mut_ptr(), registers.as_mut_ptr(), 1) },
            1
        );
        assert_eq!(page.0[0x300 / 4], 0x45);
        assert_eq!(page.0[0x310 / 4], 0x1200_0000);
        registers[0] = 0;
        registers[2] = 0;
        assert_eq!(
            unsafe { test_hyperv_apic(context.as_mut_ptr(), registers.as_mut_ptr(), 0) },
            1
        );
        assert_eq!(registers, [0x45, 0x4000_0071, 0x1200_0000]);
        registers = [0xa0, 0x4000_0072, 0];
        assert_eq!(
            unsafe { test_hyperv_apic(context.as_mut_ptr(), registers.as_mut_ptr(), 1) },
            1
        );
        assert_eq!(page.0[0x80 / 4], 0xa0);
        context[1] &= !0x800;
        assert_eq!(
            unsafe { test_hyperv_apic(context.as_mut_ptr(), registers.as_mut_ptr(), 1) },
            0
        );
    }

    #[test]
    fn hyperv_icr_preserves_full_x2apic_destinations_and_broadcast() {
        for (destination, native_destination) in [(0x12, 0x12), (0xffff_ffff, 0xffff_ffff), (0x1234_00a5, 0x1234_00a5)] {
            let mut context = [1, 0xfee0_0c00, 0, 0, 0];
            let mut registers = [0x45, 0x4000_0071, destination];
            assert_eq!(
                unsafe { test_hyperv_apic(context.as_mut_ptr(), registers.as_mut_ptr(), 1) },
                1
            );
            assert_eq!(context[2], 0x830);
            assert_eq!(context[3], (native_destination << 32) | 0x45);
            assert_eq!(registers, [0x45, 0x4000_0071, destination]);
        }
    }

    #[test]
    fn hyperv_eoi_accepts_low_values_and_normalizes_the_native_x2apic_write() {
        for value in [1, 0xff, u32::MAX as u64] {
            let mut context = [1, 0xfee0_0c00, 0, u64::MAX, 0];
            let mut registers = [value, 0x4000_0070, 0];
            assert_eq!(unsafe { test_hyperv_apic(context.as_mut_ptr(), registers.as_mut_ptr(), 1) }, 1);
            assert_eq!(&context[2..4], &[0x80b, 0]);
        }
    }

    #[test]
    fn hyperv_xapic_denies_unmapped_bases_including_zero_without_native_msr_access() {
        for base in [0, 0x1234_5000] {
            for write in [0, 1] {
                let mut context = [1, base | 0x800, 0, 0, base];
                let mut registers = [0, 0x4000_0072, 0];
                assert_eq!(unsafe { test_hyperv_apic(context.as_mut_ptr(), registers.as_mut_ptr(), write) }, 0);
                assert_eq!(context[2], 0);
            }
        }
    }

    #[test]
    fn hyperv_x2apic_logical_icr_keeps_cluster_and_processor_mask() {
        let mut context = [1, 0xfee0_0c00, 0, 0, 0];
        let mut registers = [0x845, 0x4000_0071, 0x1234_a005];
        assert_eq!(unsafe { test_hyperv_apic(context.as_mut_ptr(), registers.as_mut_ptr(), 1) }, 1);
        assert_eq!(context[3], 0x1234_a005_0000_0845);
    }

    struct ResidentPages {
        bytes: [u8; 4096],
    }

    impl ResidentPages {
        fn new() -> Self {
            Self {
                bytes: [0xff; 4096],
            }
        }

        fn intercepts(&self, index: u32, write: bool) -> bool {
            let offset = ((index & 0x1fff) >> 3) as usize
                + if index >= 0xc000_0000 { 1024 } else { 0 }
                + if write { 2048 } else { 0 };
            self.bytes[offset] & (1 << (index & 7)) != 0
        }
    }

    #[test]
    fn physical_clock_and_deadline_share_native_reads_and_writes() {
        let bitmap = clock_bitmap();
        for index in [0x10, 0x3b, 0x6e0] {
            for write in [false, true] {
                assert!(
                    !bitmap.intercepts(index, write),
                    "clock MSR {index:#x}, write={write}"
                );
            }
        }
        for index in [0xfe, 0x200, 0x201, 0x250, 0x2ff] {
            assert!(!bitmap.intercepts(index, false));
            assert!(bitmap.intercepts(index, true));
        }
        assert!(bitmap.intercepts(0x480, false));
        assert!(bitmap.intercepts(0x480, true));
    }

    #[test]
    fn sysenter_state_does_not_generate_unsolicited_l1_exits() {
        let bitmap = clock_bitmap();
        for index in [0x174, 0x175, 0x176] {
            for write in [false, true] {
                assert!(
                    !bitmap.intercepts(index, write),
                    "VMCS-backed SYSENTER MSR {index:#x}, write={write} must not create an unsolicited L1 exit"
                );
            }
        }
        for index in [0x173, 0x177, 0x480] {
            assert_eq!(bitmap.intercepts(index, false), index == 0x480);
            assert!(bitmap.intercepts(index, true));
        }
    }

    global_asm!(include_str!(
        "../builds/resident-msr-tests/resident-msr-bitmap.S"
    ));

    unsafe extern "C" {
        fn test_merge_msr_bitmaps(l0: *const u8, composed: *mut u8, l1: *const u8);
    }

    #[test]
    fn sysenter_intercepts_follow_l1_read_and_write_policy() {
        let l0 = clock_bitmap();
        for index in [0x174_u32, 0x175, 0x176] {
            for requested in 0..4 {
                let mut l1 = [0_u8; 4096];
                for write in [false, true] {
                    let offset = (index >> 3) as usize + if write { 2048 } else { 0 };
                    if requested & (1 << u32::from(write)) != 0 {
                        l1[offset] |= 1 << (index & 7);
                    }
                }
                let mut composed = ResidentPages::new();
                unsafe {
                    test_merge_msr_bitmaps(
                        l0.bytes.as_ptr(),
                        composed.bytes.as_mut_ptr(),
                        l1.as_ptr(),
                    );
                }
                for write in [false, true] {
                    assert_eq!(
                        composed.intercepts(index, write),
                        requested & (1 << u32::from(write)) != 0,
                        "SYSENTER MSR {index:#x}, write={write}, requested={requested}"
                    );
                }
                for other in [0x173, 0x177, 0x480] {
                    assert_eq!(composed.intercepts(other, false), other == 0x480);
                    assert!(composed.intercepts(other, true));
                }
            }
        }
    }

    #[test]
    fn only_virtualized_msr_reads_require_a_resident_exit() {
        let bitmap = clock_bitmap();
        for base in [0, 0xc000_0000] {
            for index in base..base + 0x2000 {
                let virtualized =
                    index == 0x3a || (0x480..=0x49f).contains(&index) || index == 0xc000_0080;
                assert_eq!(
                    bitmap.intercepts(index, false),
                    virtualized,
                    "MSR {index:#x}"
                );
            }
        }
    }

    #[test]
    fn native_read_policy_preserves_every_l1_intercept() {
        let l0 = clock_bitmap();
        for pattern in [0, 0x55, 0xaa, 0xff] {
            let l1 = [pattern; 4096];
            let mut composed = ResidentPages::new();
            unsafe {
                test_merge_msr_bitmaps(l0.bytes.as_ptr(), composed.bytes.as_mut_ptr(), l1.as_ptr())
            };
            for base in [0, 0xc000_0000] {
                for index in base..base + 0x2000 {
                    for write in [false, true] {
                        let requested = pattern & (1 << (index & 7)) != 0;
                        assert_eq!(
                            composed.intercepts(index, write),
                            requested || l0.intercepts(index, write),
                            "MSR {index:#x}, write={write}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn native_read_policy_never_changes_write_intercepts() {
        let mut bitmap = [0_u8; 4096];
        for (index, byte) in bitmap.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(73);
        }
        let before = bitmap;
        allow_native_msr_reads(&mut bitmap);
        assert_eq!(&bitmap[2048..], &before[2048..]);
    }

    #[test]
    fn bitmap_boundaries_keep_read_write_and_address_ranges_separate() {
        let mut bitmap = [0xff; 4096];
        allow_low_msr_read_passthrough(&mut bitmap, 0);
        allow_low_msr_write_passthrough(&mut bitmap, 0x1fff);
        allow_high_msr_passthrough(&mut bitmap, 0xc000_0000);
        allow_high_msr_passthrough(&mut bitmap, 0xc000_1fff);
        for (offset, byte) in bitmap.into_iter().enumerate() {
            let expected = match offset {
                0 | 1024 | 3072 => 0xfe,
                2047 | 3071 | 4095 => 0x7f,
                _ => 0xff,
            };
            assert_eq!(byte, expected, "unexpected bitmap byte at {offset}");
        }
    }

    #[test]
    fn bitmap_helpers_reject_invalid_registers_and_short_buffers() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let mut bitmap = [0xff; 4096];
        for index in [0x2000, u32::MAX] {
            for helper in [
                allow_low_msr_passthrough,
                allow_low_msr_read_passthrough,
                allow_low_msr_write_passthrough,
            ] {
                assert!(catch_unwind(AssertUnwindSafe(|| helper(&mut bitmap, index))).is_err());
                assert_eq!(bitmap, [0xff; 4096]);
            }
        }
        for index in [0, 0xbfff_ffff, 0xc000_2000, u32::MAX] {
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    allow_high_msr_passthrough(&mut bitmap, index);
                }))
                .is_err()
            );
            assert_eq!(bitmap, [0xff; 4096]);
        }
        assert!(catch_unwind(|| allow_low_msr_passthrough(&mut [], 0)).is_err());
        assert!(
            catch_unwind(|| allow_high_msr_passthrough(&mut [0xff; 1024], 0xc000_0000)).is_err()
        );
    }

    global_asm!(include_str!(
        "../builds/resident-msr-tests/resident-cache-flush.S"
    ));

    #[repr(C)]
    #[derive(Default)]
    struct CacheFlush {
        unprivileged: u64,
        flushes: u64,
        rip: u64,
        fault: u64,
    }

    unsafe extern "C" {
        fn test_cache_flush(state: &mut CacheFlush);
    }

    #[test]
    fn startup_cache_invalidation_resumes_and_preserves_dirty_data() {
        let mut state = CacheFlush {
            rip: 0x8000,
            ..Default::default()
        };
        unsafe { test_cache_flush(&mut state) };
        assert_eq!(state.flushes, 1);
        assert_eq!(state.rip, 0x8002);
        assert_eq!(state.fault, 0);
    }

    #[test]
    fn unprivileged_cache_invalidation_faults_without_advancing() {
        let mut state = CacheFlush {
            unprivileged: 1,
            rip: 0x8000,
            ..Default::default()
        };
        unsafe { test_cache_flush(&mut state) };
        assert_eq!(state.flushes, 0);
        assert_eq!(state.rip, 0x8000);
        assert_eq!(state.fault, 1);
    }

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq)]
    struct MsrEntry {
        index: u32,
        reserved: u32,
        value: u64,
    }

    #[repr(C)]
    struct Context {
        exit_store: *const MsrEntry,
        guest: *mut MsrEntry,
        l1_store: *mut MsrEntry,
        l1_store_count: u64,
        captured_count: u64,
        l1_load: *const MsrEntry,
        l1_load_count: u64,
        entry: *mut MsrEntry,
    }

    global_asm!(
        include_str!("../builds/resident-msr-tests/resident-msr.S"),
        b_nested_vmcs02_exit_store_msr_list = const core::mem::offset_of!(Context, exit_store),
        b_nested_l0_msr_guest_list = const core::mem::offset_of!(Context, guest),
        b_nested_vmcs12_vm_exit_msr_store_addr = const core::mem::offset_of!(Context, l1_store),
        b_nested_vmcs12_vm_exit_msr_store_count = const core::mem::offset_of!(Context, l1_store_count),
        b_nested_captured_msr_store_count = const core::mem::offset_of!(Context, captured_count),
        b_nested_current_vmcs = const core::mem::offset_of!(Context, l1_store),
        b_nested_vmcs12_vm_exit_msr_load_addr = const core::mem::offset_of!(Context, l1_load),
        b_nested_vmcs12_vm_exit_msr_load_count = const core::mem::offset_of!(Context, l1_load_count),
        b_nested_vmcs01_entry_msr_list = const core::mem::offset_of!(Context, entry),
    );

    unsafe extern "C" {
        fn test_complete_msr_exit(context: &mut Context, count: u64, reason: u32);
        fn test_validate_efer(
            value: &mut u64,
            old: u64,
            unused: u64,
            features: u32,
            cr0: u64,
        ) -> u32;
        fn test_validate_canonical(value: u64, cr4: u64) -> u32;
    }

    fn entry(index: u32, value: u64) -> MsrEntry {
        MsrEntry {
            index,
            reserved: 0,
            value,
        }
    }

    #[test]
    fn spec_ctrl_requires_an_architectural_feature() {
        assert!(!spec_ctrl_available(0));
        assert!(!spec_ctrl_available((1 << 28) | (1 << 29)));
        for bit in [26, 27, 31] {
            assert!(spec_ctrl_available(1 << bit));
        }
    }

    #[test]
    fn nested_store_and_load_preserve_optional_root_prefix() {
        let _guard = TEST_LOCK.lock().unwrap();
        for root_count in [0, 1] {
            let sentinel = entry(0xdead, 0xbeef);
            let mut guest = [entry(0x48, 1), sentinel];
            let mut store = [entry(0x48, 0), entry(0xc000_0102, 0)];
            let load = [entry(0x48, 5), entry(0xc000_0102, 0x1234)];
            let mut exit_store = Vec::new();
            if root_count != 0 {
                exit_store.push(entry(0x48, 3));
            }
            // The duplicate SPEC_CTRL slot can be stale: the L0 prefix is authoritative.
            exit_store.extend([entry(0x48, 2), entry(0xc000_0102, 0x9876)]);
            let mut composed = [sentinel; 4];
            let mut context = Context {
                exit_store: exit_store.as_ptr(),
                guest: guest.as_mut_ptr(),
                l1_store: store.as_mut_ptr(),
                l1_store_count: 2,
                captured_count: 2 + root_count,
                l1_load: load.as_ptr(),
                l1_load_count: 2,
                entry: composed.as_mut_ptr(),
            };
            unsafe { test_complete_msr_exit(&mut context, root_count, 10) };
            assert_eq!(store[0].value, if root_count == 0 { 2 } else { 3 });
            assert_eq!(store[1].value, 0x9876);
            assert_eq!(guest[0].value, if root_count == 0 { 1 } else { 3 });
            assert_eq!(guest[1], sentinel);
            let offset = root_count as usize;
            assert_eq!(composed[offset..offset + 2], load);
            assert_eq!(composed[offset + 2], sentinel);
            if root_count != 0 {
                assert_eq!(composed[0], guest[0]);
            }
        }
    }

    #[test]
    fn failed_entry_never_copies_an_exit_store_list() {
        let _guard = TEST_LOCK.lock().unwrap();
        for root_count in [0, 1] {
            let mut guest = entry(0x48, 7);
            let load = [entry(0xc000_0102, 0x1234)];
            let mut composed = [entry(0, 0); 2];
            let mut context = Context {
                exit_store: core::ptr::null(),
                guest: &mut guest,
                l1_store: core::ptr::null_mut(),
                l1_store_count: 2,
                captured_count: 2 + root_count,
                l1_load: load.as_ptr(),
                l1_load_count: 1,
                entry: composed.as_mut_ptr(),
            };
            unsafe { test_complete_msr_exit(&mut context, root_count, 0x8000_0021) };
            assert_eq!(guest.value, 7);
            assert_eq!(composed[root_count as usize], load[0]);
        }
    }

    #[test]
    fn zero_counts_do_not_dereference_empty_lists() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut context = Context {
            exit_store: core::ptr::null(),
            guest: core::ptr::null_mut(),
            l1_store: core::ptr::null_mut(),
            l1_store_count: 0,
            captured_count: 0,
            l1_load: core::ptr::null(),
            l1_load_count: 0,
            entry: core::ptr::null_mut(),
        };
        unsafe { test_complete_msr_exit(&mut context, 0, 10) };
    }

    #[test]
    fn efer_rejects_reserved_bits_and_unsupported_features() {
        let features = (1 << 11) | (1 << 20) | (1 << 29);
        for bit in 0..64 {
            if 0xd01_u64 & (1 << bit) == 0 {
                let mut value = 1 << bit;
                assert_eq!(
                    unsafe { test_validate_efer(&mut value, 0, 0, features, 0) },
                    0
                );
            }
        }
        for bit in [0, 8, 11] {
            let mut value = 1 << bit;
            assert_eq!(unsafe { test_validate_efer(&mut value, 0, 0, 0, 0) }, 0);
        }
    }

    #[test]
    fn efer_preserves_read_only_lma_and_observes_paging_transition() {
        let features = (1 << 11) | (1 << 20) | (1 << 29);
        let mut value = 0x901;
        assert_eq!(
            unsafe { test_validate_efer(&mut value, 0x500, 0, features, 1 << 31) },
            1
        );
        assert_eq!(value, 0xd01);
        value = 0;
        assert_eq!(
            unsafe { test_validate_efer(&mut value, 0x500, 0, features, 1 << 31) },
            0
        );
        value = 0x500;
        assert_eq!(
            unsafe { test_validate_efer(&mut value, 0, 0, features, 0) },
            1
        );
        assert_eq!(value, 0x100);
    }

    #[test]
    fn canonical_msr_values_follow_the_guest_paging_width() {
        for value in [0, 0x7fff_ffff_ffff, 0xffff_8000_0000_0000, u64::MAX] {
            assert_eq!(unsafe { test_validate_canonical(value, 0) }, 1);
        }
        for value in [
            0x8000_0000_0000,
            0xffff_7fff_ffff_ffff,
            0x0100_0000_0000_0000,
        ] {
            assert_eq!(unsafe { test_validate_canonical(value, 0) }, 0);
        }
        assert_eq!(
            unsafe { test_validate_canonical(0x00ff_ffff_ffff_ffff, 1 << 12) },
            1
        );
        assert_eq!(
            unsafe { test_validate_canonical(0xff00_0000_0000_0000, 1 << 12) },
            1
        );
        assert_eq!(
            unsafe { test_validate_canonical(0x0100_0000_0000_0000, 1 << 12) },
            0
        );
    }

    #[repr(C)]
    #[derive(Default)]
    struct NmiContext {
        pending: u64,
        l2_active: u64,
        l1_pin: u64,
        control_cache: [u64; 2],
        vmcs: [u64; 5],
    }

    global_asm!(
        include_str!("../builds/resident-msr-tests/resident-nmi.S"),
        b_nmi_pending = const core::mem::offset_of!(NmiContext, pending),
        b_nested_l2_active = const core::mem::offset_of!(NmiContext, l2_active),
        b_nested_vmcs12_pin_based_control = const core::mem::offset_of!(NmiContext, l1_pin),
        b_nested_vmcs02_control_cache_valid = const core::mem::offset_of!(NmiContext, control_cache),
        test_vmcs = const core::mem::offset_of!(NmiContext, vmcs),
        vm_entry_intr_info_field = const 0,
        guest_interruptibility_info = const 1,
        guest_activity_state = const 2,
        cpu_based_vm_exec_control = const 3,
        guest_pending_dbg_exceptions = const 4,
    );

    unsafe extern "C" {
        fn test_deliver_nmi(context: &mut NmiContext);
    }

    #[test]
    fn nmi_delivery_waits_for_blocking_and_preserves_an_existing_event() {
        for (event, blocking) in [(0x8000030e, 0), (0, 1), (0, 2), (0, 8)] {
            let mut context = NmiContext {
                pending: 1,
                vmcs: [event, blocking, 0, 0, 0],
                ..Default::default()
            };
            unsafe { test_deliver_nmi(&mut context) };
            assert_eq!(context.pending, 1);
            assert_eq!(context.vmcs[0], event);
            assert_eq!(context.vmcs[3], 1 << 22);
        }
    }

    #[test]
    fn pending_debug_trap_precedes_physical_nmi_delivery() {
        for pending_debug in [1 << 12, 1 << 14, (1 << 12) | (1 << 14)] {
            let mut context = NmiContext {
                pending: 1,
                vmcs: [0, 0, 0, 0, pending_debug],
                ..Default::default()
            };
            unsafe { test_deliver_nmi(&mut context) };
            assert_eq!(context.pending, 1);
            assert_eq!(context.vmcs[0], 0);
            assert_eq!(context.vmcs[3], 1 << 22);
        }
    }

    #[test]
    fn nmi_delivery_wakes_halted_guests_and_respects_wait_for_sipi() {
        let mut context = NmiContext {
            pending: 1,
            vmcs: [0, 0, 1, 0, 0],
            ..Default::default()
        };
        unsafe { test_deliver_nmi(&mut context) };
        assert_eq!(context.pending, 0);
        assert_eq!(context.vmcs, [0x80000202, 0, 0, 0, 0]);
        context.pending = 1;
        context.vmcs = [0, 0, 3, 0, 0];
        unsafe { test_deliver_nmi(&mut context) };
        assert_eq!(context.pending, 1);
        assert_eq!(context.vmcs, [0, 0, 3, 0, 0]);
    }

    #[test]
    fn root_nmi_arms_l2_window_when_l1_owns_nmi_exits() {
        let mut context = NmiContext {
            pending: 1,
            l2_active: 1,
            l1_pin: 8,
            control_cache: [u64::MAX; 2],
            ..Default::default()
        };
        unsafe { test_deliver_nmi(&mut context) };
        assert_eq!(context.pending, 1);
        assert_eq!(context.vmcs, [0, 0, 0, 1 << 22, 0]);
        assert_eq!(context.control_cache, [0; 2]);
        context.l2_active = 0;
        unsafe { test_deliver_nmi(&mut context) };
        assert_eq!(context.pending, 0);
        assert_eq!(context.vmcs[0], 0x80000202);
    }
}

#[cfg(test_harness = "pages")]
use pages::firmware;
#[cfg(test_harness = "pages")]
mod pages {
    include!("../builds/resident-pages-tests/definitions.rs");

    use boot::AllocateType;
    use core::ptr::NonNull;

    const PAGE_SIZE: usize = 4096;
    const RESIDENT_MEMORY_TYPE: MemoryType = MemoryType;

    pub struct MemoryType;

    #[derive(Debug, PartialEq)]
    pub struct Status(u8);

    impl Status {
        const INVALID_PARAMETER: Self = Self(1);
        const UNSUPPORTED: Self = Self(2);

        fn status(self) -> Self {
            self
        }
    }

    pub(crate) mod firmware {
        pub fn boot_services_exited() -> bool {
            false
        }
    }

    mod boot {
        use super::*;
        use std::cell::RefCell;
        use std::collections::HashMap;

        #[repr(C, align(4096))]
        struct Page([u8; PAGE_SIZE]);

        thread_local! {
            static PAGES: RefCell<HashMap<usize, Vec<Page>>> = RefCell::new(HashMap::new());
        }

        pub enum AllocateType {
            AnyPages,
            MaxAddress(u64),
        }

        pub fn allocate_pages(
            kind: AllocateType,
            _memory_type: MemoryType,
            count: usize,
        ) -> Result<NonNull<u8>, Status> {
            if let AllocateType::MaxAddress(limit) = kind {
                assert_eq!(limit, u64::MAX);
            }
            let mut pages: Vec<Page> = (0..count).map(|_| Page([0xa5; PAGE_SIZE])).collect();
            let pointer = NonNull::new(pages.as_mut_ptr().cast()).unwrap();
            PAGES.with(|allocations| {
                allocations
                    .borrow_mut()
                    .insert(pointer.as_ptr() as usize, pages);
            });
            Ok(pointer)
        }

        pub unsafe fn free_pages(pointer: NonNull<u8>, count: usize) -> Result<(), Status> {
            PAGES.with(|allocations| {
                let pages = allocations
                    .borrow_mut()
                    .remove(&(pointer.as_ptr() as usize))
                    .unwrap();
                assert_eq!(pages.len(), count);
            });
            Ok(())
        }

        pub fn count() -> usize {
            PAGES.with(|allocations| allocations.borrow().len())
        }

        pub fn byte(address: u64, offset: usize) -> u8 {
            PAGES.with(|allocations| {
                allocations.borrow()[&(address as usize)][offset / PAGE_SIZE].0[offset % PAGE_SIZE]
            })
        }
    }

    #[test]
    fn initializer_borrows_zeroed_pages_and_keeps_writes_until_drop() {
        let pages =
            ResidentPages::allocate_initialized(2, AddressConstraint::Max(u64::MAX), |bytes| {
                assert_eq!(bytes, &[0; 2 * PAGE_SIZE]);
                bytes[0] = 0x12;
                bytes[2 * PAGE_SIZE - 1] = 0x34;
            })
            .unwrap();
        assert_eq!(pages.pages(), 2);
        assert_eq!(boot::count(), 1);
        assert_eq!(boot::byte(pages.physical_address(), 0), 0x12);
        assert_eq!(
            boot::byte(pages.physical_address(), 2 * PAGE_SIZE - 1),
            0x34
        );
        drop(pages);
        assert_eq!(boot::count(), 0);
    }

    #[test]
    fn invalid_sizes_are_rejected_before_allocation_or_initialization() {
        for pages in [
            0,
            usize::MAX,
            usize::MAX / PAGE_SIZE + 1,
            isize::MAX as usize / PAGE_SIZE + 1,
        ] {
            let result = ResidentPages::allocate_initialized(pages, AddressConstraint::Any, |_| {
                panic!("invalid allocation reached its initializer");
            });
            assert_eq!(result.err(), Some(Status::INVALID_PARAMETER));
            assert_eq!(boot::count(), 0);
        }
    }

    #[test]
    fn initializer_panic_releases_the_allocation() {
        assert!(
            std::panic::catch_unwind(|| {
                let _ = ResidentPages::allocate_initialized(1, AddressConstraint::Any, |_| {
                    panic!("initializer failed");
                });
            })
            .is_err()
        );
        assert_eq!(boot::count(), 0);
    }

    #[test]
    fn preserved_pages_remain_owned_after_the_resource_is_dropped() {
        let mut pages = ResidentPages::allocate(1, AddressConstraint::Any).unwrap();
        let pointer = pages.pointer();
        assert_eq!(pointer.as_ptr() as usize as u64, pages.physical_address());
        pages.preserve();
        drop(pages);
        assert_eq!(boot::count(), 1);
        unsafe {
            boot::free_pages(pointer, 1).unwrap();
        }
        assert_eq!(boot::count(), 0);
    }
}

#[cfg(test_harness = "telemetry")]
mod telemetry {
    core::arch::global_asm!(include_str!(
        "../builds/resident-telemetry-tests/resident-telemetry.S"
    ));
    include!("../builds/resident-telemetry-tests/offsets.rs");

    unsafe extern "win64" {
        fn test_watchdog_begin(context: *mut u64);
        fn test_watchdog_complete(context: *mut u64);
        fn test_counter(context: *mut u64) -> u64;
        fn test_profile_exit(context: *mut u64);
        fn test_nested_failure_record(context: *mut u64, kind: u64, code: u64);
        fn test_diagnostic(context: *mut u64, shared: *mut u64, subleaf: u32, result: *mut u32);
    }

    fn diagnostic(context: &mut [u64; 1024], shared: &mut [u64; 1024], subleaf: u32) -> [u32; 4] {
        let mut result = [0; 4];
        unsafe {
            test_diagnostic(
                context.as_mut_ptr(),
                shared.as_mut_ptr(),
                subleaf,
                result.as_mut_ptr(),
            );
        }
        result
    }

    #[test]
    fn l1_contract_explicitly_excludes_hardware_task_switching_and_smx() {
        let mut context = [0; 1024];
        let mut shared = [0; 1024];
        assert_eq!(diagnostic(&mut context, &mut shared, 54), [1, 3, 0, 0]);
    }

    #[test]
    fn telemetry_queries_do_not_advance_sequence_or_overwrite_last_guest() {
        let mut context = [0; 1024];
        context[offset("b_telemetry_enabled")] = 1;
        context[offset("b_last_reason")] = 10;
        context[offset("b_last_rax")] = 0x4d48_5652;
        context[offset("b_watchdog_last_rip")] = 0x1234;
        unsafe {
            test_watchdog_begin(context.as_mut_ptr());
            test_watchdog_complete(context.as_mut_ptr());
        }
        assert_eq!(context[offset("b_watchdog_sequence")], 0);
        assert_eq!(context[offset("b_watchdog_last_rip")], 0x1234);
        assert_eq!(context[offset("b_watchdog_handler_returns")], 0);
    }

    #[test]
    fn exit_transition_captures_three_states_and_counts_access_bits() {
        let mut context = [0; 1024];
        context[offset("b_telemetry_enabled")] = 1;
        context[offset("b_last_reason")] = 48;
        context[offset("b_last_qualification")] = 7;
        context[offset("b_last_guest_rip")] = 0x1122;
        context[offset("b_watchdog_deadline")] = 1000;
        context[offset("b_exit_count")] = 123;
        unsafe {
            test_watchdog_begin(context.as_mut_ptr());
        }
        assert_eq!(context[offset("b_watchdog_sequence")], 1);
        assert_eq!(context[offset("b_watchdog_phase")], 3);
        for name in [
            "b_ept_violation_read",
            "b_ept_violation_write",
            "b_ept_violation_execute",
        ] {
            assert_eq!(context[offset(name)], 1);
        }
        unsafe {
            test_watchdog_complete(context.as_mut_ptr());
        }
        assert_eq!(context[offset("b_watchdog_sequence")], 2);
        assert_eq!(context[offset("b_watchdog_phase")], 1);
        assert_eq!(context[offset("b_watchdog_exit_count")], 123);
        for name in ["b_watchdog_before", "b_watchdog_after", "b_watchdog_resume"] {
            assert_eq!(context[offset(name)], 0x123456789abcdef0);
            assert_eq!(context[offset(name) + 1], 0xabcdef0123456780);
            assert_eq!(context[offset(name) + 6], 0x500);
        }
    }

    #[test]
    fn expired_lease_disables_capture_and_first_entry_failure_is_sealed() {
        let mut context = [0; 1024];
        context[offset("b_telemetry_enabled")] = 1;
        context[offset("b_watchdog_deadline")] = 99;
        context[offset("b_last_reason")] = 0x8000_0021;
        unsafe {
            test_watchdog_begin(context.as_mut_ptr());
        }
        assert_eq!(context[offset("b_watchdog_deadline")], 0);
        assert_eq!(context[offset("b_watchdog_before")], 0);
        assert_eq!(context[offset("b_entry_failure_state")], 2);
        assert_eq!(context[offset("b_entry_failure_exit")], 0x8000_0021);
        assert_eq!(context[offset("b_entry_failure_tsc")], 100);
        context[offset("b_entry_failure_guest")] = 0xfeed;
        unsafe {
            test_watchdog_begin(context.as_mut_ptr());
        }
        assert_eq!(context[offset("b_entry_failure_guest")], 0xfeed);
    }

    #[test]
    fn remote_cpu_queries_preserve_64_bit_values_and_validate_target() {
        let mut context = [0; 1024];
        let mut remote = [0u64; 1024];
        let mut shared = [0; 1024];
        shared[offset("event_cpu_contexts") + 1] = remote.as_mut_ptr() as u64;
        remote[offset("b_watchdog_last_reason")] = 0x1122334455667788;
        remote[offset("b_watchdog_last_rip")] = 0x8877665544332211;
        std::hint::black_box(&remote);
        assert_eq!(
            diagnostic(&mut context, &mut shared, (2 << 16) | 8),
            [0x55667788, 0x11223344, 0x44332211, 0x88776655]
        );
        assert_eq!(
            diagnostic(&mut context, &mut shared, (65 << 16) | 8),
            [0; 4]
        );
        assert_eq!(diagnostic(&mut context, &mut shared, (3 << 16) | 8), [0; 4]);
        assert_eq!(diagnostic(&mut context, &mut shared, 36), [2, 0, 0, 0]);
    }

    #[test]
    fn vmx_capability_queries_distinguish_host_support_from_nested_exposure() {
        let mut context = [0; 1024];
        let mut remote = [0u64; 1024];
        let mut shared = [0; 1024];
        shared[offset("event_cpu_contexts") + 1] = remote.as_mut_ptr() as u64;
        remote[offset("b_nested_host_procbased_ctls2")] = (1 << 46) | 0x1234;
        remote[offset("b_nested_vmx_procbased_ctls2")] = 2 << 32;
        remote[offset("b_nested_host_misc")] = (1 << 29) | 5;
        remote[offset("b_nested_vmx_misc")] = 5;
        std::hint::black_box(&remote);
        assert_eq!(
            diagnostic(&mut context, &mut shared, (2 << 16) | 47),
            [0x1234, 0x4000, 0, 2]
        );
        assert_eq!(
            diagnostic(&mut context, &mut shared, (2 << 16) | 48),
            [0x20000005, 0, 5, 0]
        );
        assert_eq!(
            diagnostic(&mut context, &mut shared, (3 << 16) | 47),
            [0; 4]
        );
        assert_ne!(diagnostic(&mut context, &mut shared, 34)[0] & (1 << 12), 0);
    }

    #[test]
    fn ept_recycling_queries_distinguish_full_resets_from_single_table_evictions() {
        let mut context = [0; 1024];
        let mut remote = [0_u64; 1024];
        let mut shared = [0; 1024];
        shared[offset("event_cpu_contexts") + 1] = remote.as_mut_ptr() as u64;
        remote[offset("b_nested_ept02_recycle_count")] = 0x123456789abcdef0;
        remote[offset("b_nested_ept02_table_eviction_count")] = 0xfedcba9876543210;
        std::hint::black_box(&remote);
        assert_eq!(
            diagnostic(&mut context, &mut shared, (2 << 16) | 49),
            [0x9abcdef0, 0x12345678, 0x76543210, 0xfedcba98]
        );
        assert_eq!(
            diagnostic(&mut context, &mut shared, (3 << 16) | 49),
            [0; 4]
        );
        assert_ne!(diagnostic(&mut context, &mut shared, 34)[0] & (1 << 13), 0);
    }

    #[test]
    fn remote_control_stage_remains_visible_when_target_cpu_is_native() {
        let mut context = [0; 1024];
        let mut remote = [0_u64; 1024];
        let mut shared = [0; 1024];
        shared[offset("event_cpu_contexts") + 1] = remote.as_mut_ptr() as u64;
        remote[offset("b_processor_number")] = 1;
        std::hint::black_box(&remote);
        let stage = offset("event_control_cpu_states") + 8;
        shared[stage] = 0x1122334455667788;
        shared[stage + 1] = 0x8877665544332211;
        assert_eq!(
            diagnostic(&mut context, &mut shared, (2 << 16) | 50),
            [0x55667788, 0x11223344, 0x44332211, 0x88776655]
        );
        assert_eq!(
            diagnostic(&mut context, &mut shared, (3 << 16) | 50),
            [0; 4]
        );
        assert_ne!(diagnostic(&mut context, &mut shared, 34)[0] & (1 << 14), 0);
    }

    #[test]
    fn remote_control_failure_reports_the_complete_entry_reason_and_qualification() {
        let mut context = [0; 1024];
        let mut remote = [0_u64; 1024];
        let mut shared = [0; 1024];
        shared[offset("event_cpu_contexts") + 1] = remote.as_mut_ptr() as u64;
        remote[offset("b_processor_number")] = 1;
        std::hint::black_box(&remote);
        let state = offset("event_control_cpu_states") + 8;
        shared[state + 2] = 0x80000021;
        shared[state + 3] = 0x1122334455667788;
        assert_eq!(
            diagnostic(&mut context, &mut shared, (2 << 16) | 53),
            [0x80000021, 0, 0x55667788, 0x11223344]
        );
        assert_eq!(
            diagnostic(&mut context, &mut shared, (3 << 16) | 53),
            [0; 4]
        );
    }

    #[test]
    fn profiling_reports_remote_msr_operands_and_full_width_handler_ticks() {
        let mut context = [0; 1024];
        let mut remote = [0_u64; 1024];
        let mut shared = [0; 1024];
        shared[offset("event_cpu_contexts")] = remote.as_mut_ptr() as u64;
        remote[offset("b_rdmsr_count")] = 0x123456789abcdef0;
        remote[offset("b_wrmsr_count")] = 0x0fedcba987654321;
        remote[offset("b_last_normal_reason")] = 31;
        remote[offset("b_last_rcx")] = 0xc0000080;
        remote[offset("b_nested_exit_handler_cycles") + 3] = 0xfedcba9876543210;
        std::hint::black_box(&remote);
        assert_eq!(
            diagnostic(&mut context, &mut shared, (1 << 16) | 38),
            [0x9abcdef0, 0x12345678, 0x87654321, 0x0fedcba9]
        );
        assert_eq!(
            diagnostic(&mut context, &mut shared, (1 << 16) | 42),
            [31, 0, 0xc0000080, 0]
        );
        assert_eq!(
            diagnostic(&mut context, &mut shared, (1 << 16) | 44),
            [0, 0, 0x76543210, 0xfedcba98]
        );
        assert_eq!(diagnostic(&mut context, &mut shared, 47), [0; 4]);
        assert_eq!(diagnostic(&mut context, &mut shared, 34)[0] & 0x400, 0x400);
    }

    #[test]
    fn opt_in_handler_timing_works_without_a_serial_port() {
        for (reason, category) in [(23, 0), (25, 0), (20, 1), (24, 1), (31, 2), (50, 3)] {
            let mut context = [0; 1024];
            context[offset("b_last_reason")] = reason;
            context[offset("b_nested_exit_started_tsc")] = 25;
            unsafe { test_profile_exit(context.as_mut_ptr()) };
            assert_eq!(
                &context[offset("b_nested_exit_handler_cycles")..][..4],
                &[0; 4]
            );
            context[offset("b_telemetry_active")] = 1;
            unsafe { test_profile_exit(context.as_mut_ptr()) };
            let mut expected = [0; 4];
            expected[category] = 75;
            assert_eq!(
                &context[offset("b_nested_exit_handler_cycles")..][..4],
                &expected
            );
        }
    }

    #[test]
    fn exit_histogram_is_monotonic_and_excludes_observer_queries() {
        let mut context = [0; 1024];
        context[offset("b_telemetry_enabled")] = 1;
        let counts = offset("b_nested_exit_reason_counts");
        for reason in [20, 23, 25, 24, 23, 25, 0x8000_0021, 127, 128] {
            context[offset("b_last_reason")] = reason;
            unsafe { test_watchdog_begin(context.as_mut_ptr()) };
        }
        assert_eq!(context[counts + 23], 2);
        assert_eq!(context[counts + 25], 2);
        assert_eq!(context[counts + 33], 1);
        assert_eq!(context[counts + 127], 1);
        assert_eq!(context[counts..counts + 128].iter().sum::<u64>(), 8);
        context[offset("b_last_reason")] = 10;
        context[offset("b_last_rax")] = 0x4d48_5652;
        unsafe { test_watchdog_begin(context.as_mut_ptr()) };
        assert_eq!(context[counts + 10], 0);
        context[offset("b_last_reason")] = 23;
        context[offset("b_telemetry_enabled")] = 0;
        unsafe { test_watchdog_begin(context.as_mut_ptr()) };
        assert_eq!(context[counts + 23], 2);
    }

    #[test]
    fn remote_histogram_and_vmcs_profile_share_cumulative_counters() {
        let mut context = [0; 1024];
        let mut remote = [0_u64; 1024];
        let mut shared = [0; 1024];
        shared[offset("event_cpu_contexts")] = remote.as_mut_ptr() as u64;
        let counts = offset("b_nested_exit_reason_counts");
        remote[counts + 23] = 0x1122334455667788;
        remote[counts + 25] = 0x8877665544332211;
        remote[counts + 127] = u64::MAX;
        std::hint::black_box(&remote);
        assert_eq!(
            diagnostic(&mut context, &mut shared, (1 << 16) | 40),
            [0x55667788, 0x11223344, 0x44332211, 0x88776655]
        );
        assert_eq!(
            diagnostic(&mut context, &mut shared, (1 << 16) | 0x30b),
            [0, 0, 0x55667788, 0x11223344]
        );
        assert_eq!(
            diagnostic(&mut context, &mut shared, (1 << 16) | 0x33f),
            [0, 0, u32::MAX, u32::MAX]
        );
        for selector in [0x2ff, 0x340] {
            assert_eq!(diagnostic(&mut context, &mut shared, selector), [0; 4]);
        }
    }

    #[test]
    fn nested_failure_trace_exposes_each_record_word_pair() {
        let mut context = [0; 1024];
        let mut shared = [0; 1024];
        context[offset("b_nested_failure_count")] = 1;
        let trace = offset("b_nested_failure_trace");
        context[trace] = 0x1122334455667788;
        context[trace + 1] = 25;
        context[trace + 2] = 1;
        context[trace + 3] = 12;
        context[trace + 4] = 0x2806;
        context[trace + 5] = 0x1234;
        assert_eq!(diagnostic(&mut context, &mut shared, 0x100), [1, 0, 32, 0]);
        assert_eq!(
            diagnostic(&mut context, &mut shared, 0x101),
            [0x55667788, 0x11223344, 25, 0]
        );
        assert_eq!(diagnostic(&mut context, &mut shared, 0x102), [1, 0, 12, 0]);
        assert_eq!(
            diagnostic(&mut context, &mut shared, 0x103),
            [0x2806, 0, 0x1234, 0]
        );
        assert_eq!(diagnostic(&mut context, &mut shared, 0x104), [0; 4]);
    }

    #[test]
    fn nested_failure_recorder_captures_instruction_context_and_bounds_the_trace() {
        let mut context = [0; 1024];
        let trace = offset("b_nested_failure_trace");
        context[offset("b_telemetry_active")] = 1;
        context[offset("b_nested_failure_count")] = 1;
        context[offset("b_nested_current_vmcs")] = 0x3000;
        context[offset("b_last_guest_rip")] = 0x140001234;
        context[offset("b_last_reason")] = 25;
        context[offset("b_nested_last_vmcs_field")] = 0x2806;
        context[offset("b_nested_last_operand")] = 0xabc;
        unsafe { test_nested_failure_record(context.as_mut_ptr(), 1, 12) };
        assert_eq!(
            &context[trace..trace + 6],
            &[0x140001234, 25, 1, 12, 0x2806, 0xabc]
        );
        context[offset("b_nested_failure_count")] = 2;
        context[offset("b_nested_current_vmcs")] = u64::MAX;
        unsafe { test_nested_failure_record(context.as_mut_ptr(), 1, 7) };
        assert_eq!(&context[trace + 6..trace + 10], &[0x140001234, 25, 6, 7]);
        context[offset("b_nested_failure_count")] = 33;
        unsafe { test_nested_failure_record(context.as_mut_ptr(), 1, 8) };
        assert_eq!(&context[trace + 6 * 31..trace + 6 * 32], &[0; 6]);
    }

    #[test]
    fn watchdog_control_uses_a_15_second_lease_on_the_selected_cpu() {
        let mut context = [0; 1024];
        let mut remote = [0u64; 1024];
        let mut shared = [0; 1024];
        shared[offset("event_cpu_contexts")] = remote.as_mut_ptr() as u64;
        remote[offset("b_watchdog_tsc_hz")] = 200;
        remote[offset("b_telemetry_enabled")] = 1;
        diagnostic(&mut context, &mut shared, (1 << 16) | 0x200);
        assert_eq!(remote[offset("b_watchdog_deadline")], 3100);
        assert_eq!(context[offset("b_watchdog_deadline")], 0);
        diagnostic(&mut context, &mut shared, (1 << 16) | 0x201);
        assert_eq!(remote[offset("b_watchdog_deadline")], 0);
    }

    #[test]
    fn collection_is_disabled_until_enabled_and_freezes_existing_records() {
        let mut context = [0; 1024];
        let mut shared = [0; 1024];
        context[offset("b_last_reason")] = 48;
        context[offset("b_last_qualification")] = 7;
        context[offset("b_last_guest_rip")] = 0x1122;
        let before = context;
        unsafe {
            test_watchdog_begin(context.as_mut_ptr());
            test_watchdog_complete(context.as_mut_ptr());
        }
        assert_eq!(context, before);
        assert_eq!(diagnostic(&mut context, &mut shared, 37), [0; 4]);
        assert_eq!(diagnostic(&mut context, &mut shared, 0x202), [1, 0, 0, 0]);
        unsafe {
            test_watchdog_begin(context.as_mut_ptr());
            test_watchdog_complete(context.as_mut_ptr());
        }
        assert_eq!(context[offset("b_watchdog_sequence")], 2);
        assert_eq!(context[offset("b_watchdog_handler_returns")], 1);
        assert_eq!(context[offset("b_watchdog_last_rip")], 0x1122);
        diagnostic(&mut context, &mut shared, 0x200);
        diagnostic(&mut context, &mut shared, 0x203);
        assert_eq!(context[offset("b_watchdog_deadline")], 0);
        unsafe { test_watchdog_begin(context.as_mut_ptr()) };
        let frozen = context;
        unsafe { test_watchdog_complete(context.as_mut_ptr()) };
        assert_eq!(context, frozen);
        assert_eq!(context[offset("b_watchdog_sequence")], 2);
        assert_eq!(context[offset("b_ept_violation_execute")], 1);
        diagnostic(&mut context, &mut shared, 0x200);
        assert_eq!(context[offset("b_watchdog_deadline")], 0);
    }

    #[test]
    fn remote_toggle_applies_to_selected_cpu_and_finishes_an_inflight_exit() {
        let mut context = [0; 1024];
        let mut remote = [0u64; 1024];
        let mut shared = [0; 1024];
        shared[offset("event_cpu_contexts") + 1] = remote.as_mut_ptr() as u64;
        remote[offset("b_last_reason")] = 28;
        remote[offset("b_last_qualification")] = 3;
        diagnostic(&mut context, &mut shared, (2 << 16) | 0x202);
        assert_eq!(remote[offset("b_telemetry_enabled")], 1);
        assert_eq!(context[offset("b_telemetry_enabled")], 0);
        unsafe { test_watchdog_begin(remote.as_mut_ptr()) };
        diagnostic(&mut context, &mut shared, (2 << 16) | 0x203);
        unsafe { test_watchdog_complete(remote.as_mut_ptr()) };
        assert_eq!(remote[offset("b_watchdog_sequence")], 2);
        assert_eq!(remote[offset("b_cr3_exits")], 1);
        unsafe {
            test_watchdog_begin(remote.as_mut_ptr());
            test_watchdog_complete(remote.as_mut_ptr());
        }
        assert_eq!(remote[offset("b_watchdog_sequence")], 2);
        assert_eq!(
            diagnostic(&mut context, &mut shared, (65 << 16) | 0x202),
            [0; 4]
        );
        assert_eq!(remote[offset("b_telemetry_enabled")], 0);
    }

    #[test]
    fn basic_counters_freeze_when_disabled_and_preserve_carry_flag() {
        let mut context = [0; 1024];
        context[offset("b_exit_count")] = 17;
        for active in [0, 1, 0] {
            context[offset("b_telemetry_active")] = active;
            let before = context[offset("b_exit_count")];
            let flags = unsafe { test_counter(context.as_mut_ptr()) };
            assert_eq!(flags & 1, 1);
            assert_eq!(context[offset("b_exit_count")], before + active);
        }
    }

    #[test]
    fn startup_probe_does_not_enable_user_telemetry() {
        let mut context = [0; 1024];
        let mut shared = [0; 1024];
        context[offset("b_telemetry_probe_active")] = 1;
        context[offset("b_last_reason")] = 10;
        unsafe {
            test_watchdog_begin(context.as_mut_ptr());
            test_watchdog_complete(context.as_mut_ptr());
        }
        assert_eq!(context[offset("b_watchdog_sequence")], 2);
        assert_eq!(diagnostic(&mut context, &mut shared, 37), [0; 4]);
        assert_ne!(diagnostic(&mut context, &mut shared, 34)[0] & (1 << 8), 0);
        context[offset("b_telemetry_probe_active")] = 0;
        unsafe {
            test_watchdog_begin(context.as_mut_ptr());
            test_watchdog_complete(context.as_mut_ptr());
        }
        assert_eq!(context[offset("b_watchdog_sequence")], 2);
    }
}

#[cfg(test_harness = "visual")]
mod visual {
    include!("../builds/resident-visual-tests/definitions.rs");

    use core::arch::global_asm;

    const WIDTH: usize = 512;
    const HEIGHT: usize = 384;
    const BACKGROUND: u32 = 0x1234_5678;
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[repr(C)]
    #[derive(Default)]
    struct TimerContext {
        interval_tsc: u64,
        rate: u64,
        deadline_tsc: u64,
        samples: u64,
        expired: u64,
        pin_controls: u64,
        cached_pin_controls: u64,
        event_context: *mut EventContext,
        snapshots: u64,
        processor_number: u64,
        nested_l2_active: u64,
    }

    global_asm!(
        include_str!("../builds/resident-visual-tests/resident-timer.S"),
        b_diagnostic_interval = const core::mem::offset_of!(TimerContext, interval_tsc),
        b_diagnostic_rate = const core::mem::offset_of!(TimerContext, rate),
        b_diagnostic_deadline = const core::mem::offset_of!(TimerContext, deadline_tsc),
        b_diagnostic_samples = const core::mem::offset_of!(TimerContext, samples),
        b_diagnostic_expired = const core::mem::offset_of!(TimerContext, expired),
        b_nested_vmcs01_pin_based_controls = const core::mem::offset_of!(TimerContext, cached_pin_controls),
        b_event_context = const core::mem::offset_of!(TimerContext, event_context),
        test_pin_controls = const core::mem::offset_of!(TimerContext, pin_controls),
        test_snapshot_count = const core::mem::offset_of!(TimerContext, snapshots),
        b_processor_number = const core::mem::offset_of!(TimerContext, processor_number),
        b_nested_l2_active = const core::mem::offset_of!(TimerContext, nested_l2_active),
        log_framebuffer_sink = const 2,
        event_visual_base = const core::mem::offset_of!(EventContext, visual_base),
        event_tsc_hz = const core::mem::offset_of!(EventContext, tsc_hz),
        event_ebs_seen = const core::mem::offset_of!(EventContext, exit_boot_services_seen),
        event_diagnostic_halted = const core::mem::offset_of!(EventContext, diagnostic_halted),
        event_visual_deadline = const core::mem::offset_of!(EventContext, visual_deadline),
        pin_based_vm_exec_control = const 0x4000,
        vmx_preemption_timer_value = const 0x482e,
    );

    #[repr(C)]
    struct EventContext {
        telemetry_enabled: u64,
        diagnostic_halted: u64,
        exit_boot_services_seen: u64,
        virtual_address_change_seen: u64,
        visual_base: u64,
        visual_stride_bytes: u64,
        host_fault_vector: u64,
        host_fault_rip: u64,
        host_fault_error_code: u64,
        host_fault_address: u64,
        nmi_pending: u64,
        sync_nmi: u64,
        nmi_count: u64,
        tsc_hz: u64,
        visual_deadline: u64,
        control_va_error: u64,
        runtime_get_variable: u64,
        runtime_set_variable: u64,
        runtime_context: u64,
        native_storage_runtime: [u64; 64],
        primary_controls: u64,
        nested_l2_active: u64,
        vmcs02_control_cache_valid: [u64; 2],
        root_vmx_active: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct GpFrameTest {
        fault_rip: u64,
        error_code: u64,
        input_rax: u64,
        input_rdx: u64,
        recovered_rip: u64,
        recovered_rax: u64,
        recovered_rdx: u64,
        unhandled: u64,
    }

    global_asm!(
        include_str!("../builds/resident-visual-tests/resident-visual.S"),
        event_visual_base = const core::mem::offset_of!(EventContext, visual_base),
        event_diagnostic_halted = const core::mem::offset_of!(EventContext, diagnostic_halted),
        event_visual_stride_bytes = const core::mem::offset_of!(EventContext, visual_stride_bytes),
        event_host_fault_vector = const core::mem::offset_of!(EventContext, host_fault_vector),
        event_host_fault_rip = const core::mem::offset_of!(EventContext, host_fault_rip),
        event_host_fault_error_code = const core::mem::offset_of!(EventContext, host_fault_error_code),
        event_host_fault_address = const core::mem::offset_of!(EventContext, host_fault_address),
        b_nmi_pending = const core::mem::offset_of!(EventContext, nmi_pending),
        b_nested_eptp_sync_nmi = const core::mem::offset_of!(EventContext, sync_nmi),
        b_nmi_count = const core::mem::offset_of!(EventContext, nmi_count),
        b_telemetry_enabled = const core::mem::offset_of!(EventContext, telemetry_enabled),
        b_nested_l2_active = const core::mem::offset_of!(EventContext, nested_l2_active),
        b_nested_vmcs02_control_cache_valid = const core::mem::offset_of!(EventContext, vmcs02_control_cache_valid),
        b_root_vmx_active = const core::mem::offset_of!(EventContext, root_vmx_active),
        cpu_based_vm_exec_control = const 0x4002,
        test_primary_controls = const core::mem::offset_of!(EventContext, primary_controls),
        visual_marker_step_bytes = const MARKER_STEP * 4,
        visual_marker_row_step = const MARKER_ROW_STEP,
        visual_marker_side = const MARKER_SIDE,
        visual_hex_y = const HEX_Y,
        visual_hex_row_step = const HEX_ROW_STEP,
        visual_hex_last_row = const HEX_ROWS - 1,
        visual_hex_column_step_bytes = const HEX_COLUMN_STEP * 4,
        log_framebuffer_sink = const 2,
        log_serial_sink = const 1,
        event_ebs_seen = const core::mem::offset_of!(EventContext, exit_boot_services_seen),
        event_va_seen = const core::mem::offset_of!(EventContext, virtual_address_change_seen),
        event_control_va_error = const core::mem::offset_of!(EventContext, control_va_error),
        event_runtime_get_variable = const core::mem::offset_of!(EventContext, runtime_get_variable),
        event_runtime_set_variable = const core::mem::offset_of!(EventContext, runtime_set_variable),
        event_runtime_context = const core::mem::offset_of!(EventContext, runtime_context),
        event_control_cpu_states = const core::mem::offset_of!(EventContext, native_storage_runtime),
        control_cpu_state_size = const core::mem::size_of::<u64>(),
        control_cpu_native_storage_runtime = const 0,
        event_tsc_hz = const core::mem::offset_of!(EventContext, tsc_hz),
        event_visual_deadline = const core::mem::offset_of!(EventContext, visual_deadline),
    );

    unsafe extern "win64" {
        fn test_sample_framebuffer(context: *mut TimerContext);
        fn test_dispatch_timer(context: *mut TimerContext);
        static mut test_visual_tsc: u64;
        fn test_claim_diagnostic(context: *mut EventContext) -> u64;
        fn matrixhv_resident_ebs_callback(event: usize, context: *mut EventContext);
        fn matrixhv_resident_va_callback(event: usize, context: *mut EventContext);
        fn test_set_backend(backend: u8);
        fn test_copy_serial(buffer: *mut u8, capacity: usize) -> usize;
        fn test_emit_value(context: *const EventContext, value: u64, row: u32);
        fn test_reload_timer(context: *const TimerContext, now: u64, result: *mut [u64; 2]);
        fn test_paint_stage(context: *const EventContext, index: u32);
        fn test_paint_byte(context: *const EventContext, value: u32, first_index: u32);
        fn test_paint_hex(context: *const EventContext, value: u64, row: u32);
        fn test_msr_fault_fixup(fault_rip: u64) -> u64;
        fn test_read_fault_rip() -> u64;
        fn test_write_fault_rip() -> u64;
        fn test_xsetbv_fault_rip() -> u64;
        fn test_fault_resume_rip() -> u64;
        fn test_gp_frame(frame: *mut GpFrameTest);
        fn test_exception_frame(
            vector: u32,
            context: *mut EventContext,
            error_code: u64,
            fault_rip: u64,
        );
    }

    #[test]
    fn serial_sink_formats_shared_fields_without_writing_the_framebuffer() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
        let event_context = context(&mut pixels);
        unsafe {
            test_set_backend(1);
            test_emit_value(&event_context, 31, 1);
            test_emit_value(&event_context, 0x1234, 24);
            test_emit_value(&event_context, 0x3456, 33);
            let mut bytes = [0u8; 512];
            let length = test_copy_serial(bytes.as_mut_ptr(), bytes.len());
            assert_eq!(
                std::str::from_utf8(&bytes[..length]).unwrap(),
                " reason=0x000000000000001F rsp=0x0000000000001234 host_cr3=0x0000000000003456"
            );
            test_set_backend(2);
        }
        assert!(pixels.iter().all(|&pixel| pixel == BACKGROUND));
    }

    #[test]
    fn framebuffer_sink_renders_shared_fields_without_serial_output() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut actual = vec![BACKGROUND; WIDTH * HEIGHT];
        let mut expected = actual.clone();
        let actual_context = context(&mut actual);
        let expected_context = context(&mut expected);
        unsafe {
            test_emit_value(&actual_context, 0x1234, 19);
            test_paint_hex(&expected_context, 0x1234, 19);
            let mut bytes = [0u8; 512];
            assert_eq!(test_copy_serial(bytes.as_mut_ptr(), bytes.len()), 0);
        }
        assert_eq!(actual, expected);
        assert!(actual.iter().any(|&pixel| pixel != BACKGROUND));
    }

    #[test]
    fn valid_serial_does_not_disable_framebuffer_diagnostics() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut actual = vec![BACKGROUND; WIDTH * HEIGHT];
        let mut expected = actual.clone();
        let actual_context = context(&mut actual);
        let expected_context = context(&mut expected);
        unsafe {
            test_set_backend(3);
            test_emit_value(&actual_context, 0x1234, 19);
            let mut bytes = [0u8; 512];
            let length = test_copy_serial(bytes.as_mut_ptr(), bytes.len());
            assert_eq!(
                std::str::from_utf8(&bytes[..length]).unwrap(),
                " efer=0x0000000000001234"
            );
            test_set_backend(2);
            test_paint_hex(&expected_context, 0x1234, 19);
        }
        assert_eq!(actual, expected);
        assert!(actual.iter().any(|&pixel| pixel != BACKGROUND));
    }

    #[test]
    fn serial_mirror_does_not_draw_over_the_preboot_password_prompt() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
        let mut event_context = context(&mut pixels);
        event_context.exit_boot_services_seen = 0;
        unsafe {
            test_set_backend(3);
            test_emit_value(&event_context, 0x1234, 19);
            let mut bytes = [0u8; 512];
            let length = test_copy_serial(bytes.as_mut_ptr(), bytes.len());
            assert_eq!(
                std::str::from_utf8(&bytes[..length]).unwrap(),
                " efer=0x0000000000001234"
            );
            test_set_backend(2);
        }
        assert!(pixels.iter().all(|&pixel| pixel == BACKGROUND));
    }

    #[test]
    fn disabled_logger_suppresses_both_sinks_and_serial_mode_suppresses_painting() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
        let event_context = context(&mut pixels);
        unsafe {
            for backend in [0, 1] {
                test_set_backend(backend);
                test_paint_stage(&event_context, 4);
                test_paint_byte(&event_context, 0xff, 5);
                test_paint_hex(&event_context, u64::MAX, 0);
                if backend == 0 {
                    test_emit_value(&event_context, u64::MAX, 0);
                }
                let mut bytes = [0u8; 512];
                assert_eq!(test_copy_serial(bytes.as_mut_ptr(), bytes.len()), 0);
            }
            test_set_backend(2);
        }
        assert!(pixels.iter().all(|&pixel| pixel == BACKGROUND));
    }

    #[test]
    fn boot_timer_reload_preserves_deadline_and_clamps_hardware_ticks() {
        let _guard = TEST_LOCK.lock().unwrap();
        for (deadline_tsc, now, rate, expected) in [
            (10_000, 1_000, 3, 1_125),
            (10_000, 8_000, 3, 250),
            (10_000, 9_999, 0, 2),
            (10_000, 10_000, 0, 2),
            (10_000, 10_001, 0, 2),
            (u64::MAX, 0, 0, u64::from(u32::MAX)),
            (0x1_0000_4000, 0x1_0000_0000, 3, 0x800),
        ] {
            let context = TimerContext {
                interval_tsc: 1_000,
                rate,
                deadline_tsc,
                ..Default::default()
            };
            let mut result = [u64::MAX; 2];
            unsafe { test_reload_timer(&context, now, &mut result) };
            assert_eq!(result, [expected, 0x482e]);
            assert_eq!(context.deadline_tsc, deadline_tsc);
        }
    }

    #[test]
    fn disabled_boot_timer_does_not_access_unsupported_vmcs_field() {
        let _guard = TEST_LOCK.lock().unwrap();
        let context = TimerContext {
            interval_tsc: 0,
            rate: 0,
            deadline_tsc: 10_000,
            ..Default::default()
        };
        let mut result = [u64::MAX; 2];
        unsafe { test_reload_timer(&context, 1_000, &mut result) };
        assert_eq!(result, [u64::MAX; 2]);
    }

    #[test]
    fn boot_timer_retires_after_the_visual_deadline() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
        let mut event_context = context(&mut pixels);
        event_context.visual_deadline = 5_000;
        let mut timer = TimerContext {
            interval_tsc: 100,
            pin_controls: 1 << 6,
            cached_pin_controls: 1 << 6,
            event_context: &mut event_context,
            ..Default::default()
        };
        unsafe {
            test_visual_tsc = 4_999;
            test_dispatch_timer(&mut timer);
        }
        assert_eq!(timer.samples, 1);
        assert_eq!(timer.snapshots, 1);
        assert_eq!(timer.expired, 0);
        unsafe {
            test_visual_tsc = 5_000;
            test_dispatch_timer(&mut timer);
        }
        assert_eq!(timer.interval_tsc, 0);
        assert_eq!(timer.pin_controls & (1 << 6), 0);
        assert_eq!(timer.cached_pin_controls & (1 << 6), 0);
        assert_eq!(timer.expired, 1);
        assert_eq!(event_context.visual_base, 0);
        unsafe { test_set_backend(2) };
    }

    #[test]
    fn ordinary_exits_sample_without_a_vmx_timer_or_user_telemetry() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
        let mut event_context = context(&mut pixels);
        event_context.telemetry_enabled = 0;
        event_context.visual_deadline = 5_000;
        let mut timer = TimerContext {
            event_context: &mut event_context,
            ..Default::default()
        };
        unsafe {
            test_set_backend(2);
            test_visual_tsc = 1_000;
            test_sample_framebuffer(&mut timer);
        }
        assert_eq!(timer.samples, 1);
        assert_eq!(timer.snapshots, 1);
        assert_eq!(timer.deadline_tsc, 1_100);
        for now in [1_001, 1_050, 1_099] {
            unsafe {
                test_visual_tsc = now;
                test_sample_framebuffer(&mut timer);
            }
        }
        assert_eq!(timer.snapshots, 1);
        unsafe {
            test_visual_tsc = 1_100;
            test_sample_framebuffer(&mut timer);
        }
        assert_eq!(timer.snapshots, 2);
        assert_eq!(timer.deadline_tsc, 1_200);
        unsafe {
            test_visual_tsc = 5_000;
            test_sample_framebuffer(&mut timer);
        }
        assert_eq!(timer.expired, 1);
        assert_eq!(event_context.visual_base, 0);
        unsafe {
            test_set_backend(2);
            test_visual_tsc = 1_000;
            test_sample_framebuffer(&mut timer);
        }
        assert_eq!(timer.snapshots, 2);
    }

    #[test]
    fn ordinary_exit_sampling_respects_boot_display_and_cpu_guards() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
        let mut event_context = context(&mut pixels);
        for case in 0..8 {
            event_context.exit_boot_services_seen = u64::from(case != 0);
            event_context.diagnostic_halted = u64::from(case == 1);
            let mut timer = TimerContext {
                event_context: if case == 2 {
                    core::ptr::null_mut()
                } else {
                    &mut event_context
                },
                processor_number: u64::from(case == 3),
                nested_l2_active: u64::from(case == 4),
                interval_tsc: u64::from(case == 5),
                ..Default::default()
            };
            unsafe {
                test_set_backend(if case == 6 {
                    0
                } else if case == 7 {
                    1
                } else {
                    2
                });
                test_visual_tsc = 1_000;
                test_sample_framebuffer(&mut timer);
            }
            assert_eq!(timer.snapshots, 0, "case {case}");
            assert_eq!(timer.deadline_tsc, 0, "case {case}");
        }
        event_context.diagnostic_halted = 0;
        event_context.visual_base = 0;
        let mut timer = TimerContext {
            event_context: &mut event_context,
            ..Default::default()
        };
        unsafe {
            test_set_backend(2);
            test_sample_framebuffer(&mut timer);
        }
        assert_eq!(timer.snapshots, 0);
        assert_eq!(timer.expired, 1);
    }

    fn context(pixels: &mut [u32]) -> EventContext {
        EventContext {
            telemetry_enabled: 1,
            nmi_pending: 0,
            sync_nmi: 0,
            nmi_count: 0,
            tsc_hz: 100,
            visual_deadline: u64::MAX,
            diagnostic_halted: 0,
            exit_boot_services_seen: 1,
            virtual_address_change_seen: 0,
            control_va_error: 0,
            runtime_get_variable: 0,
            runtime_set_variable: 0,
            runtime_context: 0,
            native_storage_runtime: [0; 64],
            primary_controls: 0,
            nested_l2_active: 0,
            vmcs02_control_cache_valid: [0; 2],
            root_vmx_active: 1,
            visual_base: pixels.as_mut_ptr().wrapping_add(WIDTH * 16 + 16) as u64,
            visual_stride_bytes: (WIDTH * 4) as u64,
            host_fault_vector: 0,
            host_fault_rip: 0,
            host_fault_error_code: 0,
            host_fault_address: 0,
        }
    }

    #[test]
    fn runtime_callbacks_are_idempotent_and_preserve_framebuffer_diagnostics() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
        let mut event_context = context(&mut pixels);
        event_context.exit_boot_services_seen = 0;
        let original_base = event_context.visual_base;
        let original_stride = event_context.visual_stride_bytes;
        for _ in 0..2 {
            unsafe {
                matrixhv_resident_ebs_callback(0, &mut event_context);
                matrixhv_resident_va_callback(0, &mut event_context);
            }
            assert_eq!(event_context.exit_boot_services_seen, 1);
            assert_eq!(event_context.virtual_address_change_seen, 1);
            assert_eq!(event_context.visual_base, original_base);
            assert_eq!(event_context.visual_stride_bytes, original_stride);
            assert!(pixels.iter().all(|&pixel| pixel == BACKGROUND));
        }
        unsafe {
            test_set_backend(2);
            test_emit_value(&event_context, 0x1234, 2);
        }
        assert!(pixels.iter().any(|&pixel| pixel != BACKGROUND));
    }

    #[test]
    fn framebuffer_window_starts_at_ebs_and_expires_after_forty_seconds() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
        let mut event_context = context(&mut pixels);
        event_context.exit_boot_services_seen = 0;
        event_context.visual_deadline = 0;
        unsafe {
            test_visual_tsc = 1000;
            test_set_backend(3);
            test_paint_stage(&event_context, 1);
            test_paint_hex(&event_context, 1, 0);
        }
        assert!(pixels.iter().all(|&pixel| pixel == BACKGROUND));
        unsafe { matrixhv_resident_ebs_callback(0, &mut event_context) };
        assert_eq!(event_context.visual_deadline, 5000);
        unsafe {
            test_visual_tsc = 4999;
            matrixhv_resident_ebs_callback(0, &mut event_context);
            matrixhv_resident_va_callback(0, &mut event_context);
            test_paint_hex(&event_context, u64::MAX, 0);
        }
        assert_eq!(event_context.visual_deadline, 5000);
        assert!(pixels.iter().any(|&pixel| pixel != BACKGROUND));
        pixels.fill(BACKGROUND);
        unsafe {
            test_visual_tsc = 5000;
            test_paint_stage(&event_context, 1);
            test_paint_byte(&event_context, 0xff, 5);
            test_paint_hex(&event_context, u64::MAX, 0);
            test_emit_value(&event_context, 0x1234, 19);
            let mut bytes = [0u8; 512];
            let length = test_copy_serial(bytes.as_mut_ptr(), bytes.len());
            assert_eq!(
                std::str::from_utf8(&bytes[..length]).unwrap(),
                " efer=0x0000000000001234"
            );
        }
        assert_eq!(event_context.visual_base, 0);
        assert!(pixels.iter().all(|&pixel| pixel == BACKGROUND));
        unsafe {
            // A repeated notification or a clock rollback must not revive the aperture.
            test_visual_tsc = 1000;
            matrixhv_resident_ebs_callback(0, &mut event_context);
            test_paint_stage(&event_context, 1);
            test_set_backend(2);
        }
        assert_eq!(event_context.visual_base, 0);
        assert_eq!(event_context.visual_deadline, 5000);
        assert!(pixels.iter().all(|&pixel| pixel == BACKGROUND));
    }

    fn check_pixels(pixels: &[u32], marker_indices: &[usize]) {
        for (offset, &pixel) in pixels.iter().enumerate() {
            let x = offset % WIDTH;
            let y = offset / WIDTH;
            let marked = marker_indices.iter().any(|&index| {
                let (row, column) = if index == 29 {
                    (0, 4)
                } else if index <= 4 {
                    (0, index - 1)
                } else {
                    (1 + (index - 5) / 8, (index - 5) % 8)
                };
                let marker_x = 16 + column * MARKER_STEP;
                let marker_y = 16 + row * MARKER_ROW_STEP;
                (marker_x..marker_x + MARKER_SIDE).contains(&x)
                    && (marker_y..marker_y + MARKER_SIDE).contains(&y)
            });
            assert_eq!(
                pixel,
                if marked { u32::MAX } else { BACKGROUND },
                "pixel ({x}, {y})"
            );
        }
    }

    #[test]
    fn all_marker_positions_stay_inside_their_rectangles() {
        let _guard = TEST_LOCK.lock().unwrap();
        for index in 1..=29 {
            let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
            let event_context = context(&mut pixels);
            unsafe { test_paint_stage(&event_context, index) };
            check_pixels(&pixels, &[index as usize]);
        }
    }

    #[test]
    fn invalid_marker_indices_do_not_write_pixels() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
        let event_context = context(&mut pixels);
        for index in [0, 30, u32::MAX] {
            unsafe { test_paint_stage(&event_context, index) };
        }
        check_pixels(&pixels, &[]);
    }

    #[test]
    fn byte_rows_preserve_bit_order_and_ignore_high_bits() {
        let _guard = TEST_LOCK.lock().unwrap();
        for first_index in [5, 13] {
            let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
            let event_context = context(&mut pixels);
            unsafe { test_paint_byte(&event_context, 0xdead_bea5, first_index) };
            let expected = [0, 2, 5, 7].map(|bit| first_index as usize + bit);
            check_pixels(&pixels, &expected);
        }
    }

    #[test]
    fn missing_framebuffer_is_ignored() {
        let _guard = TEST_LOCK.lock().unwrap();
        let event_context = EventContext {
            telemetry_enabled: 1,
            nmi_pending: 0,
            sync_nmi: 0,
            nmi_count: 0,
            tsc_hz: 100,
            visual_deadline: u64::MAX,
            diagnostic_halted: 0,
            exit_boot_services_seen: 1,
            virtual_address_change_seen: 0,
            control_va_error: 0,
            runtime_get_variable: 0,
            runtime_set_variable: 0,
            runtime_context: 0,
            native_storage_runtime: [0; 64],
            primary_controls: 0,
            nested_l2_active: 0,
            vmcs02_control_cache_valid: [0; 2],
            root_vmx_active: 1,
            visual_base: 0,
            visual_stride_bytes: (WIDTH * 4) as u64,
            host_fault_vector: 0,
            host_fault_rip: 0,
            host_fault_error_code: 0,
            host_fault_address: 0,
        };
        unsafe {
            test_paint_stage(&event_context, 4);
            test_paint_byte(&event_context, 0xff, 5);
            test_paint_hex(&event_context, u64::MAX, 0);
        }
    }

    #[test]
    fn hex_rows_render_complete_values_and_clear_previous_pixels() {
        let _guard = TEST_LOCK.lock().unwrap();
        const GLYPHS: [[u8; 5]; 16] = [
            [7, 5, 5, 5, 7],
            [2, 6, 2, 2, 7],
            [7, 1, 7, 4, 7],
            [7, 1, 7, 1, 7],
            [5, 5, 7, 1, 1],
            [7, 4, 7, 1, 7],
            [7, 4, 7, 5, 7],
            [7, 1, 2, 2, 2],
            [7, 5, 7, 5, 7],
            [7, 5, 7, 1, 7],
            [7, 5, 7, 5, 5],
            [6, 5, 6, 5, 6],
            [7, 4, 4, 4, 7],
            [6, 5, 5, 5, 6],
            [7, 4, 7, 4, 7],
            [7, 4, 7, 4, 4],
        ];
        for row in 0..HEX_ROWS {
            for value in [0, u64::MAX, 0x0123_4567_89ab_cdef] {
                let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
                let event_context = context(&mut pixels);
                unsafe {
                    test_paint_hex(&event_context, u64::MAX, row as u32);
                    test_paint_hex(&event_context, value, row as u32);
                }
                let text = format!("{:X} {value:016X}", row % 16);
                let first_x = 16 + row / 16 * HEX_COLUMN_STEP;
                let first_y = 16 + HEX_Y + row % 16 * HEX_ROW_STEP;
                for (offset, &pixel) in pixels.iter().enumerate() {
                    let x = offset % WIDTH;
                    let y = offset / WIDTH;
                    let expected = if (first_x..first_x + 18 * 8).contains(&x)
                        && (first_y..first_y + 10).contains(&y)
                    {
                        let cell = (x - first_x) / 8;
                        let glyph_x = (x - first_x) % 8;
                        let character = text.as_bytes()[cell] as char;
                        let lit = character.to_digit(16).is_some_and(|digit| {
                            glyph_x < 6
                                && GLYPHS[digit as usize][(y - first_y) / 2]
                                    & (1 << (2 - glyph_x / 2))
                                    != 0
                        });
                        if lit { u32::MAX } else { 0 }
                    } else {
                        BACKGROUND
                    };
                    assert_eq!(
                        pixel, expected,
                        "row {row}, value {value:X}, pixel ({x}, {y})"
                    );
                }
            }
        }
    }

    #[test]
    fn invalid_hex_rows_do_not_write_pixels() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
        let event_context = context(&mut pixels);
        for row in [HEX_ROWS as u32, u32::MAX] {
            unsafe { test_paint_hex(&event_context, u64::MAX, row) };
        }
        check_pixels(&pixels, &[]);
    }

    #[test]
    fn msr_fault_recovery_matches_only_guarded_instruction_addresses() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            let read_rip = test_read_fault_rip();
            let write_rip = test_write_fault_rip();
            let resume_rip = test_fault_resume_rip();
            assert_ne!(read_rip, write_rip);
            assert_ne!(resume_rip, 0);
            for fault_rip in [read_rip, write_rip, test_xsetbv_fault_rip()] {
                assert_eq!(test_msr_fault_fixup(fault_rip), resume_rip);
            }
            for fault_rip in [0, u64::MAX, read_rip + 1, write_rip + 1, resume_rip] {
                assert_eq!(test_msr_fault_fixup(fault_rip), 0);
            }
        }
    }

    #[test]
    fn gp_frame_recovery_preserves_registers_and_removes_only_the_error_code() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            let resume_rip = test_fault_resume_rip();
            for fault_rip in [
                test_read_fault_rip(),
                test_write_fault_rip(),
                test_xsetbv_fault_rip(),
                resume_rip,
            ] {
                let mut frame = GpFrameTest {
                    fault_rip,
                    error_code: 0,
                    input_rax: 0x1122_3344_5566_7788,
                    input_rdx: 0x8899_aabb_ccdd_eeff,
                    ..GpFrameTest::default()
                };
                test_gp_frame(&mut frame);
                let unhandled = fault_rip == resume_rip;
                assert_eq!(frame.unhandled, u64::from(unhandled));
                assert_eq!(
                    frame.recovered_rip,
                    if unhandled { fault_rip } else { resume_rip }
                );
                assert_eq!(frame.recovered_rax, frame.input_rax);
                assert_eq!(frame.recovered_rdx, frame.input_rdx);
            }
        }
    }

    #[test]
    fn every_exception_stub_preserves_vector_error_code_and_fault_rip() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
        let mut event_context = context(&mut pixels);
        for vector in 0..32 {
            event_context.diagnostic_halted = 0;
            if vector == 2 {
                event_context.nested_l2_active = 1;
                event_context.vmcs02_control_cache_valid = [1, 1];
            }
            let has_error_code = [8, 10, 11, 12, 13, 14, 17, 21, 29, 30].contains(&vector);
            let fault_rip = 0x1234_5678_90ab_cdef;
            unsafe { test_exception_frame(vector, &mut event_context, 0x55, fault_rip) };
            if vector == 2 {
                assert_eq!(event_context.nmi_pending, 1);
                assert_eq!(event_context.nmi_count, 1);
                assert_ne!(event_context.primary_controls & (1 << 22), 0);
                assert_eq!(event_context.vmcs02_control_cache_valid, [0, 0]);
                assert_eq!(event_context.diagnostic_halted, 0);
                continue;
            }
            assert_eq!(event_context.host_fault_vector, u64::from(vector));
            assert_eq!(event_context.host_fault_rip, fault_rip);
            assert_eq!(
                event_context.host_fault_error_code,
                if has_error_code { 0x55 } else { 0 }
            );
            assert_eq!(
                event_context.host_fault_address,
                if vector == 14 { 0x1234_5678 } else { 0 }
            );
        }
    }

    #[test]
    fn later_cpu_faults_cannot_overwrite_the_first_diagnostic() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut pixels = vec![BACKGROUND; WIDTH * HEIGHT];
        let mut event_context = context(&mut pixels);
        unsafe {
            test_exception_frame(14, &mut event_context, 0x55, 0x1234);
            test_exception_frame(6, &mut event_context, 0, 0x5678);
            assert_eq!(test_claim_diagnostic(&mut event_context), 0);
        }
        assert_eq!(event_context.diagnostic_halted, 1);
        assert_eq!(event_context.host_fault_vector, 14);
        assert_eq!(event_context.host_fault_error_code, 0x55);
        assert_eq!(event_context.host_fault_rip, 0x1234);
        assert_eq!(event_context.host_fault_address, 0x1234_5678);
    }
}
