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
    let status = unsafe { test_control_off(scenario.shared.as_mut_ptr(), &mut scenario.model, 2) };
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
