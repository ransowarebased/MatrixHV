core::arch::global_asm!(include_str!("../builds/debugctl-tests/debugctl.S"));

#[repr(C)]
struct DebugctlModel {
    native_value: u64,
    guest_value: u64,
    supported_bits: u64,
    reads: u64,
    writes: u64,
    unsafe_branch_store_enables: u64,
    vmcs_writes: u64,
    rip_advances: u64,
    fail_write: u64,
    reserved: u64,
    write_values: [u64; 4],
    fail_read: u64,
    fatal_count: u64,
}

impl Default for DebugctlModel {
    fn default() -> Self {
        Self {
            native_value: 3,
            guest_value: 0x1234,
            supported_bits: 0xffc3 | (1 << 48),
            reads: 0,
            writes: 0,
            unsafe_branch_store_enables: 0,
            vmcs_writes: 0,
            rip_advances: 0,
            fail_write: 0,
            reserved: 0,
            write_values: [0; 4],
            fail_read: 0,
            fatal_count: 0,
        }
    }
}

unsafe extern "win64" {
    fn test_debugctl_write(model: &mut DebugctlModel, value: u64) -> u32;
}

#[test]
fn branch_trace_store_never_uses_the_guest_ds_area_in_root() {
    for value in [0xc0, 0, 3, 0x40, 0x80, 0xffc3, (1 << 48) | 0xc3] {
        let mut model = DebugctlModel::default();
        let original = model.native_value;
        assert_eq!(unsafe { test_debugctl_write(&mut model, value) }, 1);
        assert_eq!(model.native_value, original);
        assert_eq!(model.guest_value, value);
        assert_eq!(model.unsafe_branch_store_enables, 0);
        assert_eq!((model.vmcs_writes, model.rip_advances), (1, 1));
        assert_eq!(model.write_values[0], value & !0x40);
        if value & 0x40 != 0 {
            assert_eq!(model.write_values[1], value & !0x80);
        }
        assert_eq!(model.write_values[model.writes as usize - 1], original);
    }
}

#[test]
fn hardware_rejects_reserved_bits_before_the_vmcs_or_guest_rip_changes() {
    for reserved_bit in [2, 5, 16, 32, 63] {
        let mut model = DebugctlModel::default();
        let original = model.native_value;
        assert_eq!(unsafe { test_debugctl_write(&mut model, 0xc0 | 1 << reserved_bit) }, 0);
        assert_eq!(model.native_value, original);
        assert_eq!(model.guest_value, 0x1234);
        assert_eq!(model.unsafe_branch_store_enables, 0);
        assert_eq!((model.vmcs_writes, model.rip_advances), (0, 0));
    }
}

#[test]
fn unsupported_trace_enable_restores_root_state_after_the_first_probe() {
    let mut model = DebugctlModel::default();
    model.supported_bits &= !0x40;
    let original = model.native_value;
    assert_eq!(unsafe { test_debugctl_write(&mut model, 0xc3) }, 0);
    assert_eq!(model.native_value, original);
    assert_eq!(model.guest_value, 0x1234);
    assert_eq!(model.writes, 3);
    assert_eq!(model.write_values[0], 0x83);
    assert_eq!(model.write_values[2], original);
    assert_eq!(model.unsafe_branch_store_enables, 0);
    assert_eq!((model.vmcs_writes, model.rip_advances), (0, 0));
}

#[test]
fn guarded_faults_preserve_the_guest_state_and_restore_after_partial_validation() {
    for fail_write in [1, 2] {
        let mut model = DebugctlModel { fail_write, ..Default::default() };
        let original = model.native_value;
        assert_eq!(unsafe { test_debugctl_write(&mut model, 0xc3) }, 0);
        assert_eq!(model.native_value, original);
        assert_eq!(model.guest_value, 0x1234);
        assert_eq!(model.unsafe_branch_store_enables, 0);
        assert_eq!((model.vmcs_writes, model.rip_advances, model.fatal_count), (0, 0, 0));
    }
    let mut model = DebugctlModel { fail_read: 1, ..Default::default() };
    assert_eq!(unsafe { test_debugctl_write(&mut model, 0xc3) }, 0);
    assert_eq!((model.writes, model.vmcs_writes, model.rip_advances), (0, 0, 0));
}

#[test]
fn failed_root_state_restore_stops_before_guest_entry() {
    let mut model = DebugctlModel { fail_write: 3, ..Default::default() };
    assert_eq!(unsafe { test_debugctl_write(&mut model, 0xc3) }, 3);
    assert_eq!((model.vmcs_writes, model.rip_advances, model.fatal_count), (0, 0, 1));
    assert_eq!(model.unsafe_branch_store_enables, 0);
}
