use std::mem::offset_of;

core::arch::global_asm!(include_str!("../builds/flight-recorder-tests/recorder.S"));

unsafe extern "win64" {
    fn test_record_exit(context: *mut Context, flags: u64, guest_rcx: u64) -> u64;
    fn test_record_failure(context: *mut Context, flags: u64) -> u64;
}

#[repr(C)]
struct Context {
    sequence: u64,
    frozen: u64,
    reason: u64,
    rip: u64,
    qualification: u64,
    processor: u64,
    nested_active: u64,
    l2_active: u64,
    current_vmcs: u64,
    gpa: u64,
    instruction_error: u64,
    vmread_failure: u64,
    telemetry_active: u64,
    records: [[u64; 10]; 2048],
}

fn context() -> Box<Context> {
    assert_eq!(offset_of!(Context, records), 104);
    let mut value = Box::<Context>::new_uninit();
    unsafe {
        value.as_mut_ptr().write_bytes(0, 1);
        let mut value = value.assume_init();
        value.processor = 7;
        value.rip = 0xffff_f800_1234_5678;
        value.qualification = 0x123;
        value.gpa = 0xdead_beef_000;
        value.current_vmcs = 0x1234_000;
        value.instruction_error = 7;
        value.telemetry_active = 1;
        value
    }
}

#[test]
fn disabled_collection_skips_timestamp_and_record_publication() {
    let mut value = context();
    value.telemetry_active = 0;
    let flags = unsafe { test_record_exit(&mut *value, 0x243, 0) };
    assert_eq!(flags & 0x243, 0x243);
    assert_eq!(value.sequence, 0);
    assert!(value.records.iter().flatten().all(|word| *word == 0));
    unsafe { test_record_failure(&mut *value, 0x242) };
    assert_eq!(value.sequence, 1);
}

#[test]
fn wraps_at_capacity_and_overwrites_only_the_oldest_slot() {
    let mut value = context();
    value.reason = 10;
    for sequence in 1..=2051 {
        unsafe { test_record_exit(&mut *value, 0x202, 0) };
        assert_eq!(value.sequence, sequence);
    }
    let mut sequences: Vec<_> = value.records.iter().map(|entry| entry[0]).collect();
    sequences.sort_unstable();
    assert_eq!(sequences, (4..=2051).collect::<Vec<_>>());
    let entry = value.records[2];
    assert_eq!(entry[0], 2051);
    assert_ne!(entry[1], 0);
    assert_eq!(entry[2..9], [10, value.rip, 0x123, 0, 7, 0, value.current_vmcs]);
    assert_eq!(entry[9], 0);
}

#[test]
fn frozen_recorder_preserves_both_records_and_publication_sequence() {
    let mut value = context();
    unsafe { test_record_exit(&mut *value, 0x202, 0) };
    let before = value.records;
    value.frozen = 1;
    unsafe { test_record_failure(&mut *value, 0x242) };
    assert_eq!(value.sequence, 1);
    assert_eq!(value.records, before);
}

#[test]
fn records_ept_addresses_without_reusing_them_for_other_exits() {
    let mut value = context();
    for reason in [48, 49, 10] {
        value.reason = reason;
        unsafe { test_record_exit(&mut *value, 0x202, 0) };
    }
    assert_eq!(value.records[0][5], value.gpa);
    assert_eq!(value.records[1][5], value.gpa);
    assert_eq!(value.records[2][5], 0);
    value.vmread_failure = 1;
    value.reason = 48;
    unsafe { test_record_exit(&mut *value, 0x202, 0) };
    assert_eq!(value.records[3][5], 0);
}

#[test]
fn entry_failures_distinguish_valid_error_from_stale_vmfailinvalid_error() {
    let mut value = context();
    value.nested_active = 1;
    value.l2_active = 1;
    unsafe { test_record_failure(&mut *value, 0x242) };
    assert_eq!(value.records[0][7], (1 << 32) | 3);
    assert_eq!(value.records[0][9], 7);
    unsafe { test_record_failure(&mut *value, 0x203) };
    assert_eq!(value.records[1][9], u64::MAX);
    value.vmread_failure = 1;
    unsafe { test_record_failure(&mut *value, 0x242) };
    assert_eq!(value.records[2][9], u64::MAX);
}

#[test]
fn vmx_status_flags_survive_recording_and_frozen_fast_path() {
    let mut value = context();
    for flags in [0x202, 0x203, 0x242] {
        let observed = unsafe { test_record_failure(&mut *value, flags) };
        assert_eq!(observed & 0x41, flags & 0x41);
        value.frozen = 1;
        let observed = unsafe { test_record_exit(&mut *value, flags, 0) };
        assert_eq!(observed & 0x41, flags & 0x41);
        value.frozen = 0;
    }
}

#[test]
fn msr_details_come_from_the_saved_guest_frame_and_preserve_only_the_index() {
    let mut value = context();
    for reason in [31, 32, 10] {
        value.reason = reason;
        unsafe { test_record_exit(&mut *value, 0x202, 0x1234_5678_4000_0020) };
    }
    assert_eq!(value.records[0][9], 0x4000_0020);
    assert_eq!(value.records[1][9], 0x4000_0020);
    assert_eq!(value.records[2][9], 0);
    assert_ne!(value.records[0][7] & (1 << 33), 0);
    assert_ne!(value.records[1][7] & (1 << 33), 0);
    assert_eq!(value.records[2][7] & (1 << 33), 0);
}
