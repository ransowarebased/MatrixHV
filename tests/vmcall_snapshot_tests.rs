use std::sync::Mutex;

core::arch::global_asm!(include_str!("../builds/vmcall-snapshot-tests/snapshot.S"));

static SNAPSHOT_LOCK: Mutex<()> = Mutex::new(());

#[repr(C)]
struct Context {
    processor_id: u64,
    telemetry_active: u64,
    exit_reason: u64,
    timing: u64,
    evmcs: u64,
    failed_field: u64,
    vmcs: [u64; 10],
}

impl Context {
    fn new(processor_id: u64) -> Self {
        Self {
            processor_id,
            telemetry_active: 1,
            exit_reason: 18,
            timing: 0,
            evmcs: 0,
            failed_field: u64::MAX,
            vmcs: [0x106fcda, 0x1234000, 0x5678000, 0x202, 0x80000001,
                0x40000, 0xd01, 0xfb, 3, 0x80000306],
        }
    }
}

unsafe extern "win64" {
    fn test_capture_vmcall(context: *const Context, frame: *mut u64, complete: u64) -> *const u64;
    fn test_complete_vmcall(context: *const Context, result: u64);
    fn test_query_vmcall(context: *const Context, subleaf: u32, result: *mut u64);
}

fn frame() -> [u64; 15] {
    core::array::from_fn(|index| 0x1234_0000_0000_0000 | index as u64)
}

#[test]
fn capture_retains_every_guest_register_and_the_injected_exception() {
    let _guard = SNAPSHOT_LOCK.lock().unwrap();
    let context = Context::new(0);
    let mut registers = frame();
    let before = registers;
    let pointer = unsafe { test_capture_vmcall(&context, registers.as_mut_ptr(), 1) };
    let record = unsafe { core::slice::from_raw_parts(pointer, 32) };
    assert_eq!(registers, before);
    assert_eq!(record[0] & 1, 0);
    assert_ne!(record[0], 0);
    assert_ne!(record[1], 0);
    assert_eq!(&record[2..11], &context.vmcs[..9]);
    assert_eq!(record[11], 0x80000306);
    assert_eq!(record[12], context.vmcs[0]);
    assert_eq!(record[13], registers[0]);
    assert_eq!(record[14], 0);
    assert_eq!(record[15], 0);
    assert_eq!(&record[16..31], &registers);
    assert_eq!(record[31], 0);
    for pair in 0..16 {
        let mut result = [0; 2];
        unsafe { test_query_vmcall(&context, 0x620 + pair, result.as_mut_ptr()) };
        assert_eq!(&result, &record[pair as usize * 2..pair as usize * 2 + 2]);
    }
}

#[test]
fn disabled_capture_and_unrelated_exits_preserve_the_published_record() {
    let _guard = SNAPSHOT_LOCK.lock().unwrap();
    let mut context = Context::new(1);
    let mut registers = frame();
    let pointer = unsafe { test_capture_vmcall(&context, registers.as_mut_ptr(), 1) };
    let before = unsafe { *(pointer as *const [u64; 32]) };
    context.telemetry_active = 0;
    registers[0] = 0;
    unsafe { test_capture_vmcall(&context, registers.as_mut_ptr(), 1) };
    assert_eq!(unsafe { *(pointer as *const [u64; 32]) }, before);
    context.exit_reason = 10;
    unsafe { test_complete_vmcall(&context, 0) };
    assert_eq!(unsafe { *(pointer as *const [u64; 32]) }, before);
}

#[test]
fn in_progress_snapshots_are_odd_and_publish_completion_without_losing_inputs() {
    let _guard = SNAPSHOT_LOCK.lock().unwrap();
    let mut context = Context::new(2);
    context.timing = 1;
    context.evmcs = 1;
    let mut registers = frame();
    let pointer = unsafe { test_capture_vmcall(&context, registers.as_mut_ptr(), 0) };
    let before = unsafe { *(pointer as *const [u64; 32]) };
    assert_eq!(before[0] & 1, 1);
    assert_eq!(before[15], 3);
    context.vmcs[0] += 3;
    context.vmcs[9] = 0;
    unsafe { test_complete_vmcall(&context, 0xabc) };
    let after = unsafe { *(pointer as *const [u64; 32]) };
    assert_eq!(after[0], before[0] + 1);
    assert_eq!(after[11], 0);
    assert_eq!(after[12], context.vmcs[0]);
    assert_eq!(after[13], 0xabc);
    assert_eq!(&after[16..31], &registers);
}

#[test]
fn vmread_failures_are_reported_without_changing_the_guest_frame() {
    let _guard = SNAPSHOT_LOCK.lock().unwrap();
    let mut context = Context::new(63);
    context.failed_field = 2;
    let mut registers = frame();
    let before = registers;
    let pointer = unsafe { test_capture_vmcall(&context, registers.as_mut_ptr(), 1) };
    let record = unsafe { core::slice::from_raw_parts(pointer, 32) };
    assert_eq!(registers, before);
    assert_eq!(record[4], u64::MAX);
    assert_eq!(record[14], 1);
    assert_eq!(record[0] & 1, 0);
    assert_eq!(record[31], 63);
}

#[test]
fn invalid_processor_slots_cannot_read_or_write_snapshot_storage() {
    let _guard = SNAPSHOT_LOCK.lock().unwrap();
    for processor_id in [64, u64::MAX] {
        let context = Context::new(processor_id);
        let mut registers = frame();
        assert!(unsafe { test_capture_vmcall(&context, registers.as_mut_ptr(), 1) }.is_null());
        let mut result = [u64::MAX; 2];
        unsafe { test_query_vmcall(&context, 0x620, result.as_mut_ptr()) };
        assert_eq!(result, [0; 2]);
    }
}
