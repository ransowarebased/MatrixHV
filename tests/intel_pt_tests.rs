include!("../builds/intel-pt-tests/definitions.rs");
core::arch::global_asm!(include_str!("../builds/intel-pt-tests/pt.S"));

#[repr(C)]
#[derive(Default)]
struct Context {
    trace: TraceState,
    reason: u64,
    host_misc: u64,
}

#[repr(C)]
struct Model {
    msrs: [u64; 4],
    reads: u64,
    writes: u64,
    fail_read: u64,
    fail_write: u64,
    ebs: u64,
    flush_bytes: u64,
    flush_status: u64,
    operation: u64,
    result: [u32; 4],
    cpuid_max: u64,
    cpuid_leaf7_ebx: u64,
    cpuid_pt_ecx: u64,
}

impl Default for Model {
    fn default() -> Self {
        Self {
            msrs: [0x100, 0x20, 0x9000, 0x7f],
            reads: 0,
            writes: 0,
            fail_read: 0,
            fail_write: 0,
            ebs: 1,
            flush_bytes: 320,
            flush_status: 0,
            operation: 0,
            result: [0; 4],
            cpuid_max: 0x1b,
            cpuid_leaf7_ebx: 0xf2bf67eb,
            cpuid_pt_ecx: 7,
        }
    }
}

unsafe extern "win64" {
    fn test_enter(context: &mut Context, model: &mut Model, flags: u64, guest_rax: u64) -> u64;
    fn test_leave(context: &mut Context, model: &mut Model, flags: u64, guest_rax: u64) -> u64;
    fn test_code_base() -> u64;
    fn test_request(context: &mut Context, model: &mut Model);
}

fn context() -> Context {
    Context {
        trace: TraceState {
            code_base: unsafe { test_code_base() },
            support: 1,
            armed: 1,
            table: 0x1000,
            buffer: 0x10000,
            output_pointer: 0x7f,
            ..Default::default()
        },
        reason: 10,
        host_misc: 0x7004c1e7,
    }
}

#[test]
fn support_requires_pt_topa_and_vmx_tracing() {
    assert!(supported(0x14, 1 << 25, 1, 1 << 14));
    assert!(supported(0x1b, 0xf2bf67eb, 7, 0x7004c1e7));
    for values in [
        (0x13, 1 << 25, 1, 1 << 14),
        (0x14, 0, 1, 1 << 14),
        (0x14, 1 << 26, 1, 1 << 14),
        (0x14, 1 << 25, 0, 1 << 14),
        (0x14, 1 << 25, 1, 0),
    ] {
        assert!(!supported(values.0, values.1, values.2, values.3));
    }
}

#[test]
fn runtime_query_rechecks_unsupported_capabilities_without_msr_access() {
    for (host_misc, max_leaf, features, topa, expected) in [
        (0x7004c1e7, 0x1b, 0xf2bf67eb, 7, 1),
        (0x7004c1e7, 0x1b, 1 << 26, 7, 2),
        (0x7004c1e7, 0x1b, 0xf2bf67eb, 0, 2),
        (0x700481e7, 0x1b, 0xf2bf67eb, 7, 2),
        (0x7004c1e7, 0x13, 0xf2bf67eb, 7, 2),
    ] {
        let mut context = context();
        context.trace.support = 2;
        context.trace.armed = 0;
        context.host_misc = host_misc;
        let mut model = Model {
            cpuid_max: max_leaf,
            cpuid_leaf7_ebx: features,
            cpuid_pt_ecx: topa,
            ..Default::default()
        };
        unsafe { test_request(&mut context, &mut model) };
        assert_eq!(model.result, [expected, 0, 0, 0]);
        assert_eq!((model.reads, model.writes), (0, 0));
    }
}

#[test]
fn disabled_and_diagnostic_exits_never_access_msrs_and_preserve_flags() {
    let mut context = context();
    let mut model = Model::default();
    context.trace.armed = 0;
    for flags in [0x202, 0x203, 0x242] {
        assert_eq!(
            unsafe { test_enter(&mut context, &mut model, flags, 0) } & 0x41,
            flags & 0x41
        );
        assert_eq!(
            unsafe { test_leave(&mut context, &mut model, flags, 0) } & 0x41,
            flags & 0x41
        );
    }
    context.trace.armed = 1;
    unsafe { test_enter(&mut context, &mut model, 0x202, 0x4d485652) };
    assert_eq!((model.reads, model.writes), (0, 0));
}

#[test]
fn intervals_flush_packets_and_restore_every_borrowed_msr() {
    let mut context = context();
    let mut model = Model::default();
    let original = model.msrs;
    unsafe { test_enter(&mut context, &mut model, 0x243, 0) };
    assert_eq!(model.msrs, [0x2105, 0, 0x1000, 0x7f]);
    assert_eq!(context.trace.owned, 1);
    assert_eq!(
        unsafe { test_leave(&mut context, &mut model, 0x243, 0) } & 0x41,
        0x41
    );
    assert_eq!(model.msrs, original);
    assert_eq!(context.trace.bytes, 320);
    assert_eq!(context.trace.owned, 0);
    unsafe { test_enter(&mut context, &mut model, 0x202, 0) };
    assert_eq!(model.msrs[3] >> 32, 320);
    unsafe { test_leave(&mut context, &mut model, 0x202, 0) };
}

#[test]
fn full_or_errored_buffers_disarm_without_overwriting_saved_state() {
    for status in [0x20, 0x10] {
        let mut context = context();
        let mut model = Model {
            flush_bytes: 65536,
            flush_status: status,
            ..Default::default()
        };
        let original = model.msrs;
        unsafe {
            test_enter(&mut context, &mut model, 0x202, 0);
            test_leave(&mut context, &mut model, 0x202, 0);
        }
        assert_eq!(context.trace.armed, 0);
        assert_eq!(context.trace.bytes, 65536);
        assert_eq!(context.trace.status, status);
        assert_eq!(model.msrs, original);
    }
}

#[test]
fn active_external_engine_is_never_reprogrammed() {
    let mut context = context();
    let mut model = Model::default();
    model.msrs[0] |= 1;
    let original = model.msrs;
    unsafe { test_enter(&mut context, &mut model, 0x202, 0) };
    assert_eq!(model.msrs, original);
    assert_eq!(model.writes, 0);
    assert_eq!((context.trace.support, context.trace.armed), (3, 0));
}

#[test]
fn read_and_partial_setup_faults_fail_closed() {
    for (fail_read, fail_write) in [(0x571, 0), (0, 0x560)] {
        let mut context = context();
        let mut model = Model {
            fail_read,
            fail_write,
            ..Default::default()
        };
        let original = model.msrs;
        unsafe { test_enter(&mut context, &mut model, 0x202, 0) };
        assert_eq!(model.msrs, original);
        assert_eq!(
            (
                context.trace.support,
                context.trace.armed,
                context.trace.owned
            ),
            (4, 0, 0)
        );
    }
}

#[test]
fn corrupt_output_offset_cannot_escape_the_reserved_buffer() {
    let mut context = context();
    let mut model = Model {
        flush_bytes: 65537,
        ..Default::default()
    };
    unsafe {
        test_enter(&mut context, &mut model, 0x202, 0);
        test_leave(&mut context, &mut model, 0x202, 0);
    }
    assert_eq!(
        (
            context.trace.support,
            context.trace.armed,
            context.trace.bytes
        ),
        (4, 0, 0)
    );
}

#[test]
fn changed_resident_image_disarms_before_any_msr_access() {
    let mut context = context();
    let mut model = Model::default();
    context.trace.code_base += 4096;
    unsafe { test_enter(&mut context, &mut model, 0x202, 0) };
    assert_eq!(context.trace.armed, 0);
    assert_eq!((model.reads, model.writes), (0, 0));
}

#[test]
fn snapshot_read_fault_restores_the_external_state() {
    let mut context = context();
    let mut model = Model::default();
    let original = model.msrs;
    unsafe { test_enter(&mut context, &mut model, 0x202, 0) };
    model.fail_read = 0x571;
    unsafe { test_leave(&mut context, &mut model, 0x202, 0) };
    assert_eq!(model.msrs, original);
    assert_eq!((context.trace.support, context.trace.armed, context.trace.owned), (4, 0, 0));
}

#[test]
fn start_requires_runtime_and_stopped_export_is_bounded() {
    let mut context = context();
    let mut buffer = vec![0x5a_u8; 65536];
    context.trace.buffer = buffer.as_mut_ptr() as u64;
    context.trace.armed = 0;
    let mut model = Model {
        operation: 1,
        ebs: 0,
        ..Default::default()
    };
    unsafe { test_request(&mut context, &mut model) };
    assert_eq!(context.trace.armed, 0);
    model.ebs = 1;
    unsafe { test_request(&mut context, &mut model) };
    assert_eq!(context.trace.armed, 1);
    assert_eq!(context.trace.generation, 1);
    unsafe { test_request(&mut context, &mut model) };
    assert_eq!(context.trace.generation, 1);
    assert!(buffer.iter().all(|byte| *byte == 0));
    buffer[..16].fill(0x5a);
    context.trace.bytes = 16;
    model.operation = 0x1000;
    unsafe { test_request(&mut context, &mut model) };
    assert_eq!(model.result, [0; 4]);
    model.operation = 2;
    unsafe { test_request(&mut context, &mut model) };
    model.operation = 0x1000;
    unsafe { test_request(&mut context, &mut model) };
    assert_eq!(model.result, [0x5a5a5a5a; 4]);
    model.operation = 0x1001;
    unsafe { test_request(&mut context, &mut model) };
    assert_eq!(model.result, [0; 4]);
}
