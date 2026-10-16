use core::arch::global_asm;

global_asm!(include_str!("../builds/cet-state-tests/handlers.S"));

#[repr(C)]
struct CetContext {
    selected: *mut [u64; 12],
    native_value: u64,
    native_reads: u64,
}

unsafe extern "C" {
    fn test_cet_select(context: *mut CetContext, destination: *const *mut [u64; 12]);
    fn test_cet_saved_msr(context: *mut CetContext, index: u32) -> u64;
}

#[test]
fn nested_entries_and_exits_preserve_the_live_cet_triple() {
    let mut l1 = [0u64; 12];
    let mut l2 = [0u64; 12];
    l1[..4].copy_from_slice(&[1 << 20, 1, 0xffff_9000_0000_1000, 0xffff_9000_0000_2000]);
    l2[0] = 1 << 20;
    let l1_pointer = &mut l1 as *mut _;
    let l2_pointer = &mut l2 as *mut _;
    let mut context = CetContext {
        selected: l1_pointer,
        native_value: 0,
        native_reads: 0,
    };
    unsafe { test_cet_select(&mut context, &l2_pointer) };
    assert_eq!(context.selected, l2_pointer);
    assert_eq!(&l2[1..4], &l1[1..4]);
    l2[1..4].copy_from_slice(&[5, 0x0000_7fff_0000_1000, 0xffff_a000_0000_2000]);
    unsafe { test_cet_select(&mut context, &l1_pointer) };
    assert_eq!(context.selected, l1_pointer);
    assert_eq!(&l1[1..4], &l2[1..4]);
    assert_eq!(context.native_reads, 0);
}

#[test]
fn repeated_nested_entry_inherits_the_latest_l1_state() {
    let mut l1 = [0u64; 12];
    let mut l2 = [0u64; 12];
    l1[0] = 1 << 20;
    l2[0] = 1 << 20;
    let l1_pointer = &mut l1 as *mut _;
    let l2_pointer = &mut l2 as *mut _;
    let mut context = CetContext {
        selected: l1_pointer,
        native_value: 0,
        native_reads: 0,
    };
    unsafe { test_cet_select(&mut context, &l2_pointer) };
    context.selected = l1_pointer;
    l1[1..4].copy_from_slice(&[3, 0xffff_b000_0000_1000, 0xffff_b000_0000_2000]);
    unsafe { test_cet_select(&mut context, &l2_pointer) };
    assert_eq!(&l2[1..4], &l1[1..4]);
}

#[test]
fn disabled_cet_load_controls_do_not_touch_destination_fields() {
    let mut source = [0; 12];
    let mut destination = [0xfeedu64; 12];
    let destination_pointer = &mut destination as *mut _;
    let mut context = CetContext {
        selected: &mut source,
        native_value: 0,
        native_reads: 0,
    };
    unsafe { test_cet_select(&mut context, &destination_pointer) };
    assert_eq!(context.selected, destination_pointer);
    assert_eq!(destination, [0xfeed; 12]);
}

#[test]
fn nested_cet_msr_stores_read_saved_guest_values() {
    let mut bank = [0; 12];
    bank[..4].copy_from_slice(&[1 << 20, 5, 0x1234_5678, 0xffff_c000_0000_2000]);
    let mut context = CetContext {
        selected: &mut bank,
        native_value: 0,
        native_reads: 0,
    };
    assert_eq!(unsafe { test_cet_saved_msr(&mut context, 0x6a2) }, bank[1]);
    assert_eq!(unsafe { test_cet_saved_msr(&mut context, 0x6a8) }, bank[3]);
    assert_eq!(context.native_reads, 0);
}

#[test]
fn unswitched_cet_and_user_state_keep_native_msr_reads() {
    let mut bank = [0; 12];
    let mut context = CetContext {
        selected: &mut bank,
        native_value: 0xffff_d000_0000_4000,
        native_reads: 0,
    };
    for index in [0x6a0, 0x6a2, 0x6a4, 0x6a5, 0x6a6, 0x6a7, 0x6a8] {
        assert_eq!(
            unsafe { test_cet_saved_msr(&mut context, index) },
            context.native_value
        );
    }
    assert_eq!(context.native_reads, 7);
}
