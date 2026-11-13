core::arch::global_asm!(include_str!("../builds/root-history-tests/record.S"));

unsafe extern "C" {
    fn test_record_root(event: *mut u64, root: u64);
}

fn record(event: &mut [u64; 18], root: u64) {
    unsafe { test_record_root(event.as_mut_ptr(), root) };
}

#[test]
fn repeated_roots_and_pcids_do_not_evict_other_roots() {
    let mut event = [0; 18];
    for _ in 0..100 {
        record(&mut event, 0x1007);
        record(&mut event, 0x2009);
        record(&mut event, 0x100a);
        record(&mut event, 0x200b);
    }
    assert_eq!(event[0], 0x200b);
    assert_eq!(event[1], 2);
    assert_eq!(&event[2..4], &[0x1007, 0x2009]);
    assert!(event[4..].iter().all(|root| *root == 0));
}

#[test]
fn new_distinct_roots_replace_old_entries_after_capacity_is_reached() {
    let mut event = [0; 18];
    for root in 1..=16 {
        record(&mut event, root * 4096);
    }
    assert_eq!(event[1], 16);
    record(&mut event, 17 * 4096);
    assert_eq!(event[1], 17);
    assert_eq!(event[2], 17 * 4096);
    assert_eq!(event[3], 2 * 4096);
}

#[test]
fn high_control_bits_are_not_discarded_from_an_observed_root() {
    let mut event = [0; 18];
    record(&mut event, (1u64 << 62) | 0x1000);
    record(&mut event, 0x1000);
    assert_eq!(event[1], 2);
    assert_eq!(event[2], (1u64 << 62) | 0x1000);
    assert_eq!(event[3], 0x1000);
}
