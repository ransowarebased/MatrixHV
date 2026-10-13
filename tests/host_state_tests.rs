include!("../builds/host-state-tests/definitions.rs");

fn firmware_segments(cs: u16) -> arch::SegmentationState {
    arch::SegmentationState {
        cs: arch::SegmentState { selector: cs },
        ..Default::default()
    }
}

#[test]
fn inherited_code_selectors_reject_both_reserved_tss_slots() {
    for selector in [HOST_TSS_SELECTOR, HOST_TSS_SELECTOR + 8] {
        assert!(matches!(
            ResidentHostSelectors::inherited(firmware_segments(selector)),
            Err(HostTablesError::InvalidCodeLayout)
        ));
    }
}

#[test]
fn inherited_data_selectors_reject_both_reserved_tss_slots() {
    for selector in [HOST_TSS_SELECTOR, HOST_TSS_SELECTOR + 8] {
        for segment_index in 0..5 {
            let mut segments = firmware_segments(HOST_CODE_SELECTOR);
            let segment = match segment_index {
                0 => &mut segments.es,
                1 => &mut segments.ss,
                2 => &mut segments.ds,
                3 => &mut segments.fs,
                _ => &mut segments.gs,
            };
            segment.selector = selector;
            assert!(matches!(
                ResidentHostSelectors::inherited(segments),
                Err(HostTablesError::InvalidCodeLayout)
            ));
        }
    }
}

#[test]
fn inherited_selectors_keep_usable_gdt_slots_and_reject_tss_memory() {
    for selector in (8..TSS_OFFSET as u16).step_by(8) {
        if selector == HOST_TSS_SELECTOR || selector == HOST_TSS_SELECTOR + 8 {
            continue;
        }
        assert!(ResidentHostSelectors::inherited(firmware_segments(selector)).is_ok());
    }
    for selector in [0, TSS_OFFSET as u16, 0xfff8] {
        assert!(matches!(
            ResidentHostSelectors::inherited(firmware_segments(selector)),
            Err(HostTablesError::InvalidCodeLayout)
        ));
    }
}

#[test]
fn fixed_and_inherited_layouts_preserve_host_selector_normalization() {
    let fixed = ResidentHostSelectors::fixed();
    assert_eq!(fixed.cs, HOST_CODE_SELECTOR);
    assert_eq!([fixed.es, fixed.ss, fixed.ds, fixed.fs, fixed.gs], [HOST_DATA_SELECTOR; 5]);
    let inherited = ResidentHostSelectors::inherited(firmware_segments(0x3b)).unwrap();
    assert_eq!(inherited.cs, 0x38);
    assert_eq!([inherited.es, inherited.ss, inherited.ds, inherited.fs, inherited.gs], [0; 5]);
}
