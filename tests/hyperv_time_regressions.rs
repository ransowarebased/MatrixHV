core::arch::global_asm!(include_str!("../builds/hyperv-time-tests/hypercall.S"));

unsafe extern "win64" {
    fn test_hypercall(context: *mut u64, registers: *mut u64) -> u32;
}

#[test]
fn outer_evmcs_is_filtered_only_when_matrixhv_owns_nested_vmx() {
    for nested in [false, true] {
        let mut scenario = Scenario::new();
        scenario.context[1] = 0;
        scenario.context[4] = 0;
        scenario.context[8] = u64::from(nested);
        for leaf in [0x4000_0004, 0x4000_000a] {
            let mut registers = [u32::MAX, 0x55, 0x66, 0x77];
            unsafe { test_time_cpuid(scenario.context.as_mut_ptr(), registers.as_mut_ptr(), leaf) };
            let expected = if !nested {
                [u32::MAX, 0x55, 0x66, 0x77]
            } else if leaf == 0x4000_0004 {
                [u32::MAX & !(1 << 14), 0x55, 0x66, 0x77]
            } else {
                [0; 4]
            };
            assert_eq!(registers, expected);
        }
    }
}

#[test]
fn spin_notification_supports_fast_and_memory_inputs_in_both_conventions() {
    for long_mode in [false, true] {
        for fast in [false, true] {
            let mut scenario = Scenario::new();
            scenario.shared[4] = 1;
            scenario.shared[5] = 1;
            let mut context = [0; 12];
            context[..8].copy_from_slice(&scenario.context[..8]);
            context[8] = 1;
            context[9] = if long_mode { 0x2000 } else { 0 };
            context[10] = if long_mode { 0x400 } else { 0 };
            scenario.page.0[0] = 123;
            let input = if fast {
                123
            } else {
                scenario.page.0.as_ptr() as u64
            };
            let control = 8 | u64::from(fast) << 16;
            let mut registers = if long_mode {
                [0xdeadbeef, control, input, 0x12345678]
            } else {
                [control, input as u32 as u64, 0, input >> 32]
            };
            let before = registers;
            assert_eq!(
                unsafe { test_hypercall(context.as_mut_ptr(), registers.as_mut_ptr()) },
                1
            );
            assert_eq!(registers[0], 0);
            assert_eq!(registers[1], before[1]);
            assert_eq!(registers[3], before[3]);
            assert_eq!(registers[2], if long_mode { before[2] } else { 0 });
            assert_eq!(scenario.page.0[0], 123);
        }
    }
}

#[test]
fn hypercalls_validate_control_reserved_input_and_page_permissions() {
    let mut scenario = Scenario::new();
    scenario.shared[4] = 1;
    scenario.shared[5] = 1;
    let mut context = [0; 12];
    context[..8].copy_from_slice(&scenario.context[..8]);
    context[8..11].copy_from_slice(&[1, 0x2000, 0x400]);
    let address = scenario.page.0.as_ptr() as u64;
    scenario.page.0[0] = 0;
    for (control, input, status) in [
        (0x777, 0, 2),
        (8 | 1 << 17, 0, 3),
        (8 | 1 << 32, 0, 3),
        (8 | 1 << 16, 1 << 32, 5),
        (8, address | 1, 4),
        (8, address + 4096, 5),
    ] {
        let mut registers = [0, control, input, 0];
        assert_eq!(
            unsafe { test_hypercall(context.as_mut_ptr(), registers.as_mut_ptr()) },
            1
        );
        assert_eq!(registers[0], status);
    }
    scenario.tables[3].0[((address >> 12) & 511) as usize] &= !1;
    let mut registers = [0, 8, address, 0];
    assert_eq!(
        unsafe { test_hypercall(context.as_mut_ptr(), registers.as_mut_ptr()) },
        1
    );
    assert_eq!(registers[0], 5);
}

#[test]
fn hypercalls_require_enabled_interface_protected_mode_and_kernel_privilege() {
    for invalid in 0..5 {
        let mut scenario = Scenario::new();
        scenario.shared[4] = 1;
        scenario.shared[5] = 1;
        let mut context = [0; 12];
        context[..8].copy_from_slice(&scenario.context[..8]);
        context[8..11].copy_from_slice(&[1, 0x2000, 0x400]);
        match invalid {
            0 => scenario.shared[4] = 0,
            1 => scenario.shared[5] = 0,
            2 => context[8] = 0,
            3 => context[11] = 3,
            _ => {
                context[1] = 0;
                context[4] = 0;
            }
        }
        let mut registers = [0x55, 0x10008, 0, 0];
        let before = registers;
        assert_eq!(
            unsafe { test_hypercall(context.as_mut_ptr(), registers.as_mut_ptr()) },
            if invalid == 4 { 2 } else { 0 }
        );
        assert_eq!(registers, before);
    }
}

#[test]
fn calibration_uses_the_pm_clock_and_rejects_unstable_or_missing_samples() {
    assert_eq!(
        calibrated_tsc_hz(|| Some((2_500_000_000, 3_579_545))),
        2_500_000_000
    );
    assert_eq!(calibrated_tsc_hz(|| None), 0);
    assert_eq!(calibrated_tsc_hz(|| Some((100, 100))), 0);
    let mut samples = [
        2_400_000_000,
        2_500_000_000,
        2_501_000_000,
        2_502_000_000,
        2_900_000_000,
    ]
    .into_iter();
    assert_eq!(
        calibrated_tsc_hz(|| Some((samples.next().unwrap(), 3_579_545))),
        2_501_000_000
    );
    let mut samples = [
        2_400_000_000,
        2_500_000_000,
        2_501_000_000,
        2_520_000_000,
        2_900_000_000,
    ]
    .into_iter();
    assert_eq!(
        calibrated_tsc_hz(|| Some((samples.next().unwrap(), 3_579_545))),
        0
    );
}

#[test]
fn incomplete_cpuid_frequency_uses_calibration_and_never_nominal_cpuid16() {
    for maximum in [0x14, 0x16] {
        let cpuid = |leaf| {
            assert_ne!(leaf, 0x16);
            core::arch::x86_64::CpuidResult {
                eax: match leaf {
                    0 => maximum,
                    0x8000_0000 => 0x8000_0007,
                    _ => 0,
                },
                ebx: 0,
                ecx: 0,
                edx: if leaf == 0x8000_0007 { 1 << 8 } else { 0 },
            }
        };
        let (scale, offset) = native_hyperv_reference_tsc(cpuid, 2_500_000_000, || 2_500_000_000);
        assert_eq!(scale, hyperv_reference_tsc_scale_from_hz(2_500_000_000));
        assert_eq!(offset.wrapping_add(9_999_999), 0);
        assert_eq!(native_hyperv_reference_tsc(cpuid, 100, || 0), (0, 0));
    }
}

#[test]
fn synthetic_identity_limits_and_hardware_match_the_implemented_interface() {
    let mut scenario = Scenario::new();
    assert_eq!(scenario.features(0x4000_0002), [1, 1, 0, 0]);
    assert_eq!(scenario.features(0x4000_0005), [64, 64, 0, 0]);
    assert_eq!(scenario.features(0x4000_0006), [0xa, 0, 0, 0]);
    for leaf in 0x4000_0007..=0x4000_0009 {
        assert_eq!(scenario.features(leaf), [0; 4]);
    }
}

#[test]
fn reference_scale_retains_fractional_cpuid_frequency_without_overflow() {
    for (denominator, numerator, crystal_hz) in [
        (3, 1, 30_000_001),
        (3, 1, 31_000_001),
        (7, 5, 24_000_001),
        (u32::MAX, u32::MAX - 1, u32::MAX),
        (1, u32::MAX, u32::MAX),
    ] {
        let expected = ((10_000_000_u128 * u128::from(denominator)) << 64)
            / (u128::from(numerator) * u128::from(crystal_hz));
        assert_eq!(
            hyperv_reference_tsc_scale(denominator, numerator, crystal_hz),
            expected as u64
        );
    }
    assert_ne!(
        hyperv_reference_tsc_scale(3, 1, 31_000_001),
        hyperv_reference_tsc_scale_from_hz(31_000_001 / 3)
    );
    assert_ne!(hyperv_reference_tsc_scale(3, 1, 30_000_001), 0);
}

#[test]
fn hypercall_register_preserves_reserved_bits_across_enable_and_identity_clear() {
    let mut scenario = Scenario::new();
    let address = scenario.page.0.as_ptr() as u64;
    for reserved in [4, 0x800, 0xffc] {
        assert_eq!(scenario.msr(6, 1).0, 1);
        assert_eq!(scenario.msr(7, address | reserved | 1).0, 1);
        assert_eq!(scenario.msr(5, 0), (1, address | reserved | 1));
        assert_eq!(scenario.page.0[0] as u32, 0xc3c1010f);
        assert_eq!(scenario.shared[6], 0);
        assert_eq!(scenario.msr(6, 0).0, 1);
        assert_eq!(scenario.msr(5, 0), (1, address | reserved));
    }
}

#[test]
fn synthetic_shared_pages_accept_guest_physical_page_zero_when_ept_maps_it() {
    for operation in [2, 7] {
        let mut scenario = Scenario::new();
        for table in scenario.tables.iter_mut() {
            table.0.fill(0);
        }
        for level in 0..3 {
            scenario.tables[level].0[0] = scenario.tables[level + 1].0.as_ptr() as u64 | 7;
        }
        scenario.tables[3].0[0] = scenario.page.0.as_ptr() as u64 | 7;
        assert_eq!(scenario.msr(6, 1).0, 1);
        assert_eq!(scenario.msr(operation, 1).0, 1);
        if operation == 2 {
            assert_eq!(scenario.msr(1, 0), (1, 1));
            assert_eq!(scenario.page.0[0], 1);
            assert_eq!(scenario.page.0[1], scenario.shared[0]);
            assert_eq!(scenario.msr(2, 0).0, 1);
            assert_eq!(scenario.page.0[0], 0);
        } else {
            assert_eq!(scenario.msr(5, 0), (1, 1));
            assert_eq!(scenario.page.0[0] as u32, 0xc3c1010f);
        }
    }
}

#[test]
fn acpi_pm_timer_access_size_requires_a_dword_register() {
    let mut fadt = [0_u8; 220];
    fadt[91] = 4;
    fadt[208] = 1;
    fadt[212..220].copy_from_slice(&0x508_u64.to_le_bytes());
    for width in [24, 32] {
        fadt[209] = width;
        for access_size in [0, 3] {
            fadt[211] = access_size;
            assert_eq!(acpi_pm_timer_register(&fadt), Some((0x508, 0xff_ffff)));
        }
        for access_size in [1, 2, 4, 0xff] {
            fadt[211] = access_size;
            assert_eq!(acpi_pm_timer_register(&fadt), None);
        }
    }
}

#[test]
fn acpi_timer_discovery_validates_checksums_and_extended_registers() {
    fn checksum(table: &mut [u8], index: usize) {
        table[index] = 0;
        table[index] =
            0_u8.wrapping_sub(table.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte)));
    }
    let mut fadt = [0_u8; 220];
    fadt[..4].copy_from_slice(b"FACP");
    fadt[4..8].copy_from_slice(&220_u32.to_le_bytes());
    fadt[76..80].copy_from_slice(&0x408_u32.to_le_bytes());
    fadt[91] = 4;
    checksum(&mut fadt, 9);
    let mut xsdt = [0_u8; 44];
    xsdt[..4].copy_from_slice(b"XSDT");
    xsdt[4..8].copy_from_slice(&44_u32.to_le_bytes());
    xsdt[36..44].copy_from_slice(&(fadt.as_ptr() as u64).to_le_bytes());
    checksum(&mut xsdt, 9);
    let mut root = [0_u8; 36];
    root[..8].copy_from_slice(b"RSD PTR ");
    root[15] = 2;
    root[20..24].copy_from_slice(&36_u32.to_le_bytes());
    root[24..32].copy_from_slice(&(xsdt.as_ptr() as u64).to_le_bytes());
    checksum(&mut root[..20], 8);
    checksum(&mut root, 32);
    assert_eq!(
        unsafe { acpi_pm_timer(root.as_ptr() as usize) },
        Some((0x408, 0xff_ffff))
    );
    root[8] ^= 1;
    assert_eq!(unsafe { acpi_pm_timer(root.as_ptr() as usize) }, None);
    fadt[208..212].copy_from_slice(&[1, 32, 0, 3]);
    fadt[212..220].copy_from_slice(&0x508_u64.to_le_bytes());
    fadt[112..116].copy_from_slice(&(1_u32 << 8).to_le_bytes());
    assert_eq!(acpi_pm_timer_register(&fadt), Some((0x508, u32::MAX)));
    fadt[208] = 0;
    assert_eq!(acpi_pm_timer_register(&fadt), None);
    fadt[208] = 1;
    fadt[112..116].copy_from_slice(&(1_u32 << 20).to_le_bytes());
    assert_eq!(acpi_pm_timer_register(&fadt), None);
}

#[test]
fn acpi_timer_discovery_skips_bad_children_and_rejects_partial_root_entries() {
    fn checksum(table: &mut [u8], index: usize) {
        table[index] = 0;
        table[index] =
            0_u8.wrapping_sub(table.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte)));
    }
    let mut fadt = [0_u8; 116];
    fadt[..4].copy_from_slice(b"FACP");
    fadt[4..8].copy_from_slice(&116_u32.to_le_bytes());
    fadt[76..80].copy_from_slice(&0x408_u32.to_le_bytes());
    fadt[91] = 4;
    checksum(&mut fadt, 9);
    let mut invalid_child = [0_u8; 36];
    invalid_child[..4].copy_from_slice(b"APIC");
    invalid_child[4..8].copy_from_slice(&36_u32.to_le_bytes());
    let mut xsdt = [0_u8; 61];
    xsdt[..4].copy_from_slice(b"XSDT");
    xsdt[4..8].copy_from_slice(&60_u32.to_le_bytes());
    xsdt[44..52].copy_from_slice(&(invalid_child.as_ptr() as u64).to_le_bytes());
    xsdt[52..60].copy_from_slice(&(fadt.as_ptr() as u64).to_le_bytes());
    checksum(&mut xsdt, 9);
    let mut root = [0_u8; 36];
    root[..8].copy_from_slice(b"RSD PTR ");
    root[15] = 2;
    root[20..24].copy_from_slice(&36_u32.to_le_bytes());
    root[24..32].copy_from_slice(&(xsdt.as_ptr() as u64).to_le_bytes());
    checksum(&mut root[..20], 8);
    checksum(&mut root, 32);
    assert_eq!(unsafe { acpi_pm_timer(0) }, None);
    assert_eq!(
        unsafe { acpi_pm_timer(root.as_ptr() as usize) },
        Some((0x408, 0xff_ffff))
    );
    xsdt[4..8].copy_from_slice(&61_u32.to_le_bytes());
    checksum(&mut xsdt, 9);
    assert_eq!(unsafe { acpi_pm_timer(root.as_ptr() as usize) }, None);
}
