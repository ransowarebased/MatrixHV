#[test]
fn review_loader_contract_survives_capability_filtering() {
    // The oracle is hvloader.dll SHA-256 09c9676c944f5db21619a6aa2611271dc8a91f624c4c7ed5f65b2e2c50d2d811,
    // RVA 0x1e788. Inputs use true controls and are synthetic, not captures from any boot.
    let control_requirements = [
        (0x0000_001e_u32, 0x0000_003f_u32),
        (0xa420_65fa, 0xe7f9_fffe),
        (0x0003_6fff, 0x002b_efff),
        (0x0000_11ff, 0x0000_d3ff),
    ];
    let controls = control_requirements.map(|(low, high)| u64::from(low) | (u64::from(high) << 32));
    let required_ept = 0x0f01_0610_4040_u64;
    let mut cases = 0;
    for evmcs in [false, true] {
        for features in 0..128 {
            let mut secondary = 0x26_u64;
            for (selector, bit) in [(1, 22), (2, 20), (4, 13), (8, 14)] {
                if features & selector != 0 {
                    secondary |= 1 << bit;
                }
            }
            let mut ept = required_ept;
            for (selector, bit) in [(16, 0), (32, 21), (64, 22)] {
                if features & selector != 0 {
                    ept |= 1 << bit;
                }
            }
            let host = nested::HostVmxCapabilities {
                vmx_basic: 1 | (4096 << 32) | (6 << 50) | (1 << 55),
                pinbased_ctls: controls[0],
                procbased_ctls: controls[1],
                exit_ctls: controls[2],
                entry_ctls: controls[3],
                misc: 0,
                cr0_fixed0: 0x8000_0031,
                cr0_fixed1: 0x8005_003f,
                cr4_fixed0: 0x2040,
                cr4_fixed1: 0x27ff,
                vmcs_enum: 44,
                procbased_ctls2: secondary << 32,
                ept_vpid_cap: ept,
                true_pinbased_ctls: controls[0],
                true_procbased_ctls: controls[1],
                true_exit_ctls: controls[2],
                true_entry_ctls: controls[3],
            };
            let mut guest = nested::NestedVmxCapabilities::from_host(host);
            guest.vmx_procbased_ctls2 =
                crate::hyperv::restrict_evmcs_controls(guest.vmx_procbased_ctls2, evmcs);
            let guest_controls = [
                guest.vmx_true_pinbased_ctls,
                guest.vmx_true_procbased_ctls,
                guest.vmx_true_exit_ctls,
                guest.vmx_true_entry_ctls,
            ];
            for (value, (accepted_low, required_high)) in
                guest_controls.into_iter().zip(control_requirements)
            {
                assert_eq!(value as u32 & !accepted_low, 0);
                assert_eq!((value >> 32) as u32 & required_high, required_high);
            }
            assert_eq!((guest.vmx_basic >> 50) & 15, 6);
            assert!((guest.vmx_basic >> 32) & 0x1fff <= 4096);
            assert_eq!(guest.feature_control & 5, 5);
            assert_eq!(guest.vmx_procbased_ctls2 as u32, 0);
            assert_eq!((guest.vmx_procbased_ctls2 >> 32) & 0x26, 0x26);
            assert_eq!(guest.vmx_ept_vpid_cap & required_ept, required_ept);
            assert_eq!(guest.vmx_cr0_fixed0 & !0x8000_0031, 0);
            assert_eq!(guest.vmx_cr0_fixed1 & 0x8005_003f, 0x8005_003f);
            assert_eq!(guest.vmx_cr4_fixed0 & !0x2040, 0);
            assert_eq!(guest.vmx_cr4_fixed1 & 0x27ff, 0x27ff);
            cases += 1;
        }
    }
    assert_eq!(cases, 256);
    println!(
        "Validated {cases} synthetic VMX contracts against the extracted loader oracle; no physical boot was evaluated."
    );
}
