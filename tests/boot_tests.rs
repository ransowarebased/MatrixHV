#[cfg(test_harness = "order")]
mod order {
    include!("../builds/boot-order-tests/definitions.rs");

    use boot_order::{ParseError, parse_boot_option, parse_boot_order};

    fn load_option(path: &str, optional_data: &[u8]) -> Vec<u8> {
        let mut image_path = vec![4, 1, 42, 0];
        image_path.extend_from_slice(&1u32.to_le_bytes());
        image_path.extend_from_slice(&2048u64.to_le_bytes());
        image_path.extend_from_slice(&4096u64.to_le_bytes());
        image_path.extend_from_slice(&[0x5a; 16]);
        image_path.extend_from_slice(&[2, 2]);

        let mut file_path = Vec::new();
        for character in path.encode_utf16().chain(core::iter::once(0)) {
            file_path.extend_from_slice(&character.to_le_bytes());
        }
        image_path.extend_from_slice(&[4, 4]);
        image_path.extend_from_slice(&((file_path.len() + 4) as u16).to_le_bytes());
        image_path.extend_from_slice(&file_path);
        image_path.extend_from_slice(&[0x7f, 0xff, 4, 0]);

        let mut option = Vec::new();
        option.extend_from_slice(&1u32.to_le_bytes());
        option.extend_from_slice(&(image_path.len() as u16).to_le_bytes());
        for character in "VeraCrypt".encode_utf16().chain(core::iter::once(0)) {
            option.extend_from_slice(&character.to_le_bytes());
        }
        option.extend_from_slice(&image_path);
        option.extend_from_slice(optional_data);
        option
    }

    #[test]
    fn boot_order_preserves_firmware_order() {
        assert_eq!(parse_boot_order(&[2, 0, 0x34, 0x12]).unwrap(), [2, 0x1234]);
        assert_eq!(
            parse_boot_order(&[2]).unwrap_err(),
            ParseError::InvalidBootOrder
        );
    }

    #[test]
    fn boot_option_extracts_original_path_and_optional_data() {
        let option = load_option(r"\EFI\VeraCrypt\DcsBoot.efi", &[0x12, 0x34, 0x56]);
        let parsed = parse_boot_option(&option).unwrap();
        assert!(parsed.is_active());
        assert_eq!(parsed.description.len(), "VeraCrypt".len() * 2);
        assert!(parsed.image_file_path_matches(r"\efi\veracrypt\dcsboot.efi"));
        assert_eq!(parsed.image_path[0..4], [4, 1, 42, 0]);
        assert_eq!(parsed.optional_data, [0x12, 0x34, 0x56]);
        assert!(!parsed.image_file_path_matches(r"\EFI\Microsoft\Boot\bootmgfw.efi"));
    }

    #[test]
    fn rejects_truncated_or_ambiguous_binary_paths() {
        let valid = load_option(r"\EFI\VeraCrypt\DcsBoot.efi", &[]);
        let mut truncated = valid.clone();
        truncated.pop();
        assert_eq!(
            parse_boot_option(&truncated).err(),
            Some(ParseError::TruncatedLoadOption)
        );

        let mut zero_length_node = valid.clone();
        let image_offset = 6 + ("VeraCrypt".len() + 1) * 2;
        zero_length_node[image_offset + 2..image_offset + 4].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            parse_boot_option(&zero_length_node).err(),
            Some(ParseError::InvalidDevicePath)
        );

        let mut missing_description_terminator = valid.clone();
        missing_description_terminator[6 + "VeraCrypt".len() * 2] = b'X';
        assert!(parse_boot_option(&missing_description_terminator).is_err());

        let mut interior_nul = valid;
        let file_path_offset = image_offset + 42 + 4;
        interior_nul[file_path_offset + 2..file_path_offset + 4]
            .copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            parse_boot_option(&interior_nul).err(),
            Some(ParseError::InvalidDevicePath)
        );
    }

    #[test]
    fn parses_firmware_fixture_when_provided() {
        let Ok(path) = std::env::var("MATRIXHV_BOOT_OPTION_FIXTURE") else {
            return;
        };
        let bytes = std::fs::read(path).unwrap();
        let parsed = parse_boot_option(&bytes).unwrap();
        assert!(parsed.is_active());
        assert!(parsed.image_file_path_matches(r"\EFI\VeraCrypt\DcsBoot.efi"));
        assert_eq!(parsed.image_path[0..4], [4, 1, 42, 0]);
        assert!(parsed.optional_data.is_empty());
    }
}

#[cfg(test_harness = "config")]
mod config {
    include!("../builds/config-tests/definitions.rs");

    #[test]
    fn nested_vmx_defaults_to_enabled_and_test_boot_to_disabled() {
        assert_eq!(
            boot::parse(
                b"MATRIXHV_CONFIG_V2\ncpuidpresence=false\nlogger=true\nVtNested=true\nVmxTest=false\n"
            )
            .unwrap(),
            boot::MatrixConfig::default()
        );
    }

    #[test]
    fn missing_or_empty_configuration_is_rejected() {
        assert_eq!(boot::parse(b""), Err(boot::ParseError::MissingHeader));
        assert_eq!(
            boot::parse(b"logger=false\n"),
            Err(boot::ParseError::MissingHeader)
        );
    }

    #[test]
    fn vt_nested_parses_as_a_boolean() {
        let enabled = boot::parse(b"MATRIXHV_CONFIG_V2\nVtNested=true\n").unwrap();
        let disabled = boot::parse(b"MATRIXHV_CONFIG_V2\nVtNested=false\n").unwrap();

        assert!(enabled.vt_nested);
        assert!(!disabled.vt_nested);
    }

    #[test]
    fn vt_nested_rejects_invalid_values() {
        assert_eq!(
            boot::parse(b"MATRIXHV_CONFIG_V2\nVtNested=enabled\n"),
            Err(boot::ParseError::InvalidBoolean)
        );
    }

    #[test]
    fn vmx_test_requires_nested_vmx_exposure() {
        assert_eq!(
            boot::parse(b"MATRIXHV_CONFIG_V2\nVtNested=false\nVmxTest=true\n"),
            Err(boot::ParseError::VmxTestRequiresVtNested)
        );

        let config = boot::parse(b"MATRIXHV_CONFIG_V2\nVtNested=true\nVmxTest=true\n").unwrap();
        assert!(config.vt_nested);
        assert!(config.vmx_test);
    }

    #[test]
    fn evmcs_enables_nested_vmx_and_hypervisor_cpuid() {
        for input in [
            b"MATRIXHV_CONFIG_V2\nVtEvmcs=true\n".as_slice(),
            b"MATRIXHV_CONFIG_V2\ncpuidpresence=false\nlogger=false\nVtNested=false\nVtEvmcs=true\nVmxTest=false\n",
            b"MATRIXHV_CONFIG_V2\nVtEvmcs=true\ncpuidpresence=false\nVtNested=false\n",
            b"MATRIXHV_CONFIG_V2\ncpuidpresence=true\nVtNested=false\nVtEvmcs=true\n",
        ] {
            let config = boot::parse(input).unwrap();
            assert!(config.cpuid_presence);
            assert!(config.vt_nested);
            assert!(config.vt_evmcs);
        }

        let config = boot::parse(
            b"MATRIXHV_CONFIG_V2\ncpuidpresence=false\nlogger=false\nVtNested=false\nVtEvmcs=true\nVmxTest=false\n",
        )
        .unwrap();
        assert!(!config.logger);
        assert!(!config.vmx_test);
    }

    #[test]
    fn edited_configuration_round_trips_through_runtime_state() {
        let edited = boot::parse(
            b"MATRIXHV_CONFIG_V2\ncpuidpresence=true\nlogger=false\nVtNested=true\nVmxTest=true\n",
        )
        .unwrap();
        boot::apply(edited);

        assert_eq!(boot::current(), edited);
    }
}
