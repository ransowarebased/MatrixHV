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
    fn boot_file_paths_join_all_nodes_with_one_separator() {
        let image_offset = 6 + ("VeraCrypt".len() + 1) * 2;
        for (directory, file) in [
            (r"\EFI\VeraCrypt", "DcsBoot.efi"),
            (r"\EFI\VeraCrypt\", r"\DcsBoot.efi"),
            (r"EFI\VeraCrypt", r"\DcsBoot.efi"),
        ] {
            let mut option = load_option(directory, &[0xaa]);
            let suffix = load_option(file, &[]);
            let file_node = &suffix[image_offset + 42..suffix.len() - 4];
            let end_offset = option.len() - 5;
            option.splice(end_offset..end_offset, file_node.iter().copied());
            let path_size = u16::from_le_bytes(option[4..6].try_into().unwrap());
            option[4..6].copy_from_slice(&(path_size + file_node.len() as u16).to_le_bytes());
            let parsed = parse_boot_option(&option).unwrap();
            assert!(parsed.image_file_path_matches(r"\EFI\VeraCrypt\DcsBoot.efi"));
            assert_eq!(parsed.optional_data, [0xaa]);
        }
    }

    #[test]
    fn boot_file_path_does_not_join_separate_device_instances() {
        let image_offset = 6 + ("VeraCrypt".len() + 1) * 2;
        let mut option = load_option(r"\EFI\VeraCrypt", &[]);
        let end_offset = option.len() - 4;
        option[end_offset + 1] = 1;
        let suffix = load_option("DcsBoot.efi", &[]);
        option.extend_from_slice(&suffix[image_offset..]);
        let path_size = (option.len() - image_offset) as u16;
        option[4..6].copy_from_slice(&path_size.to_le_bytes());
        let parsed = parse_boot_option(&option).unwrap();
        assert!(!parsed.image_file_path_matches(r"\EFI\VeraCrypt\DcsBoot.efi"));
    }

    #[test]
    fn unsigned_partitions_require_matching_geometry() {
        let mut original = [0_u8; 38];
        original[..4].copy_from_slice(&1_u32.to_le_bytes());
        original[4..12].copy_from_slice(&2048_u64.to_le_bytes());
        original[12..20].copy_from_slice(&4096_u64.to_le_bytes());
        original[36] = 1;
        assert!(same_hd_partition(&original, &original));
        for offset in [0, 4, 12, 36, 37] {
            let mut candidate = original;
            candidate[offset] ^= 1;
            assert!(!same_hd_partition(&original, &candidate));
        }
        assert!(!same_hd_partition(&original[..37], &original));
    }

    #[test]
    fn signed_partition_matching_uses_only_the_declared_signature() {
        for signature_type in [1, 2] {
            let mut original = [0_u8; 38];
            original[0] = 1;
            original[20] = 0x5a;
            original[36] = signature_type;
            original[37] = signature_type;
            let mut candidate = original;
            candidate[4] = 0x80;
            candidate[12] = 0x40;
            assert!(same_hd_partition(&original, &candidate));
            candidate[20] ^= 1;
            assert!(!same_hd_partition(&original, &candidate));
            candidate = original;
            candidate[24] ^= 1;
            assert_eq!(same_hd_partition(&original, &candidate), signature_type == 1);
        }
        let mut reserved = [0_u8; 38];
        reserved[37] = 3;
        assert!(!same_hd_partition(&reserved, &reserved));
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
    pub mod boot {
        include!("../src/boot/config.rs");
    }

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
    fn edited_configuration_preserves_explicit_startup_options() {
        let edited = boot::parse(
            b"MATRIXHV_CONFIG_V2\ncpuidpresence=true\nlogger=false\nVtNested=true\nVmxTest=true\n",
        )
        .unwrap();
        assert!(edited.cpuid_presence);
        assert!(!edited.logger);
        assert!(edited.vt_nested);
        assert!(edited.vmx_test);
    }
}
