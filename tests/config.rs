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
fn edited_configuration_round_trips_through_runtime_state() {
    let edited = boot::parse(
        b"MATRIXHV_CONFIG_V2\ncpuidpresence=true\nlogger=false\nVtNested=true\nVmxTest=true\n",
    )
    .unwrap();
    boot::apply(edited);

    assert_eq!(boot::current(), edited);
}
