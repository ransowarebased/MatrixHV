#[test]
fn nested_vmx_and_test_boot_default_to_disabled() {
    assert_eq!(
        boot::parse(boot::DEFAULT_FILE_TEXT.as_bytes()).unwrap(),
        boot::MatrixConfig::default()
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
        boot::parse(b"MATRIXHV_CONFIG_V2\nVmxTest=true\n"),
        Err(boot::ParseError::VmxTestRequiresVtNested)
    );

    let config = boot::parse(b"MATRIXHV_CONFIG_V2\nVtNested=true\nVmxTest=true\n").unwrap();
    assert!(config.vt_nested);
    assert!(config.vmx_test);
}

#[test]
fn embedded_configuration_round_trips_through_runtime_state() {
    let embedded = boot::load_embedded().unwrap();
    boot::apply(embedded);

    assert_eq!(boot::current(), embedded);
}
