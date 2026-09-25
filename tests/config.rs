#[path = "../src/boot/config.rs"]
mod config;

#[test]
fn nested_vmx_and_test_boot_default_to_disabled() {
    assert_eq!(
        config::parse(config::DEFAULT_FILE_TEXT.as_bytes()).unwrap(),
        config::MatrixConfig::default()
    );
}

#[test]
fn vt_nested_parses_as_a_boolean() {
    let enabled = config::parse(b"MATRIXHV_CONFIG_V2\nVtNested=true\n").unwrap();
    let disabled = config::parse(b"MATRIXHV_CONFIG_V2\nVtNested=false\n").unwrap();

    assert!(enabled.vt_nested);
    assert!(!disabled.vt_nested);
}

#[test]
fn vt_nested_rejects_invalid_values() {
    assert_eq!(
        config::parse(b"MATRIXHV_CONFIG_V2\nVtNested=enabled\n"),
        Err(config::ParseError::InvalidBoolean)
    );
}

#[test]
fn vmx_test_requires_nested_vmx_exposure() {
    assert_eq!(
        config::parse(b"MATRIXHV_CONFIG_V2\nVmxTest=true\n"),
        Err(config::ParseError::VmxTestRequiresVtNested)
    );

    let config = config::parse(b"MATRIXHV_CONFIG_V2\nVtNested=true\nVmxTest=true\n").unwrap();
    assert!(config.vt_nested);
    assert!(config.vmx_test);
}

#[test]
fn embedded_configuration_round_trips_through_runtime_state() {
    let embedded = config::load_embedded().unwrap();
    config::apply(embedded);

    assert_eq!(config::current(), embedded);
}
