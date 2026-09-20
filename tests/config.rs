#[path = "../src/boot/config.rs"]
mod config;

#[test]
fn vmxflat_defaults_to_disabled() {
    assert_eq!(
        config::parse(config::DEFAULT_FILE_TEXT.as_bytes()).unwrap(),
        config::MatrixConfig::default()
    );
}

#[test]
fn vmxflat_parses_as_a_boolean() {
    let enabled = config::parse(b"MATRIXHV_CONFIG_V1\nvmxflat=true\n").unwrap();
    let disabled = config::parse(b"MATRIXHV_CONFIG_V1\nvmxflat=false\n").unwrap();

    assert!(enabled.vmx_flat);
    assert!(!disabled.vmx_flat);
}

#[test]
fn vmxflat_rejects_invalid_values() {
    assert_eq!(
        config::parse(b"MATRIXHV_CONFIG_V1\nvmxflat=enabled\n"),
        Err(config::ParseError::InvalidBoolean)
    );
}

#[test]
fn embedded_configuration_round_trips_through_runtime_state() {
    let embedded = config::load_embedded().unwrap();
    config::apply(embedded);

    assert_eq!(config::current(), embedded);
}
