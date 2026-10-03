use core::str;

pub const CONFIG_HEADER: &str = "MATRIXHV_CONFIG_V2";
pub const CPUIDPRESENCE_KEY: &str = "cpuidpresence";
pub const LOGGER_KEY: &str = "logger";
pub const VT_NESTED_KEY: &str = "VtNested";
pub const VT_EVMCS_KEY: &str = "VtEvmcs";
pub const VMX_TEST_KEY: &str = "VmxTest";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatrixConfig {
    pub cpuid_presence: bool,
    pub logger: bool,
    pub vt_nested: bool,
    pub vt_evmcs: bool,
    pub vmx_test: bool,
}

impl Default for MatrixConfig {
    fn default() -> Self {
        Self {
            cpuid_presence: false,
            logger: true,
            vt_nested: true,
            vt_evmcs: false,
            vmx_test: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    MissingHeader,
    InvalidEncoding,
    InvalidLine,
    InvalidBoolean,
    UnknownKey,
    VmxTestRequiresVtNested,
}

pub fn parse(bytes: &[u8]) -> Result<MatrixConfig, ParseError> {
    let text = str::from_utf8(bytes).map_err(|_| ParseError::InvalidEncoding)?;
    let mut config = MatrixConfig::default();
    let mut has_header = false;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line == CONFIG_HEADER {
            has_header = true;
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, value) = line.split_once('=').ok_or(ParseError::InvalidLine)?;
        let parsed = parse_bool(value.trim())?;
        match key.trim() {
            CPUIDPRESENCE_KEY => config.cpuid_presence = parsed,
            LOGGER_KEY => config.logger = parsed,
            VT_NESTED_KEY => config.vt_nested = parsed,
            VT_EVMCS_KEY => config.vt_evmcs = parsed,
            VMX_TEST_KEY => config.vmx_test = parsed,
            _ => return Err(ParseError::UnknownKey),
        }
    }

    if !has_header {
        return Err(ParseError::MissingHeader);
    }
    normalize_exposure(
        &mut config.cpuid_presence,
        &mut config.vt_nested,
        config.vt_evmcs,
    );
    if config.vmx_test && !config.vt_nested {
        return Err(ParseError::VmxTestRequiresVtNested);
    }

    Ok(config)
}

fn parse_bool(value: &str) -> Result<bool, ParseError> {
    if value.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(ParseError::InvalidBoolean)
    }
}

pub fn normalize_exposure(cpuid_presence: &mut bool, vt_nested: &mut bool, vt_evmcs: bool) {
    if vt_evmcs {
        *cpuid_presence = true;
        *vt_nested = true;
    }
}
