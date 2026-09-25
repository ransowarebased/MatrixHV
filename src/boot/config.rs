use core::str;
use core::sync::atomic::{AtomicBool, Ordering};

pub const CONFIG_HEADER: &str = "MATRIXHV_CONFIG_V2";
pub const DEFAULT_FILE_TEXT: &str =
    "MATRIXHV_CONFIG_V2\ncpuidpresence=true\nlogger=true\nVtNested=false\nVmxTest=false\n";
pub const CPUIDPRESENCE_KEY: &str = "cpuidpresence";
pub const LOGGER_KEY: &str = "logger";
pub const VT_NESTED_KEY: &str = "VtNested";
pub const VMX_TEST_KEY: &str = "VmxTest";

#[cfg(not(test))]
const EMBEDDED_CONFIG: &[u8] = include_bytes!("../../builds/MatrixConfig.bin");
#[cfg(test)]
const EMBEDDED_CONFIG: &[u8] = DEFAULT_FILE_TEXT.as_bytes();

static CPUID_PRESENCE: AtomicBool = AtomicBool::new(true);
static LOGGER: AtomicBool = AtomicBool::new(true);
static VT_NESTED: AtomicBool = AtomicBool::new(false);
static VMX_TEST: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatrixConfig {
    pub cpuid_presence: bool,
    pub logger: bool,
    pub vt_nested: bool,
    pub vmx_test: bool,
}

impl Default for MatrixConfig {
    fn default() -> Self {
        Self {
            cpuid_presence: true,
            logger: true,
            vt_nested: false,
            vmx_test: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    InvalidEncoding,
    InvalidLine,
    InvalidBoolean,
    UnknownKey,
    VmxTestRequiresVtNested,
}

pub fn parse(bytes: &[u8]) -> Result<MatrixConfig, ParseError> {
    let text = str::from_utf8(bytes).map_err(|_| ParseError::InvalidEncoding)?;
    let mut config = MatrixConfig::default();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line == CONFIG_HEADER {
            continue;
        }

        let (key, value) = line.split_once('=').ok_or(ParseError::InvalidLine)?;
        let parsed = parse_bool(value.trim())?;
        match key.trim() {
            CPUIDPRESENCE_KEY => config.cpuid_presence = parsed,
            LOGGER_KEY => config.logger = parsed,
            VT_NESTED_KEY => config.vt_nested = parsed,
            VMX_TEST_KEY => config.vmx_test = parsed,
            _ => return Err(ParseError::UnknownKey),
        }
    }

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

pub fn load_embedded() -> Result<MatrixConfig, ParseError> {
    if EMBEDDED_CONFIG.is_empty() {
        return parse(DEFAULT_FILE_TEXT.as_bytes());
    }
    parse(EMBEDDED_CONFIG)
}

pub fn apply(config: MatrixConfig) {
    CPUID_PRESENCE.store(config.cpuid_presence, Ordering::Relaxed);
    LOGGER.store(config.logger, Ordering::Relaxed);
    VT_NESTED.store(config.vt_nested, Ordering::Relaxed);
    VMX_TEST.store(config.vmx_test, Ordering::Relaxed);
}

pub fn current() -> MatrixConfig {
    MatrixConfig {
        cpuid_presence: CPUID_PRESENCE.load(Ordering::Relaxed),
        logger: LOGGER.load(Ordering::Relaxed),
        vt_nested: VT_NESTED.load(Ordering::Relaxed),
        vmx_test: VMX_TEST.load(Ordering::Relaxed),
    }
}
