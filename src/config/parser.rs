use core::str;

use super::flags::{CPUIDPRESENCE_KEY, LOGGER_KEY};
use super::format::{CONFIG_HEADER, MatrixConfig};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    InvalidEncoding,
    InvalidLine,
    InvalidBoolean,
    UnknownKey,
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
            _ => return Err(ParseError::UnknownKey),
        }
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
