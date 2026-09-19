use crate::config::format::DEFAULT_FILE_TEXT;
use crate::config::{MatrixConfig, ParseError, parse};

const EMBEDDED_CONFIG: &[u8] = include_bytes!("../../config/MatrixConfig.bin");

pub fn load_embedded() -> Result<MatrixConfig, ParseError> {
    if EMBEDDED_CONFIG.is_empty() {
        return parse(DEFAULT_FILE_TEXT.as_bytes());
    }
    parse(EMBEDDED_CONFIG)
}
