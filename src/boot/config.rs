use core::sync::atomic::{AtomicBool, Ordering};

use crate::config::{MatrixConfig, ParseError};

use super::matrix_config;

static CPUID_PRESENCE: AtomicBool = AtomicBool::new(true);
static LOGGER: AtomicBool = AtomicBool::new(true);

pub fn load_embedded() -> Result<MatrixConfig, ParseError> {
    matrix_config::load_embedded()
}

pub fn apply(config: MatrixConfig) {
    CPUID_PRESENCE.store(config.cpuid_presence, Ordering::Relaxed);
    LOGGER.store(config.logger, Ordering::Relaxed);
}

pub fn current() -> MatrixConfig {
    MatrixConfig {
        cpuid_presence: CPUID_PRESENCE.load(Ordering::Relaxed),
        logger: LOGGER.load(Ordering::Relaxed),
    }
}
