pub const CONFIG_HEADER: &str = "MATRIXHV_CONFIG_V1";
pub const DEFAULT_FILE_TEXT: &str = "MATRIXHV_CONFIG_V1\ncpuidpresence=true\nlogger=true\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatrixConfig {
    pub cpuid_presence: bool,
    pub logger: bool,
}

impl Default for MatrixConfig {
    fn default() -> Self {
        Self {
            cpuid_presence: true,
            logger: true,
        }
    }
}
