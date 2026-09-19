pub mod flags;
pub mod format;
pub mod parser;

pub use format::MatrixConfig;
pub use parser::{ParseError, parse};
