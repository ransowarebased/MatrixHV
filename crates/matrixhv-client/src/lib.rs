//! Host-side MatrixHV client API.
//!
//! Packet builders and the CPUID memory transport used by any program that talks
//! to a running MatrixHV core. Neo is one consumer of this crate.

pub mod memory;

pub use matrixhv_protocol as protocol;
pub use memory::*;
