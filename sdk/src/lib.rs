//! Shared MatrixHV instrumentation ABI and guest-side client API.
//!
//! The client feature provides packet builders and CPUID transport on guest OS targets.

#![cfg_attr(any(not(feature = "client"), target_os = "uefi"), no_std)]

pub mod protocol;

#[cfg(all(feature = "client", not(target_os = "uefi")))]
pub mod memory;
#[cfg(all(feature = "client", not(target_os = "uefi")))]
pub use memory::*;
