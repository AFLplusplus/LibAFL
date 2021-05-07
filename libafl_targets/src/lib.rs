//! `libafl_targets` contains runtime code, injected in the target itself during compilation.

#[macro_use]
extern crate serde_big_array;

#[cfg(any(feature = "sancov_pcguard_edges", feature = "sancov_pcguard_hitcounts"))]
pub mod sancov_pcguard;
#[cfg(any(feature = "sancov_pcguard_edges", feature = "sancov_pcguard_hitcounts"))]
pub use sancov_pcguard::*;

#[cfg(feature = "libfuzzer")]
pub mod libfuzzer;
#[cfg(feature = "libfuzzer")]
pub use libfuzzer::*;

pub mod value_profile;
pub use value_profile::*;

pub mod cmplog;
pub use cmplog::*;

pub mod drcov;
