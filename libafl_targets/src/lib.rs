//! `libafl_targets` contains runtime code, injected in the target itself during compilation.

#[cfg(any(feature = "pcguard_edges", feature = "pcguard_hitcounts"))]
pub mod pcguard;
#[cfg(any(feature = "pcguard_edges", feature = "pcguard_hitcounts"))]
pub use pcguard::*;

#[cfg(feature = "libfuzzer")]
pub mod libfuzzer;
#[cfg(feature = "libfuzzer")]
pub use libfuzzer::*;

pub mod value_profile;
pub use value_profile::*;

pub mod cmplog;
pub use cmplog::*;

pub mod drcov;
