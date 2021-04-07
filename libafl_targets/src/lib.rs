//! `libafl_targets` contains runtime code, injected in the target itself during compilation.

#[cfg(any(feature = "pcguard_edges", feature = "pcguard_hitcounts"))]
pub mod pcguard;
#[cfg(any(feature = "pcguard_edges", feature = "pcguard_hitcounts"))]
pub use pcguard::*;

#[cfg(feature = "value_profile")]
pub mod value_profile;
#[cfg(feature = "value_profile")]
pub use value_profile::*;

#[cfg(feature = "libfuzzer")]
pub mod libfuzzer;
#[cfg(feature = "libfuzzer")]
pub use libfuzzer::*;
