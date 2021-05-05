//! `libafl_targets` contains runtime code, injected in the target itself during compilation.

#[cfg(any(feature = "pcguard_edges", feature = "pcguard_hitcounts"))]
pub mod pcguard;
#[cfg(any(feature = "pcguard_edges", feature = "pcguard_hitcounts"))]
pub use pcguard::*;

#[cfg(feature = "libfuzzer")]
pub mod libfuzzer;
#[cfg(feature = "libfuzzer")]
pub use libfuzzer::*;

#[cfg(all(feature = "value_profile", feature = "cmplog"))]
#[cfg(not(any(doc, feature = "clippy")))]
compile_error!("the libafl_targets `value_profile` and `cmplog` features are mutually exclusive.");

#[cfg(feature = "value_profile")]
pub mod value_profile;
#[cfg(feature = "value_profile")]
pub use value_profile::*;

#[cfg(feature = "cmplog")]
pub mod cmplog;
#[cfg(feature = "cmplog")]
pub use cmplog::*;

pub mod drcov;
