#[cfg(any(feature = "pcguard_edges", feature = "pcguard_hitcounts"))]
pub mod pcguard;
#[cfg(any(feature = "pcguard_edges", feature = "pcguard_hitcounts"))]
pub use pcguard::*;

#[cfg(feature = "libfuzzer")]
pub mod libfuzzer;
#[cfg(feature = "libfuzzer")]
pub use libfuzzer::*;
