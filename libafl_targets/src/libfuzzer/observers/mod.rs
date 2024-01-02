/// oom observer
#[cfg(feature = "libfuzzer_oom")]
pub mod oom;
#[cfg(feature = "libfuzzer_oom")]
pub use oom::*;
