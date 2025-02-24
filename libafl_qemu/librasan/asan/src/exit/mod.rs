//! # die
//! This module supports exiting the process
#[cfg(feature = "libc")]
pub use crate::exit::libc::abort;
#[cfg(feature = "libc")]
pub use crate::exit::libc::exit;
#[cfg(all(feature = "linux", not(feature = "libc")))]
pub use crate::exit::linux::abort;
#[cfg(all(feature = "linux", not(feature = "libc")))]
pub use crate::exit::linux::exit;

#[cfg(feature = "libc")]
pub mod libc;

#[cfg(feature = "linux")]
pub mod linux;
