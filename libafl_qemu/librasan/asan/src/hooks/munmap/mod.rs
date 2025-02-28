#[cfg(feature = "libc")]
pub mod libc;

#[cfg(all(feature = "linux", not(feature = "libc")))]
pub mod linux;
