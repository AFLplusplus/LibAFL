#[cfg(feature = "libc")]
pub mod libc;

#[cfg(all(feature = "linux", target_os = "linux", not(feature = "libc")))]
pub mod linux;
