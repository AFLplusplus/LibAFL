#[cfg(feature = "libc")]
pub mod libc;

#[cfg(all(feature = "syscalls", target_os = "linux", not(feature = "libc")))]
pub mod linux;
