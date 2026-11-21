#[cfg(feature = "libc")]
pub mod libc;

#[cfg(all(feature = "syscalls", target_os = "linux"))]
pub mod linux;
