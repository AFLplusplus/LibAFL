//! Operating System specific abstractions

//#[cfg(target_os = "android")]
pub mod ashmem_server;

#[cfg(unix)]
pub mod unix_signals;
#[cfg(windows)]
pub mod windows_exceptions;
