//! Operating System specific abstractions

#[cfg(all(unix, feature = "std"))]
pub mod ashmem_server;

#[cfg(unix)]
pub mod unix_signals;
#[cfg(all(windows, feature = "std"))]
pub mod windows_exceptions;
