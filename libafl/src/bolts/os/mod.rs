//! Operating System specific abstractions

#[cfg(unix)]
pub mod unix_signals;
#[cfg(windows)]
pub mod windows_exceptions;
