#![allow(clippy::module_name_repetitions, clippy::missing_panics_doc)]
#![forbid(unexpected_cfgs)]

#[cfg(target_os = "linux")]
pub mod executor;
#[cfg(target_os = "linux")]
pub mod helper;
#[cfg(target_os = "linux")]
pub mod settings;
