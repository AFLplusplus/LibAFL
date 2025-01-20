//! A libfuzzer-like fuzzer using qemu for binary-only coverage
#[cfg(target_os = "linux")]
mod client;
#[cfg(target_os = "linux")]
mod fuzzer;
#[cfg(target_os = "linux")]
mod instance;
#[cfg(target_os = "linux")]
mod options;

#[cfg(target_os = "linux")]
use crate::fuzzer::Fuzzer;

#[cfg(target_os = "linux")]
pub fn main() {
    Fuzzer::new().fuzz().unwrap();
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("libafl_nyx is only supported on linux!");
}
