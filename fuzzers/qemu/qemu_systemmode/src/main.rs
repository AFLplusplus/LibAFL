//! A libfuzzer-like fuzzer using qemu for binary-only coverage
#[cfg(all(target_os = "linux", feature = "classic"))]
mod fuzzer_classic;

#[cfg(all(target_os = "linux", feature = "breakpoint"))]
mod fuzzer_breakpoint;

#[cfg(all(target_os = "linux", feature = "sync_exit"))]
mod fuzzer_sync_exit;

#[cfg(target_os = "linux")]
pub fn main() {
    #[cfg(feature = "classic")]
    fuzzer_classic::fuzz();

    #[cfg(feature = "breakpoint")]
    fuzzer_breakpoint::fuzz();

    #[cfg(feature = "sync_exit")]
    fuzzer_sync_exit::fuzz();
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("qemu-user and libafl_qemu is only supported on linux!");
}
