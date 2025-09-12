//! A binary-only systemmode fuzzer using qemu for binary-only coverage
#[cfg(all(target_os = "linux", feature = "low_level"))]
mod fuzzer_low_level;

#[cfg(all(target_os = "linux", feature = "breakpoint"))]
mod fuzzer_breakpoint;

#[cfg(all(target_os = "linux", feature = "custom_insn"))]
mod fuzzer_custom_insn;

#[cfg(target_os = "linux")]
pub fn main() {
    #[cfg(feature = "low_level")]
    fuzzer_low_level::fuzz();

    #[cfg(feature = "breakpoint")]
    fuzzer_breakpoint::fuzz();

    #[cfg(feature = "custom_insn")]
    fuzzer_custom_insn::fuzz();
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("qemu-user and libafl_qemu is only supported on linux!");
}
