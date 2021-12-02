//! A libfuzzer-like fuzzer using qemu for binary-only coverage
#[cfg(linux)]
mod fuzzer;

#[cfg(linux)]
pub fn main() {
    fuzzer::fuzz();
}

#[cfg(not(linux))]
pub fn main() {
    panic!("qemu-user and libafl_qemu is only supported on linux!");
}
