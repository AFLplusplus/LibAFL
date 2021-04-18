//! Architecture agnostic utility functions

/// Read the time counter. This is primarily used for benchmarking various components in
/// the fuzzer.
#[cfg(target_arch = "x86_64")]
pub fn read_time_counter() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}
