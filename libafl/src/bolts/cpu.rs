//! Architecture agnostic processor features

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
use crate::bolts::current_nanos;

// TODO: Add more architectures, using C code, see
// https://github.com/google/benchmark/blob/master/src/cycleclock.h
// Or using llvm intrinsics (if they ever should become available in stable rust?)

/// Read a timestamp for measurements.
///
/// This function is a wrapper around different ways to get a timestamp, fast.
/// In this way, an experiment only has to
/// change this implementation rather than every instead of `read_time_counter`.
/// It is using `rdtsc` on `x86_64` and `x86`.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[must_use]
pub fn read_time_counter() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(target_arch = "x86")]
    unsafe {
        core::arch::x86::_rdtsc()
    }
}

/// Read a timestamp for measurements.
///
/// This function is a wrapper around different ways to get a timestamp, fast.
/// In this way, an experiment only has to
/// change this implementation rather than every instead of [`read_time_counter`]
/// On unsupported architectures, it's falling back to normal system time, in millis.
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
#[must_use]
pub fn read_time_counter() -> u64 {
    current_nanos()
}
