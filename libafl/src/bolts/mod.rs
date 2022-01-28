//! Bolts are no conceptual fuzzing elements, but they keep libafl-based fuzzers together.

#[cfg(any(feature = "cli", feature = "frida_cli", feature = "qemu_cli"))]
pub mod cli;
pub mod anymap;
#[cfg(feature = "llmp_compression")]
pub mod compress;
pub mod cpu;
#[cfg(feature = "std")]
pub mod fs;
#[cfg(feature = "std")]
pub mod launcher;
pub mod llmp;
#[cfg(all(feature = "std", unix))]
pub mod minibsod;
pub mod os;
pub mod ownedref;
pub mod rands;
pub mod serdeany;
pub mod shmem;
#[cfg(feature = "std")]
pub mod staterestore;
pub mod tuples;

use alloc::string::String;
use core::time;
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

/// Can be converted to a slice
pub trait AsSlice<T> {
    /// Convert to a slice
    fn as_slice(&self) -> &[T];
}

/// Can be converted to a mutable slice
pub trait AsMutSlice<T> {
    /// Convert to a slice
    fn as_mut_slice(&mut self) -> &mut [T];
}

/// Has a length field
pub trait HasLen {
    /// The length
    fn len(&self) -> usize;

    /// Returns `true` if it has no elements.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Has a ref count
pub trait HasRefCnt {
    /// The ref count
    fn refcnt(&self) -> isize;
    /// The ref count, mutable
    fn refcnt_mut(&mut self) -> &mut isize;
}

/// Current time
#[cfg(feature = "std")]
#[must_use]
#[inline]
pub fn current_time() -> time::Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

/// external defined function in case of no_std
///
/// Define your own `external_current_millis()` function via `extern "C"`
/// which is linked into the binary and called from here.
#[cfg(not(feature = "std"))]
extern "C" {
    //#[no_mangle]
    fn external_current_millis() -> u64;
}

/// Current time (fixed fallback for no_std)
#[cfg(not(feature = "std"))]
#[inline]
pub fn current_time() -> time::Duration {
    let millis = unsafe { external_current_millis() };
    time::Duration::from_millis(millis)
}

/// Gets current nanoseconds since [`UNIX_EPOCH`]
#[must_use]
#[inline]
pub fn current_nanos() -> u64 {
    current_time().as_nanos() as u64
}

/// Gets current milliseconds since [`UNIX_EPOCH`]
#[must_use]
#[inline]
pub fn current_milliseconds() -> u64 {
    current_time().as_millis() as u64
}

/// Format a `Duration` into a HMS string
#[must_use]
pub fn format_duration_hms(duration: &time::Duration) -> String {
    let secs = duration.as_secs();
    format!("{}h-{}m-{}s", (secs / 60) / 60, (secs / 60) % 60, secs % 60)
}
