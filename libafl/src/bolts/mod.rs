//! Bolts are no conceptual fuzzing elements, but they keep libafl-based fuzzers together.

pub mod bindings;
#[cfg(feature = "llmp_compression")]
pub mod compress;
pub mod cpu;
#[cfg(feature = "std")]
pub mod fs;
pub mod launcher;
pub mod llmp;
pub mod os;
pub mod ownedref;
pub mod rands;
pub mod serdeany;
pub mod shmem;
#[cfg(feature = "std")]
pub mod staterestore;
pub mod tuples;

use core::time;
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

/// Can be converted to a slice
pub trait AsSlice<T> {
    /// Convert to a slice
    fn as_slice(&self) -> &[T];
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
