//! Bolts are no conceptual fuzzing elements, but they keep libafl-based fuzzers together.

pub mod bindings;
pub mod cpu;
pub mod launcher;
pub mod llmp;
pub mod os;
pub mod ownedref;
pub mod rands;
pub mod serdeany;
pub mod shmem;
pub mod staterestore;
pub mod tuples;

#[cfg(feature = "llmp_compression")]
pub mod compress;

use core::time;
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

/// Can be converted to a slice
pub trait AsSlice<T> {
    /// Convert to a slice
    fn as_slice(&self) -> &[T];
}

/// Current time
#[cfg(feature = "std")]
#[must_use]
#[inline]
pub fn current_time() -> time::Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

/// Current time (fixed fallback for no_std)
#[cfg(not(feature = "std"))]
#[inline]
pub fn current_time() -> time::Duration {
    // We may not have a rt clock available.
    // TODO: Make it somehow plugin-able
    time::Duration::from_millis(1)
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
