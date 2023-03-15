//! Bolts are no conceptual fuzzing elements, but they keep libafl-based fuzzers together.

pub mod anymap;
#[cfg(feature = "std")]
pub mod build_id;
#[cfg(all(
    any(feature = "cli", feature = "frida_cli", feature = "qemu_cli"),
    feature = "std"
))]
pub mod cli;
#[cfg(feature = "llmp_compression")]
pub mod compress;
#[cfg(feature = "std")]
pub mod core_affinity;
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

use alloc::{string::String, vec::Vec};
use core::{iter::Iterator, ops::AddAssign, time};
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use crate::Error;

/// The client ID == the sender id.
#[repr(transparent)]
#[derive(
    Debug, Default, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct ClientId(pub u32);

#[cfg(feature = "std")]
use log::{Metadata, Record};

/// Can be converted to a slice
pub trait AsSlice {
    /// Type of the entries in this slice
    type Entry;
    /// Convert to a slice
    fn as_slice(&self) -> &[Self::Entry];
}

/// Can be converted to a mutable slice
pub trait AsMutSlice {
    /// Type of the entries in this mut slice
    type Entry;
    /// Convert to a slice
    fn as_mut_slice(&mut self) -> &mut [Self::Entry];
}

impl<T> AsSlice for Vec<T> {
    type Entry = T;

    fn as_slice(&self) -> &[Self::Entry] {
        self
    }
}

impl<T> AsMutSlice for Vec<T> {
    type Entry = T;

    fn as_mut_slice(&mut self) -> &mut [Self::Entry] {
        self
    }
}

impl<T> AsSlice for &[T] {
    type Entry = T;

    fn as_slice(&self) -> &[Self::Entry] {
        self
    }
}

impl<T> AsSlice for [T] {
    type Entry = T;

    fn as_slice(&self) -> &[Self::Entry] {
        self
    }
}

impl<T> AsMutSlice for &mut [T] {
    type Entry = T;

    fn as_mut_slice(&mut self) -> &mut [Self::Entry] {
        self
    }
}

impl<T> AsMutSlice for [T] {
    type Entry = T;

    fn as_mut_slice(&mut self) -> &mut [Self::Entry] {
        self
    }
}

/// Create an `Iterator` from a reference
pub trait AsIter<'it> {
    /// The item type
    type Item: 'it;
    /// The iterator type
    type IntoIter: Iterator<Item = &'it Self::Item>;

    /// Create an iterator from &self
    fn as_iter(&'it self) -> Self::IntoIter;
}

/// Create an `Iterator` from a mutable reference
pub trait AsIterMut<'it> {
    /// The item type
    type Item: 'it;
    /// The iterator type
    type IntoIter: Iterator<Item = &'it mut Self::Item>;

    /// Create an iterator from &mut self
    fn as_iter_mut(&'it mut self) -> Self::IntoIter;
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

/// Trait to truncate slices and maps to a new size
pub trait Truncate {
    /// Reduce the size of the slice
    fn truncate(&mut self, len: usize);
}

/// Current time
#[cfg(feature = "std")]
#[must_use]
#[inline]
pub fn current_time() -> time::Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

// external defined function in case of `no_std`
//
// Define your own `external_current_millis()` function via `extern "C"`
// which is linked into the binary and called from here.
#[cfg(not(feature = "std"))]
extern "C" {
    //#[no_mangle]
    fn external_current_millis() -> u64;
}

/// Current time (fixed fallback for `no_std`)
#[cfg(not(feature = "std"))]
#[inline]
#[must_use]
pub fn current_time() -> time::Duration {
    let millis = unsafe { external_current_millis() };
    time::Duration::from_millis(millis)
}

/// Given a u64 number, return a hashed number using this mixing function
/// This function is used to hash an address into a more random number (used in `libafl_frida`).
/// Mixing function: <http://mostlymangling.blogspot.com/2018/07/on-mixing-functions-in-fast-splittable.html>
#[inline]
#[must_use]
pub fn xxh3_rrmxmx_mixer(v: u64) -> u64 {
    let tmp = (v >> 32) + ((v & 0xffffffff) << 32);
    let bitflip = 0x1cad21f72c81017c ^ 0xdb979082e96dd4de;
    let mut h64 = tmp ^ bitflip;
    h64 = h64.rotate_left(49) & h64.rotate_left(24);
    h64 = h64.wrapping_mul(0x9FB21C651E98DF25);
    h64 ^= (h64 >> 35) + 8;
    h64 = h64.wrapping_mul(0x9FB21C651E98DF25);
    h64 ^= h64 >> 28;
    h64
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

/// Calculates the cumulative sum for a slice, in-place.
/// The values are useful for example for cumulative probabilities.
///
/// So, to give an example:
/// ```rust
/// use libafl::bolts::calculate_cumulative_sum_in_place;
///
/// let mut value = [2, 4, 1, 3];
/// calculate_cumulative_sum_in_place(&mut value);
/// assert_eq!(&[2, 6, 7, 10], &value);
/// ```
pub fn calculate_cumulative_sum_in_place<T>(mut_slice: &mut [T])
where
    T: Default + AddAssign<T> + Copy,
{
    let mut acc = T::default();

    for val in mut_slice {
        acc += *val;
        *val = acc;
    }
}

/// Stderr logger
#[cfg(feature = "std")]
pub static LIBAFL_STDERR_LOGGER: SimpleStderrLogger = SimpleStderrLogger::new();

/// Stdout logger
#[cfg(feature = "std")]
pub static LIBAFL_STDOUT_LOGGER: SimpleStdoutLogger = SimpleStdoutLogger::new();

/// A simple logger struct that logs to stderr when used with [`log::set_logger`].
#[derive(Debug)]
#[cfg(feature = "std")]
pub struct SimpleStdoutLogger {}

#[cfg(feature = "std")]
impl Default for SimpleStdoutLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl SimpleStdoutLogger {
    /// Create a new [`log::Log`] logger that will wrte log to stdout
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// register stdout logger
    pub fn set_logger() -> Result<(), Error> {
        log::set_logger(&LIBAFL_STDOUT_LOGGER)
            .map_err(|_| Error::unknown("Failed to register logger"))
    }
}

#[cfg(feature = "std")]
impl log::Log for SimpleStdoutLogger {
    #[inline]
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        println!(
            "[{:?}] {}: {}",
            current_time(),
            record.level(),
            record.args()
        );
    }

    fn flush(&self) {}
}

/// A simple logger struct that logs to stderr when used with [`log::set_logger`].
#[derive(Debug)]
#[cfg(feature = "std")]
pub struct SimpleStderrLogger {}

#[cfg(feature = "std")]
impl Default for SimpleStderrLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl SimpleStderrLogger {
    /// Create a new [`log::Log`] logger that will wrte log to stdout
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// register stderr logger
    pub fn set_logger() -> Result<(), Error> {
        log::set_logger(&LIBAFL_STDERR_LOGGER)
            .map_err(|_| Error::unknown("Failed to register logger"))
    }
}

#[cfg(feature = "std")]
impl log::Log for SimpleStderrLogger {
    #[inline]
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        eprintln!(
            "[{:?}] {}: {}",
            current_time(),
            record.level(),
            record.args()
        );
    }

    fn flush(&self) {}
}
/// The purpose of this module is to alleviate imports of the bolts by adding a glob import.
#[cfg(feature = "prelude")]
pub mod bolts_prelude {
    #[cfg(feature = "std")]
    pub use super::build_id::*;
    #[cfg(all(
        any(feature = "cli", feature = "frida_cli", feature = "qemu_cli"),
        feature = "std"
    ))]
    pub use super::cli::*;
    #[cfg(feature = "llmp_compression")]
    pub use super::compress::*;
    #[cfg(feature = "std")]
    pub use super::core_affinity::*;
    #[cfg(feature = "std")]
    pub use super::fs::*;
    #[cfg(feature = "std")]
    pub use super::launcher::*;
    #[cfg(all(feature = "std", unix))]
    pub use super::minibsod::*;
    #[cfg(feature = "std")]
    pub use super::staterestore::*;
    pub use super::{
        anymap::*, cpu::*, llmp::*, os::*, ownedref::*, rands::*, serdeany::*, shmem::*, tuples::*,
    };
}
