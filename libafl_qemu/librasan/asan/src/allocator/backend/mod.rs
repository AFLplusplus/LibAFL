//! # backend
//! The backend is responsible for allocating the underlying memory used by the
//! application. A backend should implement the `GlobalAlloc` trait. At present
//! there are two implemented backends:
//!
//! - `dlmalloc` - A pure rust allocator based on the `dlmalloc` crate.
//! - `mimalloc` - A rust allocator using the baby_mimalloc crate which wraps
//!   another backend
//!
//! A number other of possible implementations could be considered:
//! - A simple bump allocator allocating from a fixed memory buffer
//! - An allocator which calls down into the original `libc` implementation of `malloc`

#[cfg(feature = "dlmalloc")]
pub mod dlmalloc;

#[cfg(feature = "mimalloc")]
pub mod mimalloc;
