//! # asan
//!
//! `asan` is a library intended to be used by a guest running in QEMU to
//! support address sanitizer.
//!
//! It has a modular design intended to support different use cases and
//! environments. The following initial variants are proposed:
//!
//! - `qasan` - Intended as a drop in replacement for the original libqasan,
//!   this will have dependency on `libc` and will interact with QEMU using the
//!   bespoke syscall interface to perform memory tracking and shadowing.
//! - `gasan` - This is similar to `qasan`, but rather than having QEMU perform
//!   the management of the shadow memory and memory tracking, this work will be
//!   carried out purely in the guest (and hence should be more performant).
//! - `zasan` - This variant is intended to have no dependencies on libc, nor
//!   any other libraries. It is intended to be used in bare-metal targets or
//!   targets which have statically linked `libc`.
//!
//! The following ancilliary crates are provided as follows:
//! - `dummy_libc` - A dummy libc library used during linking which provides
//!   only the symbols `dlsym` and `dlerror`. This is intended to ensure that
//!   `gasan` and `qasan` do not have any direct dependency on libc and hence
//!   avoids the possibility of accidental re-entrancy. (e.g. in the case that
//!   we have hooked a function such as `malloc` and in our handling of the call
//!   inadvertently call `malloc`, or one of our other hooked functions
//!   ourselves).
//! - `fuzz` - A few different fuzzing harnesses used to test `asan`.
//!
//! The componentized nature of the design is intended to permit the user to
//! adapt `asan` to their needs with minimal modification by selecting and
//! combining alternative implementations of the various key components.
#![cfg_attr(not(feature = "test"), no_std)]
#![cfg_attr(target_arch = "powerpc", feature(asm_experimental_arch))]
#![cfg_attr(feature = "document-features", doc = document_features::document_features!())]

pub mod allocator;

#[cfg(not(feature = "test"))]
pub mod arch;

pub mod exit;

#[cfg(feature = "hooks")]
pub mod hooks;

#[cfg(feature = "host")]
pub mod host;

pub mod logger;

pub mod maps;

#[cfg(not(feature = "test"))]
pub mod mem;

pub mod mmap;

#[cfg(not(feature = "test"))]
mod nostd;

pub mod patch;

pub mod shadow;

pub mod symbols;

#[cfg(feature = "test")]
pub mod test;

#[cfg(feature = "test")]
pub use test::*;

pub mod tracking;

extern crate alloc;

pub type GuestAddr = usize;

#[cfg(all(feature = "linux", not(feature = "libc")))]
#[allow(non_camel_case_types)]
pub type size_t = usize;

#[cfg(feature = "libc")]
#[allow(non_camel_case_types)]
pub type size_t = libc::size_t;

#[cfg(all(feature = "linux", not(feature = "libc")))]
#[allow(non_camel_case_types)]
pub type ssize_t = isize;

#[cfg(feature = "libc")]
#[allow(non_camel_case_types)]
pub type ssize_t = libc::ssize_t;

#[cfg(all(feature = "linux", not(feature = "libc")))]
#[allow(non_camel_case_types)]
pub type wchar_t = i32;

#[cfg(feature = "libc")]
#[allow(non_camel_case_types)]
pub type wchar_t = libc::wchar_t;

#[cfg(all(feature = "linux", not(feature = "libc")))]
#[allow(non_camel_case_types)]
pub type off_t = isize;

#[cfg(feature = "libc")]
#[allow(non_camel_case_types)]
pub type off_t = libc::off_t;

#[cfg(not(feature = "test"))]
use ::core::ffi::{c_char, c_void};

#[cfg(not(feature = "test"))]
unsafe extern "C" {
    pub fn asan_load(addr: *const c_void, size: usize);
    pub fn asan_store(addr: *const c_void, size: usize);
    pub fn asan_alloc(len: usize, align: usize) -> *mut c_void;
    pub fn asan_dealloc(addr: *const c_void);
    pub fn asan_get_size(addr: *const c_void) -> usize;
    pub fn asan_sym(name: *const c_char) -> *const c_void;
    pub fn asan_page_size() -> usize;
    pub fn asan_unpoison(addr: *mut c_void, len: usize);
    pub fn asan_track(addr: *mut c_void, len: usize);
    pub fn asan_untrack(addr: *mut c_void);
    pub fn asan_panic(msg: *const c_char) -> !;
    pub fn asan_swap(enabled: bool);
}
