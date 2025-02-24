//! # logger
//! This module provides an implementation of a logger which can be used to
//! provide logging information about the operation of the `asan` library
//! during execution.
#[cfg(feature = "libc")]
pub mod libc;

#[cfg(feature = "linux")]
pub mod linux;

use core::ffi::{c_char, CStr};

use log::trace;

/// # Safety
/// `msg` must be a pointer to a zero-terminated string
#[no_mangle]
pub unsafe extern "C" fn log_trace(msg: *const c_char) {
    if msg.is_null() {
        return;
    }
    let c_str = unsafe { CStr::from_ptr(msg) };
    if let Ok(rust_str) = c_str.to_str() {
        trace!("{}", rust_str);
    }
}
