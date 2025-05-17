use core::ffi::c_void;

use log::trace;

use crate::{asan_get_size, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_malloc_usable_size")]
pub unsafe extern "C" fn malloc_usable_size(ptr: *mut c_void) -> size_t {
    unsafe {
        trace!("malloc_usable_size - ptr: {ptr:p}");
        if ptr.is_null() { 0 } else { asan_get_size(ptr) }
    }
}
