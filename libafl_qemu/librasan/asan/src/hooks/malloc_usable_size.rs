use core::ffi::c_void;

use log::trace;

use crate::{asan_get_size, size_t};

/// # Safety
/// See man pages
#[cfg_attr(not(feature = "test"), no_mangle)]
#[cfg_attr(feature = "test", export_name = "patch_malloc_usable_size")]
pub unsafe extern "C" fn malloc_usable_size(ptr: *mut c_void) -> size_t {
    trace!("malloc_usable_size - ptr: {:p}", ptr);
    if ptr.is_null() {
        0
    } else {
        asan_get_size(ptr)
    }
}
