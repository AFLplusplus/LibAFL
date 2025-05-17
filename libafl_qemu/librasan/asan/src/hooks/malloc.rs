use core::{ffi::c_void, ptr::null_mut};

use log::trace;

use crate::{asan_alloc, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_malloc")]
pub unsafe extern "C" fn malloc(size: size_t) -> *mut c_void {
    unsafe {
        trace!("malloc - size: {size:#x}");
        if size == 0 {
            null_mut()
        } else {
            asan_alloc(size, 0)
        }
    }
}
