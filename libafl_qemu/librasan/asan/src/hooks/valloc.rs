use core::{ffi::c_void, ptr::null_mut};

use log::trace;

use crate::{asan_alloc, asan_page_size, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_valloc")]
pub unsafe extern "C" fn valloc(size: size_t) -> *mut c_void {
    unsafe {
        trace!("valloc - size: {size:#x}");

        if size == 0 {
            null_mut()
        } else {
            asan_alloc(size, asan_page_size())
        }
    }
}
