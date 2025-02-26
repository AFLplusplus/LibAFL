use core::{ffi::c_void, ptr::null_mut};

use log::trace;

use crate::{asan_alloc, asan_page_size, size_t};

/// # Safety
/// See man pages
#[cfg_attr(not(feature = "test"), unsafe(no_mangle))]
#[cfg_attr(feature = "test", unsafe(export_name = "patch_valloc"))]
pub unsafe extern "C" fn valloc(size: size_t) -> *mut c_void {
    unsafe {
        trace!("valloc - size: {:#x}", size);

        if size == 0 {
            null_mut()
        } else {
            asan_alloc(size, asan_page_size())
        }
    }
}
