use core::ffi::c_void;

use log::trace;

use crate::{asan_alloc, asan_page_size, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_pvalloc")]
pub unsafe extern "C" fn pvalloc(size: size_t) -> *mut c_void {
    unsafe {
        trace!("pvalloc - size: {size:#x}");
        let page_size = asan_page_size();
        let aligned_size = if size == 0 {
            page_size
        } else {
            (size + page_size - 1) & !(page_size - 1)
        };
        assert_ne!(aligned_size, 0);
        asan_alloc(aligned_size, page_size)
    }
}
