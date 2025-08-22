use core::ffi::c_void;

use log::trace;

use crate::asan_dealloc;

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_free")]
pub unsafe extern "C" fn free(p: *mut c_void) {
    unsafe {
        trace!("free - p: {p:p}");
        asan_dealloc(p);
    }
}
