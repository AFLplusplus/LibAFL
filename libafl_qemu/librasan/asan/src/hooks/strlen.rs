use core::ffi::{c_char, c_void};

use log::trace;

use crate::{asan_load, asan_panic, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_strlen")]
pub unsafe extern "C" fn strlen(cs: *const c_char) -> size_t {
    unsafe {
        trace!("strlen - cs: {cs:p}");

        if cs.is_null() {
            asan_panic(c"strlen - cs is null".as_ptr() as *const c_char);
        }

        let mut len = 0;
        while *cs.add(len) != 0 {
            len += 1;
        }
        asan_load(cs as *const c_void, len + 1);
        len
    }
}
