use core::{
    ffi::{c_char, c_void},
    ptr::copy,
};

use log::trace;

use crate::{asan_alloc, asan_load, asan_panic};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_strdup")]
pub unsafe extern "C" fn strdup(cs: *const c_char) -> *mut c_char {
    unsafe {
        trace!("strdup - cs: {cs:p}");

        if cs.is_null() {
            asan_panic(c"strdup - cs is null".as_ptr() as *const c_char);
        }

        let mut len = 0;
        while *cs.add(len) != 0 {
            len += 1;
        }
        asan_load(cs as *const c_void, len + 1);

        let dest = asan_alloc(len + 1, 0) as *mut c_char;
        copy(cs, dest, len + 1);
        dest
    }
}
