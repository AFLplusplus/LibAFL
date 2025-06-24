use core::{
    ffi::{c_char, c_void},
    ptr::copy,
};

use log::trace;

use crate::{asan_alloc, asan_load, asan_panic, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_strndup")]
pub unsafe extern "C" fn strndup(cs: *const c_char, n: size_t) -> *mut c_char {
    unsafe {
        trace!("strndup - cs: {cs:p}, n: {n:#x}");

        if cs.is_null() {
            if n == 0 {
                let dest = asan_alloc(1, 0) as *mut c_char;
                *dest = 0;
                return dest;
            } else {
                asan_panic(c"strndup - cs is null".as_ptr() as *const c_char);
            }
        }

        let mut len = 0;
        while len < n && *cs.add(len) != 0 {
            len += 1;
        }
        asan_load(cs as *const c_void, len + 1);

        let dest = asan_alloc(len + 1, 0) as *mut c_char;
        copy(cs, dest, len + 1);
        *dest.add(len) = 0;
        dest
    }
}
