use core::{
    ffi::{c_char, c_void},
    ptr::copy,
};

use log::trace;

use crate::{asan_load, asan_panic, asan_store, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_strncpy")]
pub unsafe extern "C" fn strncpy(dst: *mut c_char, src: *const c_char, n: size_t) -> *mut c_char {
    unsafe {
        trace!("strncpy - dst: {dst:p}, src: {src:p}, n: {n:#x}");

        if n == 0 {
            return dst;
        }

        if dst.is_null() {
            asan_panic(c"strncpy - dst is null".as_ptr() as *const c_char);
        }

        if src.is_null() {
            asan_panic(c"strncpy - src is null".as_ptr() as *const c_char);
        }

        let mut len = 0;
        while len < n && *src.add(len) != 0 {
            len += 1;
        }
        asan_store(dst as *const c_void, len);

        asan_load(src as *const c_void, len);
        copy(src, dst, len);

        dst
    }
}
