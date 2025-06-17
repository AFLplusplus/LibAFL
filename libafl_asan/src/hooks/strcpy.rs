use core::{
    ffi::{c_char, c_void},
    ptr::copy,
};

use log::trace;

use crate::{asan_load, asan_panic, asan_store};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_strcpy")]
pub unsafe extern "C" fn strcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    unsafe {
        trace!("strcpy - dst: {dst:p}, src: {src:p}");

        if dst.is_null() {
            asan_panic(c"strcpy - dst is null".as_ptr() as *const c_char);
        }

        if src.is_null() {
            asan_panic(c"strcpy - src is null".as_ptr() as *const c_char);
        }

        let mut len = 0;
        while *src.add(len) != 0 {
            len += 1;
        }
        asan_load(src as *const c_void, len + 1);
        asan_store(dst as *const c_void, len + 1);
        copy(src, dst, len + 1);
        dst
    }
}
