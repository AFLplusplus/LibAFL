use core::{
    ffi::{c_char, c_void},
    ptr::copy,
};

use log::trace;

use crate::{asan_load, asan_panic, asan_store, wchar_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_wcscpy")]
pub unsafe extern "C" fn wcscpy(dst: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    unsafe {
        trace!("wcscpy - dst: {dst:p}, src: {src:p}");

        if dst.is_null() {
            asan_panic(c"wcscpy - dst is null".as_ptr() as *const c_char);
        }

        if src.is_null() {
            asan_panic(c"wcscpy - src is null".as_ptr() as *const c_char);
        }

        let mut len = 0;
        while *src.add(len) != 0 {
            len += 1;
        }
        asan_load(src as *const c_void, size_of::<wchar_t>() * (len + 1));
        asan_store(dst as *const c_void, size_of::<wchar_t>() * (len + 1));
        copy(src, dst, len + 1);
        dst
    }
}
