use core::{
    ffi::{c_char, c_void},
    ptr::copy,
};

use log::trace;

use crate::{asan_load, asan_panic, asan_store};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_strcat")]
pub unsafe extern "C" fn strcat(s: *mut c_char, ct: *const c_char) -> *mut c_char {
    unsafe {
        trace!("strcat - s: {:p}, ct: {:p}", s, ct);

        if s.is_null() {
            asan_panic(c"strcat - s is null".as_ptr() as *const c_char);
        }

        if ct.is_null() {
            asan_panic(c"strcat - ct is null".as_ptr() as *const c_char);
        }

        let mut s_len = 0;
        while *s.add(s_len) != 0 {
            s_len += 1;
        }
        let mut ct_len = 0;
        while *ct.add(ct_len) != 0 {
            ct_len += 1;
        }
        asan_store(s.add(s_len) as *const c_void, ct_len + 1);
        asan_load(ct as *const c_void, ct_len + 1);
        copy(ct, s.add(s_len), ct_len + 1);
        s
    }
}
