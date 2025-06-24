use core::{
    ffi::{c_char, c_void},
    ptr::copy,
};

use log::trace;

use crate::{asan_load, asan_panic, asan_store, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_strncat")]
pub unsafe extern "C" fn strncat(s: *mut c_char, ct: *const c_char, n: size_t) -> *mut c_char {
    unsafe {
        trace!("strncat - s: {s:p}, ct: {ct:p}, n: {n:#x}");

        if n == 0 {
            return s;
        }

        if s.is_null() {
            asan_panic(c"strncat - s is null".as_ptr() as *const c_char);
        }

        if ct.is_null() {
            asan_panic(c"strncat - ct is null".as_ptr() as *const c_char);
        }

        let mut s_len = 0;
        while *s.add(s_len) != 0 {
            s_len += 1;
        }
        let mut ct_len = 0;
        while *ct.add(ct_len) != 0 {
            ct_len += 1;
        }

        let c_len = ct_len.min(n);

        asan_store(s.add(s_len) as *const c_void, c_len + 1);
        asan_load(ct as *const c_void, c_len);
        copy(ct, s.add(s_len), c_len);
        *s.add(s_len + c_len + 1) = 0;
        s
    }
}
