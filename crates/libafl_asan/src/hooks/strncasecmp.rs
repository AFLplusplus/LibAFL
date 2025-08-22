use core::{
    ffi::{c_char, c_int, c_void},
    slice::from_raw_parts,
};

use log::trace;

use crate::{asan_load, asan_panic, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_strncasecmp")]
pub unsafe extern "C" fn strncasecmp(s1: *const c_char, s2: *const c_char, n: size_t) -> c_int {
    unsafe {
        trace!("strncasecmp - s1: {s1:p}, s2: {s2:p}, n: {n:#x}");

        if n == 0 {
            return 0;
        }

        if s1.is_null() {
            asan_panic(c"strncasecmp - s1 is null".as_ptr() as *const c_char);
        }

        if s2.is_null() {
            asan_panic(c"strncasecmp - s2 is null".as_ptr() as *const c_char);
        }

        let mut s1_len = 0;
        while s1_len < n && *s1.add(s1_len) != 0 {
            s1_len += 1;
        }
        let mut s2_len = 0;
        while s2_len < n && *s2.add(s2_len) != 0 {
            s2_len += 1;
        }
        asan_load(s1 as *const c_void, s1_len + 1);
        asan_load(s2 as *const c_void, s2_len + 1);

        let to_upper = |c: c_char| -> c_char {
            if ('a' as c_char..='z' as c_char).contains(&c) {
                c - 'a' as c_char + 'A' as c_char
            } else {
                c
            }
        };

        let s1_slice = from_raw_parts(s1, s1_len);
        let s2_slice = from_raw_parts(s2, s2_len);
        for i in 0..s1_len.max(s2_len) {
            if i >= s1_len {
                return -1;
            }

            if i >= s2_len {
                return 1;
            }

            let c1u = to_upper(s1_slice[i]);
            let c2u = to_upper(s2_slice[i]);

            if c1u < c2u {
                return -1;
            }

            if c1u > c2u {
                return 1;
            }
        }

        0
    }
}
