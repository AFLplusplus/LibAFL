use core::{
    ffi::{c_char, c_longlong, c_ulonglong, c_void},
    slice::from_raw_parts,
};

use log::trace;

use crate::{asan_load, asan_panic};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_atoll")]
pub unsafe extern "C" fn atoll(s: *const c_char) -> c_longlong {
    unsafe {
        trace!("atoll - s: {s:p}");

        if s.is_null() {
            asan_panic(c"atol - s is null".as_ptr() as *const c_char);
        }

        let mut len = 0;
        while *s.add(len) != 0 {
            len += 1;
        }
        asan_load(s as *const c_void, len + 1);
        let slice = from_raw_parts(s, len);

        let mut i = 0;

        let ws = [
            0x20, /* ' ' */
            0xc,  /* \f */
            0xa,  /* \n */
            0xd,  /* \r */
            0x9,  /* \t */
            0xb,  /* \v */
        ];
        while ws.contains(&slice[i]) {
            i += 1;
        }

        let mut negative = false;
        if slice[i] == 0x2d
        /* '-' */
        {
            negative = true;
            i += 1;
        } else if slice[i] == 0x2b
        /* '+' */
        {
            i += 1;
        }

        let mut val = 0 as c_ulonglong;
        for c in slice.iter().skip(i) {
            if ('0' as c_char..='9' as c_char).contains(c) {
                match val.checked_mul(10) {
                    Some(m) => val = m,
                    None => asan_panic(c"atoi - overflow #1".as_ptr() as *const c_char),
                }
                let digit = (c - '0' as c_char) as c_ulonglong;
                match val.checked_add(digit) {
                    Some(a) => val = a,
                    None => asan_panic(c"atoi - overflow #2".as_ptr() as *const c_char),
                }
            } else {
                break;
            }
        }

        if val == 0 {
            0
        } else if negative {
            if val > (c_longlong::MAX as c_ulonglong) + 1 {
                asan_panic(c"atoi - overflow #3".as_ptr() as *const c_char);
            }
            -((val - 1) as c_longlong) - 1
        } else {
            if val > c_longlong::MAX as c_ulonglong {
                asan_panic(c"atoi - overflow #4".as_ptr() as *const c_char);
            }
            val as c_longlong
        }
    }
}
