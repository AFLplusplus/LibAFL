use core::ffi::{CStr, c_char, c_int, c_void};

use log::trace;

use crate::{asan_load, asan_panic};

pub(super) unsafe fn parse_c_int(
    s: *const c_char,
    max_pos: u64,
    null_msg: &'static CStr,
    overflow_msg: &'static CStr,
) -> i64 {
    unsafe {
        if s.is_null() {
            asan_panic(null_msg.as_ptr());
        }

        let bytes = s.cast::<u8>();
        let mut i = 0;
        while matches!(*bytes.add(i), b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
            i += 1;
        }

        let negative = match *bytes.add(i) {
            b'-' => {
                i += 1;
                true
            }
            b'+' => {
                i += 1;
                false
            }
            _ => false,
        };

        let limit = max_pos + u64::from(negative);
        let mut val: u64 = 0;
        let mut overflow = false;
        loop {
            let b = *bytes.add(i);
            i += 1;
            if !b.is_ascii_digit() {
                break;
            }
            match val
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(b - b'0')))
            {
                Some(v) if v <= limit => val = v,
                _ => overflow = true,
            }
        }

        asan_load(s as *const c_void, i);
        if overflow {
            asan_panic(overflow_msg.as_ptr());
        }
        if negative {
            0u64.wrapping_sub(val) as i64
        } else {
            val as i64
        }
    }
}

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_atoi")]
pub unsafe extern "C" fn atoi(s: *const c_char) -> c_int {
    unsafe {
        trace!("atoi - s: {s:p}");
        parse_c_int(
            s,
            c_int::MAX as u64,
            c"atoi - s is null",
            c"atoi - overflow",
        ) as c_int
    }
}
