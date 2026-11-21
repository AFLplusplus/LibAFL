use core::{
    cmp::Ordering,
    ffi::{c_char, c_int, c_void},
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

        let mut checked = 0;
        let mut diff = Ordering::Equal;
        while checked < n {
            let b1 = *s1.cast::<u8>().add(checked);
            let b2 = *s2.cast::<u8>().add(checked);
            checked += 1;
            diff = b1.to_ascii_lowercase().cmp(&b2.to_ascii_lowercase());
            if diff != Ordering::Equal || b1 == 0 {
                break;
            }
        }
        asan_load(s1 as *const c_void, checked);
        asan_load(s2 as *const c_void, checked);
        diff as c_int
    }
}
