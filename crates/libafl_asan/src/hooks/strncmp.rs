use core::{
    cmp::Ordering,
    ffi::{c_char, c_int, c_void},
};

use log::trace;

use crate::{asan_load, asan_panic, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_strncmp")]
pub unsafe extern "C" fn strncmp(cs: *const c_char, ct: *const c_char, n: size_t) -> c_int {
    unsafe {
        trace!("strncmp - cs: {cs:p}, ct: {ct:p}, n: {n:#x}");

        if n == 0 {
            return 0;
        }

        if cs.is_null() {
            asan_panic(c"strncmp - cs is null".as_ptr() as *const c_char);
        }

        if ct.is_null() {
            asan_panic(c"strncmp - ct is null".as_ptr() as *const c_char);
        }

        let mut checked = 0;
        let mut diff = Ordering::Equal;
        while checked < n {
            let b1 = *cs.cast::<u8>().add(checked);
            let b2 = *ct.cast::<u8>().add(checked);
            checked += 1;
            diff = b1.cmp(&b2);
            if diff != Ordering::Equal || b1 == 0 {
                break;
            }
        }
        asan_load(cs as *const c_void, checked);
        asan_load(ct as *const c_void, checked);
        diff as c_int
    }
}
