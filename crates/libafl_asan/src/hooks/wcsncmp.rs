use core::{
    cmp::Ordering,
    ffi::{c_char, c_int, c_void},
};

use log::trace;

use crate::{asan_load, asan_panic, size_t, wchar_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_wcsncmp")]
pub unsafe extern "C" fn wcsncmp(cs: *const wchar_t, ct: *const wchar_t, n: size_t) -> c_int {
    unsafe {
        trace!("wcsncmp - cs: {cs:p}, ct: {ct:p}, n: {n:#x}");

        if n == 0 {
            return 0;
        }

        if cs.is_null() {
            asan_panic(c"wcsncmp - cs is null".as_ptr() as *const c_char);
        }

        if ct.is_null() {
            asan_panic(c"wcsncmp - ct is null".as_ptr() as *const c_char);
        }

        if !cs.is_aligned() || !ct.is_aligned() {
            asan_panic(c"wcsncmp - unaligned pointer".as_ptr() as *const c_char);
        }

        let mut checked = 0;
        let mut diff = Ordering::Equal;
        while checked < n {
            let w1 = *cs.add(checked);
            let w2 = *ct.add(checked);
            checked += 1;
            diff = w1.cmp(&w2);
            if diff != Ordering::Equal || w1 == 0 {
                break;
            }
        }
        let checked_bytes = checked * size_of::<wchar_t>();
        asan_load(cs as *const c_void, checked_bytes);
        asan_load(ct as *const c_void, checked_bytes);
        diff as c_int
    }
}
