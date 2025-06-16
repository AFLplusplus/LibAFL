use core::{
    cmp::Ordering,
    ffi::{c_char, c_int, c_void},
    slice::from_raw_parts,
};

use log::trace;

use crate::{asan_load, asan_panic, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_bcmp")]
pub unsafe extern "C" fn bcmp(cx: *const c_void, ct: *const c_void, n: size_t) -> c_int {
    unsafe {
        trace!("bcmp - cx: {cx:p}, ct: {ct:p}, n: {n:#x}");

        if n == 0 {
            return 0;
        }

        if cx.is_null() {
            asan_panic(c"bcmp - cx is null".as_ptr() as *const c_char);
        }

        if ct.is_null() {
            asan_panic(c"bcmp - ct is null".as_ptr() as *const c_char);
        }

        asan_load(cx, n);
        asan_load(ct, n);

        let slice1 = from_raw_parts(cx as *const u8, n);
        let slice2 = from_raw_parts(ct as *const u8, n);

        for i in 0..n {
            match slice1[i].cmp(&slice2[i]) {
                Ordering::Equal => (),
                Ordering::Less => return -1,
                Ordering::Greater => return 1,
            }
        }

        0
    }
}
