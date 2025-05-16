use core::{
    cmp::Ordering,
    ffi::{c_char, c_int, c_void},
    slice::from_raw_parts,
};

use log::trace;

use crate::{asan_load, asan_panic, wchar_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_wcscmp")]
pub unsafe extern "C" fn wcscmp(cs: *const wchar_t, ct: *const wchar_t) -> c_int {
    unsafe {
        trace!("wcscmp - cs: {cs:p}, ct: {ct:p}");

        if cs.is_null() {
            asan_panic(c"wcscmp - cs is null".as_ptr() as *const c_char);
        }

        if ct.is_null() {
            asan_panic(c"wcscmp - ct is null".as_ptr() as *const c_char);
        }

        let mut cs_len = 0;
        while *cs.add(cs_len) != 0 {
            cs_len += 1;
        }

        let mut ct_len = 0;
        while *ct.add(ct_len) != 0 {
            ct_len += 1;
        }

        asan_load(cs as *const c_void, size_of::<wchar_t>() * (cs_len + 1));
        asan_load(ct as *const c_void, size_of::<wchar_t>() * (ct_len + 1));

        let slice1 = from_raw_parts(cs, cs_len);
        let slice2 = from_raw_parts(ct, ct_len);

        for i in 0..cs_len.max(ct_len) {
            if i >= cs_len {
                return -1;
            }

            if i >= ct_len {
                return 1;
            }

            match slice1[i].cmp(&slice2[i]) {
                Ordering::Equal => (),
                Ordering::Less => return -1,
                Ordering::Greater => return 1,
            }
        }

        0
    }
}
