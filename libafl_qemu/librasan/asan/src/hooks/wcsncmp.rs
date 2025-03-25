use core::{
    cmp::Ordering,
    ffi::{c_char, c_int, c_void},
    slice::from_raw_parts,
};

use log::trace;

use crate::{asan_load, asan_panic, size_t, wchar_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_wcsncmp")]
pub unsafe extern "C" fn wcsncmp(cs: *const wchar_t, ct: *const wchar_t, n: size_t) -> c_int {
    unsafe {
        trace!("wcsncmp - cs: {:p}, ct: {:p}, n: {:#x}", cs, ct, n);

        if n == 0 {
            return 0;
        }

        if cs.is_null() {
            asan_panic(c"wcsncmp - cs is null".as_ptr() as *const c_char);
        }

        if ct.is_null() {
            asan_panic(c"wcsncmp - ct is null".as_ptr() as *const c_char);
        }

        let mut cs_len = 0;
        while cs_len < n && *cs.add(cs_len) != 0 {
            cs_len += 1;
        }
        let mut ct_len = 0;
        while ct_len < n && *ct.add(ct_len) != 0 {
            ct_len += 1;
        }
        asan_load(cs as *const c_void, (cs_len + 1) * size_of::<wchar_t>());
        asan_load(ct as *const c_void, (ct_len + 1) * size_of::<wchar_t>());

        let slice1 = from_raw_parts(cs as *const u32, cs_len);
        let slice2 = from_raw_parts(ct as *const u32, ct_len);

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
