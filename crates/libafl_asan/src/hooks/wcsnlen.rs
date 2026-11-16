use core::ffi::{c_char, c_void};

use log::trace;

use crate::{asan_load, asan_panic, hooks::wcslen::wide_string_len, size_t, wchar_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_wcsnlen")]
pub unsafe extern "C" fn wcsnlen(cs: *const wchar_t, maxlen: size_t) -> size_t {
    unsafe {
        trace!("wcsnlen - cs: {cs:p}, maxlen: {maxlen:#x}");

        if maxlen == 0 {
            return 0;
        }

        if cs.is_null() {
            asan_panic(c"wcsnlen - cs is null".as_ptr() as *const c_char);
        }

        let len = wide_string_len(cs, maxlen);

        if len < maxlen {
            asan_load(cs as *const c_void, (len + 1) * size_of::<wchar_t>());
            len
        } else {
            asan_load(cs as *const c_void, maxlen * size_of::<wchar_t>());
            maxlen
        }
    }
}
