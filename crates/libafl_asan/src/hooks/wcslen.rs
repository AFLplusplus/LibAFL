use core::ffi::{c_char, c_void};

use log::trace;

use crate::{asan_load, asan_panic, size_t, wchar_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_wcslen")]
pub unsafe extern "C" fn wcslen(buf: *const wchar_t) -> size_t {
    unsafe {
        trace!("wcslen - buf: {buf:p}");

        if buf.is_null() {
            asan_panic(c"wcslen - buf is null".as_ptr() as *const c_char);
        }

        let mut len = 0;
        while *buf.add(len) != 0 {
            len += 1;
        }
        asan_load(buf as *const c_void, size_of::<wchar_t>() * (len + 1));
        len
    }
}
