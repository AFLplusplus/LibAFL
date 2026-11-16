use core::ffi::{c_char, c_void};

use log::trace;

use crate::{asan_load, asan_panic, size_t, wchar_t};

/// # Safety
/// `buf` must be readable up to and including its first NUL or for `max_len` elements.
#[inline]
pub(super) unsafe fn wide_string_len(buf: *const wchar_t, max_len: usize) -> usize {
    let mut len = 0;
    // Prevent LLVM from lowering this scan to a libc wcslen call.
    while len < max_len && unsafe { buf.add(len).read_volatile() } != 0 {
        len += 1;
    }
    len
}

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_wcslen")]
pub unsafe extern "C" fn wcslen(buf: *const wchar_t) -> size_t {
    unsafe {
        trace!("wcslen - buf: {buf:p}");

        if buf.is_null() {
            asan_panic(c"wcslen - buf is null".as_ptr() as *const c_char);
        }

        let len = wide_string_len(buf, usize::MAX);
        asan_load(buf as *const c_void, size_of::<wchar_t>() * (len + 1));
        len
    }
}
