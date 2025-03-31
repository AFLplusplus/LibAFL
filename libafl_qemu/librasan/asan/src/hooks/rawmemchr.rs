use core::ffi::{c_char, c_int, c_void};

use log::trace;

use crate::{asan_load, asan_panic};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_rawmemchr")]
pub unsafe extern "C" fn rawmemchr(s: *const c_void, c: c_int) -> *mut c_void {
    unsafe {
        trace!("rawmemchr - s: {:p}, c: {:#x}", s, c);

        if s.is_null() {
            asan_panic(c"rawmemchr - s is null".as_ptr() as *const c_char);
        }

        let mut len = 0;
        let pc = s as *const c_char;
        while *pc.add(len) != c as c_char {
            len += 1;
        }
        asan_load(s, len);
        s.add(len) as *mut c_void
    }
}
