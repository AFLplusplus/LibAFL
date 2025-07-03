use core::{
    ffi::{c_char, c_void},
    ptr::write_bytes,
};

use log::trace;

use crate::{asan_panic, asan_store, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_explicit_bzero")]
pub unsafe extern "C" fn explicit_bzero(s: *mut c_void, len: size_t) {
    unsafe {
        trace!("explicit_bzero - s: {s:p}, len: {len:#x}");

        if len == 0 {
            return;
        }

        if s.is_null() {
            asan_panic(b"explicit_bzero - s is null".as_ptr() as *const c_char);
        }

        asan_store(s, len);
        write_bytes(s, 0, len);
    }
}
