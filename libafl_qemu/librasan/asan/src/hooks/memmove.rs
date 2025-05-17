use core::{
    ffi::{c_char, c_void},
    ptr::copy,
};

use log::trace;

use crate::{asan_load, asan_panic, asan_store, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_memmove")]
pub unsafe extern "C" fn memmove(dest: *mut c_void, src: *const c_void, n: size_t) -> *mut c_void {
    unsafe {
        trace!("memmove - dest: {dest:p}, src: {src:p}, n: {n:#x}");

        if n == 0 {
            return dest;
        }

        if dest.is_null() {
            asan_panic(c"memmove - dest is null".as_ptr() as *const c_char);
        }

        if src.is_null() {
            asan_panic(c"memmove - src is null".as_ptr() as *const c_char);
        }

        asan_load(src, n);
        asan_store(dest, n);
        copy(src, dest, n);
        dest
    }
}
