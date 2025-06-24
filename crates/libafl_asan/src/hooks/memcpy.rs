use core::{
    ffi::{c_char, c_void},
    ptr::copy_nonoverlapping,
};

use log::trace;

use crate::{asan_load, asan_panic, asan_store, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_memcpy")]
pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: size_t) -> *mut c_void {
    unsafe {
        trace!("memcpy - dest: {dest:p}, src: {src:p}, n: {n:#x}");

        if n == 0 {
            return dest;
        }

        if dest.is_null() {
            asan_panic(c"memcpy - dest is null".as_ptr() as *const c_char);
        }

        if src.is_null() {
            asan_panic(c"memcpy - src is null".as_ptr() as *const c_char);
        }

        let src_end = src.add(n);
        let dest_end = dest.add(n) as *const c_void;
        if src_end > dest && dest_end > src {
            asan_panic(c"memcpy - overlap".as_ptr() as *const c_char);
        }

        asan_load(src, n);
        asan_store(dest, n);
        copy_nonoverlapping(src, dest, n);
        dest
    }
}
