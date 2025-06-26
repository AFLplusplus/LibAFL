use core::{
    ffi::{c_char, c_int, c_void},
    ptr::null_mut,
    slice::from_raw_parts,
};

use log::trace;

use crate::{asan_load, asan_panic, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_memchr")]
pub unsafe extern "C" fn memchr(cx: *const c_void, c: c_int, n: size_t) -> *mut c_void {
    unsafe {
        trace!("memchr - cx: {cx:p}, c: {c:#x}, n: {n:#x}");

        if n == 0 {
            return null_mut();
        }

        if cx.is_null() && n != 0 {
            asan_panic(c"memchr - cx is null".as_ptr() as *const c_char);
        }

        asan_load(cx, n);
        let slice = from_raw_parts(cx as *const u8, n);
        let pos = slice.iter().position(|&x| x as c_int == c);
        match pos {
            Some(pos) => cx.add(pos) as *mut c_void,
            None => null_mut(),
        }
    }
}
