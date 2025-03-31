use core::{
    ffi::{c_char, c_void},
    ptr::null_mut,
    slice::from_raw_parts,
};

use log::trace;

use crate::{asan_load, asan_panic, size_t, wchar_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_wmemchr")]
pub unsafe extern "C" fn wmemchr(cx: *const wchar_t, c: wchar_t, n: size_t) -> *mut wchar_t {
    unsafe {
        trace!("wmemchr - cx: {:p}, c: {:#x}, n: {:#x}", cx, c, n);

        if n == 0 {
            return null_mut();
        }

        if cx.is_null() && n != 0 {
            asan_panic(c"wmemchr - cx is null".as_ptr() as *const c_char);
        }

        asan_load(cx as *const c_void, n * size_of::<wchar_t>());
        let slice = from_raw_parts(cx, n);
        let pos = slice.iter().position(|&x| x == c);
        match pos {
            Some(pos) => cx.add(pos) as *mut wchar_t,
            None => null_mut(),
        }
    }
}
