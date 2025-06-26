use core::{
    ffi::{c_char, c_void},
    ptr::null_mut,
    slice::from_raw_parts,
};

use log::trace;

use crate::{asan_load, asan_panic, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_memmem")]
pub unsafe extern "C" fn memmem(
    haystack: *const c_void,
    haystacklen: size_t,
    needle: *const c_void,
    needlelen: size_t,
) -> *mut c_void {
    unsafe {
        trace!(
            "memmem - haystack: {haystack:p}, haystacklen: {haystacklen:#x}, needle: {needle:p}, needlelen: {needlelen:#x}",
        );

        if needlelen == 0 {
            return haystack as *mut c_void;
        }

        if needlelen > haystacklen {
            return null_mut();
        }

        if haystack.is_null() {
            asan_panic(c"memmem - haystack is null".as_ptr() as *const c_char);
        }

        if needle.is_null() {
            asan_panic(c"memmem - needle is null".as_ptr() as *const c_char);
        }

        asan_load(haystack, haystacklen);
        asan_load(needle, needlelen);

        let haystack_buffer = from_raw_parts(haystack as *const u8, haystacklen);
        let needle_buffer = from_raw_parts(needle as *const u8, needlelen);

        for i in 0..(haystacklen - needlelen + 1) {
            if &haystack_buffer[i..i + needlelen] == needle_buffer {
                return haystack.add(i) as *mut c_void;
            }
        }

        null_mut()
    }
}
