use core::{
    ffi::{c_char, c_void},
    ptr::{copy_nonoverlapping, null_mut},
};

use log::trace;

use crate::{asan_alloc, asan_dealloc, asan_get_size, asan_load, asan_panic, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_reallocarray")]
pub unsafe extern "C" fn reallocarray(
    ptr: *mut c_void,
    nmemb: size_t,
    size: size_t,
) -> *mut c_void {
    unsafe {
        trace!("reallocarray - ptr: {ptr:p}, nmemb: {nmemb:#x}, size: {size:#x}",);
        match nmemb.checked_mul(size) {
            Some(size) => {
                if ptr.is_null() && size == 0 {
                    null_mut()
                } else if ptr.is_null() {
                    asan_alloc(size, 0)
                } else if size == 0 {
                    asan_dealloc(ptr);
                    null_mut()
                } else {
                    let old_size = asan_get_size(ptr);
                    asan_load(ptr, old_size);
                    let q = asan_alloc(size, 0);
                    let min = old_size.min(size);
                    copy_nonoverlapping(ptr as *const u8, q as *mut u8, min);
                    asan_dealloc(ptr);
                    q
                }
            }
            None => asan_panic(c"reallocarray - size would overflow".as_ptr() as *const c_char),
        }
    }
}
