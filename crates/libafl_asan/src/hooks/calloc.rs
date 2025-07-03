use core::{
    ffi::{c_char, c_void},
    ptr::{null_mut, write_bytes},
};

use log::trace;

use crate::{asan_alloc, asan_panic, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_calloc")]
pub unsafe extern "C" fn calloc(nobj: size_t, size: size_t) -> *mut c_void {
    unsafe {
        trace!("calloc - nobj: {nobj:#x}, size: {size:#x}");
        match nobj.checked_mul(size) {
            Some(0) => null_mut(),
            Some(size) => {
                let ptr = asan_alloc(size, 0);
                write_bytes(ptr, 0, size);
                ptr
            }
            None => {
                asan_panic(c"calloc - size would overflow".as_ptr() as *const c_char);
            }
        }
    }
}
