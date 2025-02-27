use core::ffi::{c_int, c_void};

use log::trace;
use rustix::mm::munmap as rmunmap;

use crate::{asan_untrack, hooks::size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_munmap")]
pub unsafe extern "C" fn munmap(addr: *mut c_void, len: size_t) -> c_int {
    unsafe {
        trace!("munmap - addr: {:p}, len: {:#x}", addr, len);

        if rmunmap(addr, len).is_ok() {
            asan_untrack(addr);
            0
        } else {
            -1
        }
    }
}
