use core::ffi::{c_char, c_int, c_void};

use log::trace;
use syscalls::{Sysno, syscall3};

use crate::{asan_panic, asan_store, size_t, ssize_t};

/// # Safety
/// See man pages
#[cfg_attr(not(feature = "libc"), unsafe(export_name = "patch_read"))]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
    unsafe {
        trace!("read - fd: {fd:#x}, buf: {buf:p}, count: {count:#x}");

        if count != 0 {
            if buf.is_null() {
                asan_panic(c"read - buf is null".as_ptr() as *const c_char);
            }
            asan_store(buf, count);
        }
        syscall3(Sysno::read, fd as usize, buf as usize, count).map_or(-1, |ret| ret as ssize_t)
    }
}
