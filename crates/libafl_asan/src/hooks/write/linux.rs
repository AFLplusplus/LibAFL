use core::ffi::{c_char, c_int, c_void};

use log::trace;
use syscalls::{Sysno, syscall3};

use crate::{asan_load, asan_panic, size_t, ssize_t};

/// # Safety
/// See man pages
#[cfg_attr(not(feature = "libc"), unsafe(export_name = "patch_write"))]
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
    unsafe {
        trace!("write - fd: {fd:#x}, buf: {buf:p}, count: {count:#x}");

        if count != 0 {
            if buf.is_null() {
                asan_panic(c"write - buf is null".as_ptr() as *const c_char);
            }
            asan_load(buf, count);
        }
        syscall3(Sysno::write, fd as usize, buf as usize, count).map_or(-1, |ret| ret as ssize_t)
    }
}
