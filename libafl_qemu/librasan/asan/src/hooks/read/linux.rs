use core::{
    ffi::{c_char, c_int, c_void},
    slice::from_raw_parts_mut,
};

use log::trace;
use rustix::{fd::BorrowedFd, io};

use crate::{asan_panic, asan_store, size_t, ssize_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_read")]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
    unsafe {
        trace!("read - fd: {:#x}, buf: {:p}, count: {:#x}", fd, buf, count);

        if buf.is_null() && count != 0 {
            asan_panic(c"read - buf is null".as_ptr() as *const c_char);
        }

        asan_store(buf, count);
        let file = BorrowedFd::borrow_raw(fd);
        let data = from_raw_parts_mut(buf as *mut u8, count as usize);
        if let Ok(ret) = io::read(file, data) {
            return ret as ssize_t;
        } else {
            return -1;
        }
    }
}
