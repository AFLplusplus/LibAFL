use libc::{c_int, size_t, ssize_t};

use crate::{Context, Pointer};

extern "C" {
    // ssize_t __libafl_raw_write(int fd, const void *buf, size_t count);
    fn __libafl_raw_write(fd: c_int, buf: Pointer, count: size_t) -> ssize_t;
    // ssize_t __libafl_raw_read(int fd, void *buf, size_t count)
    fn __libafl_raw_read(fd: c_int, buf: Pointer, count: size_t) -> ssize_t;
}

#[no_mangle]
pub unsafe fn write(fd: c_int, buf: Pointer, count: size_t) -> ssize_t {
    let ctx = Context::get();

    if ctx.enabled && (fd == 1 || fd == 2) {
        count as ssize_t
    } else {
        __libafl_raw_write(fd, buf, count)
    }
}

#[no_mangle]
pub unsafe fn read(fd: c_int, buf: Pointer, count: size_t) -> ssize_t {
    let ctx = Context::get();

    if ctx.enabled && fd >= 0 && fd <= 2 {
        0
    } else {
        __libafl_raw_read(fd, buf, count)
    }
}
