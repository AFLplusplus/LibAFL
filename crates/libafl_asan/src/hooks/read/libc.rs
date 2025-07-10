use core::ffi::{CStr, c_char, c_long};

#[cfg(not(target_os = "macos"))]
use libc::SYS_read;
use libc::{c_int, c_void};
use log::trace;

use crate::{
    GuestAddr, asan_panic, asan_store, asan_swap, asan_sym, size_t, ssize_t,
    symbols::{AtomicGuestAddr, Function, FunctionPointer},
};

#[cfg(target_os = "macos")]
#[expect(non_upper_case_globals)]
const SYS_read: libc::c_long = 0x2000003;

#[derive(Debug)]
struct FunctionSyscall;

impl Function for FunctionSyscall {
    type Func = unsafe extern "C" fn(num: c_long, ...) -> c_long;
    const NAME: &'static CStr = c"syscall";
}

static SYSCALL_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_read")]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
    unsafe {
        trace!("read - fd: {fd:#x}, buf: {buf:p}, count: {count:#x}");

        if buf.is_null() && count != 0 {
            asan_panic(c"read - buf is null".as_ptr() as *const c_char);
        }

        asan_store(buf, count);
        let addr = SYSCALL_ADDR.get_or_insert_with(|| {
            asan_sym(FunctionSyscall::NAME.as_ptr() as *const c_char) as GuestAddr
        });
        let fn_syscall = FunctionSyscall::as_ptr(addr).unwrap();
        asan_swap(false);
        let ret = fn_syscall(SYS_read, fd, buf, count);
        asan_swap(true);
        ret as ssize_t
    }
}
