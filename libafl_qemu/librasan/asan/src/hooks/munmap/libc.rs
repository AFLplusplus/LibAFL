use core::ffi::{CStr, c_char};

use libc::{c_int, c_void};
use log::trace;

use crate::{
    GuestAddr, asan_swap, asan_sym, asan_untrack, size_t,
    symbols::{AtomicGuestAddr, Function, FunctionPointer},
};

#[derive(Debug)]
struct FunctionMunmap;

impl Function for FunctionMunmap {
    type Func = unsafe extern "C" fn(addr: *mut c_void, len: size_t) -> c_int;
    const NAME: &'static CStr = c"munmap";
}

static MUNMAP_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_munmap")]
pub unsafe extern "C" fn munmap(addr: *mut c_void, len: size_t) -> c_int {
    unsafe {
        trace!("munmap - addr: {:p}, len: {:#x}", addr, len);
        let mmap_addr = MUNMAP_ADDR.get_or_insert_with(|| {
            asan_sym(FunctionMunmap::NAME.as_ptr() as *const c_char) as GuestAddr
        });
        asan_swap(false);
        let fn_munmap = FunctionMunmap::as_ptr(mmap_addr).unwrap();
        asan_swap(true);
        let ret = fn_munmap(addr, len);
        if ret < 0 {
            return ret;
        }

        asan_untrack(addr);
        ret
    }
}
