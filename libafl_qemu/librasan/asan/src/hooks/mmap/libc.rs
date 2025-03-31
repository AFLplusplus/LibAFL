use core::ffi::{CStr, c_char};

use libc::{c_int, c_void};
use log::trace;

use crate::{
    GuestAddr, asan_swap, asan_sym, asan_track, asan_unpoison, off_t, size_t,
    symbols::{AtomicGuestAddr, Function, FunctionPointer},
};

#[derive(Debug)]
struct FunctionMmap;

impl Function for FunctionMmap {
    type Func = unsafe extern "C" fn(
        addr: *mut c_void,
        len: size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> *mut c_void;
    const NAME: &'static CStr = c"mmap";
}

static MMAP_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_mmap")]
pub unsafe extern "C" fn mmap(
    addr: *mut c_void,
    len: size_t,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: off_t,
) -> *mut c_void {
    unsafe {
        trace!(
            "mmap - addr: {:p}, len: {:#x}, prot: {:#x}, flags: {:#x}, fd: {:#x}, offset: {:#x}",
            addr, len, prot, flags, fd, offset
        );
        let mmap_addr = MMAP_ADDR.get_or_insert_with(|| {
            asan_sym(FunctionMmap::NAME.as_ptr() as *const c_char) as GuestAddr
        });
        asan_swap(false);
        let fn_mmap = FunctionMmap::as_ptr(mmap_addr).unwrap();
        asan_swap(true);
        let map = fn_mmap(addr, len, prot, flags, fd, offset);
        if map == libc::MAP_FAILED {
            return libc::MAP_FAILED;
        }

        asan_unpoison(map, len);
        asan_track(map, len);
        map
    }
}
