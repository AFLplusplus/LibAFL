use core::ffi::{CStr, c_char, c_int, c_void};

use libc::FILE;
use log::trace;

use crate::{
    GuestAddr, asan_load, asan_panic, asan_store, asan_swap, asan_sym,
    symbols::{AtomicGuestAddr, Function, FunctionPointer},
};

#[derive(Debug)]
struct FunctionFgets;

impl Function for FunctionFgets {
    type Func = unsafe extern "C" fn(buf: *mut c_char, n: c_int, stream: *mut FILE) -> *mut c_char;
    const NAME: &'static CStr = c"fgets";
}

static FGETS_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();

/// # Safety
/// See man pages
#[cfg_attr(not(feature = "test"), unsafe(no_mangle))]
#[cfg_attr(feature = "test", unsafe(export_name = "patch_fgets"))]
pub unsafe extern "C" fn fgets(buf: *mut c_char, n: c_int, stream: *mut FILE) -> *mut c_char {
    unsafe {
        trace!("fgets - buf: {:p}, n: {:#x}, stream: {:p}", buf, n, stream);

        if buf.is_null() && n != 0 {
            asan_panic(c"fgets - buf is null".as_ptr() as *const c_char);
        }

        if stream.is_null() {
            asan_panic(c"fgets - stream is null".as_ptr() as *const c_char);
        }

        asan_store(buf as *const c_void, n as usize);
        asan_load(stream as *const c_void, size_of::<FILE>());
        let addr = FGETS_ADDR.get_or_insert_with(|| {
            asan_sym(FunctionFgets::NAME.as_ptr() as *const c_char) as GuestAddr
        });
        let fn_fgets = FunctionFgets::as_ptr(addr).unwrap();
        asan_swap(false);
        let ret = fn_fgets(buf, n, stream);
        asan_swap(true);
        ret
    }
}
