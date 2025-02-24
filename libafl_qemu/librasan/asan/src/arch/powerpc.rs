use core::ffi::{c_int, c_void};

use crate::size_t;

#[allow(non_camel_case_types)]
type pid_t = i32;

// Rustix does not currently implement these necessary symbols for powerpc.
#[no_mangle]
pub unsafe extern "C" fn mmap64(
    _addr: *mut c_void,
    _length: usize,
    _prot: c_int,
    _flags: c_int,
    _fd: c_int,
    _offset: u64,
) -> *mut c_void {
    unimplemented!();
}

#[no_mangle]
pub unsafe extern "C" fn __errno_location() -> *mut c_int {
    unimplemented!();
}

#[no_mangle]
pub unsafe extern "C" fn kill(_pid: pid_t, _sig: c_int) -> c_int {
    unimplemented!();
}

#[no_mangle]
pub unsafe extern "C" fn posix_madvise(_addr: *mut c_void, _len: size_t, _advice: c_int) -> c_int {
    unimplemented!();
}

#[no_mangle]
pub unsafe extern "C" fn madvise(_addr: *mut c_void, _len: size_t, _advice: c_int) -> c_int {
    unimplemented!();
}
