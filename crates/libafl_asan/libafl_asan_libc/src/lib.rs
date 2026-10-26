#![cfg_attr(not(feature = "test"), no_std)]
use core::ffi::{c_char, c_void};
#[cfg(all(not(feature = "test"), not(test)))]
use core::panic::PanicInfo;

/// # Safety
/// See man pages
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlsym(_handle: *mut c_void, _symbol: *const c_char) -> *mut c_void {
    todo!();
}

/// # Safety
/// See man pages
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlerror() -> *mut c_char {
    todo!();
}

#[panic_handler]
#[cfg(all(not(feature = "test"), not(test)))]
fn panic(_info: &PanicInfo) -> ! {
    unimplemented!()
}

#[cfg(target_arch = "arm")]
#[unsafe(no_mangle)]
extern "C" fn __aeabi_unwind_cpp_pr0() {
    unimplemented!()
}

#[cfg(target_arch = "powerpc")]
#[unsafe(no_mangle)]
extern "C" fn rust_eh_personality() {
    unimplemented!();
}

#[cfg(target_arch = "powerpc")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(
    _dest: *mut c_void,
    _src: *const c_void,
    _count: usize,
) -> *mut c_void {
    unimplemented!();
}

#[cfg(target_arch = "powerpc")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(_dest: *mut c_void, _value: i32, _count: usize) -> *mut c_void {
    unimplemented!();
}
