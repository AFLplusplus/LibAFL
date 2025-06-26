use core::{
    ffi::{c_char, c_void},
    mem::size_of,
    ptr::null_mut,
};

use log::trace;

use crate::{GuestAddr, asan_alloc, asan_panic, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_memalign")]
pub unsafe extern "C" fn memalign(align: size_t, size: size_t) -> *mut c_void {
    unsafe {
        trace!("memalign - align: {align:#x}, size: {size:#x}");
        fn is_power_of_two(n: size_t) -> bool {
            n != 0 && (n & (n - 1)) == 0
        }

        if align % size_of::<GuestAddr>() != 0 {
            asan_panic(
                c"memalign - align is not a multiple of pointer size".as_ptr() as *const c_char,
            );
        } else if !is_power_of_two(align) {
            asan_panic(c"memalign - align is not a power of two".as_ptr() as *const c_char);
        } else if size == 0 {
            null_mut()
        } else {
            asan_alloc(size, align)
        }
    }
}
