use core::{
    ffi::{c_char, c_void},
    ptr::{copy, write_bytes},
};

use log::trace;

use crate::{asan_load, asan_panic, asan_store, size_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_stpncpy")]
pub unsafe extern "C" fn stpncpy(
    dst: *mut c_char,
    src: *const c_char,
    dsize: size_t,
) -> *mut c_char {
    unsafe {
        trace!("stpncpy - dst: {dst:p}, src: {src:p}, dsize: {dsize:#x}");

        if dsize == 0 {
            return dst;
        }

        if dst.is_null() {
            asan_panic(c"stpncpy - dst is null".as_ptr() as *const c_char);
        }

        if src.is_null() {
            asan_panic(c"stpncpy - src is null".as_ptr() as *const c_char);
        }

        let mut len = 0;
        while len < dsize && *src.add(len) != 0 {
            len += 1;
        }
        asan_load(
            src as *const c_void,
            if len < dsize { len + 1 } else { len },
        );
        asan_store(dst as *const c_void, dsize);

        copy(src, dst, len);
        write_bytes(dst.add(len), 0, dsize - len);
        dst.add(len)
    }
}
