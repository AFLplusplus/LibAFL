use core::{
    ffi::{c_char, c_int, c_void},
    slice::from_raw_parts,
};

use log::trace;

use crate::{asan_load, asan_panic};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_strchrnul")]
pub unsafe extern "C" fn strchrnul(cs: *const c_char, c: c_int) -> *mut c_char {
    unsafe {
        trace!("strchrnul - cs: {:p}, c: {:#x}", cs, c);

        if cs.is_null() {
            asan_panic(c"strchrnul - cs is null".as_ptr() as *const c_char);
        }

        let mut len = 0;
        while *cs.add(len) != 0 {
            len += 1;
        }
        asan_load(cs as *const c_void, len + 1);
        let cs_slice = from_raw_parts(cs, len);
        let pos = cs_slice.iter().position(|&x| x as c_int == c);
        match pos {
            Some(pos) => cs.add(pos) as *mut c_char,
            None => cs.add(len) as *mut c_char,
        }
    }
}
