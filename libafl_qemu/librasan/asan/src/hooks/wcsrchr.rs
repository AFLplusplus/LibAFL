use core::{
    ffi::{c_char, c_int, c_void},
    ptr::null_mut,
    slice::from_raw_parts,
};

use log::trace;

use crate::{asan_load, asan_panic, wchar_t};

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_wcsrchr")]
pub unsafe extern "C" fn wcsrchr(cs: *const wchar_t, c: c_int) -> *mut wchar_t {
    unsafe {
        trace!("wcsrchr - cs: {:p}, c: {:#x}", cs, c);

        if cs.is_null() {
            asan_panic(c"wcsrchr - cs is null".as_ptr() as *const c_char);
        }

        let mut len = 0;
        while *cs.add(len) != 0 {
            len += 1;
        }
        asan_load(cs as *const c_void, (len + 1) * size_of::<wchar_t>());
        let cs_slice = from_raw_parts(cs, len);
        let pos = cs_slice.iter().rev().position(|&x| x as c_int == c);
        match pos {
            Some(pos) => cs.add(len - pos - 1) as *mut wchar_t,
            None => null_mut(),
        }
    }
}
