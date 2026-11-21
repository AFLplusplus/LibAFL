use core::ffi::{c_char, c_longlong};

use log::trace;

use super::atoi::parse_c_int;

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_atoll")]
pub unsafe extern "C" fn atoll(s: *const c_char) -> c_longlong {
    unsafe {
        trace!("atoll - s: {s:p}");
        parse_c_int(
            s,
            c_longlong::MAX as u64,
            c"atoll - s is null",
            c"atoll - overflow",
        ) as c_longlong
    }
}
