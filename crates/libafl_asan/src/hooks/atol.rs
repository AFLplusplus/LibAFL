use core::ffi::{c_char, c_long};

use log::trace;

use super::atoi::parse_c_int;

/// # Safety
/// See man pages
#[unsafe(export_name = "patch_atol")]
pub unsafe extern "C" fn atol(s: *const c_char) -> c_long {
    unsafe {
        trace!("atol - s: {s:p}");
        parse_c_int(
            s,
            c_long::MAX as u64,
            c"atol - s is null",
            c"atol - overflow",
        ) as c_long
    }
}
