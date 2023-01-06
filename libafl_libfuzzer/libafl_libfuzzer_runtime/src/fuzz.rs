use core::ffi::c_int;

use libafl::Error;

use crate::options::LibfuzzerOptions;

pub fn fuzz(
    options: LibfuzzerOptions,
    harness: &extern "C" fn(*const u8, usize) -> c_int,
) -> Result<(), Error> {
    let bytes = [];
    harness(bytes.as_ptr(), 0);
    Ok(())
}
