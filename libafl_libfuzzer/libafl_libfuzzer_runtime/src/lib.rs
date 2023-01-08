use core::ffi::{c_char, c_int, CStr};

pub use libafl_targets::*;

use crate::options::{LibfuzzerMode, LibfuzzerOptions};

mod fuzz;
mod options;

#[allow(non_snake_case)]
#[no_mangle]
pub fn LLVMFuzzerRunDriver(
    argc: *const c_int,
    argv: *const *const *const c_char,
    harness_fn: Option<extern "C" fn(*const u8, usize) -> c_int>,
) -> c_int {
    let harness = harness_fn
        .as_ref()
        .expect("Illegal harness provided to libafl.");
    let argc = unsafe { *argc } as isize;
    let argv = unsafe { *argv };

    let options = LibfuzzerOptions::new(
        (0..argc)
            .map(|i| unsafe { *argv.offset(i) })
            .map(|cstr| unsafe { CStr::from_ptr(cstr) })
            .map(|cstr| cstr.to_str().unwrap()),
    )
    .unwrap();
    let res = match options.mode() {
        LibfuzzerMode::Fuzz => fuzz::fuzz(options, harness),
        LibfuzzerMode::Merge => unimplemented!(),
        LibfuzzerMode::Cmin => unimplemented!(),
    };
    res.expect("Encountered error while performing libfuzzer shimming");
    return 0;
}
