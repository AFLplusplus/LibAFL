use std::ffi::{c_char, c_int};

pub use libafl_targets::*;

use crate::options::{LibfuzzerMode, LibfuzzerOptions};

mod fuzz;
mod options;

#[allow(non_snake_case)]
#[no_mangle]
pub fn LLVMFuzzerRunDriver(
    _argc: *const c_int,
    _argv: *const *const c_char,
    harness_fn: Option<extern "C" fn(*const u8, usize) -> c_int>,
) -> c_int {
    let harness = harness_fn
        .as_ref()
        .expect("Illegal harness provided to libafl.");
    let args = Vec::from_iter(std::env::args());
    let options = LibfuzzerOptions::new(args.iter().map(|s| s.as_ref())).unwrap();
    let res = match options.mode() {
        LibfuzzerMode::Fuzz => fuzz::fuzz(options, harness),
        LibfuzzerMode::Merge => unimplemented!(),
        LibfuzzerMode::Cmin => unimplemented!(),
    };
    res.expect("Encountered error while performing libfuzzer shimming");
    return 0;
}
