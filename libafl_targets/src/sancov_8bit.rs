//! [`LLVM` `8-bi-counters`](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards) runtime for `LibAFL`.
use alloc::vec::Vec;

use libafl::bolts::ownedref::OwnedMutSlice;

/// A [`Vec`] of `8-bit-counters` maps for multiple modules.
/// They are initialized by calling [`__sanitizer_cov_8bit_counters_init`](
pub static mut COUNTERS_MAPS: Vec<OwnedMutSlice<'static, u8>> = Vec::new();

/// Initialize the sancov `8-bit-counters` - usually called by `llvm`.
#[no_mangle]
#[allow(clippy::cast_sign_loss)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn __sanitizer_cov_8bit_counters_init(start: *mut u8, stop: *mut u8) {
    unsafe {
        COUNTERS_MAPS.push(OwnedMutSlice::from_raw_parts_mut(
            start,
            stop.offset_from(start) as usize,
        ));
    }
}
