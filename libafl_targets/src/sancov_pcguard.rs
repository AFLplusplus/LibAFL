//! [`LLVM` `PcGuard`](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards) runtime for `LibAFL`.

use crate::coverage::*;

#[cfg(all(feature = "sancov_pcguard_edges", feature = "sancov_pcguard_hitcounts"))]
#[cfg(not(any(doc, feature = "clippy")))]
compile_error!(
    "the libafl_targets `pcguard_edges` and `pcguard_hitcounts` features are mutually exclusive."
);

/// Callback for sancov `pc_guard` - usually called by `llvm` on each block or edge.
///
/// # Safety
/// Dereferences `guard`, reads the position from there, then dereferences the [`EDGES_MAP`] at that position.
/// Should usually not be called directly.
#[cfg(any(feature = "sancov_pcguard_edges", feature = "sancov_pcguard_hitcounts"))]
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    let pos = *guard as usize;
    #[cfg(feature = "sancov_pcguard_edges")]
    {
        *EDGES_MAP.get_unchecked_mut(pos) = 1;
    }
    #[cfg(feature = "sancov_pcguard_hitcounts")]
    {
        let val = (*EDGES_MAP.get_unchecked(pos) as u8).wrapping_add(1);
        *EDGES_MAP.get_unchecked_mut(pos) = val;
    }
}

/// Initialize the sancov `pc_guard` - usually called by `llvm`.
///
/// # Safety
/// Dereferences at `start` and writes to it.
#[cfg(any(feature = "sancov_pcguard_edges", feature = "sancov_pcguard_hitcounts"))]
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) {
    if start == stop || *start != 0 {
        return;
    }

    while start < stop {
        MAX_EDGES_NUM = MAX_EDGES_NUM.wrapping_add(1);
        *start = (MAX_EDGES_NUM & (EDGES_MAP_SIZE - 1)) as u32;
        start = start.offset(1);
    }
}
