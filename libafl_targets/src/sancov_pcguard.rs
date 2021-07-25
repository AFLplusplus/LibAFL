//! [`LLVM` `PcGuard`](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards) runtime for `LibAFL`.

use crate::coverage::{EDGES_MAP, EDGES_MAP_PTR, MAX_EDGES_NUM};

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
        (EDGES_MAP_PTR as *mut u8).add(pos).write_volatile(1);
    }
    #[cfg(feature = "sancov_pcguard_hitcounts")]
    {
        let val = (EDGES_MAP_PTR as *mut u8).add(pos).read_volatile();
        (EDGES_MAP_PTR as *mut u8).add(pos).write_volatile(val + 1);
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
        *start = MAX_EDGES_NUM as u32;
        start = start.offset(1);
        MAX_EDGES_NUM = MAX_EDGES_NUM.wrapping_add(1);
        if MAX_EDGES_NUM > EDGES_MAP.len() {
            panic!("The number of edges reported by SanitizerCoverage exceed the size of the edges map ({}). Use the LIBAFL_EDGES_MAP_SIZE env to increase it at compile time.", EDGES_MAP.len());
        }
    }
}
