//! [`LLVM` `PcGuard`](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards) runtime for `LibAFL`.

#[cfg(any(
    feature = "sancov_pcguard_edges_ptr",
    feature = "sancov_pcguard_hitcounts_ptr"
))]
use crate::coverage::EDGES_MAP_PTR;
use crate::coverage::{EDGES_MAP, MAX_EDGES_NUM};

#[cfg(all(
    feature = "sancov_pcguard_edges_ptr",
    feature = "sancov_pcguard_hitcounts_ptr"
))]
#[cfg(not(any(doc, feature = "clippy")))]
compile_error!(
    "the libafl_targets `pcguard_edges_ptr` and `pcguard_hitcounts_ptr` features are mutually exclusive."
);

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
#[cfg(any(
    feature = "sancov_pcguard_edges",
    feature = "sancov_pcguard_hitcounts",
    feature = "sancov_pcguard_edges_ptr",
    feature = "sancov_pcguard_hitcounts_ptr"
))]
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
    #[cfg(feature = "sancov_pcguard_edges_ptr")]
    {
        (EDGES_MAP_PTR as *mut u8).add(pos).write(1);
    }
    #[cfg(feature = "sancov_pcguard_hitcounts_ptr")]
    {
        let addr = (EDGES_MAP_PTR as *mut u8).add(pos);
        let val = addr.read().wrapping_add(1);
        addr.write(val);
    }
}

/// Initialize the sancov `pc_guard` - usually called by `llvm`.
///
/// # Safety
/// Dereferences at `start` and writes to it.
#[cfg(any(
    feature = "sancov_pcguard_edges",
    feature = "sancov_pcguard_hitcounts",
    feature = "sancov_pcguard_edges_ptr",
    feature = "sancov_pcguard_hitcounts_ptr"
))]
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) {
    #[cfg(any(
        feature = "sancov_pcguard_edges_ptr",
        feature = "sancov_pcguard_hitcounts_ptr"
    ))]
    if EDGES_MAP_PTR.is_null() {
        EDGES_MAP_PTR = EDGES_MAP.as_mut_ptr();
    }

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
