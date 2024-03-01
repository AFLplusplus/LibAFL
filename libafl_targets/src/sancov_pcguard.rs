//! [`LLVM` `PcGuard`](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards) runtime for `LibAFL`.

#[rustversion::nightly]
#[cfg(feature = "sancov_ngram4")]
use core::simd::num::SimdUint;

#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ctx"))]
use libafl::executors::{hooks::ExecutorHook, HasObservers};

#[cfg(feature = "pointer_maps")]
use crate::coverage::{EDGES_MAP_PTR, EDGES_MAP_PTR_NUM};
use crate::{
    coverage::{EDGES_MAP, MAX_EDGES_NUM},
    EDGES_MAP_SIZE,
};

#[cfg(all(feature = "sancov_pcguard_edges", feature = "sancov_pcguard_hitcounts"))]
#[cfg(not(any(doc, feature = "clippy")))]
compile_error!(
    "the libafl_targets `sancov_pcguard_edges` and `sancov_pcguard_hitcounts` features are mutually exclusive."
);

#[cfg(feature = "sancov_ngram4")]
#[rustversion::nightly]
type Ngram4 = core::simd::u32x4;

/// The array holding the previous locs. This is required for NGRAM-4 instrumentation
#[cfg(feature = "sancov_ngram4")]
#[rustversion::nightly]
pub static mut PREV_ARRAY: Ngram4 = Ngram4::from_array([0, 0, 0, 0]);

/// The hook to initialize ngram everytime we run the harness
#[cfg(feature = "sancov_ngram4")]
#[rustversion::nightly]
#[derive(Default, Debug, Clone, Copy)]
pub struct NgramHook {}

/// The hook to initialize ctx everytime we run the harness
#[cfg(feature = "sancov_ctx")]
#[derive(Default, Debug, Clone, Copy)]
pub struct CtxHook {}

#[cfg(feature = "sancov_ngram4")]
#[rustversion::nightly]
impl ExecutorHook for NgramHook {
    fn init<E: HasObservers, S>(&mut self, _state: &mut S) {}
    fn pre_exec<EM, I, S, Z>(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) {
        unsafe {
            PREV_ARRAY = Ngram4::from_array([0, 0, 0, 0]);
        }
    }
    fn post_exec<EM, I, S, Z>(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) {
    }
}

#[cfg(feature = "sancov_ctx")]
impl ExecutorHook for CtxHook {
    fn init<E: HasObservers, S>(&mut self, _state: &mut S) {}
    fn pre_exec<EM, I, S, Z>(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) {
        unsafe {
            __afl_prev_ctx = 0;
        }
    }
    fn post_exec<EM, I, S, Z>(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) {
    }
}

#[rustversion::nightly]
#[cfg(feature = "sancov_ngram4")]
unsafe fn update_ngram(mut pos: usize) -> usize {
    #[cfg(feature = "sancov_ngram4")]
    {
        PREV_ARRAY = PREV_ARRAY.rotate_elements_right::<1>();
        PREV_ARRAY.as_mut_array()[0] = pos as u32;
        let reduced = PREV_ARRAY.reduce_xor() as usize;
        pos ^= reduced;
        pos %= EDGES_MAP_SIZE;
    }
    pos
}

#[rustversion::not(nightly)]
#[cfg(feature = "sancov_ngram4")]
unsafe fn update_ngram(pos: usize) -> usize {
    pos
}

extern "C" {
    /// The ctx variable
    pub static mut __afl_prev_ctx: u32;
}

/// Callback for sancov `pc_guard` - usually called by `llvm` on each block or edge.
///
/// # Safety
/// Dereferences `guard`, reads the position from there, then dereferences the [`EDGES_MAP`] at that position.
/// Should usually not be called directly.
#[no_mangle]
#[allow(unused_assignments)]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    let mut pos = *guard as usize;

    #[cfg(feature = "sancov_ngram4")]
    {
        pos = update_ngram(pos);
        // println!("Wrinting to {} {}", pos, EDGES_MAP_SIZE);
    }

    #[cfg(feature = "sancov_ctx")]
    {
        pos ^= __afl_prev_ctx as usize;
        // println!("Wrinting to {} {}", pos, EDGES_MAP_SIZE);
    }

    #[cfg(feature = "pointer_maps")]
    {
        #[cfg(feature = "sancov_pcguard_edges")]
        {
            EDGES_MAP_PTR.add(pos).write(1);
        }
        #[cfg(feature = "sancov_pcguard_hitcounts")]
        {
            let addr = EDGES_MAP_PTR.add(pos);
            let val = addr.read().wrapping_add(1);
            addr.write(val);
        }
    }
    #[cfg(not(feature = "pointer_maps"))]
    {
        #[cfg(feature = "sancov_pcguard_edges")]
        {
            *EDGES_MAP.get_unchecked_mut(pos) = 1;
        }
        #[cfg(feature = "sancov_pcguard_hitcounts")]
        {
            let val = (*EDGES_MAP.get_unchecked(pos)).wrapping_add(1);
            *EDGES_MAP.get_unchecked_mut(pos) = val;
        }
    }
}

/// Initialize the sancov `pc_guard` - usually called by `llvm`.
///
/// # Safety
/// Dereferences at `start` and writes to it.
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) {
    #[cfg(feature = "pointer_maps")]
    if EDGES_MAP_PTR.is_null() {
        EDGES_MAP_PTR = EDGES_MAP.as_mut_ptr();
        EDGES_MAP_PTR_NUM = EDGES_MAP.len();
    }

    if start == stop || *start != 0 {
        return;
    }

    while start < stop {
        *start = MAX_EDGES_NUM as u32;
        start = start.offset(1);

        #[cfg(feature = "pointer_maps")]
        {
            MAX_EDGES_NUM = MAX_EDGES_NUM.wrapping_add(1) % EDGES_MAP_PTR_NUM;
        }
        #[cfg(not(feature = "pointer_maps"))]
        {
            MAX_EDGES_NUM = MAX_EDGES_NUM.wrapping_add(1);
            // assert!((MAX_EDGES_NUM <= EDGES_MAP.len()), "The number of edges reported by SanitizerCoverage exceed the size of the edges map ({}). Use the LIBAFL_EDGES_MAP_SIZE env to increase it at compile time.", EDGES_MAP.len());
        }
    }
}
