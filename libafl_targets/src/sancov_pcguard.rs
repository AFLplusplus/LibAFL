//! [`LLVM` `PcGuard`](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards) runtime for `LibAFL`.

#[rustversion::nightly]
#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ngram8"))]
use core::simd::num::SimdUint;
use core::{mem::align_of, slice};

#[cfg(any(
    feature = "sancov_ngram4",
    feature = "sancov_ctx",
    feature = "sancov_ngram8"
))]
use libafl::executors::hooks::ExecutorHook;

#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ngram8"))]
#[allow(unused_imports)] // only used in an unused function
use crate::EDGES_MAP_DEFAULT_SIZE;
#[cfg(any(
    feature = "pointer_maps",
    feature = "sancov_pcguard_edges",
    feature = "sancov_pcguard_hitcounts",
    feature = "sancov_ctx",
    feature = "sancov_ngram4",
    feature = "sancov_ngram8",
))]
use crate::coverage::EDGES_MAP;
use crate::coverage::MAX_EDGES_FOUND;
#[cfg(feature = "pointer_maps")]
use crate::{EDGES_MAP_ALLOCATED_SIZE, coverage::EDGES_MAP_PTR};

#[cfg(all(feature = "sancov_pcguard_edges", feature = "sancov_pcguard_hitcounts"))]
#[cfg(not(any(doc, feature = "clippy")))]
compile_error!(
    "the libafl_targets `sancov_pcguard_edges` and `sancov_pcguard_hitcounts` features are mutually exclusive."
);

#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ngram8"))]
#[allow(unused_imports)] // only used in an unused function
use core::ops::ShlAssign;

#[cfg(feature = "sancov_ngram4")]
#[rustversion::nightly]
type Ngram4 = core::simd::u32x4;

#[cfg(feature = "sancov_ngram8")]
#[rustversion::nightly]
type Ngram8 = core::simd::u32x8;

/// The array holding the previous locs. This is required for NGRAM-4 instrumentation
#[cfg(feature = "sancov_ngram4")]
#[rustversion::nightly]
pub static mut PREV_ARRAY_4: Ngram4 = Ngram4::from_array([0, 0, 0, 0]);

/// The array holding the previous locs. This is required for NGRAM-4 instrumentation
#[cfg(feature = "sancov_ngram8")]
#[rustversion::nightly]
pub static mut PREV_ARRAY_8: Ngram8 = Ngram8::from_array([0, 0, 0, 0, 0, 0, 0, 0]);

/// We shift each of the values in ngram4 everytime we see new edges
#[cfg(feature = "sancov_ngram4")]
#[rustversion::nightly]
pub static SHR_4: Ngram4 = Ngram4::from_array([1, 1, 1, 1]);

/// We shift each of the values in ngram8 everytime we see new edges
#[cfg(feature = "sancov_ngram8")]
#[rustversion::nightly]
pub static SHR_8: Ngram8 = Ngram8::from_array([1, 1, 1, 1, 1, 1, 1, 1]);

static mut PC_TABLES: Vec<&'static [PcTableEntry]> = Vec::new();

use alloc::vec::Vec;
#[cfg(any(
    feature = "sancov_ngram4",
    feature = "sancov_ngram8",
    feature = "sancov_ctx"
))]
use core::marker::PhantomData;

/// The hook to initialize ngram everytime we run the harness
#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ngram8"))]
#[rustversion::nightly]
#[derive(Debug, Clone, Copy)]
pub struct NgramHook<I, S> {
    phantom: PhantomData<(I, S)>,
}

/// The hook to initialize ctx everytime we run the harness
#[cfg(feature = "sancov_ctx")]
#[derive(Debug, Clone, Copy)]
pub struct CtxHook<I, S> {
    phantom: PhantomData<(I, S)>,
}

#[cfg(feature = "sancov_ctx")]
impl<I, S> CtxHook<I, S> {
    /// The constructor for this struct
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "sancov_ctx")]
impl<I, S> Default for CtxHook<I, S> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ngram8"))]
#[rustversion::nightly]
impl<I, S> ExecutorHook<I, S> for NgramHook<I, S> {
    fn init(&mut self, _state: &mut S) {}
    fn pre_exec(&mut self, _state: &mut S, _input: &I) {
        #[cfg(feature = "sancov_ngram4")]
        unsafe {
            PREV_ARRAY_4 = Ngram4::from_array([0, 0, 0, 0]);
        }

        #[cfg(feature = "sancov_ngram8")]
        unsafe {
            PREV_ARRAY_8 = Ngram8::from_array([0, 0, 0, 0, 0, 0, 0, 0]);
        }
    }
    fn post_exec(&mut self, _state: &mut S, _input: &I) {}
}

#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ngram8"))]
#[rustversion::nightly]
impl<I, S> NgramHook<I, S> {
    /// The constructor for this struct
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ngram8"))]
#[rustversion::nightly]
impl<I, S> Default for NgramHook<I, S> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "sancov_ctx")]
impl<I, S> ExecutorHook<I, S> for CtxHook<I, S> {
    fn init(&mut self, _state: &mut S) {}
    fn pre_exec(&mut self, _state: &mut S, _input: &I) {
        unsafe {
            __afl_prev_ctx = 0;
        }
    }
    fn post_exec(&mut self, _state: &mut S, _input: &I) {}
}

#[rustversion::nightly]
#[expect(unused)]
#[inline]
#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ngram8"))]
unsafe fn update_ngram(pos: usize) -> usize {
    let mut reduced = pos;
    #[cfg(feature = "sancov_ngram4")]
    {
        let prev_array_4_ptr = &raw mut PREV_ARRAY_4;
        // # Safety
        // the array is valid, this function is called from a single thread.
        let prev_array_4 = unsafe { &mut *prev_array_4_ptr };
        *prev_array_4 = prev_array_4.rotate_elements_right::<1>();
        prev_array_4.shl_assign(SHR_4);
        prev_array_4.as_mut_array()[0] = pos as u32;
        reduced = prev_array_4.reduce_xor() as usize;
    }
    #[cfg(feature = "sancov_ngram8")]
    {
        let prev_array_8_ptr = &raw mut PREV_ARRAY_8;
        let prev_array_8 = unsafe { &mut *prev_array_8_ptr };
        *prev_array_8 = prev_array_8.rotate_elements_right::<1>();
        prev_array_8.shl_assign(SHR_8);
        prev_array_8.as_mut_array()[0] = pos as u32;
        reduced = prev_array_8.reduce_xor() as usize;
    }
    reduced %= EDGES_MAP_DEFAULT_SIZE;
    reduced
}

#[rustversion::not(nightly)]
#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ngram8"))]
unsafe fn update_ngram(pos: usize) -> usize {
    pos
}

unsafe extern "C" {
    /// The ctx variable
    pub static mut __afl_prev_ctx: u32;
}

/// Callback for sancov `pc_guard` - usually called by `llvm` on each block or edge.
///
/// # Safety
/// Dereferences `guard`, reads the position from there, then dereferences the [`EDGES_MAP`] at that position.
/// Should usually not be called directly.
#[unsafe(no_mangle)]
#[allow(unused_assignments)] // cfg dependent
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    unsafe {
        #[allow(unused_variables, unused_mut)] // cfg dependent
        let mut pos = *guard as usize;

        #[cfg(any(feature = "sancov_ngram4", feature = "sancov_ngram8"))]
        {
            pos = update_ngram(pos);
            // println!("Wrinting to {} {}", pos, EDGES_MAP_DEFAULT_SIZE);
        }

        #[cfg(feature = "sancov_ctx")]
        {
            pos ^= __afl_prev_ctx as usize;
            // println!("Wrinting to {} {}", pos, EDGES_MAP_DEFAULT_SIZE);
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
        #[cfg(any(feature = "sancov_pcguard_hitcounts", feature = "sancov_pcguard_edges"))]
        {
            let edges_map_ptr = &raw mut EDGES_MAP;
            let edges_map = &mut *edges_map_ptr;
            #[cfg(feature = "sancov_pcguard_edges")]
            {
                *(edges_map).get_unchecked_mut(pos) = 1;
            }
            #[cfg(feature = "sancov_pcguard_hitcounts")]
            {
                let val = (*edges_map.get_unchecked(pos)).wrapping_add(1);
                *edges_map.get_unchecked_mut(pos) = val;
            }
        }
    }
}

/// Initialize the sancov `pc_guard` - usually called by `llvm`.
///
/// # Safety
/// Dereferences at `start` and writes to it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) {
    unsafe {
        #[cfg(feature = "pointer_maps")]
        if EDGES_MAP_PTR.is_null() {
            EDGES_MAP_PTR = &raw mut EDGES_MAP as *mut u8;
        }

        if core::ptr::eq(start, stop) || *start != 0 {
            return;
        }

        while start < stop {
            *start = MAX_EDGES_FOUND as u32;
            start = start.offset(1);

            #[cfg(feature = "pointer_maps")]
            {
                MAX_EDGES_FOUND = MAX_EDGES_FOUND.wrapping_add(1) % EDGES_MAP_ALLOCATED_SIZE;
            }
            #[cfg(not(feature = "pointer_maps"))]
            {
                let edges_map_ptr = &raw const EDGES_MAP;
                let edges_map_len = (*edges_map_ptr).len();
                MAX_EDGES_FOUND = MAX_EDGES_FOUND.wrapping_add(1);
                assert!(
                    (MAX_EDGES_FOUND <= edges_map_len),
                    "The number of edges reported by SanitizerCoverage exceed the size of the edges map ({edges_map_len}). Use the LIBAFL_EDGES_MAP_DEFAULT_SIZE env to increase it at compile time."
                );
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __sanitizer_cov_pcs_init(pcs_beg: *const usize, pcs_end: *const usize) {
    // "The Unsafe Code Guidelines also notably defines that usize and isize are respectively compatible with uintptr_t and intptr_t defined in C."
    unsafe {
        let len = pcs_end.offset_from(pcs_beg);
        let Ok(len) = usize::try_from(len) else {
            panic!("Invalid PC Table bounds - start: {pcs_beg:x?} end: {pcs_end:x?}")
        };
        assert_eq!(
            len % 2,
            0,
            "PC Table size is not evens - start: {pcs_beg:x?} end: {pcs_end:x?}"
        );
        assert_eq!(
            (pcs_beg as usize) % align_of::<PcTableEntry>(),
            0,
            "Unaligned PC Table - start: {pcs_beg:x?} end: {pcs_end:x?}"
        );

        let pc_tables_ptr = &raw mut PC_TABLES;
        let pc_tables = &mut *pc_tables_ptr;
        pc_tables.push(slice::from_raw_parts(pcs_beg as *const PcTableEntry, len));
    }
}

/// An entry to the `sanitizer_cov` `pc_table`
#[repr(C, packed)]
#[derive(Debug, PartialEq, Eq)]
pub struct PcTableEntry {
    addr: usize,
    flags: usize,
}

impl PcTableEntry {
    /// Returns whether the PC corresponds to a function entry point.
    #[must_use]
    pub fn is_function_entry(&self) -> bool {
        self.flags == 0x1
    }

    /// Returns the address associated with this PC.
    #[must_use]
    pub fn addr(&self) -> usize {
        self.addr
    }
}

/// Returns an iterator over the PC tables. If no tables were registered, this will be empty.
pub fn sanitizer_cov_pc_table<'a>() -> impl Iterator<Item = &'a [PcTableEntry]> {
    // SAFETY: Once PCS_BEG and PCS_END have been initialized, will not be written to again. So
    // there's no TOCTOU issue.
    unsafe {
        let pc_tables_ptr = &raw const PC_TABLES;
        let pc_tables = &*pc_tables_ptr;
        pc_tables.iter().copied()
    }
}
