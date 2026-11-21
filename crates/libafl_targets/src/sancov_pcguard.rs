//! [`LLVM` `PcGuard`](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards) runtime for `LibAFL`.

#[rustversion::nightly]
#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ngram8"))]
use core::simd::num::SimdUint;
#[cfg(any(
    feature = "sancov_pcguard_dump_cov",
    all(feature = "coverage", feature = "pointer_maps")
))]
use core::sync::atomic::AtomicPtr;
use core::{
    cell::UnsafeCell,
    slice,
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(any(
    feature = "sancov_ngram4",
    feature = "sancov_ctx",
    feature = "sancov_ngram8"
))]
#[rustversion::nightly]
use libafl::executors::hooks::ExecutorHook;

#[cfg(feature = "coverage")]
use crate::EDGES_MAP_ALLOCATED_SIZE;
#[cfg(any(
    feature = "sancov_ngram4",
    feature = "sancov_ngram8",
    feature = "sancov_ctx"
))]
#[allow(unused_imports)] // only used in an unused function
use crate::EDGES_MAP_DEFAULT_SIZE;
#[cfg(feature = "coverage")]
use crate::coverage::EDGES_MAP;
#[cfg(all(feature = "coverage", feature = "pointer_maps"))]
use crate::coverage::EDGES_MAP_PTR;
#[cfg(feature = "coverage")]
use crate::coverage::MAX_EDGES_FOUND;

#[cfg(all(feature = "sancov_pcguard_edges", feature = "sancov_pcguard_hitcounts"))]
#[cfg(not(any(doc, feature = "clippy", test)))]
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

struct PcTables {
    locked: AtomicBool,
    tables: UnsafeCell<Vec<&'static [PcTableEntry]>>,
}

// SAFETY: Access to `tables` is serialized by `locked` using Acquire/Release ordering.
unsafe impl Sync for PcTables {}

struct PcTablesUnlockGuard<'a>(&'a AtomicBool);

impl Drop for PcTablesUnlockGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl PcTables {
    const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            tables: UnsafeCell::new(Vec::new()),
        }
    }

    fn with_lock<R>(&self, f: impl FnOnce(&mut Vec<&'static [PcTableEntry]>) -> R) -> R {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let _guard = PcTablesUnlockGuard(&self.locked);
        // SAFETY: Exclusive access is guaranteed while `self.locked` is held.
        f(unsafe { &mut *self.tables.get() })
    }
}

static PC_TABLES: PcTables = PcTables::new();

/// Type for the PC guard hook
pub type PcGuardHook = unsafe extern "C" fn(*mut u32);

/// Type for the target PC guard hook (with PC)
#[cfg(feature = "sancov_pcguard_dump_cov")]
pub type TargetPcGuardHook = unsafe extern "C" fn(*mut u32, usize);

/// Function ptr that does nothing.
#[cfg(feature = "sancov_pcguard_dump_cov")]
pub(crate) unsafe extern "C" fn nop_target_pc_guard(_guard: *mut u32, _pc: usize) {}

/// The global hook for `__libafl_targets_trace_pc_guard`
#[cfg(feature = "sancov_pcguard_dump_cov")]
pub(crate) static LIBAFL_TARGETS_TRACE_PC_GUARD_HOOK: AtomicPtr<()> =
    AtomicPtr::new(nop_target_pc_guard as *mut ());

use alloc::vec::Vec;
#[cfg(any(
    feature = "sancov_ngram4",
    feature = "sancov_ngram8",
    feature = "sancov_ctx"
))]
#[rustversion::nightly]
use core::marker::PhantomData;

/// The hook to initialize ngram everytime we run the harness
#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ngram8"))]
#[rustversion::nightly]
#[derive(Debug, Copy, Clone)]
pub struct NgramHook<I, S> {
    phantom: PhantomData<(I, S)>,
}

/// The hook to initialize ctx everytime we run the harness
#[cfg(feature = "sancov_ctx")]
#[rustversion::nightly]
#[derive(Debug, Copy, Clone)]
pub struct CtxHook<I, S> {
    phantom: PhantomData<(I, S)>,
}

#[cfg(feature = "sancov_ctx")]
#[rustversion::nightly]
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
#[rustversion::nightly]
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
            let ptr = (&raw mut PREV_ARRAY_4).cast::<u32>();
            for i in 0..4 {
                core::sync::atomic::AtomicU32::from_ptr(ptr.add(i)).store(0, Ordering::Relaxed);
            }
        }

        #[cfg(feature = "sancov_ngram8")]
        unsafe {
            let ptr = (&raw mut PREV_ARRAY_8).cast::<u32>();
            for i in 0..8 {
                core::sync::atomic::AtomicU32::from_ptr(ptr.add(i)).store(0, Ordering::Relaxed);
            }
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
#[rustversion::nightly]
impl<I, S> ExecutorHook<I, S> for CtxHook<I, S> {
    fn init(&mut self, _state: &mut S) {}
    fn pre_exec(&mut self, _state: &mut S, _input: &I) {
        unsafe {
            core::sync::atomic::AtomicU32::from_ptr(&raw mut __afl_prev_ctx)
                .store(0, Ordering::Relaxed);
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
    unsafe {
        let ptr = (&raw mut PREV_ARRAY_4).cast::<u32>();
        let mut lanes = [0u32; 4];
        for (i, lane) in lanes.iter_mut().enumerate() {
            *lane = core::sync::atomic::AtomicU32::from_ptr(ptr.add(i)).load(Ordering::Relaxed);
        }
        let mut prev_array_4 = Ngram4::from_array(lanes).rotate_elements_right::<1>();
        prev_array_4.shl_assign(SHR_4);
        prev_array_4.as_mut_array()[0] = pos as u32;
        for (i, &lane) in prev_array_4.as_array().iter().enumerate() {
            core::sync::atomic::AtomicU32::from_ptr(ptr.add(i)).store(lane, Ordering::Relaxed);
        }
        reduced = prev_array_4.reduce_xor() as usize;
    }
    #[cfg(feature = "sancov_ngram8")]
    unsafe {
        let ptr = (&raw mut PREV_ARRAY_8).cast::<u32>();
        let mut lanes = [0u32; 8];
        for (i, lane) in lanes.iter_mut().enumerate() {
            *lane = core::sync::atomic::AtomicU32::from_ptr(ptr.add(i)).load(Ordering::Relaxed);
        }
        let mut prev_array_8 = Ngram8::from_array(lanes).rotate_elements_right::<1>();
        prev_array_8.shl_assign(SHR_8);
        prev_array_8.as_mut_array()[0] = pos as u32;
        for (i, &lane) in prev_array_8.as_array().iter().enumerate() {
            core::sync::atomic::AtomicU32::from_ptr(ptr.add(i)).store(lane, Ordering::Relaxed);
        }
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

#[cfg(feature = "coverage")]
unsafe extern "C" {
    /// The ctx variable
    pub static mut __afl_prev_ctx: u32;
}

#[allow(clippy::inline_always)]
#[inline(always)]
#[allow(unused_assignments)]
pub(crate) unsafe fn sanitizer_cov_pcguard_impl(guard: *mut u32) {
    unsafe {
        #[allow(unused_variables, unused_mut)] // cfg dependent
        let mut pos = *guard as usize;

        #[cfg(any(feature = "sancov_ngram4", feature = "sancov_ngram8"))]
        {
            pos = update_ngram(pos);
            // println!("Writing to {} {}", pos, EDGES_MAP_DEFAULT_SIZE);
        }

        #[cfg(feature = "sancov_ctx")]
        {
            pos ^= core::sync::atomic::AtomicU32::from_ptr(&raw mut __afl_prev_ctx)
                .load(Ordering::Relaxed) as usize;
            pos %= EDGES_MAP_DEFAULT_SIZE;
        }

        #[cfg(all(feature = "coverage", feature = "pointer_maps"))]
        #[cfg(any(feature = "sancov_pcguard_hitcounts", feature = "sancov_pcguard_edges"))]
        {
            let map_ptr = AtomicPtr::from_ptr(&raw mut EDGES_MAP_PTR).load(Ordering::Relaxed);
            #[cfg(feature = "sancov_pcguard_edges")]
            {
                map_ptr.add(pos).write(1);
            }
            #[cfg(feature = "sancov_pcguard_hitcounts")]
            {
                let addr = map_ptr.add(pos);
                let val = addr.read().wrapping_add(1);
                addr.write(val);
            }
        }
        #[cfg(all(feature = "coverage", not(feature = "pointer_maps")))]
        #[cfg(any(feature = "sancov_pcguard_hitcounts", feature = "sancov_pcguard_edges"))]
        {
            #[cfg(feature = "sancov_pcguard_edges")]
            {
                let p = (core::ptr::addr_of_mut!(EDGES_MAP) as *mut u8).add(pos);
                *p = 1;
            }
            #[cfg(feature = "sancov_pcguard_hitcounts")]
            {
                let p = (core::ptr::addr_of_mut!(EDGES_MAP) as *mut u8).add(pos);
                let val = (*p).wrapping_add(1);
                *p = val;
            }
        }
    }
}

/// Callback for sancov `pc_guard` - usually called by `llvm` on each block or edge.
///
/// # Safety
/// Dereferences `guard`, reads the position from there, then dereferences the [`EDGES_MAP`] at that position.
/// Should usually not be called directly.
#[unsafe(no_mangle)]
#[allow(unused_assignments)] // cfg dependent
#[cfg(not(feature = "sancov_pcguard_dump_cov"))]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    unsafe {
        sanitizer_cov_pcguard_impl(guard);
    }
}

/// The C shim for `__sanitizer_cov_trace_pc_guard`
///
/// # Safety
/// Dereferences `guard`, reads the position from there, then dereferences the [`EDGES_MAP`] at that position.
/// Should usually not be called directly.
#[cfg(feature = "sancov_pcguard_dump_cov")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libafl_targets_trace_pc_guard(guard: *mut u32, pc: usize) {
    unsafe {
        sanitizer_cov_pcguard_impl(guard);
        let hook_ptr = LIBAFL_TARGETS_TRACE_PC_GUARD_HOOK.load(Ordering::Relaxed);
        let hook: TargetPcGuardHook = core::mem::transmute(hook_ptr);
        (hook)(guard, pc);
    }
}

/// Initialize the sancov `pc_guard` - usually called by `llvm`.
///
/// # Safety
/// Dereferences the edges map at `start` and writes to it.
/// Should usually not be called directly, but is called by `llvm`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(
    #[allow(unused_variables)] // only used with the `coverage` feature
    start: *mut u32,
    #[allow(unused_variables)] // only used with the `coverage` feature
    stop: *mut u32,
) {
    #[cfg(all(feature = "coverage", feature = "pointer_maps"))]
    unsafe {
        let edges_ptr_atomic = AtomicPtr::from_ptr(&raw mut EDGES_MAP_PTR);
        if edges_ptr_atomic
            .compare_exchange(
                core::ptr::null_mut(),
                (&raw mut EDGES_MAP).cast::<u8>(),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
        {}
    }

    #[cfg(feature = "coverage")]
    {
        if start.is_null() || stop.is_null() || start >= stop {
            return;
        }
        assert!(
            start.is_aligned() && stop.is_aligned(),
            "Unaligned PC guard range: {start:p}..{stop:p}"
        );
        if unsafe { *start != 0 } {
            return;
        }
        let count = unsafe { stop.offset_from_unsigned(start) };
        let max_edges_atomic =
            unsafe { core::sync::atomic::AtomicUsize::from_ptr(&raw mut MAX_EDGES_FOUND) };
        let base = max_edges_atomic.fetch_add(count, Ordering::Relaxed);
        #[cfg(not(feature = "pointer_maps"))]
        {
            let edges_map_len = EDGES_MAP_ALLOCATED_SIZE;
            assert!(
                base.saturating_add(count) <= edges_map_len,
                "The number of edges reported by SanitizerCoverage exceed the size of the edges map ({edges_map_len}). Use the LIBAFL_EDGES_MAP_DEFAULT_SIZE env to increase it at compile time."
            );
        }
        for i in 0..count {
            #[cfg(feature = "pointer_maps")]
            let guard_id = (base.wrapping_add(i) % EDGES_MAP_ALLOCATED_SIZE) as u32;
            #[cfg(not(feature = "pointer_maps"))]
            let guard_id = (base + i) as u32;
            unsafe {
                *start.add(i) = guard_id;
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __sanitizer_cov_pcs_init(pcs_beg: *const usize, pcs_end: *const usize) {
    if pcs_beg.is_null() || pcs_end.is_null() || core::ptr::eq(pcs_beg, pcs_end) {
        return;
    }
    assert!(
        pcs_beg.is_aligned() && pcs_end.is_aligned() && pcs_beg < pcs_end,
        "Invalid PC Table bounds - start: {pcs_beg:x?} end: {pcs_end:x?}"
    );
    unsafe {
        let len = pcs_end.offset_from_unsigned(pcs_beg);
        assert_eq!(
            len % 2,
            0,
            "PC Table size is not even - start: {pcs_beg:x?} end: {pcs_end:x?}"
        );

        let table = slice::from_raw_parts(pcs_beg.cast::<PcTableEntry>(), len / 2);
        PC_TABLES.with_lock(|pc_tables| pc_tables.push(table));
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
    let snapshot: Vec<&'a [PcTableEntry]> = PC_TABLES.with_lock(|pc_tables| pc_tables.clone());
    snapshot.into_iter()
}

#[cfg(test)]
mod tests {
    use super::{__sanitizer_cov_pcs_init, sanitizer_cov_pc_table};

    #[test]
    fn test_pcs_init_entry_count_and_empty_bounds() {
        static SAMPLE_PCS: [usize; 4] = [0x1000, 1, 0x1008, 0];

        unsafe {
            // Empty / null bounds must be a safe no-op.
            __sanitizer_cov_pcs_init(core::ptr::null(), core::ptr::null());
            __sanitizer_cov_pcs_init(SAMPLE_PCS.as_ptr(), SAMPLE_PCS.as_ptr());

            let end = SAMPLE_PCS.as_ptr().add(SAMPLE_PCS.len());
            __sanitizer_cov_pcs_init(SAMPLE_PCS.as_ptr(), end);
        }

        let found = sanitizer_cov_pc_table()
            .find(|tbl| !tbl.is_empty() && tbl[0].addr() == 0x1000)
            .expect("registered PC table must be present");
        // 4 usize words == 2 PcTableEntry items (not 4!).
        assert_eq!(found.len(), 2);
        assert!(found[0].is_function_entry());
        assert_eq!(found[1].addr(), 0x1008);
        assert!(!found[1].is_function_entry());
    }
}
