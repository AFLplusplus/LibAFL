#![allow(non_snake_case)]

#[cfg(any(feature = "sancov_pcguard_edges", feature = "sancov_pcguard_hitcounts"))]
#[cfg(not(any(doc, feature = "clippy")))]
compile_error!(
    "the libafl_targets `sancov_pcguard_edges` and `sancov_pcguard_hitcounts` are incompatible with `dfsan`."
);

use alloc::{string::String, vec::Vec};
use core::{
    borrow::Borrow,
    sync::atomic::{AtomicBool, Ordering},
};

pub mod dfsan_interface {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(missing_docs)]
    #![allow(unused)]
    #![allow(clippy::unreadable_literal)]
    include!(concat!(env!("OUT_DIR"), "/dfsan_interface.rs"));
}

use dfsan_interface::*;
use libafl::{
    bolts::AsSlice,
    executors::ExitKind,
    inputs::{BytesInput, HasTargetBytes},
    stages::mutational::MutatedTransform,
    Error,
};

static OBSERVER_HELD: AtomicBool = AtomicBool::new(false);

static mut NUM_FUNCS: u32 = 0;

static mut DFT_GUARDS: &'static mut [u32] = &mut [];
static mut DFT_PCS: &'static [usize] = &[];

static mut DFT_WORK: Vec<u8> = Vec::new();

// TODO before each run, clear and resize
static mut FUNC_LABELS: Vec<u8> = Vec::new();

static mut CURRENT_FUNC: u32 = 0;

pub static mut CMPLOG_ENABLED: bool = false;

unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(start: *mut u32, stop: *mut u32) {
    assert_eq!(NUM_FUNCS, 0, "DSOs are not supported by libfuzzer.");
    assert!(start < stop, "Code is not instrumented for coverage!");

    if start == stop || *start == 0 {
        return;
    }

    DFT_GUARDS = core::slice::from_raw_parts_mut(start, stop as usize - start as usize);
}

unsafe extern "C" fn __sanitizer_cov_pcs_init(pcs_beg: *const usize, pcs_end: *const usize) {
    if !DFT_PCS.is_empty() {
        return;
    }
    DFT_PCS = core::slice::from_raw_parts(pcs_beg, pcs_end as usize - pcs_beg as usize);

    assert_eq!(DFT_GUARDS.len(), DFT_PCS.len() / 2);

    for (block, guard) in DFT_PCS.iter().skip(1).step_by(2).zip(DFT_GUARDS.iter_mut()) {
        if *block & 1 != 0 {
            NUM_FUNCS += 1;
            *guard = NUM_FUNCS;
        }
    }
}

extern "C" fn __sanitizer_cov_trace_pc_indir(_: u64) {}

unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    CURRENT_FUNC = (*guard).checked_sub(1).unwrap_or(CURRENT_FUNC);
}

unsafe extern "C" fn __dfsw___sanitizer_cov_trace_switch(
    _val: u64,
    _cases: *const u64,
    l1: dfsan_label,
    _l2: dfsan_label,
) {
    FUNC_LABELS[CURRENT_FUNC as usize] |= l1;
}

macro_rules! cmplog {
    ($name:ident, $arg_type:ty) => {
        static mut $name: Vec<($arg_type, $arg_type, dfsan_label, dfsan_label)> = Vec::new();
    };
}

macro_rules! cmplog_const {
    ($name:ident, $arg_type:ty) => {
        static mut $name: Vec<($arg_type, $arg_type, dfsan_label)> = Vec::new();
    };
}

macro_rules! hook {
    ($name:ident, $cmplog:ident, $arg_type:ty) => {
        cmplog!($cmplog, $arg_type);

        unsafe extern "C" fn $name(
            arg1: $arg_type,
            arg2: $arg_type,
            l1: dfsan_label,
            l2: dfsan_label,
        ) {
            FUNC_LABELS[CURRENT_FUNC as usize] |= l1 | l2;
            if CMPLOG_ENABLED {
                $cmplog.push((arg1, arg2, l1, l2));
            }
        }
    };
}

// https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-data-flow
// const variants of sanitizer cov have the first argument as a compile-time constant, so we do not
// need to record the labels of these values
macro_rules! hook_const {
    ($name:ident, $cmplog:ident, $arg_type:ty) => {
        cmplog_const!($cmplog, $arg_type);

        unsafe extern "C" fn $name(
            arg1: $arg_type,
            arg2: $arg_type,
            _l1: dfsan_label,
            l2: dfsan_label,
        ) {
            FUNC_LABELS[CURRENT_FUNC as usize] |= l2;
            if CMPLOG_ENABLED {
                $cmplog.push((arg1, arg2, l2));
            }
        }
    };
}

hook_const!(__dfsw___sanitizer_cov_trace_const_cmp1, CMPLOG_CONST1, u8);
hook_const!(__dfsw___sanitizer_cov_trace_const_cmp2, CMPLOG_CONST2, u16);
hook_const!(__dfsw___sanitizer_cov_trace_const_cmp4, CMPLOG_CONST4, u32);
hook_const!(__dfsw___sanitizer_cov_trace_const_cmp8, CMPLOG_CONST8, u64);
hook!(__dfsw___sanitizer_cov_trace_cmp1, CMPLOG1, u8);
hook!(__dfsw___sanitizer_cov_trace_cmp2, CMPLOG2, u16);
hook!(__dfsw___sanitizer_cov_trace_cmp4, CMPLOG4, u32);
hook!(__dfsw___sanitizer_cov_trace_cmp8, CMPLOG8, u64);

pub fn create_dataflow_harness<I: HasTargetBytes>(
    f: impl Fn(&[u8]) -> ExitKind,
) -> impl Fn(&I) -> ExitKind {
    |input| {
        let target = input.target_bytes();
        let bytes = target.as_slice();

        dfsan_set_label(1, bytes.as_ptr(), bytes.len());
        f(bytes)
    }
}

pub struct DFSanObserver {
    last_funcs: Vec<u8>,
}

impl DFSanObserver {
    pub fn new() -> Result<Self, Error> {
        if OBSERVER_HELD.swap(true, Ordering::Relaxed) {
            Err(Error::illegal_state(
                "DFSanObserver already held; there can only be one at a time!",
            ))
        } else {
            Ok(Self { _hidden: () })
        }
    }
}
