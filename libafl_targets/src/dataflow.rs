#![allow(non_snake_case)]

#[cfg(any(
    feature = "sancov_pcguard_edges",
    feature = "sancov_pcguard_hitcounts",
    feature = "sancov_value_profile",
    feature = "sancov_cmplog"
))]
#[cfg(not(any(doc, feature = "clippy")))]
compile_error!(
    "the libafl_targets `sancov_pcguard_edges`, `sancov_pcguard_hitcounts`, `sancov_value_profile`, and `sancov_cmplog` are incompatible with `dfsan`."
);

use alloc::vec::Vec;
use core::{
    ffi::c_int,
    fmt::Debug,
    sync::atomic::{AtomicBool, Ordering},
};

use serde::{Deserialize, Serialize};

pub mod dfsan_interface {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(missing_docs)]
    #![allow(unused)]
    #![allow(clippy::unreadable_literal)]
    include!(concat!(env!("OUT_DIR"), "/dfsan_interface.rs"));
}

extern "C" {
    #[link_name = "libafl_dataflow_test_one_input.dfsan"]
    fn libafl_dataflow_test_one_input(data: *const u8, len: usize) -> c_int;

    #[link_name = "libafl_dataflow_test_one_input_with_labels.dfsan"]
    fn libafl_dataflow_test_one_input_with_labels(
        data: *const u8,
        len: usize,
        labels: *const u8,
    ) -> c_int;
}

use dfsan_interface::*;
use libafl::{
    bolts::{tuples::Named, AsIter, AsSlice, HasLen},
    executors::ExitKind,
    feedbacks::MaxMapFeedback,
    inputs::{HasTargetBytes, UsesInput},
    observers::{hash_slice, MapObserver, Observer},
    Error,
};

static OBSERVER_HELD: AtomicBool = AtomicBool::new(false);

static mut DFT_GUARDS: &'static mut [u32] = &mut [];
static mut DFT_PCS: &'static [usize] = &[];

// TODO before each run, clear and resize
static mut GUARD_LABELS: Vec<u8> = Vec::new();

static mut LAST_GUARD: usize = 0;

pub static mut CMPLOG_ENABLED: bool = false;

#[no_mangle]
pub unsafe fn __sanitizer_cov_trace_pc_guard_init(start: *mut u32, stop: *mut u32) {
    assert!(
        DFT_GUARDS.is_empty(),
        "DSOs are not supported by libfuzzer."
    );
    assert!(start < stop, "Code is not instrumented for coverage!");

    if start == stop || *start != 0 {
        eprintln!("Cowardly refusing to create an empty DFT guard range.");
        return;
    }

    DFT_GUARDS =
        core::slice::from_raw_parts_mut(start, stop.offset_from(start).try_into().unwrap());
}

#[no_mangle]
pub unsafe fn __sanitizer_cov_pcs_init(pcs_beg: *const usize, pcs_end: *const usize) {
    if DFT_GUARDS.is_empty() {
        return; // nothing was sanitized; fail fast
    }
    DFT_PCS =
        core::slice::from_raw_parts(pcs_beg, pcs_end.offset_from(pcs_beg).try_into().unwrap());

    assert_eq!(DFT_GUARDS.len(), DFT_PCS.len() / 2);

    println!(
        "Initialised {} DFT PCs and {} guards.",
        DFT_PCS.len(),
        DFT_GUARDS.len()
    );
}

#[no_mangle]
pub fn __sanitizer_cov_trace_pc_indir(_: u64) {}

#[no_mangle]
pub unsafe fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    LAST_GUARD = guard.offset_from(DFT_GUARDS.as_ptr()).try_into().unwrap();
}

#[no_mangle]
pub unsafe fn __dfsw___sanitizer_cov_trace_switch(
    _val: u64,
    _cases: *const u64,
    l1: dfsan_label,
    _l2: dfsan_label,
) {
    GUARD_LABELS[LAST_GUARD as usize] |= l1;
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

        #[no_mangle]
        pub unsafe fn $name(arg1: $arg_type, arg2: $arg_type, l1: dfsan_label, l2: dfsan_label) {
            let name = stringify!($name);
            println!("{}: {} ({}) {} ({})", name, arg1, l1, arg2, l2);
            GUARD_LABELS[LAST_GUARD as usize] |= l1 | l2;
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

        #[no_mangle]
        pub unsafe fn $name(arg1: $arg_type, arg2: $arg_type, _l1: dfsan_label, l2: dfsan_label) {
            let name = stringify!($name);
            GUARD_LABELS[LAST_GUARD as usize] |= l2;
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

#[derive(Debug, Serialize, Deserialize)]
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
            Ok(Self {
                last_funcs: vec![0; unsafe { DFT_GUARDS.len() }],
            })
        }
    }
}

impl Named for DFSanObserver {
    fn name(&self) -> &str {
        "dfsan-blocks"
    }
}

impl<S> Observer<S> for DFSanObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.reset_map()?;
        core::mem::swap(&mut self.last_funcs, unsafe { &mut GUARD_LABELS });
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        core::mem::swap(&mut self.last_funcs, unsafe { &mut GUARD_LABELS });
        Ok(())
    }
}

impl HasLen for DFSanObserver {
    fn len(&self) -> usize {
        self.last_funcs.len()
    }
}

impl MapObserver for DFSanObserver {
    type Entry = u8;

    fn get(&self, idx: usize) -> &Self::Entry {
        &self.last_funcs[idx]
    }

    fn get_mut(&mut self, idx: usize) -> &mut Self::Entry {
        &mut self.last_funcs[idx]
    }

    fn usable_count(&self) -> usize {
        self.last_funcs.len()
    }

    fn count_bytes(&self) -> u64 {
        self.last_funcs.iter().filter(|&&e| e != 0).count() as u64
    }

    fn hash(&self) -> u64 {
        hash_slice(&self.last_funcs)
    }

    fn initial(&self) -> Self::Entry {
        0
    }

    fn reset_map(&mut self) -> Result<(), Error> {
        self.last_funcs.clear();
        self.last_funcs.resize(unsafe { DFT_GUARDS.len() }, 0);
        Ok(())
    }

    fn to_vec(&self) -> Vec<Self::Entry> {
        self.last_funcs.clone()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        indexes
            .iter()
            .filter(|&&idx| self.last_funcs[idx] != 0)
            .count()
    }
}

impl AsSlice for DFSanObserver {
    type Entry = <DFSanObserver as MapObserver>::Entry;

    fn as_slice(&self) -> &[Self::Entry] {
        &self.last_funcs
    }
}

impl<'it> AsIter<'it> for DFSanObserver {
    type Item = <DFSanObserver as MapObserver>::Entry;
    type IntoIter = core::slice::Iter<'it, <DFSanObserver as MapObserver>::Entry>;

    fn as_iter(&'it self) -> Self::IntoIter {
        self.last_funcs.iter()
    }
}

pub type DFSanMapFeedback<S> =
    MaxMapFeedback<DFSanObserver, S, <DFSanObserver as MapObserver>::Entry>;

pub fn create_dfsan_harness<I: HasTargetBytes>() -> impl FnMut(&I) -> ExitKind {
    |input| {
        let target_bytes = input.target_bytes();
        let slice = target_bytes.as_slice();

        unsafe {
            libafl_dataflow_test_one_input(slice.as_ptr(), slice.len());
        }

        ExitKind::Ok
    }
}
