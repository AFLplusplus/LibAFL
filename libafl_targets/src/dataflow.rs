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
    cmp::min,
    ffi::c_int,
    fmt::Debug,
    marker::PhantomData,
    ops::Range,
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
    bolts::{
        tuples::{tuple_list_type, Named},
        AsIter, AsSlice, HasLen,
    },
    corpus::{Corpus, CorpusId},
    executors::{
        inprocess::OwnedInProcessExecutor, Executor, ExitKind, HasObservers, InProcessExecutor,
    },
    feedbacks::MaxMapFeedback,
    inputs::{HasTargetBytes, UsesInput},
    observers::{hash_slice, MapObserver, Observer, ObserversTuple},
    prelude::{tuple_list, MatchName},
    stages::Stage,
    state::{HasCorpus, UsesState},
    Error,
};

static mut DFT_GUARDS: &'static mut [u32] = &mut [];
static mut DFT_PCS: &'static [usize] = &[];

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
    GUARD_LABELS[LAST_GUARD] |= l1;
}

macro_rules! hook {
    ($name:ident, $cmplog:ident, $arg_type:ty) => {
        #[no_mangle]
        pub unsafe fn $name(arg1: $arg_type, arg2: $arg_type, l1: dfsan_label, l2: dfsan_label) {
            let name = stringify!($name);
            GUARD_LABELS
                .get_mut(LAST_GUARD)
                .map(|label| *label |= l1 | l2);
            if CMPLOG_ENABLED && (l1 != 0 || l2 != 0) {
                $cmplog.push((
                    core::mem::size_of::<$arg_type>() as u8,
                    arg1.into(),
                    arg2.into(),
                    LAST_GUARD,
                    l1,
                    l2,
                ));
            }
        }
    };
}

// https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-data-flow
// const variants of sanitizer cov have the first argument as a compile-time constant, so we do not
// need to record the labels of these values
macro_rules! hook_const {
    ($name:ident, $cmplog:ident, $arg_type:ty) => {
        #[no_mangle]
        pub unsafe fn $name(arg1: $arg_type, arg2: $arg_type, _l1: dfsan_label, l2: dfsan_label) {
            let name = stringify!($name);
            GUARD_LABELS.get_mut(LAST_GUARD).map(|label| *label |= l2);
            if CMPLOG_ENABLED && l2 != 0 {
                $cmplog.push((
                    core::mem::size_of::<$arg_type>() as u8,
                    arg1.into(),
                    arg2.into(),
                    LAST_GUARD,
                    l2,
                ));
            }
        }
    };
}

static mut CMPLOG: Vec<(u8, u64, u64, usize, dfsan_label, dfsan_label)> = Vec::new();
static mut CMPLOG_CONST: Vec<(u8, u64, u64, usize, dfsan_label)> = Vec::new();

hook!(__dfsw___sanitizer_cov_trace_cmp1, CMPLOG, u8);
hook!(__dfsw___sanitizer_cov_trace_cmp2, CMPLOG, u16);
hook!(__dfsw___sanitizer_cov_trace_cmp4, CMPLOG, u32);
hook!(__dfsw___sanitizer_cov_trace_cmp8, CMPLOG, u64);
hook_const!(__dfsw___sanitizer_cov_trace_const_cmp1, CMPLOG_CONST, u8);
hook_const!(__dfsw___sanitizer_cov_trace_const_cmp2, CMPLOG_CONST, u16);
hook_const!(__dfsw___sanitizer_cov_trace_const_cmp4, CMPLOG_CONST, u32);
hook_const!(__dfsw___sanitizer_cov_trace_const_cmp8, CMPLOG_CONST, u64);

#[derive(Debug, Serialize, Deserialize)]
pub struct DFSanObserver {
    last_guards: Vec<u8>,
}

impl DFSanObserver {
    pub fn new() -> Self {
        Self {
            last_guards: vec![0; unsafe { DFT_GUARDS.len() }],
        }
    }
}

impl Named for DFSanObserver {
    fn name(&self) -> &str {
        "dfsan-guards"
    }
}

impl<S> Observer<S> for DFSanObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.reset_map()?;
        core::mem::swap(&mut self.last_guards, unsafe { &mut GUARD_LABELS });
        unsafe {
            dfsan_flush();
        }
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        core::mem::swap(&mut self.last_guards, unsafe { &mut GUARD_LABELS });
        Ok(())
    }
}

impl HasLen for DFSanObserver {
    fn len(&self) -> usize {
        self.last_guards.len()
    }
}

impl MapObserver for DFSanObserver {
    type Entry = u8;

    fn get(&self, idx: usize) -> &Self::Entry {
        &self.last_guards[idx]
    }

    fn get_mut(&mut self, idx: usize) -> &mut Self::Entry {
        &mut self.last_guards[idx]
    }

    fn usable_count(&self) -> usize {
        self.last_guards.len()
    }

    fn count_bytes(&self) -> u64 {
        self.last_guards.iter().filter(|&&e| e != 0).count() as u64
    }

    fn hash(&self) -> u64 {
        hash_slice(&self.last_guards)
    }

    fn initial(&self) -> Self::Entry {
        0
    }

    fn reset_map(&mut self) -> Result<(), Error> {
        self.last_guards.clear();
        self.last_guards.resize(unsafe { DFT_GUARDS.len() }, 0);
        Ok(())
    }

    fn to_vec(&self) -> Vec<Self::Entry> {
        self.last_guards.clone()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        indexes
            .iter()
            .filter(|&&idx| self.last_guards[idx] != 0)
            .count()
    }
}

impl AsSlice for DFSanObserver {
    type Entry = <DFSanObserver as MapObserver>::Entry;

    fn as_slice(&self) -> &[Self::Entry] {
        &self.last_guards
    }
}

impl<'it> AsIter<'it> for DFSanObserver {
    type Item = <DFSanObserver as MapObserver>::Entry;
    type IntoIter = core::slice::Iter<'it, <DFSanObserver as MapObserver>::Entry>;

    fn as_iter(&'it self) -> Self::IntoIter {
        self.last_guards.iter()
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

#[derive(Debug, Serialize, Deserialize)]
struct DataflowCmplogObserver {
    last_cmplog: Vec<(u8, u64, u64, usize, dfsan_label, dfsan_label)>,
    last_cmplog_const: Vec<(u8, u64, u64, usize, dfsan_label)>,
}

impl Named for DataflowCmplogObserver {
    fn name(&self) -> &str {
        "dataflow-cmplog"
    }
}

impl<S> Observer<S> for DataflowCmplogObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.last_cmplog.clear();
        self.last_cmplog_const.clear();
        unsafe {
            CMPLOG_ENABLED = true;
            core::mem::swap(&mut self.last_cmplog, &mut CMPLOG);
            core::mem::swap(&mut self.last_cmplog_const, &mut CMPLOG_CONST);
        }
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        unsafe {
            CMPLOG_ENABLED = false;
            core::mem::swap(&mut self.last_cmplog, &mut CMPLOG);
            core::mem::swap(&mut self.last_cmplog_const, &mut CMPLOG_CONST);
        }
        Ok(())
    }
}

pub struct DataflowCmplogTracingStage<S>
where
    S: UsesInput,
{
    phantom: PhantomData<S>,
}

impl<S> UsesState for DataflowCmplogTracingStage<S>
where
    S: UsesInput,
{
    type State = S;
}

fn label_indices(label: dfsan_label) -> impl Iterator<Item = usize> {
    (0..8)
        .map(|i| label >> i)
        .enumerate()
        .filter_map(|(i, label)| (label & 1 != 0).then_some(i))
}

fn position_by_label(size: u8, mut labels: impl Iterator<Item = dfsan_label>) -> Option<usize> {
    let Some(first) = labels.next() else { return None; };
    let Some(second) = labels.next() else { return None; };
    if min(first, second) != (size + 1) / 2 {
        // this offset is impossible; we must be using multiple ranges or sources
        return None;
    }
    if first == 0 || second == 0 {
        // no indices were used :(
        return None;
    }
    let first_idx = label_indices(first).next().unwrap();
    let second_idx = label_indices(second).next().unwrap();
    // slightly misleading because we compare indices here zero-indexed, not 1-indexed... oh well
    // input:  [., ., ., ., ., ., ., ., ., ., ., ., ...]
    // label1: [1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, ...]
    // label2: [1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, ...]
    let mut offset = if first_idx == second_idx {
        // if they're the same, this is the low position of the offset
        2 * first_idx
    } else if second_idx == first_idx + 1 {
        // high bit
        2 * first_idx + 1
    } else if second_idx == 7 && first_idx == 0 {
        // we're at a boundary -- byte 15
        15
    } else {
        // something strange happened; these values are not actually comparable and must be based on
        // a combo which isn't valid
        return None;
    };

    for (idx, label) in labels.enumerate() {
        let mut indices = label_indices(label);
        let Some(first_idx) = indices.next() else { return None; };
        let next = match indices.next() {
            Some(7) if first_idx == 0 => 7,
            Some(second_idx) if second_idx == first_idx + 1 => first_idx,
            None => first_idx,
            _ => return None, // something strange happened...
        };
        if indices.next().is_some() {
            // by this point, we're handling indices that should exceed the width of any individual value
            return None;
        }
        offset |= (next << (3 * idx + 3));
    }

    Some(offset)
}

fn run_and_collect_cmplogs<E, EM, Z>(
    fuzzer: &mut Z,
    _executor: &mut E,
    state: &mut Self::State,
    manager: &mut EM,
    labels: &Vec<u8>,
    cmplogs: &mut Vec<Vec<(u8, u64, u64, usize, dfsan_label, dfsan_label)>>,
    cmplog_consts: &mut Vec<Vec<(u8, u64, u64, usize, dfsan_label)>>,
) -> Result<(), Error>
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
    E::State: HasCorpus,
    E::Input: HasTargetBytes,
{
    let mut harness = |input| {
        let target_bytes = input.target_bytes();
        let slice: &[u8] = target_bytes.as_slice();

        unsafe {
            libafl_dataflow_test_one_input_with_labels(
                slice.as_ptr(),
                slice.len(),
                labels.as_ptr(),
            );
        }

        ExitKind::Ok
    };

    let observer = DataflowCmplogObserver {
        last_cmplog: cmplogs.last().cloned().unwrap_or_else(Vec::new),
        last_cmplog_const: cmplog_consts.last().cloned().unwrap_or_else(Vec::new),
    };
    let name = observer.name();

    let mut executor =
        InProcessExecutor::new(&mut harness, tuple_list!(observer), fuzzer, state, manager)?;

    executor.observers_mut().pre_exec_all(state, &input)?;

    let kind = executor.run_target(fuzzer, state, manager, &input)?;
    if kind != ExitKind::Ok {
        return Err(Error::illegal_state(
            "Encountered a crash while performing dataflow cmplog.",
        ));
    }

    executor.observers_mut().post_exec_all(state, &input)?;

    let observer = executor
        .observers_mut()
        .match_name_mut::<DataflowCmplogObserver>(name)
        .unwrap();

    let mut cmplog = Vec::new();
    let mut cmplog_const = Vec::new();
    core::mem::swap(&mut observer.last_cmplog, &mut cmplog);
    core::mem::swap(&mut observer.last_cmplog_const, &mut cmplog_const);

    cmplogs.push(cmplog);
    cmplog_consts.push(cmplog_const);

    Ok(())
}

impl<E, EM, Z> Stage<E, EM, Z> for DataflowCmplogTracingStage<E::State>
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
    E::State: HasCorpus,
    E::Input: HasTargetBytes,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let testcase = state.corpus().get(corpus_idx)?.borrow();
        if testcase.fuzz_level() > 0 {
            return Ok(());
        }

        let input = testcase.input().clone().ok_or_else(|| {
            Error::empty_optional(format!(
                "Couldn't find an input for corpus index {}",
                corpus_idx
            ))
        })?;
        let target_bytes = input.target_bytes();
        let slice: &[u8] = target_bytes.as_slice();
        let mut labels = Vec::with_capacity(slice.len());

        let mut len = slice.len();
        if len == 0 {
            return Ok(()); // nothing to do
        }

        // We want to precisely identify the position at which the comparison is derived
        // DFSan provides us with 8 possible labels (one for each bit), so we can subdivide an input
        // such that we can uniquely identify where the comparison took place after log_8(len) runs:
        //
        // input:  [., ., ., ., ., ., ., ., ., ., ., ., ...]
        // label1: [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, ...]
        // label2: [1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, ...]
        //
        // However, because the value is provided to us as a union and not an ordered set, we have
        // to determine the offset. To do so, we collect two additional runs which allow us to
        // uniquely identify 8-bit comparison indices:
        //
        // input:  [., ., ., ., ., ., ., ., ., ., ., ., ...]
        // label1: [1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, ...]
        // label2: [1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, ...]
        //
        // By staggering, we can definitively find the index for 8-bit comparisons. We do this
        // instead of the first label pass, which only costs us 1 more execution.
        //
        // To handle potential non-determinism in the target, we sort the comparisons by their
        // compared sizes and values. If duplicates are detected, we can "guess" positions for small
        // combinations, or abort otherwise.

        let mut cmplogs = Vec::new();
        let mut cmplog_consts = Vec::new();

        for i in 0..=1 {
            labels.extend(
                core::iter::repeat(
                    (0..8)
                        .map(|label_idx| 1u8 << label_idx)
                        .flat_map(|label| core::iter::repeat(label).take(2)),
                )
                .flatten()
                .skip(i)
                .take(slice.len()),
            );
            run_and_collect_cmplogs(
                fuzzer,
                executor,
                state,
                manager,
                &labels,
                &mut cmplogs,
                &mut cmplog_consts,
            )?;
        }

        let mut repetitions = 8;
        len /= 8;
        while len > 0 {
            labels.clear();
            labels.extend(
                core::iter::repeat(
                    (0..8)
                        .map(|label_idx| 1u8 << label_idx)
                        .flat_map(|label| core::iter::repeat(label).take(repetitions)),
                )
                .flatten()
                .take(slice.len()),
            );

            run_and_collect_cmplogs(
                fuzzer,
                executor,
                state,
                manager,
                &labels,
                &mut cmplogs,
                &mut cmplog_consts,
            )?;

            len /= 8;
            repetitions *= 8;
        }

        for cmplog in &mut cmplogs {
            cmplog.sort_unstable();
            cmplog.dedup();
        }
        for cmplog in &mut cmplog_consts {
            cmplog.sort_unstable();
            cmplog.dedup();
        }

        let mut cmp_combos = Vec::new();
        let mut current_cmps = vec![Vec::new(); cmplogs.len()];
        while cmplogs.iter().all(|cmplog| !cmplog.is_empty()) {
            let (size, v1, v2, guard, _, _) = cmplogs[0].last().copied().unwrap();
            for (cmplog, current_cmp) in cmplogs.iter_mut().zip(current_cmps.iter_mut()) {
                current_cmp.clear();
                while let Some(cmp) = cmplog.last() {
                    if cmp.0 == size && cmp.1 == v1 && cmp.2 == v2 && cmp.3 == guard {
                        let (_, _, _, _, l1, l2) = cmplog.pop().unwrap();
                        current_cmp.push((l1, l2));
                    } else {
                        break;
                    }
                }
            }

            let combos = current_cmps
                .iter()
                .map(|cmps| cmps.len())
                .reduce(|combos, len| combos * len)
                .unwrap_or(0);
            if combos == 0 || combos > (1 << 8) {
                // are there no combinations? too many? skip, since we can't determine the location
                continue;
            }

            // perform combinations, but avoid cloning unnecessarily here
            let mut combined = vec![current_cmps.pop().unwrap()];
            for mut current_cmp in current_cmps {
                let prev_len = combined.len();
                let first = current_cmp.pop().unwrap();
                for label_pair in current_cmp {
                    for i in 0..prev_len {
                        let mut curr = combined[i].clone();
                        curr.push(label_pair);
                        combined.push(curr);
                    }
                }
                for i in 0..prev_len {
                    let mut curr = &mut combined[i];
                    curr.push(first);
                }
            }

            cmp_combos.push(((size, v1, v2), combined));
        }
        drop(cmplogs);

        for ((size, v1, v2), combos) in cmp_combos {
            for combo in combos {}
        }

        let mut cmp_const_combos = Vec::new();
        let mut current_cmps = vec![Vec::new(); cmplogs.len()];
        while cmplog_consts.iter().all(|cmplog| !cmplog.is_empty()) {
            let (size, v1, v2, guard, _) = cmplog_consts[0].last().copied().unwrap();
            for (cmplog, current_cmp) in cmplog_consts.iter_mut().zip(current_cmps.iter_mut()) {
                current_cmp.clear();
                while let Some(cmp) = cmplog.last() {
                    if cmp.0 == size && cmp.1 == v1 && cmp.2 == v2 && cmp.3 == guard {
                        let (_, _, _, _, l2) = cmplog.pop().unwrap();
                        current_cmp.push(l2);
                    } else {
                        break;
                    }
                }
            }

            let combos = current_cmps
                .iter()
                .map(|cmps| cmps.len())
                .reduce(|combos, len| combos * len)
                .unwrap_or(0);
            if combos == 0 || combos > (1 << 8) {
                // are there no combinations? too many? skip, since we can't determine the location
                continue;
            }

            // perform combinations, but avoid cloning unnecessarily here
            let mut combined = vec![current_cmps.pop().unwrap()];
            for mut current_cmp in current_cmps {
                let prev_len = combined.len();
                let first = current_cmp.pop().unwrap();
                for label_pair in current_cmp {
                    for i in 0..prev_len {
                        let mut curr = combined[i].clone();
                        curr.push(label_pair);
                        combined.push(curr);
                    }
                }
                for i in 0..prev_len {
                    let mut curr = &mut combined[i];
                    curr.push(first);
                }
            }

            cmp_const_combos.push(((size, v1, v2), combined));
        }
        drop(cmplog_consts);

        Ok(())
    }
}
