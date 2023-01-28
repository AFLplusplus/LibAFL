#![allow(non_snake_case)]

#[cfg(any(feature = "sancov_value_profile", feature = "sancov_cmplog"))]
#[cfg(not(any(doc, feature = "clippy")))]
compile_error!(
    "the libafl_targets `sancov_value_profile` and `sancov_cmplog` are incompatible with `dataflow`."
);

#[cfg(not(any(feature = "sancov_pcguard_edges", feature = "sancov_pcguard_hitcounts")))]
#[cfg(not(any(doc, feature = "clippy")))]
compile_error!(
    "either `sancov_pcguard_edges` or `sancov_pcguard_hitcounts` must be enabled to use `dataflow`."
);

use alloc::{collections::BTreeSet, vec::Vec};
use core::{cmp::min, ffi::c_int, fmt::Debug, marker::PhantomData};

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
        tuples::{tuple_list, MatchName, Named},
        AsIter, AsSlice, HasLen,
    },
    corpus::{Corpus, CorpusId},
    events::{EventFirer, EventRestarter},
    executors::{Executor, ExitKind, HasObservers, InProcessExecutor},
    feedbacks::MaxMapFeedback,
    impl_serdeany,
    inputs::{HasBytesVec, HasTargetBytes, Input, UsesInput},
    mutators::{MutationResult, Mutator},
    observers::{hash_slice, MapObserver, Observer, ObserversTuple},
    prelude::Rand,
    stages::Stage,
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata, HasRand, HasSolutions, UsesState},
    Error, HasObjective,
};

use crate::MAX_EDGES_NUM;

static mut GUARD_LABELS: Vec<u8> = Vec::new();

pub(crate) static mut LAST_GUARD: usize = 0;

pub static mut CMPLOG_ENABLED: bool = false;
static mut CMPLOG_MAX_LABELS: u32 = 8;

static mut CMPLOG: Vec<(u8, u64, u64, usize, dfsan_label, dfsan_label)> = Vec::new();
static mut CMPLOG_CONST: Vec<(u8, u64, u64, usize, dfsan_label)> = Vec::new();

#[no_mangle]
pub unsafe fn __dfsw___sanitizer_cov_trace_switch(
    val: u64,
    cases: *const u64,
    l1: dfsan_label,
    _l2: dfsan_label,
) {
    GUARD_LABELS.get_mut(LAST_GUARD).map(|label| *label |= l1);
    if CMPLOG_ENABLED {
        // From: https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-data-flow
        // Called before a switch statement.
        // Val is the switch operand.
        // Cases[0] is the number of case constants.
        // Cases[1] is the size of Val in bits.
        // Cases[2:] are the case constants.
        let val_size = (*cases.offset(1) / 8) as u8;
        if l1.count_ones() <= val_size as u32 && l1.count_ones() <= CMPLOG_MAX_LABELS {
            let case_counts = *cases as usize;
            let cases = core::slice::from_raw_parts(cases.offset(2), case_counts);
            for &case in cases {
                CMPLOG_CONST.push((val_size, val, case, LAST_GUARD, l1));
            }
        }
    }
}

macro_rules! hook {
    ($name:ident, $arg_type:ty) => {
        #[no_mangle]
        pub unsafe fn $name(arg1: $arg_type, arg2: $arg_type, l1: dfsan_label, l2: dfsan_label) {
            if l1 != 0 || l2 != 0 {
                GUARD_LABELS
                    .get_mut(LAST_GUARD)
                    .map(|label| *label |= l1 | l2);
                if CMPLOG_ENABLED
                    && ((l1.count_ones() <= core::mem::size_of::<$arg_type>() as u32
                        && l1.count_ones() <= CMPLOG_MAX_LABELS)
                        || (l2.count_ones() <= core::mem::size_of::<$arg_type>() as u32
                            && l2.count_ones() <= CMPLOG_MAX_LABELS))
                {
                    CMPLOG.push((
                        core::mem::size_of::<$arg_type>() as u8,
                        arg1.into(),
                        arg2.into(),
                        LAST_GUARD,
                        l1,
                        l2,
                    ));
                }
            }
        }
    };
}

// https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-data-flow
// const variants of sanitizer cov have the first argument as a compile-time constant, so we do not
// need to record the labels of these values
macro_rules! hook_const {
    ($name:ident, $arg_type:ty) => {
        #[no_mangle]
        pub unsafe fn $name(arg1: $arg_type, arg2: $arg_type, _l1: dfsan_label, l2: dfsan_label) {
            if l2 != 0 {
                GUARD_LABELS.get_mut(LAST_GUARD).map(|label| *label |= l2);
                if CMPLOG_ENABLED
                    && l2.count_ones() <= core::mem::size_of::<$arg_type>() as u32
                    && l2.count_ones() <= CMPLOG_MAX_LABELS
                {
                    CMPLOG_CONST.push((
                        core::mem::size_of::<$arg_type>() as u8,
                        arg1.into(),
                        arg2.into(),
                        LAST_GUARD,
                        l2,
                    ));
                }
            }
        }
    };
}

hook!(__dfsw___sanitizer_cov_trace_cmp1, u8);
hook!(__dfsw___sanitizer_cov_trace_cmp2, u16);
hook!(__dfsw___sanitizer_cov_trace_cmp4, u32);
hook!(__dfsw___sanitizer_cov_trace_cmp8, u64);
hook_const!(__dfsw___sanitizer_cov_trace_const_cmp1, u8);
hook_const!(__dfsw___sanitizer_cov_trace_const_cmp2, u16);
hook_const!(__dfsw___sanitizer_cov_trace_const_cmp4, u32);
hook_const!(__dfsw___sanitizer_cov_trace_const_cmp8, u64);

#[derive(Debug, Serialize, Deserialize)]
pub struct DataflowObserver {
    last_guards: Vec<u8>,
}

impl DataflowObserver {
    pub fn new() -> Self {
        Self {
            last_guards: vec![0; unsafe { MAX_EDGES_NUM }],
        }
    }
}

impl Named for DataflowObserver {
    fn name(&self) -> &str {
        "dfsan-guards"
    }
}

impl<S> Observer<S> for DataflowObserver
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

impl HasLen for DataflowObserver {
    fn len(&self) -> usize {
        self.last_guards.len()
    }
}

impl MapObserver for DataflowObserver {
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
        self.last_guards.resize(unsafe { MAX_EDGES_NUM }, 0);
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

impl AsSlice for DataflowObserver {
    type Entry = <DataflowObserver as MapObserver>::Entry;

    fn as_slice(&self) -> &[Self::Entry] {
        &self.last_guards
    }
}

impl<'it> AsIter<'it> for DataflowObserver {
    type Item = <DataflowObserver as MapObserver>::Entry;
    type IntoIter = core::slice::Iter<'it, <DataflowObserver as MapObserver>::Entry>;

    fn as_iter(&'it self) -> Self::IntoIter {
        self.last_guards.iter()
    }
}

pub type DataflowMapFeedback<S> =
    MaxMapFeedback<DataflowObserver, S, <DataflowObserver as MapObserver>::Entry>;

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

const CMPLOG_NAME: &str = "dataflow-cmplog";

impl Named for DataflowCmplogObserver {
    fn name(&self) -> &str {
        CMPLOG_NAME
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

pub struct DataflowCmplogTracingStage<S> {
    phantom: PhantomData<S>,
}

impl<S> DataflowCmplogTracingStage<S> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<S> UsesState for DataflowCmplogTracingStage<S>
where
    S: UsesInput,
{
    type State = S;
}

fn label_indices(label: dfsan_label) -> impl Iterator<Item = usize> {
    (0..8)
        .map(move |i| label >> i)
        .enumerate()
        .filter_map(|(i, label)| (label & 1 != 0).then_some(i))
}

fn position_by_label(size: u8, mut labels: impl Iterator<Item = dfsan_label>) -> Option<usize> {
    let Some(first) = labels.next() else { return None; };
    let Some(second) = labels.next() else { return None; };
    if min(first.count_ones(), second.count_ones()) != (size as u32 + 1) / 2 {
        // this offset is impossible; we must be using multiple ranges or sources
        return None;
    }
    let first_idx = label_indices(first).next().unwrap();
    let second_idx = label_indices(second).next().unwrap();

    // slightly misleading because we compare indices here zero-indexed, not one-indexed... oh well

    // input:  [., ., ., ., ., ., ., ., ., ., ., ., ...]
    // label1: [1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, ...]
    // label2: [1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, ...]
    let mut offset = if first_idx == second_idx {
        // if they're the same, this is the low position of the offset
        2 * first_idx
    } else if first_idx == (second_idx + 1) % 8 {
        // high bit
        2 * first_idx + 1
    } else if second_idx == 0 && label_indices(first).last() == Some(7) {
        // we're crossing a boundary with the last byte
        16 - (size as usize)
    } else {
        // something strange happened; these values are not actually comparable and must be based on
        // a combo which isn't valid
        return None;
    };

    // input:  [., ., ., ., ., ., ., ., ., ., ., ., ...]
    // label1: [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, ...]
    // label2: [1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, ...]
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
        offset |= next << (3 * idx + 4);
    }

    Some(offset)
}

fn check_position(size: u8, pos: usize, value: u64, slice: &[u8]) -> bool {
    let expected = match size {
        1 if pos < slice.len() => Some(slice[pos] as u64),
        2 if pos < slice.len() - 1 => {
            Some(u16::from_ne_bytes(slice[pos..(pos + 2)].try_into().unwrap()) as u64)
        }
        4 if pos < slice.len() - 3 => {
            Some(u32::from_ne_bytes(slice[pos..(pos + 4)].try_into().unwrap()) as u64)
        }
        8 if pos < slice.len() - 7 => Some(u64::from_ne_bytes(
            slice[pos..(pos + 8)].try_into().unwrap(),
        )),
        _ => None,
    };
    expected == Some(value)
}

fn run_and_collect_cmplogs<E, EM, Z>(
    fuzzer: &mut Z,
    _executor: &mut E,
    state: &mut E::State,
    manager: &mut EM,
    input: &E::Input,
    labels: &Vec<u8>,
    cmplogs: &mut Vec<Vec<(u8, u64, u64, usize, dfsan_label, dfsan_label)>>,
    cmplog_consts: &mut Vec<Vec<(u8, u64, u64, usize, dfsan_label)>>,
) -> Result<(), Error>
where
    E: UsesState,
    EM: EventFirer<State = E::State> + EventRestarter,
    Z: UsesState<State = E::State> + HasObjective,
    E::State: HasCorpus + HasSolutions + HasClientPerfMonitor,
    E::Input: HasTargetBytes,
{
    let mut harness = |input: &E::Input| {
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

    let mut executor =
        InProcessExecutor::new(&mut harness, tuple_list!(observer), fuzzer, state, manager)?;

    executor.observers_mut().pre_exec_all(state, input)?;

    let kind = executor.run_target(fuzzer, state, manager, input)?;
    if kind != ExitKind::Ok {
        return Err(Error::illegal_state(
            "Encountered a crash while performing dataflow cmplog.",
        ));
    }

    executor
        .observers_mut()
        .post_exec_all(state, input, &kind)?;

    let observer = executor
        .observers_mut()
        .match_name_mut::<DataflowCmplogObserver>(CMPLOG_NAME)
        .unwrap();

    let mut cmplog = Vec::new();
    let mut cmplog_const = Vec::new();
    core::mem::swap(&mut observer.last_cmplog, &mut cmplog);
    core::mem::swap(&mut observer.last_cmplog_const, &mut cmplog_const);

    cmplogs.push(cmplog);
    cmplog_consts.push(cmplog_const);

    Ok(())
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DataflowCmplogReplacementsMetadata {
    replacements: Vec<(u8, (usize, u64))>,
    cross_replacements: Vec<(u8, (usize, u64), (usize, u64))>,
}

impl_serdeany!(DataflowCmplogReplacementsMetadata);

impl<E, EM, Z> Stage<E, EM, Z> for DataflowCmplogTracingStage<E::State>
where
    E: UsesState,
    EM: EventFirer<State = E::State> + EventRestarter,
    Z: UsesState<State = E::State> + HasObjective,
    E::State: HasCorpus + HasSolutions + HasClientPerfMonitor,
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
        if testcase.has_metadata::<DataflowCmplogReplacementsMetadata>() {
            return Ok(());
        }

        let input = testcase.input().clone().ok_or_else(|| {
            Error::empty_optional(format!(
                "Couldn't find an input for corpus index {}",
                corpus_idx
            ))
        })?;
        drop(testcase);
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

        unsafe {
            CMPLOG_MAX_LABELS = 5;
        }
        for i in 0..=1 {
            labels.clear();
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
                &input,
                &labels,
                &mut cmplogs,
                &mut cmplog_consts,
            )?;
        }

        unsafe {
            CMPLOG_MAX_LABELS = 2;
        }
        let mut repetitions = 16;
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
                &input,
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
            if v1 == v2 {
                continue;
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
            let mut combined = vec![current_cmps[0].clone()];
            for current_cmp in current_cmps.iter_mut().skip(1) {
                let prev_len = combined.len();
                let first = current_cmp.pop().unwrap();
                for &mut label_pair in current_cmp {
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

        let mut replacements = Vec::new();
        let mut cross_replacements = Vec::new();

        for ((size, v1, v2), combos) in cmp_combos {
            for combo in combos {
                let first = if let Some(pos) =
                    position_by_label(size, combo.iter().copied().map(|(l1, _)| l1))
                {
                    if check_position(size, pos, v1, slice) {
                        Some(pos)
                    } else {
                        None
                    }
                } else {
                    None
                };
                let second = if let Some(pos) =
                    position_by_label(size, combo.into_iter().map(|(_, l2)| l2))
                {
                    if check_position(size, pos, v2, slice) {
                        Some(pos)
                    } else {
                        None
                    }
                } else {
                    None
                };
                match (first, second) {
                    (Some(pos1), Some(pos2)) => {
                        cross_replacements.push((size, (pos1, v2), (pos2, v1)));
                    }
                    (Some(pos1), None) => replacements.push((size, (pos1, v2))),
                    (None, Some(pos2)) => replacements.push((size, (pos2, v1))),
                    (None, None) => {}
                }
            }
        }

        let mut cmp_const_combos = Vec::new();
        let mut current_cmps = vec![Vec::new(); cmplog_consts.len()];
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
            if v1 == v2 {
                continue;
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
            let mut combined = vec![current_cmps[0].clone()];
            for current_cmp in current_cmps.iter_mut().skip(1) {
                let prev_len = combined.len();
                let first = current_cmp.pop().unwrap();
                for &mut label in current_cmp {
                    for i in 0..prev_len {
                        let mut curr = combined[i].clone();
                        curr.push(label);
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

        for ((size, v1, v2), combos) in cmp_const_combos {
            for combo in combos {
                if let Some(pos) = position_by_label(size, combo.into_iter()) {
                    if check_position(size, pos, v2, slice) {
                        replacements.push((size, (pos, v1)));
                    }
                }
            }
        }

        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        testcase
            .metadata_mut()
            .insert(DataflowCmplogReplacementsMetadata {
                replacements,
                cross_replacements,
            });

        Ok(())
    }
}

pub struct DataflowI2SMutator;

impl DataflowI2SMutator {
    pub fn new() -> Self {
        Self
    }
}

impl Named for DataflowI2SMutator {
    fn name(&self) -> &str {
        "DataflowI2SMutator"
    }
}

fn apply_mutation<const N: usize>(target: &mut [u8], source: [u8; N]) -> MutationResult {
    if target == &source {
        MutationResult::Skipped
    } else {
        target.copy_from_slice(&source);
        MutationResult::Mutated
    }
}

impl<I, S> Mutator<I, S> for DataflowI2SMutator
where
    I: HasBytesVec + Input,
    S: HasCorpus<Input = I> + HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let choice = state.rand_mut().next();
        let index = state.rand_mut().next() as usize;
        let tc = state
            .corpus()
            .get(state.corpus().current().unwrap())
            .unwrap()
            .borrow();
        let Some(meta) = tc.metadata().get::<DataflowCmplogReplacementsMetadata>() else { return Ok(MutationResult::Skipped); };
        let (size, (pos, value)) = if !meta.replacements.is_empty() && choice & 1 == 0 {
            let index = index % meta.replacements.len();
            meta.replacements[index]
        } else if !meta.cross_replacements.is_empty() {
            let index = index % meta.cross_replacements.len();
            let chosen = meta.cross_replacements[index];
            if choice & 2 == 0 {
                (chosen.0, (chosen.1 .0, chosen.1 .1))
            } else {
                (chosen.0, (chosen.2 .0, chosen.2 .1))
            }
        } else {
            return Ok(MutationResult::Skipped);
        };
        let res = match size {
            1 => apply_mutation(&mut input.bytes_mut()[pos..(pos + 1)], [value as u8]),
            2 => apply_mutation(
                &mut input.bytes_mut()[pos..(pos + 2)],
                (value as u16).to_ne_bytes(),
            ),
            4 => apply_mutation(
                &mut input.bytes_mut()[pos..(pos + 4)],
                (value as u32).to_ne_bytes(),
            ),
            8 => apply_mutation(&mut input.bytes_mut()[pos..(pos + 8)], value.to_ne_bytes()),
            _ => unreachable!("Illegal size while performing dataflow-based I2S mutation"),
        };
        Ok(res)
    }
}
