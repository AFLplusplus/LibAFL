#![allow(non_snake_case)]

#[cfg(any(feature = "sancov_value_profile"))]
#[cfg(not(any(doc, feature = "clippy")))]
compile_error!("the libafl_targets `sancov_value_profile` are incompatible with `dataflow`.");

#[cfg(not(any(feature = "sancov_pcguard_edges", feature = "sancov_pcguard_hitcounts")))]
#[cfg(not(any(doc, feature = "clippy")))]
compile_error!(
    "either `sancov_pcguard_edges` or `sancov_pcguard_hitcounts` must be enabled to use `dataflow`."
);

use alloc::{
    collections::{btree_map::Entry, BTreeSet},
    vec::Vec,
};
use core::{cmp::min, ffi::c_int, fmt::Debug, marker::PhantomData};
use std::collections::BTreeMap;

use rand::{rngs::StdRng, RngCore, SeedableRng};
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
#[cfg(feature = "introspection")]
use libafl::monitors::PerfFeature;
use libafl::{
    bolts::{
        rands::Rand,
        tuples::{tuple_list, MatchName, Named},
        AsIter, AsSlice, HasLen,
    },
    corpus::{Corpus, CorpusId},
    events::{EventFirer, EventRestarter},
    executors::{Executor, ExitKind, HasObservers, InProcessExecutor},
    feedbacks::MaxMapFeedback,
    impl_serdeany,
    inputs::{HasBytesVec, HasTargetBytes, Input, UsesInput},
    mark_feature_time,
    mutators::{MutationResult, Mutator},
    observers::{hash_slice, MapObserver, Observer, ObserversTuple},
    prelude::Tokens,
    stages::Stage,
    start_timer,
    state::{
        HasClientPerfMonitor, HasCorpus, HasExecutions, HasMetadata, HasRand, HasSolutions,
        UsesState,
    },
    Error, HasObjective,
};

use crate::MAX_EDGES_NUM;

static mut GUARD_LABELS: Vec<u8> = Vec::new();

pub(crate) static mut LAST_GUARD: u32 = 0;

pub static mut CMPLOG_ENABLED: bool = false;

static mut INPUT: Vec<u8> = Vec::new();
static mut LABEL_START: usize = 0;

type Cmplog = BTreeMap<u32, BTreeMap<(usize, usize), BTreeSet<(u8, u8)>>>;
type ConstCmplog = BTreeMap<u32, BTreeMap<usize, BTreeSet<(u8, u8)>>>;

static mut CMPLOG: Cmplog = Cmplog::new();
static mut CMPLOG_CONST: ConstCmplog = ConstCmplog::new();

#[allow(non_camel_case_types)]
type dfsan_label = u8;

fn valid_label(size: u8, label: dfsan_label) -> bool {
    // there is at least one bit set
    label != 0
        // there are not more bits set than the size of the value
        && label.count_ones() <= size as u32
        // the bits are all grouped together
        && label.count_zeros() == label.trailing_zeros() + label.leading_zeros()
}

fn label_indices(label: dfsan_label) -> impl Iterator<Item = usize> {
    (0..8)
        .map(move |i| label >> i)
        .enumerate()
        .filter_map(|(i, label)| (label & 1 != 0).then_some(i))
}

const INVALID_INDEX: usize = usize::MAX;

// precondition: this is a valid label
// we "guess" the validity of the check by assuming that if all of the labelled regions in the input
// line up with our value AND that the value at the computed index of the value is equal to the
// value, then the value's comparison is correct
fn checked_index(size: u8, value: u64, label: dfsan_label) -> Option<usize> {
    let mut index = unsafe { LABEL_START };
    if label.trailing_zeros() > 0 {
        index += label.trailing_zeros() as usize;
    } else if label.trailing_ones() > 0 {
        if let Some(new_index) = index.checked_sub((size as u32 - label.trailing_ones()) as usize) {
            index = new_index;
        } else {
            return None;
        }
    }
    if index + size as usize > unsafe { INPUT.len() } {
        return None;
    }
    if match size {
        1 => unsafe { INPUT[index] == value as u8 },
        2 => unsafe {
            u16::from_ne_bytes(INPUT[index..(index + 2)].try_into().unwrap()) == value as u16
        },
        4 => unsafe {
            u32::from_ne_bytes(INPUT[index..(index + 4)].try_into().unwrap()) == value as u32
        },
        8 => unsafe { u64::from_ne_bytes(INPUT[index..(index + 8)].try_into().unwrap()) == value },
        _ => unreachable!("Invalid size while performing index check."),
    } {
        Some(index)
    } else {
        None
    }
}

fn cmplog_insert_range<const N: usize>(guard: u32, v1: [u8; N], v2: [u8; N], i1: usize, i2: usize) {
    if v1 != v2 {
        let base = unsafe { CMPLOG.entry(guard).or_insert_with(BTreeMap::new) };
        for (offset, (v1, v2)) in v1.into_iter().zip(v2).enumerate() {
            base.entry((i1.saturating_add(offset), i2.saturating_add(offset)))
                .or_insert_with(BTreeSet::new)
                .insert((v1, v2));
        }
    }
}

fn cmplog_insert(guard: u32, size: u8, v1: u64, v2: u64, l1: dfsan_label, l2: dfsan_label) {
    // we have to check label validity because we might be comparing a (as of now) unlabelled value
    let first_idx = valid_label(size, l1)
        .then(|| checked_index(size, v1, l1))
        .flatten()
        .unwrap_or(INVALID_INDEX);
    let second_idx = valid_label(size, l2)
        .then(|| checked_index(size, v2, l2))
        .flatten()
        .unwrap_or(INVALID_INDEX);

    // if this doesn't pass, either both are invalid or both indices correspond to the same position
    // and thus both be equal and matching (not a good replacement candidate)
    if first_idx != second_idx {
        unsafe {
            match size {
                1 => cmplog_insert_range(guard, [v1 as u8], [v2 as u8], first_idx, second_idx),
                2 => cmplog_insert_range(
                    guard,
                    (v1 as u16).to_ne_bytes(),
                    (v2 as u16).to_ne_bytes(),
                    first_idx,
                    second_idx,
                ),
                4 => cmplog_insert_range(
                    guard,
                    (v1 as u32).to_ne_bytes(),
                    (v2 as u32).to_ne_bytes(),
                    first_idx,
                    second_idx,
                ),
                8 => cmplog_insert_range(
                    guard,
                    v1.to_ne_bytes(),
                    v2.to_ne_bytes(),
                    first_idx,
                    second_idx,
                ),
                _ => unreachable!("Illegal size while inserting to comparison log."),
            }
        }
    }
}

fn cmplog_const_insert_range<const N: usize>(guard: u32, v1: [u8; N], v2: [u8; N], i2: usize) {
    let base = unsafe { CMPLOG_CONST.entry(guard).or_insert_with(BTreeMap::new) };
    for (offset, (v1, v2)) in v1.into_iter().zip(v2).enumerate() {
        if unsafe { INPUT[i2 + offset] != v1 } {
            base.entry(i2 + offset)
                .or_insert_with(BTreeSet::new)
                .insert((v1, v2));
        }
    }
}

fn cmplog_const_insert(guard: u32, size: u8, v1: u64, v2: u64, l2: dfsan_label) {
    if let Some(index) = checked_index(size, v2, l2) {
        unsafe {
            match size {
                1 => cmplog_const_insert_range(guard, [v1 as u8], [v2 as u8], index),
                2 => cmplog_const_insert_range(
                    guard,
                    (v1 as u16).to_ne_bytes(),
                    (v2 as u16).to_ne_bytes(),
                    index,
                ),
                4 => cmplog_const_insert_range(
                    guard,
                    (v1 as u32).to_ne_bytes(),
                    (v2 as u32).to_ne_bytes(),
                    index,
                ),
                8 => cmplog_const_insert_range(guard, v1.to_ne_bytes(), v2.to_ne_bytes(), index),
                _ => unreachable!("Illegal size while inserting to comparison log."),
            }
        }
    }
}

#[no_mangle]
pub unsafe fn __dfsw___sanitizer_cov_trace_switch(
    val: u64,
    cases: *const u64,
    l1: dfsan_label,
    _l2: dfsan_label,
) {
    if l1 != 0 {
        GUARD_LABELS
            .get_mut(LAST_GUARD as usize)
            .map(|label| *label |= l1);
        if CMPLOG_ENABLED {
            // From: https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-data-flow
            // Called before a switch statement.
            // Val is the switch operand.
            // Cases[0] is the number of case constants.
            // Cases[1] is the size of Val in bits.
            // Cases[2:] are the case constants.
            let val_size = (*cases.offset(1) / 8) as u8;
            if valid_label(val_size, l1) {
                let case_counts = *cases as usize;
                let cases = core::slice::from_raw_parts(cases.offset(2), case_counts);
                for &case in cases {
                    cmplog_const_insert(LAST_GUARD, val_size, case, val, l1);
                }
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
                    .get_mut(LAST_GUARD as usize)
                    .map(|label| *label |= l1 | l2);
                if CMPLOG_ENABLED {
                    cmplog_insert(
                        LAST_GUARD,
                        core::mem::size_of::<$arg_type>() as u8,
                        arg1.into(),
                        arg2.into(),
                        l1,
                        l2,
                    );
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
                GUARD_LABELS
                    .get_mut(LAST_GUARD as usize)
                    .map(|label| *label |= l2);
                if CMPLOG_ENABLED && valid_label(core::mem::size_of::<$arg_type>() as u8, l2) {
                    cmplog_const_insert(
                        LAST_GUARD,
                        core::mem::size_of::<$arg_type>() as u8,
                        arg1.into(),
                        arg2.into(),
                        l2,
                    );
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
struct DataflowCmplogObserver;

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
        unsafe {
            CMPLOG_ENABLED = true;
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
        unsafe {
            CMPLOG_ENABLED = false;
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

fn run_and_collect_cmplogs<E, EM, Z>(
    fuzzer: &mut Z,
    _executor: &mut E,
    state: &mut E::State,
    manager: &mut EM,
    input: &E::Input,
    labels: &Vec<u8>,
) -> Result<(), Error>
where
    E: UsesState,
    EM: EventFirer<State = E::State> + EventRestarter,
    Z: UsesState<State = E::State> + HasObjective,
    E::State: HasCorpus + HasSolutions + HasClientPerfMonitor + HasExecutions,
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

    let observer = DataflowCmplogObserver;

    let mut executor =
        InProcessExecutor::new(&mut harness, tuple_list!(observer), fuzzer, state, manager)?;

    start_timer!(state);
    executor.observers_mut().pre_exec_all(state, input)?;
    mark_feature_time!(state, PerfFeature::PreExecObservers);

    start_timer!(state);
    let kind = executor.run_target(fuzzer, state, manager, input)?;
    if kind != ExitKind::Ok {
        return Err(Error::illegal_state(
            "Encountered a crash while performing dataflow cmplog.",
        ));
    }
    mark_feature_time!(state, PerfFeature::TargetExecution);

    start_timer!(state);
    executor
        .observers_mut()
        .post_exec_all(state, input, &kind)?;
    mark_feature_time!(state, PerfFeature::PostExecObservers);

    *state.executions_mut() += 1;

    Ok(())
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DataflowCmplogReplacementsMetadata {
    replacements: Vec<(usize, Vec<Vec<(u8, u8)>>)>,
    cross_replacements: Vec<(usize, usize, Vec<usize>)>,
}

impl_serdeany!(DataflowCmplogReplacementsMetadata);

impl<E, EM, Z> Stage<E, EM, Z> for DataflowCmplogTracingStage<E::State>
where
    E: UsesState,
    EM: EventFirer<State = E::State> + EventRestarter,
    Z: UsesState<State = E::State> + HasObjective,
    E::State: HasCorpus + HasSolutions + HasClientPerfMonitor + HasExecutions + HasMetadata,
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
        start_timer!(state);
        let testcase = state.corpus().get(corpus_idx)?.borrow();
        if testcase.has_metadata::<DataflowCmplogReplacementsMetadata>() {
            drop(testcase);
            mark_feature_time!(state, PerfFeature::GetInputFromCorpus);
            return Ok(());
        }

        let input = testcase.input().clone().ok_or_else(|| {
            Error::empty_optional(format!(
                "Couldn't find an input for corpus index {}",
                corpus_idx
            ))
        })?;
        drop(testcase);
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        let target_bytes = input.target_bytes();
        let slice: &[u8] = target_bytes.as_slice();
        unsafe {
            INPUT.extend_from_slice(slice);
        }
        let mut labels = Vec::with_capacity(slice.len());

        let mut len = slice.len();
        if len == 0 {
            return Ok(()); // nothing to do
        }

        // There used to be a comment here detailing a very cool approach for identifying indices in
        // the input which corresponded to comparison. Another victim of path explosion :(
        for i in (0..slice.len()).step_by(8) {
            labels.clear();
            labels.resize(slice.len(), 0);
            for (e, l) in labels[i..].iter_mut().zip(0..8) {
                *e = 1 << l;
            }
            unsafe {
                LABEL_START = i;
            }
            run_and_collect_cmplogs(fuzzer, executor, state, manager, &input, &labels)?;
        }

        start_timer!(state);
        let mut last_cmplog = Cmplog::new();
        let mut last_const_cmplog = ConstCmplog::new();
        core::mem::swap(&mut last_cmplog, unsafe { &mut CMPLOG });
        core::mem::swap(&mut last_const_cmplog, unsafe { &mut CMPLOG_CONST });

        let mut replacements = BTreeMap::new();
        let mut cross_replacements = BTreeMap::new();
        for (guard, mut comparisons) in last_cmplog {
            let mut inferred = BTreeMap::new();
            let mut first_observed = comparisons
                .range(..(usize::MAX, 0))
                .filter(|((_, second), _)| *second == INVALID_INDEX);
            for ((first, _), first_set) in first_observed {
                let mut second_observed = comparisons.range((usize::MAX, 0)..);
                for ((_, second), second_set) in second_observed {
                    let intersection = first_set.intersection(second_set).copied();
                    let intersection = intersection.collect::<BTreeSet<_>>();
                    if !intersection.is_empty() {
                        inferred.insert((*first, *second), intersection);
                    }
                }
            }

            fn insert_combo(
                replacements: &mut BTreeMap<(u32, usize), Vec<BTreeSet<(u8, u8)>>>,
                cross_replacements: &mut BTreeMap<(usize, usize), BTreeSet<usize>>,
                guard: u32,
                current: &mut Vec<BTreeSet<(u8, u8)>>,
                base: (usize, usize),
            ) {
                if base.0 == INVALID_INDEX {
                    // no index for this combo was found, so commit it to the const combos
                    let target = replacements
                        .entry((guard, base.1))
                        .or_insert_with(Vec::<BTreeSet<(u8, u8)>>::new);
                    if !target.is_empty() {
                        let existing = min(current.len(), target.len());
                        for (existing, current) in target.iter_mut().zip(current.drain(..existing))
                        {
                            existing.extend(current);
                        }
                    }
                    target.extend(current.drain(..));
                } else if base.1 == INVALID_INDEX {
                    // no index for this combo was found, so commit it to the const combos
                    // const_combo_chains expects the items to be in (const, non-const)
                    // so we have to reorder items here
                    let target = replacements.entry((guard, base.0)).or_insert_with(Vec::new);
                    if !target.is_empty() {
                        let existing = min(current.len(), target.len());
                        for (existing, current) in
                            target.iter_mut().zip(current.drain(..existing).map(|set| {
                                set.into_iter()
                                    .map(|(v1, v2)| (v2, v1))
                                    .collect::<BTreeSet<_>>()
                            }))
                        {
                            existing.extend(current);
                        }
                    }
                    target.extend(current.drain(..).map(|set| {
                        set.into_iter()
                            .map(|(v1, v2)| (v2, v1))
                            .collect::<BTreeSet<_>>()
                    }));
                } else {
                    let target = cross_replacements.entry(base).or_insert_with(BTreeSet::new);
                    current.iter().for_each(|set| {
                        assert_eq!(set.len(), 1);
                    });
                    target.insert(current.len());
                    current.clear();
                }
            }

            let mut comparisons = comparisons.into_iter().chain(inferred);
            let mut current = Vec::new();
            if let Some(mut last) = comparisons.next() {
                current.push(last.1);
                let mut base = last.0;
                let mut last = last.0;
                for (compared, values) in comparisons {
                    if compared != (last.0.saturating_add(1), last.1.saturating_add(1)) {
                        insert_combo(
                            &mut replacements,
                            &mut cross_replacements,
                            guard,
                            &mut current,
                            base,
                        );
                        base = compared;
                    }
                    current.push(values);
                    last = compared;
                }
                insert_combo(
                    &mut replacements,
                    &mut cross_replacements,
                    guard,
                    &mut current,
                    base,
                );
            }
        }

        fn insert_const_combo(
            replacements: &mut BTreeMap<(u32, usize), Vec<BTreeSet<(u8, u8)>>>,
            guard: u32,
            current: &mut Vec<BTreeSet<(u8, u8)>>,
            base: usize,
        ) {
            let target = replacements.entry((guard, base)).or_insert_with(Vec::new);
            if !target.is_empty() {
                let existing = min(current.len(), target.len());
                for (existing, current) in target.iter_mut().zip(current.drain(..existing)) {
                    existing.extend(current);
                }
            }
            target.extend(current.drain(..));
        }

        for (guard, mut comparisons) in last_const_cmplog {
            let mut comparisons = comparisons.into_iter();
            let mut current = Vec::new();
            if let Some(mut last) = comparisons.next() {
                current.push(last.1);
                let mut base = last.0;
                let mut last = last.0;
                for (compared, values) in comparisons {
                    if compared != last + 1 {
                        insert_const_combo(&mut replacements, guard, &mut current, base);
                        base = compared;
                    }
                    current.push(values);
                    last = compared;
                }
                insert_const_combo(&mut replacements, guard, &mut current, base);
            }
        }

        let mut mined_tokens = BTreeSet::new();
        for (_, replacement) in replacements.iter() {
            if replacement.len() > 3 && replacement.iter().all(|options| options.len() == 1) {
                mined_tokens.insert(
                    replacement
                        .iter()
                        .flat_map(|options| options.into_iter())
                        .map(|(k, _)| *k)
                        .collect::<Vec<_>>(),
                );
            }
        }
        mark_feature_time!(state, PerfFeature::GetFeedbackInterestingAll);

        if !state.has_metadata::<Tokens>() {
            state.add_metadata(Tokens::default());
        }
        if let Some(tokens) = state.metadata_mut().get_mut::<Tokens>() {
            tokens.add_tokens(mined_tokens);
        }

        let meta = DataflowCmplogReplacementsMetadata {
            replacements: replacements
                .into_iter()
                .map(|((_, idx), seq)| (idx, seq.into_iter().map(Vec::from_iter).collect()))
                .collect(),
            cross_replacements: cross_replacements
                .into_iter()
                .map(|((first, second), indices)| (first, second, Vec::from_iter(indices)))
                .collect(),
        };

        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        // convert for optimisations later with direct indexing
        testcase.metadata_mut().insert(meta);

        unsafe {
            CMPLOG.clear();
            CMPLOG_CONST.clear();
            INPUT.clear();
        }

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
        if !meta.replacements.is_empty() && choice & 1 == 0 {
            let index = index % meta.replacements.len();
            let (pos, value) = &meta.replacements[index];
            let mut rng = StdRng::seed_from_u64(choice >> 1);
            let mut amount = rng.next_u64() as usize % value.len() + 1;
            let mut modified = false;
            for (e, values) in input.bytes_mut()[*pos..].iter_mut().zip(value.iter()) {
                if amount == 0 {
                    break;
                }
                let (chosen, existing) = values[rng.next_u64() as usize % values.len()];
                if *e == existing {
                    *e = chosen;
                    modified = true;
                    amount -= 1;
                }
            }
            if modified {
                Ok(MutationResult::Mutated)
            } else {
                Ok(MutationResult::Skipped)
            }
        } else if !meta.cross_replacements.is_empty() {
            let index = index % meta.cross_replacements.len();
            let (mut first, mut second, amounts) = &meta.cross_replacements[index];
            if choice & 2 == 0 {
                core::mem::swap(&mut first, &mut second);
            }
            let index = (choice >> 2) as usize % amounts.len();
            let amount = amounts[index];
            if input.bytes()[first..(first + amount)] == input.bytes()[second..(second + amount)] {
                Ok(MutationResult::Skipped)
            } else {
                input
                    .bytes_mut()
                    .copy_within(first..(first + amount), second);
                Ok(MutationResult::Mutated)
            }
        } else {
            return Ok(MutationResult::Skipped);
        }
    }
}
