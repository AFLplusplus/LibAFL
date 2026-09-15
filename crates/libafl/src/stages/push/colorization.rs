//! Colorization push stage for input taint analysis and reduction.

use alloc::{borrow::Cow, collections::binary_heap::BinaryHeap, vec::Vec};
use core::{cmp::Ordering, fmt::Debug, hash::Hash, marker::PhantomData, ops::Range};

use libafl_bolts::{
    Error, Named, generic_hash_std,
    rands::Rand,
    tuples::{Handle, MatchNameRef},
};

use super::{PushStage, StageStep};
use crate::{
    common::{HasMetadata, HasNamedMetadata},
    corpus::HasCurrentCorpusId,
    fuzzer::ExecutionRequest,
    inputs::{HasMutatorBytes, ResizableMutator},
    mutators::mutations::buffer_copy,
    nonzero,
    observers::ObserversTuple,
    stages::{
        Restartable, RetryCountRestartHelper,
        colorization::{COLORIZATION_STAGE_NAME, TaintMetadata},
    },
    state::{HasCorpus, HasCurrentTestcase, HasRand},
};

#[derive(Debug, PartialEq, Eq)]
struct Bigger(Range<usize>);

impl PartialOrd for Bigger {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Bigger {
    fn cmp(&self, other: &Bigger) -> Ordering {
        self.0.len().cmp(&other.0.len())
    }
}

/// Phase of input colorization persisted in [`ColorizationStageMetadata`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ColorizationPhaseState {
    /// Initial baseline execution phase.
    Baseline,
    /// Binary search over input ranges to identify taint regions.
    Evaluating {
        /// Hash of baseline observer map.
        orig_hash: u64,
        /// Original input bytes.
        orig_bytes: Vec<u8>,
        /// Fully mutated input bytes.
        changed_bytes: Vec<u8>,
        /// Range currently under evaluation.
        current_range: Range<usize>,
        /// Remaining candidate sub-ranges to test.
        ranges: Vec<Range<usize>>,
        /// Ranges confirmed not to change observer output.
        ok_ranges: Vec<Range<usize>>,
        /// Number of range evaluations completed.
        step_count: usize,
        /// Maximum number of range evaluations allowed.
        max_steps: usize,
    },
    /// Colorization completed.
    Done,
}

/// Metadata tracking progress of a [`ColorizationStage`] in state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ColorizationStageMetadata {
    /// Current phase of colorization.
    pub phase: ColorizationPhaseState,
}

libafl_bolts::impl_serdeany!(ColorizationStageMetadata);

/// A stage that performs AFL++ style input colorization to find taint ranges.
#[derive(Debug, Clone)]
pub struct ColorizationStage<C, I, O> {
    name: Cow<'static, str>,
    map_observer_handle: Handle<C>,
    phantom: PhantomData<(I, O)>,
}

/// Backwards compatibility alias for [`ColorizationStage`].
pub type ColorizationPushStage<C, I, O> = ColorizationStage<C, I, O>;

impl<C, I, O> ColorizationStage<C, I, O> {
    /// Create a new colorization stage.
    #[must_use]
    pub fn new(map_observer_handle: impl Into<Handle<C>>) -> Self {
        Self::with_name(map_observer_handle.into(), COLORIZATION_STAGE_NAME)
    }

    /// Create a new colorization stage with custom name.
    #[must_use]
    pub fn with_name<N: Into<Cow<'static, str>>>(
        map_observer_handle: impl Into<Handle<C>>,
        name: N,
    ) -> Self {
        Self {
            name: name.into(),
            map_observer_handle: map_observer_handle.into(),
            phantom: PhantomData,
        }
    }

    fn type_replace<S>(bytes: &mut [u8], state: &mut S)
    where
        S: HasRand,
    {
        for b in bytes {
            *b = state.rand_mut().below(nonzero!(256)) as u8;
        }
    }
}

impl<C, I, O> Named for ColorizationPushStage<C, I, O> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<C, I, O, S> Restartable<S> for ColorizationPushStage<C, I, O>
where
    S: HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::no_retry(state, &self.name)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<C, EM, I, O, OT, S> PushStage<EM, I, OT, S> for ColorizationPushStage<C, I, O>
where
    C: AsRef<O> + Named,
    I: ResizableMutator<u8> + HasMutatorBytes + Clone + Debug,
    O: Hash,
    OT: ObserversTuple<I, S> + MatchNameRef,
    S: HasCorpus<I>
        + HasMetadata
        + HasRand
        + HasNamedMetadata
        + HasCurrentCorpusId
        + HasCurrentTestcase<I>,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        if state
            .named_metadata_map()
            .get::<ColorizationStageMetadata>(&self.name)
            .is_none()
        {
            state.add_named_metadata(
                &self.name,
                ColorizationStageMetadata {
                    phase: ColorizationPhaseState::Baseline,
                },
            );
        }
        Ok(())
    }

    fn step(&mut self, state: &mut S, _manager: &mut EM) -> Result<StageStep<I>, Error> {
        if state
            .named_metadata_map()
            .get::<ColorizationStageMetadata>(&self.name)
            .is_none()
        {
            state.add_named_metadata(
                &self.name,
                ColorizationStageMetadata {
                    phase: ColorizationPhaseState::Baseline,
                },
            );
        }

        let phase = state
            .named_metadata_map()
            .get::<ColorizationStageMetadata>(&self.name)
            .unwrap()
            .phase
            .clone();

        match phase {
            ColorizationPhaseState::Baseline => {
                let input = state.current_input_cloned()?;
                Ok(StageStep::Execute(ExecutionRequest::single(input)))
            }
            ColorizationPhaseState::Evaluating {
                orig_hash,
                orig_bytes,
                changed_bytes,
                mut ranges,
                ok_ranges,
                step_count,
                max_steps,
                ..
            } => {
                if step_count >= max_steps || ranges.is_empty() {
                    let taint_meta = TaintMetadata::new(orig_bytes, ok_ranges);
                    let mut tc = state.current_testcase_mut()?;
                    tc.add_metadata(taint_meta);
                    drop(tc);

                    if let Ok(meta) =
                        state.named_metadata_mut::<ColorizationStageMetadata>(&self.name)
                    {
                        meta.phase = ColorizationPhaseState::Done;
                    }
                    return Ok(StageStep::Done);
                }

                let next_range = ranges.pop().unwrap();
                let mut trial = state.current_input_cloned()?;
                trial.mutator_bytes_mut().copy_from_slice(&orig_bytes);
                unsafe {
                    buffer_copy(
                        trial.mutator_bytes_mut(),
                        &changed_bytes,
                        next_range.start,
                        next_range.start,
                        next_range.len(),
                    );
                }

                if let Ok(meta) = state.named_metadata_mut::<ColorizationStageMetadata>(&self.name)
                {
                    meta.phase = ColorizationPhaseState::Evaluating {
                        orig_hash,
                        orig_bytes,
                        changed_bytes,
                        current_range: next_range,
                        ranges,
                        ok_ranges,
                        step_count,
                        max_steps,
                    };
                }

                Ok(StageStep::Execute(ExecutionRequest::single(trial)))
            }
            ColorizationPhaseState::Done => Ok(StageStep::Done),
        }
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        obs: crate::fuzzer::BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error> {
        let Some(phase) = state
            .named_metadata_map()
            .get::<ColorizationStageMetadata>(&self.name)
            .map(|m| m.phase.clone())
        else {
            return Ok(());
        };

        match phase {
            ColorizationPhaseState::Baseline => {
                let observer = obs
                    .observers
                    .get(&self.map_observer_handle)
                    .ok_or_else(|| {
                        Error::key_not_found(
                            "MapObserver not found in ColorizationPushStage observations",
                        )
                    })?;
                let orig_hash = generic_hash_std(observer.as_ref());

                let input = state.current_input_cloned()?;
                let orig_bytes = input.mutator_bytes().to_vec();
                let mut changed = input.clone();
                let input_len = orig_bytes.len();

                Self::type_replace(changed.mutator_bytes_mut(), state);

                if input_len == 0 {
                    if let Ok(meta) =
                        state.named_metadata_mut::<ColorizationStageMetadata>(&self.name)
                    {
                        meta.phase = ColorizationPhaseState::Done;
                    }
                    return Ok(());
                }

                let changed_bytes = changed.mutator_bytes().to_vec();
                let mut ranges_heap = BinaryHeap::new();
                ranges_heap.push(Bigger(0..input_len));
                let first_range = ranges_heap.pop().unwrap().0;

                if let Ok(meta) = state.named_metadata_mut::<ColorizationStageMetadata>(&self.name)
                {
                    meta.phase = ColorizationPhaseState::Evaluating {
                        orig_hash,
                        orig_bytes,
                        changed_bytes,
                        current_range: 0..0,
                        ranges: alloc::vec![first_range],
                        ok_ranges: Vec::new(),
                        step_count: 0,
                        max_steps: input_len * 2,
                    };
                }
                Ok(())
            }
            ColorizationPhaseState::Evaluating {
                orig_hash,
                orig_bytes,
                changed_bytes,
                current_range,
                mut ranges,
                mut ok_ranges,
                mut step_count,
                max_steps,
            } => {
                let observer = obs
                    .observers
                    .get(&self.map_observer_handle)
                    .ok_or_else(|| {
                        Error::key_not_found(
                            "MapObserver not found in ColorizationPushStage observations",
                        )
                    })?;
                let changed_hash = generic_hash_std(observer.as_ref());

                if orig_hash == changed_hash {
                    ok_ranges.push(current_range.clone());
                } else {
                    let copy_len = current_range.len();
                    if copy_len > 1 {
                        let mid = current_range.start + copy_len / 2;
                        ranges.push(current_range.start..mid);
                        ranges.push(mid..current_range.end);
                    }
                }

                step_count += 1;

                if step_count >= max_steps || ranges.is_empty() {
                    let taint_meta = TaintMetadata::new(orig_bytes, ok_ranges);
                    let mut tc = state.current_testcase_mut()?;
                    tc.add_metadata(taint_meta);
                    drop(tc);

                    if let Ok(meta) =
                        state.named_metadata_mut::<ColorizationStageMetadata>(&self.name)
                    {
                        meta.phase = ColorizationPhaseState::Done;
                    }
                } else if let Ok(meta) =
                    state.named_metadata_mut::<ColorizationStageMetadata>(&self.name)
                {
                    meta.phase = ColorizationPhaseState::Evaluating {
                        orig_hash,
                        orig_bytes,
                        changed_bytes,
                        current_range,
                        ranges,
                        ok_ranges,
                        step_count,
                        max_steps,
                    };
                }
                Ok(())
            }
            ColorizationPhaseState::Done => Ok(()),
        }
    }

    fn deinit(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        let _ = state
            .named_metadata_map_mut()
            .remove::<ColorizationStageMetadata>(&self.name);
        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
#[allow(
    clippy::type_complexity,
    clippy::match_wildcard_for_single_variants,
    clippy::duration_suboptimal_units
)]
mod tests {
    use alloc::vec;

    use libafl_bolts::{rands::StdRand, tuples::Handled};

    use super::*;
    use crate::{
        corpus::{Corpus, HasCurrentCorpusId, InMemoryCorpus, Testcase},
        events::NopEventManager,
        executors::ExitKind,
        feedbacks::ConstFeedback,
        fuzzer::ExecutionObservation,
        inputs::BytesInput,
        observers::StdMapObserver,
        state::StdState,
    };

    static mut MAP: [u8; 16] = [1; 16];

    #[test]
    fn test_colorization_push_stage() {
        let rand = StdRand::with_seed(1234);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(BytesInput::new(vec![1, 2, 3, 4]));
        let id = corpus.add(testcase).unwrap();

        let mut feedback = ConstFeedback::new(true);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();
        state.set_corpus_id(id).unwrap();

        let map_ptr = &raw mut MAP as *mut u8;
        let observer = unsafe { StdMapObserver::from_mut_ptr("cov", map_ptr, 16) };
        let handle = observer.handle();

        let mut stage = ColorizationPushStage::new(handle);
        let mut mgr = NopEventManager::new();

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut stage, &mut state, &mut mgr).unwrap();

        // Step 1: baseline request
        let step1 = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(step1, StageStep::Execute(_)));

        // Provide baseline observation via post_exec
        let obs = ExecutionObservation::new(ExitKind::Ok, (observer.clone(), ()));
        let input = state.current_input_cloned().unwrap();
        stage
            .post_exec(&mut state, &mut mgr, obs.as_borrowed(&input))
            .unwrap();

        let step2 = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(step2, StageStep::Execute(_) | StageStep::Done));

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
    }
}
