//! The power schedules. This stage should be invoked after the calibration stage.

use alloc::string::{String, ToString};
use core::{fmt::Debug, marker::PhantomData};

use crate::{
    corpus::{Corpus, PowerScheduleTestcaseMetaData},
    executors::{Executor, HasObservers},
    fuzzer::Evaluator,
    inputs::Input,
    mutators::Mutator,
    observers::{MapObserver, ObserversTuple},
    schedulers::powersched::{PowerSchedule, PowerScheduleMetadata},
    stages::{MutationalStage, Stage},
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata},
    Error,
};
/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<E, EM, I, M, O, OT, S, Z>
where
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    M: Mutator<I, S>,
    O: MapObserver,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    map_observer_name: String,
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, O, OT, S, Z)>,
}

impl<E, EM, I, M, O, OT, S, Z> MutationalStage<E, EM, I, M, S, Z>
    for PowerMutationalStage<E, EM, I, M, O, OT, S, Z>
where
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    M: Mutator<I, S>,
    O: MapObserver,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    /// Gets the number of iterations as a random number
    fn iterations(&self, state: &mut S, corpus_idx: usize) -> Result<usize, Error> {
        // Calculate score
        let score = state
            .corpus()
            .get(corpus_idx)?
            .borrow()
            .calculate_score(state);

        // Update handicap
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let tcmeta = testcase
            .metadata_mut()
            .get_mut::<PowerScheduleTestcaseMetaData>()
            .ok_or_else(|| {
                Error::KeyNotFound("PowerScheduleTestcaseMetaData not found".to_string())
            })?;
        if tcmeta.handicap() >= 4 {
            tcmeta.set_handicap(tcmeta.handicap() - 4);
        } else if tcmeta.handicap() > 0 {
            tcmeta.set_handicap(tcmeta.handicap() - 1);
        }

        score
    }

    #[allow(clippy::cast_possible_wrap)]
    fn perform_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let num = self.iterations(state, corpus_idx)?;

        for i in 0..num {
            let mut input = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();

            self.mutator_mut().mutate(state, &mut input, i as i32)?;

            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, input)?;

            let observer = executor
                .observers()
                .match_name::<O>(&self.map_observer_name)
                .ok_or_else(|| Error::KeyNotFound("MapObserver not found".to_string()))?;

            let mut hash = observer.hash() as usize;

            let psmeta = state
                .metadata_mut()
                .get_mut::<PowerScheduleMetadata>()
                .ok_or_else(|| Error::KeyNotFound("PowerScheduleMetadata not found".to_string()))?;

            hash %= psmeta.n_fuzz().len();
            // Update the path frequency
            psmeta.n_fuzz_mut()[hash] = psmeta.n_fuzz()[hash].saturating_add(1);

            if let Some(idx) = corpus_idx {
                state
                    .corpus()
                    .get(idx)?
                    .borrow_mut()
                    .metadata_mut()
                    .get_mut::<PowerScheduleTestcaseMetaData>()
                    .ok_or_else(|| {
                        Error::KeyNotFound("PowerScheduleTestData not found".to_string())
                    })?
                    .set_n_fuzz_entry(hash);
            }

            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
        }

        Ok(())
    }
}

impl<E, EM, I, M, O, OT, S, Z> Stage<E, EM, S, Z> for PowerMutationalStage<E, EM, I, M, O, OT, S, Z>
where
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    M: Mutator<I, S>,
    O: MapObserver,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager, corpus_idx);
        ret
    }
}

impl<E, EM, I, M, O, OT, S, Z> PowerMutationalStage<E, EM, I, M, O, OT, S, Z>
where
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    M: Mutator<I, S>,
    O: MapObserver,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new [`PowerMutationalStage`]
    pub fn new(state: &mut S, mutator: M, map_observer_name: &O, strat: PowerSchedule) -> Self {
        state.add_metadata::<PowerScheduleMetadata>(PowerScheduleMetadata::new(strat));
        Self {
            map_observer_name: map_observer_name.name().to_string(),
            mutator,
            phantom: PhantomData,
        }
    }
}
