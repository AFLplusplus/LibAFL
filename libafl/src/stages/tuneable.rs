//! A [`crate::stages::MutationalStage`] where the mutator iteration can be tuned at runtime

use crate::{
    bolts::rands::Rand,
    impl_serdeany,
    mutators::Mutator,
    stages::{mutational::DEFAULT_MUTATIONAL_MAX_ITERATIONS, MutationalStage, Stage},
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata, HasRand, UsesState},
    Error, Evaluator,
};
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};

#[derive(Default, Clone, Copy, Eq, PartialEq, Debug, Serialize, Deserialize)]
struct TuneableMutationalStageMetadata {
    iters: Option<u64>,
}

impl_serdeany!(TuneableMutationalStageMetadata);

/// A [`crate::stages::MutationalStage`] where the mutator iteration can be tuned at runtime
#[derive(Clone, Debug)]
pub struct TuneableMutationalStage<E, EM, M, Z> {
    mutator: M,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<E, EM, M, Z> MutationalStage<E, EM, M, Z> for TuneableMutationalStage<E, EM, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
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
    #[allow(clippy::cast_possible_truncation)]
    fn iterations(&self, state: &mut Z::State, _corpus_idx: usize) -> Result<u64, Error> {
        Ok(if let Some(iters) = Self::get_iters(state) {
            iters
        } else {
            // fall back to random
            1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS)
        })
    }
}

impl<E, EM, M, Z> UsesState for TuneableMutationalStage<E, EM, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
{
    type State = Z::State;
}

impl<E, EM, M, Z> Stage<E, EM, Z> for TuneableMutationalStage<E, EM, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager, corpus_idx);

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        ret
    }
}

impl<E, EM, M, Z> TuneableMutationalStage<E, EM, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
{
    /// Creates a new default mutational stage
    #[must_use]
    pub fn new(state: &mut Z::State, mutator: M) -> Self {
        if !state.has_metadata::<TuneableMutationalStageMetadata>() {
            state.add_metadata(TuneableMutationalStageMetadata::default());
        }
        Self {
            mutator,
            phantom: PhantomData,
        }
    }

    fn metadata_mut(state: &mut Z::State) -> &mut TuneableMutationalStageMetadata {
        state
            .metadata_mut()
            .get_mut::<TuneableMutationalStageMetadata>()
            .unwrap()
    }

    fn metadata(state: &Z::State) -> &TuneableMutationalStageMetadata {
        state
            .metadata()
            .get::<TuneableMutationalStageMetadata>()
            .unwrap()
    }

    /// Set the number of iterations to be used by this mutational stage
    pub fn set_iters(state: &mut Z::State, iters: u64) {
        Self::metadata_mut(state).iters = Some(iters);
    }

    /// Get the set iterations
    pub fn get_iters(state: &Z::State) -> Option<u64> {
        Self::metadata(state).iters
    }

    /// Reset this to a normal, randomized, stage
    pub fn reset(state: &mut Z::State) {
        let metadata = Self::metadata_mut(state);
        metadata.iters = None;
    }
}
