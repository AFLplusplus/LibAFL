//! A [`crate::stages::MutationalStage`] where the mutator iteration can be tuned at runtime

use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::{
    bolts::rands::Rand,
    corpus::CorpusId,
    impl_serdeany,
    mutators::Mutator,
    stages::{
        mutational::{MutatedTransform, DEFAULT_MUTATIONAL_MAX_ITERATIONS},
        MutationalStage, Stage,
    },
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata, HasRand, UsesState},
    Error, Evaluator,
};

#[derive(Default, Clone, Copy, Eq, PartialEq, Debug, Serialize, Deserialize)]
struct TuneableMutationalStageMetadata {
    iters: Option<u64>,
}

impl_serdeany!(TuneableMutationalStageMetadata);

/// Set the number of iterations to be used by this mutational stage
pub fn set_iters<S: HasMetadata>(state: &mut S, iters: u64) -> Result<(), Error> {
    let metadata = state
        .metadata_mut()
        .get_mut::<TuneableMutationalStageMetadata>()
        .ok_or_else(|| Error::illegal_state("TuneableMutationslStage not in use"));
    metadata.map(|metadata| {
        metadata.iters = Some(iters);
    })
}

/// Get the set iterations
pub fn get_iters<S: HasMetadata>(state: &S) -> Result<Option<u64>, Error> {
    state
        .metadata()
        .get::<TuneableMutationalStageMetadata>()
        .ok_or_else(|| Error::illegal_state("TuneableMutationslStage not in use"))
        .map(|metadata| metadata.iters)
}

/// Reset this to a normal, randomized, stage
pub fn reset<S: HasMetadata>(state: &mut S) -> Result<(), Error> {
    state
        .metadata_mut()
        .get_mut::<TuneableMutationalStageMetadata>()
        .ok_or_else(|| Error::illegal_state("TuneableMutationslStage not in use"))
        .map(|metadata| metadata.iters = None)
}

/// A [`crate::stages::MutationalStage`] where the mutator iteration can be tuned at runtime
#[derive(Clone, Debug)]
pub struct TuneableMutationalStage<E, EM, I, M, Z> {
    mutator: M,
    phantom: PhantomData<(E, EM, I, Z)>,
}

impl<E, EM, I, M, Z> MutationalStage<E, EM, I, M, Z> for TuneableMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
    I: MutatedTransform<Z::Input, Z::State> + Clone,
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
    fn iterations(&self, state: &mut Z::State, _corpus_idx: CorpusId) -> Result<u64, Error> {
        Ok(if let Some(iters) = get_iters(state)? {
            iters
        } else {
            // fall back to random
            1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS)
        })
    }
}

impl<E, EM, I, M, Z> UsesState for TuneableMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
    I: MutatedTransform<Z::Input, Z::State> + Clone,
{
    type State = Z::State;
}

impl<E, EM, I, M, Z> Stage<E, EM, Z> for TuneableMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
    I: MutatedTransform<Z::Input, Z::State> + Clone,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager, corpus_idx);

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        ret
    }
}

impl<E, EM, M, Z> TuneableMutationalStage<E, EM, Z::Input, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<Z::Input, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
{
    /// Creates a new default mutational stage
    #[must_use]
    pub fn new(state: &mut Z::State, mutator: M) -> Self {
        Self::transforming(state, mutator)
    }
}

impl TuneableMutationalStage<(), (), (), (), ()> {
    /// Set the number of iterations to be used by this mutational stage
    pub fn set_iters<S: HasMetadata>(state: &mut S, iters: u64) -> Result<(), Error> {
        set_iters(state, iters)
    }

    /// Get the set iterations
    pub fn iters<S: HasMetadata>(state: &S) -> Result<Option<u64>, Error> {
        get_iters(state)
    }
}

impl<E, EM, I, M, Z> TuneableMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
{
    /// Creates a new tranforming mutational stage
    #[must_use]
    pub fn transforming(state: &mut Z::State, mutator: M) -> Self {
        if !state.has_metadata::<TuneableMutationalStageMetadata>() {
            state.add_metadata(TuneableMutationalStageMetadata::default());
        }
        Self {
            mutator,
            phantom: PhantomData,
        }
    }
}
