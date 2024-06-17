use core::marker::PhantomData;

use libafl_bolts::{rands::Rand, Error};

use crate::{
    corpus::{Corpus, CorpusId},
    events::EventRestarter,
    stages::Stage,
    state::{HasCorpus, HasRand, UsesState},
};

#[derive(Debug)]
/// The stage to probablistically disable a corpus entry.
/// This stage should be wrapped in a if stage and run only when the fuzzer perform restarting
pub struct CorpusPruning<EM> {
    /// The chance of retaining this corpus
    prob: f64,
    phantom: PhantomData<EM>,
}

impl<EM> CorpusPruning<EM> {
    fn new(prob: f64) -> Self {
        Self {
            prob,
            phantom: PhantomData,
        }
    }
}

impl<EM> Default for CorpusPruning<EM> {
    fn default() -> Self {
        Self::new(0.05)
    }
}

impl<EM> UsesState for CorpusPruning<EM>
where
    EM: UsesState,
{
    type State = EM::State;
}

impl<E, EM, Z> Stage<E, EM, Z> for CorpusPruning<EM>
where
    EM: UsesState,
    E: UsesState<State = Self::State>,
    Z: UsesState<State = Self::State>,
    Self::State: HasCorpus + HasRand,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        // Iterate over every corpus entry
        let n_corpus = state.corpus().count_all();
        let mut do_retain = vec![];
        for _ in 0..n_corpus {
            let r = state.rand_mut().below(100) as f64;
            do_retain.push((self.prob * 100 as f64) < r);
        }

        let corpus = state.corpus_mut();
        for idx in 0..n_corpus {
            if do_retain[idx] {
                let removed = corpus.remove(CorpusId(idx))?;
                corpus.add_disabled(removed)?;
            }
        }

        Ok(())
    }

    fn restart_progress_should_run(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        // Not executing the target, so restart safety is not needed
        Ok(true)
    }
    fn clear_restart_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        // Not executing the target, so restart safety is not needed
        Ok(())
    }
}

/// A stage for conditional restart
#[derive(Debug)]
#[cfg(feature = "std")]
pub struct RestartStage<CB, E, EM, Z> {
    closure: CB,
    phantom: PhantomData<(E, EM, Z)>,
}

#[cfg(feature = "std")]
impl<CB, E, EM, Z> UsesState for RestartStage<CB, E, EM, Z>
where
    E: UsesState,
{
    type State = E::State;
}

#[cfg(feature = "std")]
impl<CB, E, EM, Z> Stage<E, EM, Z> for RestartStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut Self::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = Self::State> + EventRestarter,
    Z: UsesState<State = Self::State>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if (self.closure)(fuzzer, executor, state, manager)? {
            manager.on_restart(state).unwrap();
            std::process::exit(0);
        }
        Ok(())
    }

    fn restart_progress_should_run(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_restart_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(feature = "std")]
impl<CB, E, EM, Z> RestartStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut <Self as UsesState>::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
{
    /// Constructor for this conditionally enabled stage.
    /// If the closure returns true, the wrapped stage will be executed, else it will be skipped.
    pub fn new(closure: CB) -> Self {
        Self {
            closure,
            phantom: PhantomData,
        }
    }
}
