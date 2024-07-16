//! Corpus pruning stage

use core::marker::PhantomData;

use libafl_bolts::{rands::Rand, Error};

use crate::{
    corpus::Corpus,
    stages::Stage,
    state::{HasCorpus, HasRand, UsesState},
};
#[cfg(feature = "std")]
use crate::{events::EventRestarter, state::Stoppable};

#[derive(Debug)]
/// The stage to probablistically disable a corpus entry.
/// This stage should be wrapped in a if stage and run only when the fuzzer perform restarting
/// The idea comes from `https://mschloegel.me/paper/schiller2023fuzzerrestarts.pdf`
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
    #[allow(clippy::cast_precision_loss)]
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
        let mut retain_any = false;
        for _ in 0..n_corpus {
            let r = state.rand_mut().below(100) as f64;
            let retain = self.prob * 100_f64 < r;
            if retain {
                retain_any = true;
            }
            do_retain.push(retain);
        }

        // Make sure that at least somthing is in the
        if !retain_any {
            let r = state.rand_mut().below(n_corpus);
            do_retain[r] = true;
        }

        for (i_th, retain) in do_retain.iter().enumerate().take(n_corpus) {
            if !retain {
                let corpus_id = state.corpus().nth_from_all(i_th);

                let corpus = state.corpus_mut();
                let removed = corpus.remove(corpus_id)?;
                corpus.add_disabled(removed)?;
            }
        }

        // println!("There was {}, and we retained {} corpura", n_corpus, state.corpus().count());
        Ok(())
    }

    fn should_restart(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        // Not executing the target, so restart safety is not needed
        Ok(true)
    }
    fn clear_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        // Not executing the target, so restart safety is not needed
        Ok(())
    }
}

/// A stage for conditional restart
#[derive(Debug, Default)]
#[cfg(feature = "std")]
pub struct RestartStage<E, EM, Z> {
    phantom: PhantomData<(E, EM, Z)>,
}

#[cfg(feature = "std")]
impl<E, EM, Z> UsesState for RestartStage<E, EM, Z>
where
    E: UsesState,
{
    type State = E::State;
}

#[cfg(feature = "std")]
impl<E, EM, Z> Stage<E, EM, Z> for RestartStage<E, EM, Z>
where
    E: UsesState,
    EM: UsesState<State = Self::State> + EventRestarter,
    Z: UsesState<State = Self::State>,
{
    #[allow(unreachable_code)]
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        manager.on_restart(state).unwrap();
        state.request_stop();
        Ok(())
    }

    fn should_restart(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(feature = "std")]
impl<E, EM, Z> RestartStage<E, EM, Z>
where
    E: UsesState,
{
    /// Constructor for this conditionally enabled stage.
    /// If the closure returns true, the wrapped stage will be executed, else it will be skipped.
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}
