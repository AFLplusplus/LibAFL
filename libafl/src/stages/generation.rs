//! A [`Stage`] that generates a single input via a
//! [`crate::generators::Generator`] and evaluates it using the fuzzer, possibly
//! adding it to the corpus.

use core::marker::PhantomData;

use crate::{
    generators::Generator,
    inputs::UsesInput,
    stages::Stage,
    state::{HasCorpus, HasRand, UsesState},
    Error, Evaluator,
};

/// A [`Stage`] that generates a single input via a [`Generator`] and evaluates
/// it using the fuzzer, possibly adding it to the corpus.
///
/// This stage can be used to construct black-box (e.g., grammar-based) fuzzers.
#[derive(Debug)]
pub struct GenStage<G, Z>(G, PhantomData<Z>)
where
    Z: UsesState,
    G: Generator<<<Z as UsesState>::State as UsesInput>::Input, Z::State>;

impl<G, Z> GenStage<G, Z>
where
    Z: UsesState,
    G: Generator<<<Z as UsesState>::State as UsesInput>::Input, Z::State>,
{
    /// Create a new [`GenStage`].
    pub fn new(g: G) -> Self {
        Self(g, PhantomData)
    }
}

impl<G, Z> UsesState for GenStage<G, Z>
where
    Z: UsesState,
    G: Generator<<<Z as UsesState>::State as UsesInput>::Input, Z::State>,
{
    type State = Z::State;
}

impl<E, EM, Z, G> Stage<E, EM, Z> for GenStage<G, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand,
    G: Generator<<<Z as UsesState>::State as UsesInput>::Input, Z::State>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let input = self.0.generate(state)?;
        fuzzer.evaluate_input(state, executor, manager, input)?;
        Ok(())
    }

    fn restart_progress_should_run(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_restart_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        Ok(())
    }
}
