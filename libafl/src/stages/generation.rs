//! The [`GenStage`] generates a single input and evaluates it.
//!
//! A [`Stage`] that generates a single input via a
//! [`crate::generators::Generator`] and evaluates it using the fuzzer, possibly
//! adding it to the corpus.

use core::marker::PhantomData;

use crate::{
    corpus::Corpus,
    generators::Generator,
    inputs::UsesInput,
    stages::Stage,
    state::{HasCorpus, HasRand},
    Error, Evaluator,
};

/// A [`Stage`] that generates a single input via a [`Generator`] and evaluates
/// it using the fuzzer, possibly adding it to the corpus.
///
/// This stage can be used to construct black-box (e.g., grammar-based) fuzzers.
#[derive(Debug)]
pub struct GenStage<G, S, Z>(G, PhantomData<(S, Z)>);

impl<G, S, Z> GenStage<G, S, Z> {
    /// Create a new [`GenStage`].
    pub fn new(g: G) -> Self {
        Self(g, PhantomData)
    }
}

impl<E, EM, G, S, Z> Stage<E, EM, S, Z> for GenStage<G, S, Z>
where
    Z: Evaluator<E, EM, State = S>,
    S: HasCorpus + HasRand + UsesInput<Input = <S::Corpus as Corpus>::Input>,
    G: Generator<<S::Corpus as Corpus>::Input, S>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let input = self.0.generate(state)?;
        fuzzer.evaluate_input(state, executor, manager, input)?;
        Ok(())
    }

    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        // It's a random generation stage
        // so you can restart for whatever times you want
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}
