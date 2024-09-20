//! A [`Stage`] that generates a single input via a
//! [`crate::generators::Generator`] and evaluates it using the fuzzer, possibly
//! adding it to the corpus.

use crate::{
    corpus::{Corpus, HasCorpus},
    generators::Generator,
    stages::Stage,
    state::HasRand,
    Error, Evaluator,
};

/// A [`Stage`] that generates a single input via a [`Generator`] and evaluates
/// it using the fuzzer, possibly adding it to the corpus.
///
/// This stage can be used to construct black-box (e.g., grammar-based) fuzzers.
#[derive(Debug)]
pub struct GenStage<G>(G);

impl<G> GenStage<G> {
    /// Create a new [`GenStage`].
    pub fn new(g: G) -> Self {
        Self(g)
    }
}

impl<E, EM, G, S, Z> Stage<E, EM, S, Z> for GenStage<G>
where
    Z: Evaluator<E, EM, <S::Corpus as Corpus>::Input, S>,
    S: HasCorpus + HasRand,
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
