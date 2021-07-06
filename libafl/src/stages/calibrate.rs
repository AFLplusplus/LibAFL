use core::marker::PhantomData;

use crate::{
    bolts::rands::Rand,
    corpus::Corpus,
    fuzzer::Evaluator,
    inputs::Input,
    mutators::Mutator,
    stages::Stage,
    state::{HasClientPerfStats, HasCorpus, HasRand},
    Error,
};


/// The default mutational stage
#[derive(Clone, Debug)]
pub struct CalibrateStage<C, E, EM, I, S, Z>
where
    C: Corpus<I>,
    I: Input,
    S: HasCorpus<C, I>,
    Z: Evaluator<E, EM, I, S>,
{
    total_exec_us: f64,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(C, E, EM, I, S, Z)>,
}


impl<C, E, EM, I, S, Z> Stage<E, EM, S, Z> for CalibrateStage<C, E, EM, I, S, Z>
where
    C: Corpus<I>,
    I: Input,
    S: HasCorpus<C, I>,
    Z: Evaluator<E, EM, I, S>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut S,
        _manager: &mut EM,
        _corpus_idx: usize,
    ) -> Result<(), Error> {
        /// Run the PUT via executor, check time passed
        /// Update exec_us, bitmap_size, handicap... etc.

        Ok(())
    }
}

impl<C, E, I, EM, S, Z> CalibrateStage<C, E, EM, I, S, Z>
where
    C: Corpus<I>,
    I: Input,
    S: HasCorpus<C, I>,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new default mutational stage
    pub fn new() -> Self {
        Self {
            total_exec_us: 0.0,
            phantom: PhantomData,
        }
    }
}
