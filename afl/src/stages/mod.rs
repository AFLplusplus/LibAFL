pub mod mutational;
pub use mutational::StdMutationalStage;

use crate::corpus::Corpus;
use crate::engines::{Engine, State};
use crate::events::EventManager;
use crate::executors::Executor;
use crate::inputs::Input;
use crate::utils::Rand;
use crate::AflError;

/// A stage is one step in the fuzzing process.
/// Multiple stages will be scheduled one by one for each input.
pub trait Stage<EM, E, C, I, R>
where
    EM: EventManager<C, E, I, R>,
    E: Executor<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Run the stage
    fn perform(
        &mut self,
        rand: &mut R,
        state: &mut State<I, R>,
        corpus: &mut C,
        engine: &mut Engine<E, I>,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), AflError>;
}
