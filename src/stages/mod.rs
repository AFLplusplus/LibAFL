pub mod mutational;
pub use mutational::DefaultMutationalStage;

use crate::corpus::testcase::Testcase;
use crate::corpus::Corpus;
use crate::engines::State;
use crate::events::EventManager;
use crate::executors::Executor;
use crate::inputs::Input;
use crate::utils::Rand;
use crate::AflError;
use alloc::rc::Rc;
use core::cell::RefCell;

pub trait Stage<S, C, E, EM, I, R>
where
    S: State<C, E, EM, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    EM: EventManager,
    I: Input,
    R: Rand,
{
    /// Run the stage
    fn perform(
        &mut self,
        testcase: Rc<RefCell<Testcase<I>>>,
        state: &mut S,
    ) -> Result<(), AflError>;
}
