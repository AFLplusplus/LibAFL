use crate::inputs::Input;
use crate::utils::Rand;
use crate::corpus::Corpus;
use crate::AflError;

pub mod scheduled;
pub use scheduled::ScheduledMutator;

pub trait Mutator<InputT : Input> {

    fn rand(&mut self) -> &mut Box<dyn Rand>;

    fn mutate(&mut self, input: &mut InputT, stage_idx: i32) -> Result<(), AflError>;

    fn post_exec(&mut self, _is_interesting: bool, _stage_idx: i32) -> Result<(), AflError> {
        Ok(())
    }

    fn corpus(&mut self) -> &mut Option<Box<dyn Corpus>>;

}
