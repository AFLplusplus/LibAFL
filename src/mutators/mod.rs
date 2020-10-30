use crate::inputs::Input;
use crate::AflError;

pub mod scheduled;
pub use scheduled::ScheduledMutator;

pub trait Mutator {
    //fn rand(&self) -> &Box<dyn Rand>;
    //fn rand_mut(&self) -> &mut Box<dyn Rand>;

    fn mutate(&mut self, input: &mut dyn Input) -> Result<(), AflError> {
        self.mutate_at((-1) as i32, input)
    }

    fn mutate_at(&mut self, stage_idx: i32, input: &mut dyn Input) -> Result<(), AflError>;

    fn post_exec(&mut self, is_interesting: bool) -> Result<(), AflError> {
        self.post_exec_at((-1) as i32, is_interesting)
    }

    fn post_exec_at(&mut self, _stage_idx: i32, _is_interesting: bool) -> Result<(), AflError> {
        Ok(())
    }
}
