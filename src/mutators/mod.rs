use std::io::Error;
use crate::inputs::Input;
use crate::utils::Rand;

pub mod scheduled;

pub trait Mutator {

    //fn rand(&self) -> &Box<dyn Rand>;
    //fn rand_mut(&self) -> &mut Box<dyn Rand>;

    fn mutate(&mut self, input: &mut dyn Input) -> Result<(), Error> {
        self.mutate_at((-1) as i32, input)
    }

    fn mutate_at(&mut self, stage_idx: i32, input: &mut dyn Input) -> Result<(), Error>;

    fn post_exec(&mut self, is_interesting: bool) -> Result<(), Error> {
        self.post_exec_at((-1) as i32, is_interesting)
    }

    fn post_exec_at(&mut self, stage_idx: i32, is_interesting: bool) -> Result<(), Error>;

}