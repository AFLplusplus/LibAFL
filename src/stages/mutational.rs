use crate::AflError;
use crate::mutators::Mutator;
use crate::inputs::Input;
use crate::utils::{Rand, HasRand};
use crate::stages::{Stage, HasEngine};
use crate::corpus::testcase::Testcase;
use crate::engines::Engine;

use std::cell::RefCell;
use std::rc::Rc;

pub trait MutationalStage<'a, I> : Stage<'a, I> + HasRand where I: Input {
    fn mutators(&self) -> &Vec<Box<dyn Mutator<I, R = Self::R>>>;

    fn mutators_mut(&mut self) -> &mut Vec<Box<dyn Mutator<I, R = Self::R>>>;

    fn add_mutator(&mut self, mutator: Box<dyn Mutator<I, R = Self::R>>) {
        self.mutators_mut().push(mutator);
    }

    fn iterations(&mut self) -> usize {
        1 + self.rand_mut().below(128) as usize
    }

    fn perform_mutational(&mut self, entry: Rc<RefCell<Testcase<I>>>) -> Result<(), AflError> {
        let num = self.iterations();
        let mut input = entry.borrow_mut().load_input()?.clone();

        for i in 0..num {
            for m in self.mutators_mut() {
                m.mutate(&mut input, i as i32)?;
            }

            let interesting = self.engine_mut().execute(&mut input, entry.clone())?;

            for m in self.mutators_mut() {
                m.post_exec(interesting, i as i32)?;
            }

            input = entry.borrow_mut().load_input()?.clone();
        }
        
        Ok(())
    }
}

pub struct DefaultMutationalStage<'a, I, R, E> where I: Input, R: Rand, E: Engine<'a, I> {
    rand: &'a mut R,
    engine: &'a mut E,
    mutators: Vec<Box<dyn Mutator<I, R = R>>>
}

impl<'a, I, R, E> HasRand for DefaultMutationalStage<'a, I, R, E> where I: Input, R: Rand, E: Engine<'a, I> {
    type R = R;

    fn rand(&self) -> &Self::R {
        &self.rand
    }
    fn rand_mut(&mut self) -> &mut Self::R {
        &mut self.rand
    }
}

impl<'a, I, R, E> HasEngine<'a, I> for DefaultMutationalStage<'a, I, R, E> where I: Input, R: Rand, E: Engine<'a, I> {
    type E = E;

    fn engine(&self) -> &Self::E {
        self.engine
    }

    fn engine_mut(&mut self) -> &mut Self::E {
        self.engine
    }
}