use crate::corpus::testcase::Testcase;
use crate::engines::Evaluator;
use crate::inputs::Input;
use crate::mutators::Mutator;
use crate::stages::{HasEvaluator, Stage};
use crate::utils::{HasRand, Rand};
use crate::AflError;

use std::cell::RefCell;
use std::rc::Rc;
use std::marker::PhantomData;

// TODO create HasMutatorsVec trait

pub trait MutationalStage<I, M>: Stage<I> + HasRand
where
    I: Input,
    M: Mutator<I, R = Self::R>,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    /// This call uses internal mutability, so it may change for each call
    fn iterations(&mut self) -> usize {
        1 + self.rand_below(128) as usize
    }

    /// Runs this (mutational) stage for the given testcase
    fn perform_mutational(&mut self, testcase: &Rc<RefCell<Testcase<I>>>) -> Result<(), AflError> {
        let num = self.iterations();
        let input = testcase.borrow_mut().load_input()?.clone();

        for i in 0..num {
            let mut input_tmp = input.clone();
            self.mutator_mut().mutate(&mut input_tmp, i as i32)?;

            let interesting = self
                .evaluator()
                .borrow_mut()
                .evaluate_input(&mut input_tmp, testcase.clone())?;

            self.mutator_mut().post_exec(interesting, i as i32)?;

        }
        Ok(())
    }
}

/// The default mutational stage
pub struct DefaultMutationalStage<I, R, M, E>
where
    I: Input,
    R: Rand,
    M: Mutator<I, R=R>,
    E: Evaluator<I>,
{
    rand: Rc<RefCell<R>>,
    evaluator: Rc<RefCell<E>>,
    mutator: M,
    _phantom_input: PhantomData<I>
}

impl<I, R, M, E> HasRand for DefaultMutationalStage<I, R, M, E>
where
    I: Input,
    R: Rand,
    M: Mutator<I, R=R>,
    E: Evaluator<I>,
{
    type R = R;

    fn rand(&self) -> &Rc<RefCell<R>> {
        &self.rand
    }
}

/// Indicate that this stage can eval targets
impl<I, R, M, E> HasEvaluator<I> for DefaultMutationalStage<I, R, M, E>
where
    I: Input,
    R: Rand,
    M: Mutator<I, R=R>,
    E: Evaluator<I>,
{
    type E = E;

    /// Get the evaluator
    fn evaluator(&self) -> &Rc<RefCell<Self::E>> {
        &self.evaluator
    }
}

impl<I, R, M, E> MutationalStage<I, M> for DefaultMutationalStage<I, R, M, E>
where
    I: Input,
    R: Rand,
    M: Mutator<I, R=R>,
    E: Evaluator<I>,
{
    /// The mutator, added to this stage
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }
}

impl<I, R, M, E> Stage<I> for DefaultMutationalStage<I, R, M, E>
where
    I: Input,
    R: Rand,
    M: Mutator<I, R=R>,
    E: Evaluator<I>,
{
    fn perform(&mut self, testcase: &Rc<RefCell<Testcase<I>>>) -> Result<(), AflError> {
        self.perform_mutational(testcase)
    }
}

impl<I, R, M, E> DefaultMutationalStage<I, R, M, E>
where
    I: Input,
    R: Rand,
    M: Mutator<I, R=R>,
    E: Evaluator<I>,
{
    /// Creates a new default mutational stage
    pub fn new(rand: &Rc<RefCell<R>>, evaluator: &Rc<RefCell<E>>, mutator: M) -> Self {
        DefaultMutationalStage {
            rand: Rc::clone(rand),
            evaluator: Rc::clone(evaluator),
            mutator: mutator,
            _phantom_input: PhantomData,
        }
    }
}
