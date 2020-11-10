use crate::corpus::Corpus;
use crate::corpus::TestcaseMetadata;
use crate::executors::Executor;
use crate::corpus::testcase::Testcase;
use crate::engines::Evaluator;
use crate::inputs::Input;
use crate::mutators::Mutator;
use crate::stages::Stage;
use crate::utils::{HasRand, Rand};
use crate::AflError;

use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

// TODO create HasMutatorsVec trait

pub trait MutationalStage<I, C, M, E>: Stage<I> + HasRand
where
    I: Input,
    M: Mutator<I, R = Self::R>,
    C: Corpus<I>,
    E: Executor<I, C>,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Rc Refcell to the executor
    fn executor(&self) -> &Rc<RefCell<E>>;

    /// Gets the number of iterations this mutator should run for.
    /// This call uses internal mutability, so it may change for each call
    fn iterations(&mut self) -> usize {
        1 + self.rand_below(128) as usize
    }

    /// Runs this (mutational) stage for the given testcase
    fn perform_mutational(&mut self, corpus: &mut C, testcase: &Rc<RefCell<Testcase<I>>>) -> Result<(), AflError> {
        let testcase = corpus.next()?;
        let num = self.iterations();
        let input = testcase.borrow_mut().load_input()?.clone();

        for i in 0..num {
            let mut input_tmp = input.clone();
            self.mutator_mut().mutate(&mut input_tmp, i as i32)?;

            let interesting = self.executor().borrow_mut().evaluate_input(&corpus)?;

            self.mutator_mut().post_exec(interesting, i as i32)?;
        }
        Ok(())
    }
}

/// The default mutational stage
pub struct DefaultMutationalStage<I, C, R, M, E>
where
    I: Input,
    C: Corpus<I>,
    R: Rand,
    M: Mutator<I, R = R>,
    E: Executor<I, C>,
{
    rand: Rc<RefCell<R>>,
    executor: Rc<RefCell<E>>,
    mutator: M,
    _phantom_input: PhantomData<I>,
    _phantom_corpus: PhantomData<C>,
}

impl<I, C, R, M, E> HasRand for DefaultMutationalStage<I, C, R, M, E>
where
    I: Input,
    C: Corpus<I>,
    R: Rand,
    M: Mutator<I, R = R>,
    E: Executor<I, C>,
{
    type R = R;

    fn rand(&self) -> &Rc<RefCell<R>> {
        &self.rand
    }
}


impl<I, C, R, M, E> MutationalStage<I, C, M, E> for DefaultMutationalStage<I, C, R, M, E>
where
    I: Input,
    C: Corpus<I>,
    R: Rand,
    M: Mutator<I, R = R>,
    E: Executor<I, C>,
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

impl<I, C, R, M, E> Stage<I> for DefaultMutationalStage<I, C, R, M, E>
where
    I: Input,
    C: Corpus<I>,
    R: Rand,
    M: Mutator<I, R = R>,
    E: Executor<I, C>,
{
    fn perform(&mut self, corpus: &mut C) -> Result<(), AflError> {
        self.perform_mutational(corpus)
    }
}

impl<I, C, R, M, E> DefaultMutationalStage<I, C, R, M, E>
where
    I: Input,
    R: Rand,
    C: Corpus<I>,
    M: Mutator<I, R = R>,
    E: Executor<I, C>,
{
    /// Creates a new default mutational stage
    pub fn new(rand: &Rc<RefCell<R>>, executor: &Rc<RefCell<E>>, mutator: M) -> Self {
        DefaultMutationalStage {
            rand: Rc::clone(rand),
            executor: Rc::clone(executor),
            mutator: mutator,
            _phantom_input: PhantomData,
            _phantom_corpus: PhantomData,
        }
    }
}
