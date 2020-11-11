extern crate alloc;
use crate::corpus::testcase::Testcase;
use crate::executors::Executor;
use crate::inputs::Input;
use crate::mutators::Mutator;
use crate::stages::Corpus;
use crate::stages::Stage;
use crate::utils::{HasRand, Rand};
use crate::AflError;

use alloc::rc::Rc;
use core::cell::RefCell;
use core::marker::PhantomData;

// TODO create HasMutatorsVec trait

pub trait MutationalStage<C, I, M, E>: Stage<C, I> + HasRand
where
    C: Corpus<I>,
    I: Input,
    M: Mutator<C, I, R = Self::R>,
    E: Executor<I>,
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
    fn perform_mutational(&mut self, corpus: &mut C) -> Result<(), AflError> {
        let testcase = corpus.next()?;
        let num = self.iterations();
        let input = testcase.borrow_mut().load_input()?.clone();

        for i in 0..num {
            let mut input_tmp = input.clone();
            self.mutator_mut()
                .mutate(corpus, &mut input_tmp, i as i32)?;

            let interesting = self.executor().borrow_mut().evaluate_input(&input_tmp)?;

            self.mutator_mut().post_exec(interesting, i as i32)?;

            if interesting {
                corpus.add(Testcase::new_rr(input_tmp));
            }
        }
        Ok(())
    }
}

/// The default mutational stage
pub struct DefaultMutationalStage<C, I, R, M, E>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    M: Mutator<C, I, R = R>,
    E: Executor<I>,
{
    rand: Rc<RefCell<R>>,
    executor: Rc<RefCell<E>>,
    mutator: M,
    _phantom_corpus: PhantomData<C>,
    _phantom_input: PhantomData<I>,
}

impl<C, I, R, M, E> HasRand for DefaultMutationalStage<C, I, R, M, E>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    M: Mutator<C, I, R = R>,
    E: Executor<I>,
{
    type R = R;

    fn rand(&self) -> &Rc<RefCell<R>> {
        &self.rand
    }
}

impl<C, I, R, M, E> MutationalStage<C, I, M, E> for DefaultMutationalStage<C, I, R, M, E>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    M: Mutator<C, I, R = R>,
    E: Executor<I>,
{
    /// The mutator, added to this stage
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    fn executor(&self) -> &Rc<RefCell<E>> {
        &self.executor
    }
}

impl<C, I, R, M, E> Stage<C, I> for DefaultMutationalStage<C, I, R, M, E>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    M: Mutator<C, I, R = R>,
    E: Executor<I>,
{
    fn perform(&mut self, corpus: &mut C) -> Result<(), AflError> {
        self.perform_mutational(corpus)
    }
}

impl<C, I, R, M, E> DefaultMutationalStage<C, I, R, M, E>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    M: Mutator<C, I, R = R>,
    E: Executor<I>,
{
    /// Creates a new default mutational stage
    pub fn new(rand: &Rc<RefCell<R>>, executor: &Rc<RefCell<E>>, mutator: M) -> Self {
        DefaultMutationalStage {
            rand: Rc::clone(rand),
            executor: Rc::clone(executor),
            mutator: mutator,
            _phantom_corpus: PhantomData,
            _phantom_input: PhantomData,
        }
    }
}
