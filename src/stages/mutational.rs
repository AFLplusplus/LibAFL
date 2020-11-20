use alloc::rc::Rc;
use core::cell::RefCell;
use core::marker::PhantomData;

use crate::corpus::testcase::Testcase;
use crate::engines::State;
use crate::executors::Executor;
use crate::inputs::Input;
use crate::mutators::Mutator;
use crate::stages::Corpus;
use crate::stages::Stage;
use crate::utils::{HasRand, Rand};
use crate::AflError;

// TODO multi mutators stage

pub trait MutationalStage<M, S, C, E, I>: Stage<S, C, E, I> + HasRand
where
    M: Mutator<C, I, R = Self::R>,
    S: State<C, E, I>,
    E: Executor<I>,
    C: Corpus<I>,
    I: Input,
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
    fn perform_mutational(
        &mut self,
        testcase: Rc<RefCell<Testcase<I>>>,
        state: &mut S,
    ) -> Result<(), AflError> {
        let num = self.iterations();
        let input = testcase.borrow_mut().load_input()?.clone();

        for i in 0..num {
            let mut input_tmp = input.clone();
            self.mutator_mut()
                .mutate(state.corpus_mut(), &mut input_tmp, i as i32)?;

            let interesting = state.evaluate_input(&input_tmp)?;

            self.mutator_mut().post_exec(interesting, i as i32)?;

            if interesting {
                state.corpus_mut().add(Testcase::new(input_tmp).into());
            }
        }
        Ok(())
    }
}

/// The default mutational stage
pub struct DefaultMutationalStage<M, C, I, R>
where
    M: Mutator<C, I, R = R>,
    C: Corpus<I>,
    I: Input,
    R: Rand,
{
    rand: Rc<RefCell<R>>,
    mutator: M,
    _phantom_corpus: PhantomData<C>,
    _phantom_input: PhantomData<I>,
}

impl<M, C, I, R> HasRand for DefaultMutationalStage<M, C, I, R>
where
    M: Mutator<C, I, R = R>,
    C: Corpus<I>,
    I: Input,
    R: Rand,
{
    type R = R;

    fn rand(&self) -> &Rc<RefCell<R>> {
        &self.rand
    }
}

impl<M, S, C, E, I, R> MutationalStage<M, S, C, E, I> for DefaultMutationalStage<M, C, I, R>
where
    M: Mutator<C, I, R = R>,
    S: State<C, E, I>,
    C: Corpus<I>,
    E: Executor<I>,
    I: Input,
    R: Rand,
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

impl<M, S, C, E, I, R> Stage<S, C, E, I> for DefaultMutationalStage<M, C, I, R>
where
    M: Mutator<C, I, R = R>,
    S: State<C, E, I>,
    C: Corpus<I>,
    E: Executor<I>,
    I: Input,
    R: Rand,
{
    fn perform(
        &mut self,
        testcase: Rc<RefCell<Testcase<I>>>,
        state: &mut S,
    ) -> Result<(), AflError> {
        self.perform_mutational(testcase, state)
    }
}

impl<M, C, I, R> DefaultMutationalStage<M, C, I, R>
where
    M: Mutator<C, I, R = R>,
    C: Corpus<I>,
    I: Input,
    R: Rand,
{
    /// Creates a new default mutational stage
    pub fn new(rand: &Rc<RefCell<R>>, mutator: M) -> Self {
        DefaultMutationalStage {
            rand: Rc::clone(rand),
            mutator: mutator,
            _phantom_corpus: PhantomData,
            _phantom_input: PhantomData,
        }
    }
}
