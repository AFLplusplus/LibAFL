use alloc::rc::Rc;
use core::cell::RefCell;
use core::marker::PhantomData;

use crate::corpus::testcase::Testcase;
use crate::engines::State;
use crate::events::EventManager;
use crate::executors::Executor;
use crate::inputs::Input;
use crate::mutators::Mutator;
use crate::stages::Corpus;
use crate::stages::Stage;
use crate::utils::Rand;
use crate::AflError;

// TODO multi mutators stage

pub trait MutationalStage<M, S, C, E, I, R>: Stage<S, C, E, I, R>
where
    M: Mutator<C, I, R>,
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    /// This call uses internal mutability, so it may change for each call
    fn iterations(&mut self, rand: &mut R) -> usize {
        1 + rand.below(128) as usize
    }

    /// Runs this (mutational) stage for the given testcase
    fn perform_mutational(
        &mut self,
        rand: &mut R,
        state: &mut S,
        testcase: Rc<RefCell<Testcase<I>>>,
    ) -> Result<(), AflError> {
        let num = self.iterations(rand);
        let input = testcase.borrow_mut().load_input()?.clone();

        for i in 0..num {
            let mut input_tmp = input.clone();
            self.mutator_mut()
                .mutate(rand, state, &mut input_tmp, i as i32)?;

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
pub struct DefaultMutationalStage<M, S, C, E, EM, I, R>
where
    M: Mutator<C, I, R>,
    S: State<C, E, EM, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    EM: EventManager,
    I: Input,
    R: Rand,
{
    mutator: M,
    phantom: PhantomData<(S, C, E, EM, I, R)>,
}

impl<M, S, C, E, EM, I, R> MutationalStage<M, S, C, E, EM, I, R>
    for DefaultMutationalStage<M, S, C, E, EM, I, R>
where
    M: Mutator<C, I, R>,
    S: State<C, E, EM, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    EM: EventManager,
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

impl<M, S, C, E, EM, I, R> Stage<S, C, E, EM, I, R> for DefaultMutationalStage<M, S, C, E, EM, I, R>
where
    M: Mutator<C, I, R>,
    S: State<C, E, EM, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    EM: EventManager,
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

impl<M, S, C, E, EM, I, R> DefaultMutationalStage<M, S, C, E, EM, I, R>
where
    M: Mutator<C, I, R>,
    S: State<C, E, EM, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    EM: EventManager,
    I: Input,
    R: Rand,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M) -> Self {
        DefaultMutationalStage {
            mutator: mutator,
            phantom: PhantomData,
        }
    }
}
