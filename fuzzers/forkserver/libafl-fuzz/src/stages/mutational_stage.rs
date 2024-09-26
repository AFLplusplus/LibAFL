use std::{borrow::Cow, marker::PhantomData};

use libafl::{
    corpus::Corpus,
    inputs::Input,
    mutators::Mutator,
    stages::{mutational::MutatedTransform, MutationalStage, Stage},
    state::{HasCorpus, HasRand, State, UsesState},
    Error, Evaluator, HasNamedMetadata,
};
use libafl_bolts::Named;

#[derive(Debug)]
pub enum SupportedMutationalStages<S, SM, P, E, EM, M, I, Z> {
    StdMutational(SM, PhantomData<(S, I, M, EM, Z, E)>),
    PowerMutational(P, PhantomData<(S, I, M, EM, Z, E)>),
}

impl<S, SM, P, E, EM, M, I, Z> MutationalStage<E, EM, I, M, Z>
    for SupportedMutationalStages<S, SM, P, E, EM, M, I, Z>
where
    E: UsesState<State = S>,
    EM: UsesState<State = S>,
    M: Mutator<I, S>,
    Z: Evaluator<E, EM, State = S>,
    I: MutatedTransform<S::Input, S> + Clone + Input,
    SM: MutationalStage<E, EM, I, M, Z, State = S>,
    P: MutationalStage<E, EM, I, M, Z, State = S>,
    S: State<Input = I> + HasRand + HasCorpus + HasNamedMetadata,
    <<Self as UsesState>::State as HasCorpus>::Corpus: Corpus<Input = Self::Input>, //delete me
{
    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &M {
        match self {
            Self::StdMutational(m, _) => m.mutator(),
            Self::PowerMutational(p, _) => p.mutator(),
        }
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut M {
        match self {
            Self::StdMutational(m, _) => m.mutator_mut(),
            Self::PowerMutational(p, _) => p.mutator_mut(),
        }
    }

    /// Gets the number of iterations as a random number
    fn iterations(&self, state: &mut S) -> Result<usize, Error> {
        match self {
            Self::StdMutational(m, _) => m.iterations(state),
            Self::PowerMutational(p, _) => p.iterations(state),
        }
    }
}

impl<S, SM, P, E, EM, M, I, Z> UsesState for SupportedMutationalStages<S, SM, P, E, EM, M, I, Z>
where
    S: State + HasRand,
{
    type State = S;
}

impl<S, SM, P, E, EM, M, I, Z> Named for SupportedMutationalStages<S, SM, P, E, EM, M, I, Z>
where
    SM: Named,
    P: Named,
{
    fn name(&self) -> &Cow<'static, str> {
        match self {
            Self::StdMutational(m, _) => m.name(),
            Self::PowerMutational(p, _) => p.name(),
        }
    }
}

impl<S, SM, P, E, EM, M, I, Z> Stage<E, EM, Z>
    for SupportedMutationalStages<S, SM, P, E, EM, M, I, Z>
where
    E: UsesState<State = S>,
    EM: UsesState<State = S>,
    M: Mutator<I, S>,
    Z: Evaluator<E, EM, State = S>,
    I: MutatedTransform<S::Input, S> + Clone + Input,
    SM: MutationalStage<E, EM, I, M, Z, State = S>,
    P: MutationalStage<E, EM, I, M, Z, State = S>,
    S: State<Input = I> + HasRand + HasCorpus + HasNamedMetadata,
    <<Self as UsesState>::State as HasCorpus>::Corpus: Corpus<Input = Self::Input>, //delete me
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        match self {
            Self::StdMutational(m, _) => m.perform(fuzzer, executor, state, manager),
            Self::PowerMutational(p, _) => p.perform(fuzzer, executor, state, manager),
        }
    }

    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        match self {
            Self::StdMutational(m, _) => m.should_restart(state),
            Self::PowerMutational(p, _) => p.should_restart(state),
        }
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        match self {
            Self::StdMutational(m, _) => m.clear_progress(state),
            Self::PowerMutational(p, _) => p.clear_progress(state),
        }
    }
}
