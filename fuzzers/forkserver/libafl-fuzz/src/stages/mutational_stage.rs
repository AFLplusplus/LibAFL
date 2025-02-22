use std::{borrow::Cow, marker::PhantomData};

use libafl::{
    stages::{MutationalStage, Restartable, Stage},
    Error,
};
use libafl_bolts::Named;

#[derive(Debug)]
pub enum SupportedMutationalStages<P, SM> {
    StdMutational(SM, PhantomData<P>),
    PowerMutational(P, PhantomData<SM>),
}

impl<P, S, SM> MutationalStage<S> for SupportedMutationalStages<P, SM>
where
    P: MutationalStage<S, Mutator = SM::Mutator>,
    SM: MutationalStage<S>,
{
    type Mutator = SM::Mutator;
    /// The mutator, added to this stage
    fn mutator(&self) -> &Self::Mutator {
        match self {
            Self::StdMutational(m, _) => m.mutator(),
            Self::PowerMutational(p, _) => p.mutator(),
        }
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut Self::Mutator {
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

impl<P, SM> Named for SupportedMutationalStages<P, SM>
where
    P: Named,
    SM: Named,
{
    fn name(&self) -> &Cow<'static, str> {
        match self {
            Self::StdMutational(m, _) => m.name(),
            Self::PowerMutational(p, _) => p.name(),
        }
    }
}

impl<E, EM, P, S, SM, Z> Stage<E, EM, S, Z> for SupportedMutationalStages<P, SM>
where
    P: Stage<E, EM, S, Z>,
    SM: Stage<E, EM, S, Z>,
{
    #[inline]
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
}

impl<P, S, SM> Restartable<S> for SupportedMutationalStages<P, SM>
where
    P: Restartable<S>,
    SM: Restartable<S>,
{
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
