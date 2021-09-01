use libafl::{
    bolts::{
        rands::{Rand, StdRand},
        tuples::Named,
    },
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};

use crate::input::PacketData;

use core::marker::PhantomData;
use lain::traits::Mutatable;

pub struct LainMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    inner: lain::mutator::Mutator<StdRand>,
    phantom: PhantomData<(R, S)>,
}

impl<R, S> Mutator<PacketData, S> for LainMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut PacketData,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.inner.rng_mut().set_seed(state.rand_mut().next());
        input.mutate(&mut self.inner, None);
        Ok(MutationResult::Mutated)
    }
}

impl<R, S> Named for LainMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "LainMutator"
    }
}

impl<R, S> LainMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: lain::mutator::Mutator::new(StdRand::with_seed(0)),
            phantom: PhantomData,
        }
    }
}

impl<R, S> Default for LainMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    #[must_use]
    fn default() -> Self {
        Self::new()
    }
}
