use std::borrow::Cow;

use lain::traits::Mutatable;
use libafl::{
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};
use libafl_bolts::{
    rands::{Rand, StdRand},
    Named,
};

use crate::input::PacketData;

pub struct LainMutator {
    inner: lain::mutator::Mutator<StdRand>,
}

impl<S> Mutator<PacketData, S> for LainMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut PacketData) -> Result<MutationResult, Error> {
        // Lain uses its own instance of StdRand, but we want to keep it in sync with LibAFL's state.
        self.inner.rng_mut().set_seed(state.rand_mut().next());
        input.mutate(&mut self.inner, None);
        Ok(MutationResult::Mutated)
    }
}

impl Named for LainMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("LainMutator");
        &NAME
    }
}

impl LainMutator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: lain::mutator::Mutator::new(StdRand::with_seed(0)),
        }
    }
}

impl Default for LainMutator {
    #[must_use]
    fn default() -> Self {
        Self::new()
    }
}
