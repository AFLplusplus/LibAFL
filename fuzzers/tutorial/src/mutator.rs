use lain::traits::Mutatable;
use libafl::{
    bolts::{
        rands::{Rand, StdRand},
        tuples::Named,
    },
    inputs::UsesInput,
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};

use crate::input::PacketData;

pub struct LainMutator {
    inner: lain::mutator::Mutator<StdRand>,
}

impl<S> Mutator<S> for LainMutator
where
    S: UsesInput<Input = PacketData> + HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut PacketData,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // Lain uses its own instance of StdRand, but we want to keep it in sync with LibAFL's state.
        self.inner.rng_mut().set_seed(state.rand_mut().next());
        input.mutate(&mut self.inner, None);
        Ok(MutationResult::Mutated)
    }
}

impl Named for LainMutator {
    fn name(&self) -> &str {
        "LainMutator"
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
