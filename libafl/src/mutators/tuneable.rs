//! An extension to the `ScheduledMutator` which schedules multiple mutations internally.
//! Instead of a random mutator for a random amount of iterations, we can run
//! a specific mutator for a specified amount of iterations

use core::{
    fmt::{self, Debug},
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};

pub use crate::mutators::{mutations::*, token_mutations::*};
use crate::{
    bolts::rands::Rand,
    impl_serdeany,
    mutators::{ComposedByMutations, MutationResult, Mutator, MutatorsTuple, ScheduledMutator},
    state::{HasMetadata, HasRand, State},
    Error,
};

#[derive(Default, Clone, Copy, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct TuneableScheduledMutatorMetadata {
    pub next: Option<usize>,
    pub iters: Option<u64>,
}

impl_serdeany!(TuneableScheduledMutatorMetadata);

/// A [`Mutator`] that schedules one of the embedded mutations on each call.
/// The index of the next mutation can be set.
pub struct TuneableScheduledMutator<MT, S>
where
    MT: MutatorsTuple<S>,
    S: State + HasRand,
{
    mutations: MT,
    max_stack_pow: u64,
    phantom: PhantomData<S>,
}

impl<MT, S> Debug for TuneableScheduledMutator<MT, S>
where
    MT: MutatorsTuple<S>,
    S: State + HasRand,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TuneableScheduledMutator with {} mutations for Input type {}",
            self.mutations.len(),
            core::any::type_name::<S::Input>()
        )
    }
}

impl<MT, S> Mutator<S> for TuneableScheduledMutator<MT, S>
where
    MT: MutatorsTuple<S>,
    S: State + HasRand + HasMetadata,
{
    #[inline]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input, stage_idx)
    }
}

impl<MT, S> ComposedByMutations<MT, S> for TuneableScheduledMutator<MT, S>
where
    MT: MutatorsTuple<S>,
    S: State + HasRand,
{
    /// Get the mutations
    #[inline]
    fn mutations(&self) -> &MT {
        &self.mutations
    }

    // Get the mutations (mutable)
    #[inline]
    fn mutations_mut(&mut self) -> &mut MT {
        &mut self.mutations
    }
}

impl<MT, S> ScheduledMutator<MT, S> for TuneableScheduledMutator<MT, S>
where
    MT: MutatorsTuple<S>,
    S: State + HasRand + HasMetadata,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &S::Input) -> u64 {
        if let Some((_next, iters)) = Self::get_next_and_iters(state) {
            iters
        } else {
            // fall back to random
            1 << (1 + state.rand_mut().below(self.max_stack_pow))
        }
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &S::Input) -> usize {
        debug_assert!(!self.mutations().is_empty());
        #[allow(clippy::cast_possible_truncation)]
        if let Some((next, _iters)) = Self::get_next_and_iters(state) {
            debug_assert!(self.mutations().len() > next);
            next
        } else {
            // fall back to random
            state.rand_mut().below(self.mutations().len() as u64) as usize
        }
    }
}

impl<MT, S> TuneableScheduledMutator<MT, S>
where
    MT: MutatorsTuple<S>,
    S: State + HasRand + HasMetadata,
{
    /// Create a new [`TuneableScheduledMutator`] instance specifying mutations
    pub fn new(state: &mut S, mutations: MT) -> Self {
        if !state.has_metadata::<TuneableScheduledMutatorMetadata>() {
            state.add_metadata(TuneableScheduledMutatorMetadata::default());
        }
        TuneableScheduledMutator {
            mutations,
            max_stack_pow: 7,
            phantom: PhantomData,
        }
    }

    pub fn metadata_mut(state: &mut S) -> &mut TuneableScheduledMutatorMetadata {
        state
            .metadata_mut()
            .get_mut::<TuneableScheduledMutatorMetadata>()
            .unwrap()
    }

    pub fn metadata(state: &S) -> &TuneableScheduledMutatorMetadata {
        state
            .metadata()
            .get::<TuneableScheduledMutatorMetadata>()
            .unwrap()
    }

    /// Set the next mutator id and iterations count
    /// Setting both at the same time will be faster than setting them individually
    /// as it internally only needs a single metadata lookup
    pub fn set_next_and_iter(state: &mut S, next: usize, iters: u64) {
        let metadata = Self::metadata_mut(state);
        metadata.next = Some(next);
        metadata.iters = Some(iters);
    }

    /// Sets the next mutator id, i.e., which mutator to pick.
    ///
    /// Using `set_next_and_iter` to set multiple values at the same time
    /// will be faster than setting them individually
    /// as it internally only needs a single metadata lookup
    pub fn set_next(state: &mut S, next: usize) {
        let metadata = Self::metadata_mut(state);
        metadata.next = Some(next);
    }

    /// Sets the next iterations count, i.e., how many times to mutate the input
    ///
    /// Using `set_next_and_iter` to set multiple values at the same time
    /// will be faster than setting them individually
    /// as it internally only needs a single metadata lookup
    pub fn set_iters(state: &mut S, iters: u64) {
        let metadata = Self::metadata_mut(state);
        metadata.iters = Some(iters);
    }

    /// Gets the set next mutator id and iterations count
    pub fn get_next_and_iter(state: &S) -> (Option<usize>, Option<u64>) {
        let metadata = Self::metadata(state);
        (metadata.next, metadata.iters)
    }

    /// Gets the id for the next mutator
    pub fn get_next(state: &S) -> Option<usize> {
        let metadata = Self::metadata(state);
        metadata.next
    }

    /// Gets the set iterations
    pub fn get_iters(state: &S) -> Option<u64> {
        let metadata = Self::metadata(state);
        metadata.iters
    }

    /// Resets this to a randomic mutational stage
    pub fn reset(state: &mut S) {
        let metadata = Self::metadata_mut(state);
        metadata.next = None;
        metadata.iters = None;
    }
}
