//! An extension to the `ScheduledMutator` which schedules multiple mutations internally.
//! Instead of a random mutator for a random amount of iterations, we can run
//! a specific mutator for a specified amount of iterations

use alloc::vec::Vec;
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
    state::{HasMetadata, HasRand},
    Error,
};

/// Metadata in the state, that controls the behavior of the [`TuneableScheduledMutator`] at runtime
#[derive(Default, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct TuneableScheduledMutatorMetadata {
    /// The offsets of mutators to run, in order. Clear to fall back to random.
    pub next: Vec<usize>,
    /// The next index to read from in the `next` vec
    pub next_idx: usize,
    /// The count of total mutations to perform.
    /// If `next` is of length `10`, and this number is `20`,
    /// the mutations will be iterated through twice.
    pub iters: Option<u64>,
}

impl TuneableScheduledMutatorMetadata {
    /// Gets the stored metadata, used to alter the [`TuneableScheduledMutator`] behavior
    pub fn get<S: HasMetadata>(state: &S) -> Result<&Self, Error> {
        state
            .metadata()
            .get::<Self>()
            .ok_or_else(|| Error::illegal_state("TuneableScheduledMutator not in use"))
    }

    /// Gets the stored metadata, used to alter the [`TuneableScheduledMutator`] behavior, mut
    pub fn get_mut<S: HasMetadata>(state: &mut S) -> Result<&mut Self, Error> {
        state
            .metadata_mut()
            .get_mut::<Self>()
            .ok_or_else(|| Error::illegal_state("TuneableScheduledMutator not in use"))
    }
}

impl_serdeany!(TuneableScheduledMutatorMetadata);

/// A [`Mutator`] that schedules one of the embedded mutations on each call.
/// The index of the next mutation can be set.
pub struct TuneableScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    mutations: MT,
    max_stack_pow: u64,
    phantom: PhantomData<(I, S)>,
}

impl<I, MT, S> Debug for TuneableScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TuneableScheduledMutator with {} mutations for Input type {}",
            self.mutations.len(),
            core::any::type_name::<I>()
        )
    }
}

impl<I, MT, S> Mutator<I, S> for TuneableScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand + HasMetadata,
{
    #[inline]
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input)
    }
}

impl<I, MT, S> ComposedByMutations<I, MT, S> for TuneableScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
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

impl<I, MT, S> ScheduledMutator<I, MT, S> for TuneableScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand + HasMetadata,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        if let Some(iters) = Self::get_iters(state) {
            iters
        } else {
            // fall back to random
            1 << (1 + state.rand_mut().below(self.max_stack_pow))
        }
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &I) -> usize {
        debug_assert!(!self.mutations().is_empty());
        // Assumption: we can not reach this code path without previously adding this metadatum.
        let metadata = TuneableScheduledMutatorMetadata::get_mut(state).unwrap();
        #[allow(clippy::cast_possible_truncation)]
        if metadata.next.is_empty() {
            // fall back to random if no entries in the vec
            state.rand_mut().below(self.mutations().len() as u64) as usize
        } else {
            let ret = metadata.next[metadata.next_idx];
            metadata.next_idx += 1_usize;
            if metadata.next_idx >= metadata.next.len() {
                metadata.next_idx = 0;
            }
            debug_assert!(
                self.mutations().len() > ret,
                "TuneableScheduler: next vec may not contain idx larger than number of mutations!"
            );
            ret
        }
    }
}

impl<I, MT, S> TuneableScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand + HasMetadata,
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

    fn metadata_mut(state: &mut S) -> &mut TuneableScheduledMutatorMetadata {
        state
            .metadata_mut()
            .get_mut::<TuneableScheduledMutatorMetadata>()
            .unwrap()
    }

    fn metadata(state: &S) -> &TuneableScheduledMutatorMetadata {
        state
            .metadata()
            .get::<TuneableScheduledMutatorMetadata>()
            .unwrap()
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

    /// Gets the set iterations
    pub fn get_iters(state: &S) -> Option<u64> {
        let metadata = Self::metadata(state);
        metadata.iters
    }

    /// Resets this to a randomic mutational stage
    pub fn reset(state: &mut S) {
        let metadata = Self::metadata_mut(state);
        metadata.next.clear();
        metadata.next_idx = 0;
        metadata.iters = None;
    }
}

#[cfg(test)]
mod test {
    use super::{
        BitFlipMutator, ByteDecMutator, TuneableScheduledMutator, TuneableScheduledMutatorMetadata,
    };
    use crate::{
        bolts::tuples::tuple_list,
        inputs::BytesInput,
        mutators::{ByteRandMutator, ScheduledMutator},
        state::NopState,
    };

    #[test]
    fn test_tuning() {
        let mut state: NopState<BytesInput> = NopState::new();
        let mutators = tuple_list!(
            BitFlipMutator::new(),
            ByteDecMutator::new(),
            ByteRandMutator::new()
        );
        let tuneable = TuneableScheduledMutator::new(&mut state, mutators);
        let input = BytesInput::new(vec![42]);
        let metadata = TuneableScheduledMutatorMetadata::get_mut(&mut state).unwrap();
        metadata.next.push(1);
        metadata.next.push(2);
        assert_eq!(tuneable.schedule(&mut state, &input), 1);
        assert_eq!(tuneable.schedule(&mut state, &input), 2);
        assert_eq!(tuneable.schedule(&mut state, &input), 1);
    }
}
