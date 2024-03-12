//! An extension to the `ScheduledMutator` which schedules multiple mutations internally.
//! Instead of a random mutator for a random amount of iterations, we can run
//! a specific mutator for a specified amount of iterations

use alloc::{string::String, vec::Vec};
use core::{
    fmt::{self, Debug},
    marker::PhantomData,
};

use libafl_bolts::{
    impl_serdeany, math::calculate_cumulative_distribution_in_place, rands::Rand, Named,
};
use serde::{Deserialize, Serialize};

pub use crate::mutators::{mutations::*, token_mutations::*};
use crate::{
    mutators::{
        ComposedByMutations, MutationId, MutationResult, Mutator, MutatorsTuple, ScheduledMutator,
    },
    state::{HasMetadata, HasRand},
    Error,
};

/// Metadata in the state, that controls the behavior of the [`TuneableScheduledMutator`] at runtime
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct TuneableScheduledMutatorMetadata {
    /// The offsets of mutators to run, in order. Clear to fall back to random,
    /// or use `mutation_probabilities`
    pub mutation_ids: Vec<MutationId>,
    /// The next index to read from in the `next` vec
    pub next_id: MutationId,
    /// The cumulative probability distribution for each mutation.
    /// Will not be used when `mutation_ids` are set.
    /// Clear to fall back to random.
    pub mutation_probabilities_cumulative: Vec<f32>,
    /// The count of mutations to stack.
    /// If `mutation_ids` is of length `10`, and this number is `20`,
    /// the mutations will be iterated through twice.
    pub iters: Option<u64>,
    /// The probability of each number of mutations to stack.
    pub iter_probabilities_pow_cumulative: Vec<f32>,
}

impl_serdeany!(TuneableScheduledMutatorMetadata);

impl Default for TuneableScheduledMutatorMetadata {
    fn default() -> Self {
        Self {
            mutation_ids: Vec::default(),
            next_id: 0.into(),
            mutation_probabilities_cumulative: Vec::default(),
            iters: None,
            iter_probabilities_pow_cumulative: Vec::default(),
        }
    }
}

impl TuneableScheduledMutatorMetadata {
    /// Gets the stored metadata, used to alter the [`TuneableScheduledMutator`] behavior
    pub fn get<S: HasMetadata>(state: &S) -> Result<&Self, Error> {
        state
            .metadata_map()
            .get::<Self>()
            .ok_or_else(|| Error::illegal_state("TuneableScheduledMutator not in use"))
    }

    /// Gets the stored metadata, used to alter the [`TuneableScheduledMutator`] behavior, mut
    pub fn get_mut<S: HasMetadata>(state: &mut S) -> Result<&mut Self, Error> {
        state
            .metadata_map_mut()
            .get_mut::<Self>()
            .ok_or_else(|| Error::illegal_state("TuneableScheduledMutator not in use"))
    }
}

/// A [`Mutator`] that schedules one of the embedded mutations on each call.
/// The index of the next mutation can be set.
pub struct TuneableScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    name: String,
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

impl<I, MT, S> Named for TuneableScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn name(&self) -> &str {
        &self.name
    }
}

impl<I, MT, S> ScheduledMutator<I, MT, S> for TuneableScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand + HasMetadata,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        let metadata = TuneableScheduledMutatorMetadata::get_mut(state).unwrap();

        if metadata.iter_probabilities_pow_cumulative.is_empty() {
            if let Some(iters) = metadata.iters {
                iters
            } else {
                // fall back to random
                1 << (1 + state.rand_mut().below(self.max_stack_pow))
            }
        } else {
            // We will sample using the mutation probabilities.
            // Doing this outside of the original if branch to make the borrow checker happy.
            #[allow(clippy::cast_precision_loss)]
            let coin = state.rand_mut().next() as f32 / u64::MAX as f32;
            debug_assert!(coin <= 1.0_f32);

            let metadata = TuneableScheduledMutatorMetadata::get_mut(state).unwrap();
            let power = metadata
                .iter_probabilities_pow_cumulative
                .iter()
                .position(|i| *i >= coin)
                .unwrap();

            1 << (1 + power)
        }
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &I) -> MutationId {
        debug_assert!(self.mutations.len() != 0);
        // Assumption: we can not reach this code path without previously adding this metadatum.
        let metadata = TuneableScheduledMutatorMetadata::get_mut(state).unwrap();

        #[allow(clippy::cast_possible_truncation)]
        if !metadata.mutation_ids.is_empty() {
            // using pre-set ids.
            let ret = metadata.mutation_ids[metadata.next_id.0];
            metadata.next_id.0 += 1_usize;
            if metadata.next_id.0 >= metadata.mutation_ids.len() {
                metadata.next_id = 0.into();
            }
            debug_assert!(
                self.mutations.len() > ret.0,
                "TuneableScheduler: next vec may not contain id larger than number of mutations!"
            );
            return ret;
        }

        if !metadata.mutation_probabilities_cumulative.is_empty() {
            // We will sample using the mutation probabilities.
            // Doing this outside of the original if branch to make the borrow checker happy.
            #[allow(clippy::cast_precision_loss)]
            let coin = state.rand_mut().next() as f32 / u64::MAX as f32;
            debug_assert!(coin <= 1.0_f32);

            let metadata = TuneableScheduledMutatorMetadata::get_mut(state).unwrap();
            debug_assert_eq!(
                self.mutations.len(),
                metadata.mutation_probabilities_cumulative.len(),
                "TuneableScheduler: mutation probabilities do not match with number of mutations"
            );

            let mutation_id = metadata
                .mutation_probabilities_cumulative
                .iter()
                .position(|i| *i >= coin)
                .unwrap()
                .into();

            return mutation_id;
        }

        // fall back to random if no entries in either vec, the scheduling is not tuned.
        state.rand_mut().below(self.mutations.len() as u64).into()
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
            name: format!("TuneableMutator[{}]", mutations.names().join(", ")),
            mutations,
            max_stack_pow: 7,
            phantom: PhantomData,
        }
    }
}

impl<S> TuneableScheduledMutator<(), (), S>
where
    S: HasRand + HasMetadata,
{
    fn metadata_mut(state: &mut S) -> &mut TuneableScheduledMutatorMetadata {
        state
            .metadata_map_mut()
            .get_mut::<TuneableScheduledMutatorMetadata>()
            .unwrap()
    }

    fn metadata(state: &S) -> &TuneableScheduledMutatorMetadata {
        state
            .metadata_map()
            .get::<TuneableScheduledMutatorMetadata>()
            .unwrap()
    }

    /// Sets the next iterations count, i.e., how many times to mutate the input
    ///
    /// Using `set_mutation_ids_and_iter` to set multiple values at the same time
    /// will be faster than setting them individually
    /// as it internally only needs a single metadata lookup
    pub fn set_iters(state: &mut S, iters: u64) {
        let metadata = Self::metadata_mut(state);
        metadata.iters = Some(iters);
        metadata.iter_probabilities_pow_cumulative.clear();
    }

    /// Sets the probability of next iteration counts,
    /// i.e., how many times the mutation is likely to get mutated.
    ///
    /// So, setting the `iter_probabilities` to `vec![0.1, 0.7, 0.2]`
    /// would apply 2^1 mutation with the likelihood of 10%, 2^2 mutations with the
    /// a probability of 70% (0.7), and 2^3 mutations with the likelihood of 20%.
    /// These will be applied for each call of this `mutate` function.
    ///
    /// Setting this function will unset everything previously set in `set_iters`.
    pub fn set_iter_probabilities_pow(
        state: &mut S,
        mut iter_probabilities_pow: Vec<f32>,
    ) -> Result<(), Error> {
        if iter_probabilities_pow.len() >= 32 {
            return Err(Error::illegal_argument(
                "Cannot stack more than 2^32 mutations",
            ));
        }
        let metadata = Self::metadata_mut(state);
        metadata.iters = None;

        // we precalculate the cumulative probability to be faster when sampling later.
        calculate_cumulative_distribution_in_place(&mut iter_probabilities_pow)?;
        metadata.iter_probabilities_pow_cumulative = iter_probabilities_pow;

        Ok(())
    }

    /// Gets the set amount of iterations
    pub fn get_iters(state: &S) -> Option<u64> {
        let metadata = Self::metadata(state);
        metadata.iters
    }

    /// Sets the mutation ids
    pub fn set_mutation_ids(state: &mut S, mutations: Vec<MutationId>) {
        let metadata = TuneableScheduledMutatorMetadata::get_mut(state).unwrap();
        metadata.mutation_ids = mutations;
        metadata.next_id = 0.into();
    }

    /// Sets the mutation probabilities.
    /// The `Vec` contains a probability per [`MutationId`]: between 0 and 1, and they have to add
    /// up to 1.
    /// Setting the probabilities will remove the value set through `set_mutation_ids`.
    pub fn set_mutation_probabilities(
        state: &mut S,
        mut mutation_probabilities: Vec<f32>,
    ) -> Result<(), Error> {
        let metadata = TuneableScheduledMutatorMetadata::get_mut(state).unwrap();
        metadata.mutation_ids.clear();
        metadata.next_id = 0.into();

        // we precalculate the cumulative probability to be faster when sampling later.
        calculate_cumulative_distribution_in_place(&mut mutation_probabilities)?;
        metadata.mutation_probabilities_cumulative = mutation_probabilities;
        Ok(())
    }

    /// mutation ids and iterations
    pub fn set_mutation_ids_and_iters(state: &mut S, mutations: Vec<MutationId>, iters: u64) {
        let metadata = TuneableScheduledMutatorMetadata::get_mut(state).unwrap();
        metadata.mutation_ids = mutations;
        metadata.next_id = 0.into();
        metadata.iters = Some(iters);
    }

    /// Appends a mutation id to the end of the mutations
    pub fn push_mutation_id(state: &mut S, mutation_id: MutationId) {
        let metadata = TuneableScheduledMutatorMetadata::get_mut(state).unwrap();
        metadata.mutation_ids.push(mutation_id);
    }

    /// Resets this to a randomic mutational stage
    pub fn reset(state: &mut S) {
        let metadata = Self::metadata_mut(state);
        metadata.mutation_ids.clear();
        metadata.next_id = 0.into();
        metadata.iters = None;
        metadata.mutation_probabilities_cumulative.clear();
        metadata.iter_probabilities_pow_cumulative.clear();
    }
}

#[cfg(test)]
mod test {
    use libafl_bolts::tuples::tuple_list;

    use super::{
        BitFlipMutator, ByteDecMutator, TuneableScheduledMutator, TuneableScheduledMutatorMetadata,
    };
    use crate::{
        inputs::BytesInput,
        mutators::{ByteRandMutator, ScheduledMutator},
        state::NopState,
    };

    #[test]
    fn test_tuning() {
        // # Safety
        // No concurrency per testcase
        #[cfg(any(not(feature = "serdeany_autoreg"), miri))]
        unsafe {
            TuneableScheduledMutatorMetadata::register();
        }

        let mut state: NopState<BytesInput> = NopState::new();
        let mutators = tuple_list!(
            BitFlipMutator::new(),
            ByteDecMutator::new(),
            ByteRandMutator::new()
        );
        let tuneable = TuneableScheduledMutator::new(&mut state, mutators);
        let input = BytesInput::new(vec![42]);
        let metadata = TuneableScheduledMutatorMetadata::get_mut(&mut state).unwrap();
        metadata.mutation_ids.push(1.into());
        metadata.mutation_ids.push(2.into());
        assert_eq!(tuneable.schedule(&mut state, &input), 1.into());
        assert_eq!(tuneable.schedule(&mut state, &input), 2.into());
        assert_eq!(tuneable.schedule(&mut state, &input), 1.into());
    }

    #[test]
    fn test_mutation_distribution() {
        // # Safety
        // No concurrency per testcase
        #[cfg(any(not(feature = "serdeany_autoreg"), miri))]
        unsafe {
            TuneableScheduledMutatorMetadata::register();
        }

        let mut state: NopState<BytesInput> = NopState::new();
        let mutators = tuple_list!(
            BitFlipMutator::new(),
            ByteDecMutator::new(),
            ByteRandMutator::new()
        );
        let tuneable = TuneableScheduledMutator::new(&mut state, mutators);
        let input = BytesInput::new(vec![42]);

        // Basic tests over the probability distribution.
        assert!(
            TuneableScheduledMutator::set_mutation_probabilities(&mut state, vec![0.0]).is_err()
        );
        assert!(
            TuneableScheduledMutator::set_mutation_probabilities(&mut state, vec![1.0; 3]).is_err()
        );
        assert!(TuneableScheduledMutator::set_mutation_probabilities(
            &mut state,
            vec![-1.0, 1.0, 1.0]
        )
        .is_err());
        assert!(TuneableScheduledMutator::set_mutation_probabilities(&mut state, vec![]).is_err());

        assert!(TuneableScheduledMutator::set_mutation_probabilities(
            &mut state,
            vec![0.0, 0.0, 1.0]
        )
        .is_ok());
        assert_eq!(tuneable.schedule(&mut state, &input), 2.into());
        assert!(TuneableScheduledMutator::set_mutation_probabilities(
            &mut state,
            vec![0.0, 1.0, 0.0]
        )
        .is_ok());
        assert_eq!(tuneable.schedule(&mut state, &input), 1.into());
        assert!(TuneableScheduledMutator::set_mutation_probabilities(
            &mut state,
            vec![1.0, 0.0, 0.0]
        )
        .is_ok());
        assert_eq!(tuneable.schedule(&mut state, &input), 0.into());

        // We should not choose a mutation with p=0.
        assert!(TuneableScheduledMutator::set_mutation_probabilities(
            &mut state,
            vec![0.5, 0.0, 0.5]
        )
        .is_ok());
        assert!(tuneable.schedule(&mut state, &input) != 1.into());
    }
}
