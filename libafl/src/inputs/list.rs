//! Module for list-based inputs and their mutators.
//! Provides functionality for fuzzing sequences of inputs.

use alloc::{borrow::Cow, string::String, vec::Vec};
use core::{
    hash::{Hash, Hasher},
    num::NonZero,
};

use libafl_bolts::{
    generic_hash_std,
    rands::Rand as _,
    tuples::{Map, MappingFunctor},
    HasLen, Named,
};
use serde::{Deserialize, Serialize};

use crate::{
    corpus::CorpusId,
    inputs::Input,
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};

/// Input consisting of a list of variable length of an arbitrary input.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ListInput<I> {
    parts: Vec<I>,
}

impl<I: Input + Hash> Input for ListInput<I> {
    fn generate_name(&self, _id: Option<CorpusId>) -> String {
        format!(
            "ListInput<{},{}>",
            generic_hash_std(&self.parts),
            self.parts.len()
        )
    }
}

impl<I: Hash> Hash for ListInput<I> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.parts.hash(state);
    }
}

impl<I> From<Vec<I>> for ListInput<I> {
    fn from(value: Vec<I>) -> Self {
        Self::new(value)
    }
}

impl<I> ListInput<I> {
    /// Create a new [`ListInput`].
    #[must_use]
    #[inline]
    pub fn new(parts: Vec<I>) -> Self {
        Self { parts }
    }

    /// Create a new empty [`ListInput`].
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Map a tuple of mutators targeting [`ListInput`]'s inner type to a tuple of mutators able to work on the entire [`ListInput`],
    /// by mutating on the last part. If the input is empty, [`MutationResult::Skipped`] is returned.
    #[must_use]
    #[inline]
    pub fn map_to_mutate_on_last_part<M: Map<ToLastEntryListMutator>>(
        inner: M,
    ) -> <M as Map<ToLastEntryListMutator>>::MapResult {
        inner.map(ToLastEntryListMutator)
    }

    /// Map a tuple of mutators targeting [`ListInput`]'s inner type to a tuple of mutators able to work on the entire [`ListInput`],
    /// by mutating on a random part. If the input is empty, [`MutationResult::Skipped`] is returned.
    #[must_use]
    #[inline]
    pub fn map_to_mutate_on_random_part<M: Map<ToRandomEntryListMutator>>(
        inner: M,
    ) -> <M as Map<ToRandomEntryListMutator>>::MapResult {
        inner.map(ToRandomEntryListMutator)
    }

    /// Get a slice of the parts of the [`ListInput`].
    #[must_use]
    #[inline]
    pub fn parts(&self) -> &[I] {
        &self.parts
    }

    /// Get a mutable slice of the parts of the [`ListInput`].
    #[must_use]
    #[inline]
    pub fn parts_mut(&mut self) -> &mut Vec<I> {
        &mut self.parts
    }

    /// Get the parts of the [`ListInput`].
    #[must_use]
    #[inline]
    pub fn parts_owned(self) -> Vec<I> {
        self.parts
    }
}

impl<I> HasLen for ListInput<I> {
    fn len(&self) -> usize {
        self.parts.len()
    }
}

/// Mutator that applies mutations to the last element of a [`ListInput`].
///
///  If the input is empty, [`MutationResult::Skipped`] is returned.
#[derive(Debug)]
pub struct LastEntryListMutator<M> {
    inner: M,
    name: Cow<'static, str>,
}

impl<M: Named> LastEntryListMutator<M> {
    /// Create a new [`LastEntryListMutator`].
    #[must_use]
    pub fn new(inner: M) -> Self {
        let name = Cow::Owned(format!("LastEntryListMutator<{}>", inner.name()));
        Self { inner, name }
    }
}

impl<I, S, M> Mutator<ListInput<I>, S> for LastEntryListMutator<M>
where
    M: Mutator<I, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut ListInput<I>) -> Result<MutationResult, Error> {
        match input.parts.len() {
            0 => Ok(MutationResult::Skipped),
            len => self.inner.mutate(state, &mut input.parts[len - 1]),
        }
    }
}

/// Mapping functor to convert mutators to [`LastEntryListMutator`].
#[derive(Debug)]
pub struct ToLastEntryListMutator;

impl<M: Named> MappingFunctor<M> for ToLastEntryListMutator {
    type Output = LastEntryListMutator<M>;

    fn apply(&mut self, from: M) -> Self::Output {
        LastEntryListMutator::new(from)
    }
}

impl<M> Named for LastEntryListMutator<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Mutator that applies mutations to a random element of a [`ListInput`].
///
///  If the input is empty, [`MutationResult::Skipped`] is returned.
#[derive(Debug)]
pub struct RandomEntryListMutator<M> {
    inner: M,
    name: Cow<'static, str>,
}

impl<M: Named> RandomEntryListMutator<M> {
    /// Create a new [`RandomEntryListMutator`].
    #[must_use]
    pub fn new(inner: M) -> Self {
        let name = Cow::Owned(format!("RandomEntryListMutator<{}>", inner.name()));
        Self { inner, name }
    }
}

impl<I, S, M> Mutator<ListInput<I>, S> for RandomEntryListMutator<M>
where
    M: Mutator<I, S>,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut ListInput<I>) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();
        match input.parts.len() {
            0 => Ok(MutationResult::Skipped),
            len => {
                let index = rand.below(unsafe { NonZero::new_unchecked(len) });
                self.inner.mutate(state, &mut input.parts[index])
            }
        }
    }
}

/// Mapping functor to convert mutators to [`RandomEntryListMutator`].
#[derive(Debug)]
pub struct ToRandomEntryListMutator;

impl<M: Named> MappingFunctor<M> for ToRandomEntryListMutator {
    type Output = RandomEntryListMutator<M>;

    fn apply(&mut self, from: M) -> Self::Output {
        RandomEntryListMutator::new(from)
    }
}

impl<M> Named for RandomEntryListMutator<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use tuple_list::tuple_list;

    use super::ListInput;
    use crate::{
        inputs::ValueInput,
        mutators::{numeric::IncMutator, MutationResult, MutatorsTuple as _},
        state::NopState,
    };

    #[test]
    fn map_to_mutate_on_last_part() {
        let mutator = tuple_list!(IncMutator);
        let mut mapped_mutator = ListInput::<ValueInput<u8>>::map_to_mutate_on_last_part(mutator);
        let mut input = ListInput::new(vec![ValueInput::new(1_u8), ValueInput::new(2)]);
        let mut state = NopState::<ListInput<ValueInput<u8>>>::new();
        let res = mapped_mutator.mutate_all(&mut state, &mut input);
        assert_eq!(res.unwrap(), MutationResult::Mutated);
        assert_eq!(input.parts(), vec![ValueInput::new(1), ValueInput::new(3)]);
    }

    #[test]
    fn map_to_mutate_on_last_part_empty() {
        let mutator = tuple_list!(IncMutator);
        let mut mapped_mutator = ListInput::<ValueInput<u8>>::map_to_mutate_on_last_part(mutator);
        let mut input = ListInput::<ValueInput<u8>>::empty();
        let mut state = NopState::<ListInput<ValueInput<u8>>>::new();
        let res = mapped_mutator.mutate_all(&mut state, &mut input);
        assert_eq!(res.unwrap(), MutationResult::Skipped);
        assert_eq!(input.parts(), vec![]);
    }

    #[test]
    fn map_to_mutate_on_random_part() {
        let mutator = tuple_list!(IncMutator);
        let mut mapped_mutator = ListInput::<ValueInput<u8>>::map_to_mutate_on_random_part(mutator);
        let initial_input = vec![ValueInput::new(1_u8), ValueInput::new(2)];
        let mut input = ListInput::new(initial_input.clone());
        let mut state = NopState::<ListInput<ValueInput<u8>>>::new();
        let res = mapped_mutator.mutate_all(&mut state, &mut input);
        assert_eq!(res.unwrap(), MutationResult::Mutated);
        assert_eq!(
            1,
            input
                .parts()
                .iter()
                .zip(initial_input.iter())
                .filter(|&(a, b)| a != b)
                .count()
        );
    }

    #[test]
    fn map_to_mutate_on_random_part_empty() {
        let mutator = tuple_list!(IncMutator);
        let mut mapped_mutator = ListInput::<ValueInput<u8>>::map_to_mutate_on_random_part(mutator);
        let mut input = ListInput::<ValueInput<u8>>::empty();
        let mut state = NopState::<ListInput<ValueInput<u8>>>::new();
        let res = mapped_mutator.mutate_all(&mut state, &mut input);
        assert_eq!(res.unwrap(), MutationResult::Skipped);
        assert_eq!(input.parts(), vec![]);
    }
}
