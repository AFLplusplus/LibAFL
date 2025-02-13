//! Definitions for inputs which have multiple distinct subcomponents.
//!
//! Unfortunately, since both [`serde::de::Deserialize`] and [`Clone`] require [`Sized`], it is not
//! possible to dynamically define a single input with dynamic typing. As such, [`MultipartInput`]
//! requires that each subcomponent be the same subtype.

use alloc::{
    borrow::Cow,
    fmt::Debug,
    string::{String, ToString},
    vec::Vec,
};
use core::{hash::Hash, num::NonZero};

use arrayvec::ArrayVec;
use libafl_bolts::{
    rands::Rand as _,
    tuples::{Map, MappingFunctor},
    Error, Named,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    corpus::CorpusId,
    inputs::Input,
    mutators::{MutationResult, Mutator},
    state::HasRand,
};

/// An input composed of multiple parts. Use in situations where subcomponents are not necessarily
/// related, or represent distinct parts of the input.
#[derive(Clone, Debug, Serialize, Deserialize, Hash)]
pub struct MultipartInput<I, N> {
    parts: Vec<(N, I)>,
}

impl<I, N> Default for MultipartInput<I, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I, N> MultipartInput<I, N> {
    /// Create a new multipart input.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self { parts: Vec::new() }
    }

    fn idxs_to_skips(idxs: &mut [usize]) {
        for following in (1..idxs.len()).rev() {
            let first = idxs[following - 1];
            let second = idxs[following];

            idxs[following] = second
                .checked_sub(first)
                .expect("idxs was not sorted")
                .checked_sub(1)
                .expect("idxs had duplicate elements");
        }
    }

    /// Get the individual parts of this input.
    #[must_use]
    #[inline]
    pub fn parts_and_names(&self) -> &[(N, I)] {
        &self.parts
    }

    /// Get the individual parts of this input.
    #[must_use]
    #[inline]
    pub fn parts_and_names_mut(&mut self) -> &mut [(N, I)] {
        &mut self.parts
    }

    /// Get a specific part of this input by index.
    #[must_use]
    #[inline]
    pub fn part_by_idx(&self, idx: usize) -> Option<&I> {
        self.parts.get(idx).map(|(_, i)| i)
    }

    /// Get a specific part of this input by index.
    #[must_use]
    #[inline]
    pub fn part_by_idx_mut(&mut self, idx: usize) -> Option<&mut I> {
        self.parts.get_mut(idx).map(|(_, i)| i)
    }

    /// Access multiple parts mutably.
    ///
    /// ## Panics
    ///
    /// Panics if idxs is not sorted, has duplicate elements, or any entry is out of bounds.
    #[must_use]
    pub fn parts_by_idxs_mut<const C: usize>(&mut self, mut idxs: [usize; C]) -> [&mut I; C] {
        Self::idxs_to_skips(&mut idxs);

        let mut parts = self.parts.iter_mut();
        if let Ok(arr) = idxs
            .into_iter()
            .map(|i| {
                parts
                    .nth(i)
                    .map(|(_, i)| i)
                    .expect("idx had an out of bounds entry")
            })
            .collect::<ArrayVec<_, C>>()
            .into_inner()
        {
            arr
        } else {
            // avoid Debug trait requirement for expect/unwrap
            panic!("arrayvec collection failed somehow")
        }
    }

    /// Get the names associated with the subparts of this input. Used to distinguish between the
    /// input components in the case where some parts may or may not be present, or in different
    /// orders.
    #[inline]
    pub fn names(&self) -> impl Iterator<Item = &N> {
        self.parts.iter().map(|(n, _)| n)
    }

    /// Adds a part to this input, potentially with the same name as an existing part.
    #[inline]
    pub fn append_part(&mut self, name: N, part: I) {
        self.parts.push((name, part));
    }

    /// Inserts a part to this input at the given index, potentially with the same name as an existing part.
    #[inline]
    pub fn insert_part(&mut self, idx: usize, name: N, part: I) {
        self.parts.insert(idx, (name, part));
    }

    /// Removes a part from this input at the given index.
    ///
    /// # Safety
    ///
    /// Panics if the index is out of bounds.
    #[inline]
    pub fn remove_part_at_idx(&mut self, idx: usize) {
        self.parts.remove(idx);
    }

    /// Removes the last part from this input.
    ///
    /// Returns [`None`] if the input is empty.
    #[inline]
    pub fn pop_part(&mut self) -> Option<(N, I)> {
        self.parts.pop()
    }

    /// Iterate over the parts of this input; no order is specified.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &(N, I)> {
        self.parts.iter()
    }

    /// Iterate over the parts of this input; no order is specified.
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut (N, I)> {
        self.parts.iter_mut()
    }

    /// Get the number of parts in this input.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.parts.len()
    }

    /// Check if this input has no parts.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Map a tuple of mutators targeting [`MultipartInput`]'s inner type to a tuple of mutators able to work on the entire [`MultipartInput`],
    /// by mutating on the last part. If the input is empty, [`MutationResult::Skipped`] is returned.
    #[must_use]
    #[inline]
    pub fn map_to_mutate_on_last_part<M: Map<ToLastEntryMutator>>(
        inner: M,
    ) -> <M as Map<ToLastEntryMutator>>::MapResult {
        inner.map(ToLastEntryMutator)
    }

    /// Map a tuple of mutators targeting [`MultipartInput`]'s inner type to a tuple of mutators able to work on the entire [`MultipartInput`],
    /// by mutating on a random part. If the input is empty, [`MutationResult::Skipped`] is returned.
    #[must_use]
    #[inline]
    pub fn map_to_mutate_on_random_part<M: Map<ToRandomEntryMutator>>(
        inner: M,
    ) -> <M as Map<ToRandomEntryMutator>>::MapResult {
        inner.map(ToRandomEntryMutator)
    }
}

impl<I, N> MultipartInput<I, N>
where
    N: PartialEq,
{
    /// Gets a reference to each part with the provided name.
    pub fn parts_with_name<'a, 'b>(
        &'b self,
        name: &'a N,
    ) -> impl Iterator<Item = (usize, &'b I)> + 'a
    where
        'b: 'a,
    {
        self.parts
            .iter()
            .enumerate()
            .filter_map(move |(i, (n, input))| (name == n).then_some((i, input)))
    }

    /// Gets a mutable reference to each part with the provided name.
    pub fn parts_with_name_mut<'a, 'b>(
        &'b mut self,
        name: &'a N,
    ) -> impl Iterator<Item = (usize, &'b mut I)> + 'a
    where
        'b: 'a,
    {
        self.parts
            .iter_mut()
            .enumerate()
            .filter_map(move |(i, (n, input))| (name == n).then_some((i, input)))
    }
}

impl<I, It, N> From<It> for MultipartInput<I, N>
where
    It: IntoIterator<Item = (N, I)>,
{
    fn from(parts: It) -> Self {
        let vec = parts.into_iter().collect();
        Self { parts: vec }
    }
}

impl<I, N> MultipartInput<I, N>
where
    N: Default,
{
    /// Create a new multipart input with default names.
    #[must_use]
    pub fn with_default_names<It: IntoIterator<Item = I>>(parts: It) -> Self {
        let vec = parts.into_iter().map(|i| (N::default(), i)).collect();
        Self { parts: vec }
    }

    /// Append a part to this input with a default name.
    #[inline]
    pub fn append_part_with_default_name(&mut self, part: I) {
        self.parts.push((N::default(), part));
    }
}

impl<I, N> Input for MultipartInput<I, N>
where
    I: Input,
    N: Debug + Hash + Serialize + DeserializeOwned + Clone,
{
    fn generate_name(&self, id: Option<CorpusId>) -> String {
        if self.parts.is_empty() {
            "empty_multipart_input".to_string() // empty strings cause issues with OnDiskCorpus
        } else {
            self.parts
                .iter()
                .map(|(name, input)| format!("{name:?}-{}", input.generate_name(id)))
                .collect::<Vec<_>>()
                .join(",")
        }
    }
}

/// Mutator that applies mutations to the last element of a [`MultipartInput`].
///
///  If the input is empty, [`MutationResult::Skipped`] is returned.
#[derive(Debug)]
pub struct LastEntryMutator<M> {
    inner: M,
    name: Cow<'static, str>,
}

impl<M: Named> LastEntryMutator<M> {
    /// Create a new [`LastEntryMutator`].
    #[must_use]
    pub fn new(inner: M) -> Self {
        let name = Cow::Owned(format!("LastEntryMutator<{}>", inner.name()));
        Self { inner, name }
    }
}

impl<I, M, N, S> Mutator<MultipartInput<I, N>, S> for LastEntryMutator<M>
where
    M: Mutator<I, S>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I, N>,
    ) -> Result<MutationResult, Error> {
        match input.parts.len() {
            0 => Ok(MutationResult::Skipped),
            len => self.inner.mutate(state, &mut input.parts[len - 1].1),
        }
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        self.inner.post_exec(state, new_corpus_id)
    }
}

/// Mapping functor to convert mutators to [`LastEntryMutator`].
#[derive(Debug)]
pub struct ToLastEntryMutator;

impl<M: Named> MappingFunctor<M> for ToLastEntryMutator {
    type Output = LastEntryMutator<M>;

    fn apply(&mut self, from: M) -> Self::Output {
        LastEntryMutator::new(from)
    }
}

impl<M> Named for LastEntryMutator<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Mutator that applies mutations to a random element of a [`MultipartInput`].
///
///  If the input is empty, [`MutationResult::Skipped`] is returned.
#[derive(Debug)]
pub struct RandomEntryMutator<M> {
    inner: M,
    name: Cow<'static, str>,
}

impl<M: Named> RandomEntryMutator<M> {
    /// Create a new [`RandomEntryMutator`].
    #[must_use]
    pub fn new(inner: M) -> Self {
        let name = Cow::Owned(format!("RandomEntryMutator<{}>", inner.name()));
        Self { inner, name }
    }
}

impl<I, M, N, S> Mutator<MultipartInput<I, N>, S> for RandomEntryMutator<M>
where
    M: Mutator<I, S>,
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I, N>,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();
        match input.parts.len() {
            0 => Ok(MutationResult::Skipped),
            len => {
                let index = rand.below(unsafe { NonZero::new_unchecked(len) });
                self.inner.mutate(state, &mut input.parts[index].1)
            }
        }
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        self.inner.post_exec(state, new_corpus_id)
    }
}

/// Mapping functor to convert mutators to [`RandomEntryMutator`].
#[derive(Debug)]
pub struct ToRandomEntryMutator;

impl<M: Named> MappingFunctor<M> for ToRandomEntryMutator {
    type Output = RandomEntryMutator<M>;

    fn apply(&mut self, from: M) -> Self::Output {
        RandomEntryMutator::new(from)
    }
}

impl<M> Named for RandomEntryMutator<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use tuple_list::tuple_list;

    use super::MultipartInput;
    use crate::{
        inputs::ValueInput,
        mutators::{numeric::IncMutator, MutationResult, MutatorsTuple as _},
        state::NopState,
    };

    #[test]
    fn map_to_mutate_on_last_part() {
        let mutator = tuple_list!(IncMutator);
        let mut mapped_mutator =
            MultipartInput::<ValueInput<u8>, ()>::map_to_mutate_on_last_part(mutator);
        let mut input: MultipartInput<ValueInput<u8>, ()> =
            MultipartInput::with_default_names(vec![ValueInput::new(1_u8), ValueInput::new(2)]);
        let mut state = NopState::<MultipartInput<ValueInput<u8>, ()>>::new();
        let res = mapped_mutator.mutate_all(&mut state, &mut input);
        assert_eq!(res.unwrap(), MutationResult::Mutated);
        assert_eq!(
            input.iter().map(|((), i)| *i).collect::<Vec<_>>(),
            vec![ValueInput::new(1), ValueInput::new(3)]
        );
    }

    #[test]
    fn map_to_mutate_on_last_part_empty() {
        let mutator = tuple_list!(IncMutator);
        let mut mapped_mutator =
            MultipartInput::<(), ValueInput<u8>>::map_to_mutate_on_last_part(mutator);
        let mut input = MultipartInput::<ValueInput<u8>, ()>::default();
        let mut state = NopState::<MultipartInput<ValueInput<u8>, ()>>::new();
        let res = mapped_mutator.mutate_all(&mut state, &mut input);
        assert_eq!(res.unwrap(), MutationResult::Skipped);
        assert_eq!(input.parts, vec![]);
    }

    #[test]
    fn map_to_mutate_on_random_part() {
        let mutator = tuple_list!(IncMutator);
        let mut mapped_mutator =
            MultipartInput::<ValueInput<u8>, ()>::map_to_mutate_on_random_part(mutator);
        let initial_input = vec![ValueInput::new(1_u8), ValueInput::new(2)];
        let mut input =
            MultipartInput::<ValueInput<u8>, ()>::with_default_names(initial_input.clone());
        let mut state = NopState::<MultipartInput<ValueInput<u8>, ()>>::new();
        let res = mapped_mutator.mutate_all(&mut state, &mut input);
        assert_eq!(res.unwrap(), MutationResult::Mutated);
        assert_eq!(
            1,
            input
                .iter()
                .zip(initial_input.iter())
                .filter(|&(a, b)| a.1 != *b)
                .count()
        );
    }

    #[test]
    fn map_to_mutate_on_random_part_empty() {
        let mutator = tuple_list!(IncMutator);
        let mut mapped_mutator =
            MultipartInput::<ValueInput<u8>, ()>::map_to_mutate_on_random_part(mutator);
        let mut input = MultipartInput::<ValueInput<u8>, ()>::default();
        let mut state = NopState::<MultipartInput<ValueInput<u8>, ()>>::new();
        let res = mapped_mutator.mutate_all(&mut state, &mut input);
        assert_eq!(res.unwrap(), MutationResult::Skipped);
        assert_eq!(input.parts, vec![]);
    }
}
