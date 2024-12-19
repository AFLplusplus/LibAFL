//! A wrapper around a [`Mutator`] that ensures an input really changed [`MutationResult::Mutated`]
//! by hashing pre- and post-mutation
use std::{borrow::Cow, hash::Hash};

use libafl_bolts::{generic_hash_std, Error, Named};

use super::{MutationResult, Mutator};

/// A wrapper around a [`Mutator`] that ensures an input really changed [`MutationResult::Mutated`]
/// by hashing pre- and post-mutation
#[derive(Debug)]
pub struct HashMutator<M> {
    inner: M,
    name: Cow<'static, str>,
}

impl<M> HashMutator<M>
where
    M: Named,
{
    /// Create a new [`HashMutator`]
    pub fn new(inner: M) -> Self {
        let name = Cow::Owned(format!("HashMutator<{}>", inner.name().clone()));
        Self { inner, name }
    }
}

impl<M, I, S> Mutator<I, S> for HashMutator<M>
where
    I: Hash,
    M: Mutator<I, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let before = generic_hash_std(input);
        self.inner.mutate(state, input)?;
        if before == generic_hash_std(input) {
            Ok(MutationResult::Skipped)
        } else {
            Ok(MutationResult::Mutated)
        }
    }
}

impl<M> Named for HashMutator<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        inputs::BytesInput,
        mutators::{BytesSetMutator, HashMutator, MutationResult, Mutator},
        state::NopState,
    };

    #[test]
    fn not_mutated() {
        let mut state: NopState<BytesInput> = NopState::new();
        let mut inner = BytesSetMutator::new();

        let mut input = BytesInput::new(vec![0; 5]);

        // nothing changed, yet `MutationResult::Mutated` was reported
        assert_eq!(
            MutationResult::Mutated,
            inner.mutate(&mut state, &mut input).unwrap()
        );
        assert_eq!(BytesInput::new(vec![0; 5]), input);

        // now it is correctly reported as `MutationResult::Skipped`
        let mut hash_mutator = HashMutator::new(inner);
        assert_eq!(
            MutationResult::Skipped,
            hash_mutator.mutate(&mut state, &mut input).unwrap()
        );
        assert_eq!(BytesInput::new(vec![0; 5]), input);
    }
}
