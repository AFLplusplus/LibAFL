//! Newtype pattern style wrapper for [`super::Input`]s

use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use super::MappedInput;

/// Newtype pattern wrapper around an underlying structure to implement inputs
///
/// This does not implement [`super::Input`], because for certain inputs, writing them to disk does not make sense, because they don't own their data (like [`super::MutVecInput`])
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappingInput<I>(I);

impl<I> From<I> for WrappingInput<I> {
    fn from(value: I) -> Self {
        Self(value)
    }
}

impl<I> WrappingInput<I> {
    /// Create a new [`WrappingInput`]
    pub const fn new(value: I) -> Self {
        Self(value)
    }

    /// Extract the inner value
    pub fn inner(self) -> I {
        self.0
    }
}

impl<I> AsRef<I> for WrappingInput<I> {
    fn as_ref(&self) -> &I {
        &self.0
    }
}

impl<I> AsMut<I> for WrappingInput<I> {
    fn as_mut(&mut self) -> &mut I {
        &mut self.0
    }
}

impl<'a, I> MappedInput for WrappingInput<&'a mut I> {
    type Type<'b>
        = WrappingInput<&'b mut I>
    where
        Self: 'b;
}
