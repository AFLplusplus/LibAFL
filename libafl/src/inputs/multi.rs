//! An input composed of multiple named parts.

use alloc::{fmt::Debug, string::String, vec::Vec};
use core::hash::Hash;

use serde::{de::DeserializeOwned, Serialize};

use crate::{
    corpus::CorpusId,
    inputs::{Input, ListInput},
};

/// An input composed of multiple named parts.
///
/// It relies on a list to store the names and parts.
pub type MultipartInput<I, N> = ListInput<(N, I)>;

impl<I, N> Input for MultipartInput<I, N>
where
    I: Input,
    N: PartialEq + Debug + Serialize + DeserializeOwned + Clone + Hash,
{
    fn generate_name(&self, id: Option<CorpusId>) -> String {
        self.parts()
            .iter()
            .map(|(_n, i)| i.generate_name(id))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Trait for inputs composed of multiple named parts.
pub trait NamedMultipartInput<I, N> {
    /// Get the names of the parts of this input.
    fn names<'a>(&'a self) -> impl Iterator<Item = &'a N>
    where
        N: 'a;
    /// Get a reference to each part with the provided name.
    fn parts_with_name<'a, 'b>(&'b self, name: &'a N) -> impl Iterator<Item = (usize, &'b I)> + 'a
    where
        'b: 'a,
        I: 'b;

    /// Gets a mutable reference to each part with the provided name.
    fn parts_with_name_mut<'a, 'b>(
        &'b mut self,
        name: &'a N,
    ) -> impl Iterator<Item = (usize, &'b mut I)> + 'a
    where
        'b: 'a,
        I: 'b;
}

impl<I, N> NamedMultipartInput<I, N> for MultipartInput<I, N>
where
    N: PartialEq,
{
    fn names<'a>(&'a self) -> impl Iterator<Item = &'a N>
    where
        N: 'a,
    {
        self.parts().iter().map(|(n, _)| n)
    }

    fn parts_with_name<'a, 'b>(&'b self, name: &'a N) -> impl Iterator<Item = (usize, &'b I)> + 'a
    where
        'b: 'a,
        I: 'b,
    {
        self.parts()
            .iter()
            .enumerate()
            .filter_map(move |(i, (n, input))| (name == n).then_some((i, input)))
    }

    fn parts_with_name_mut<'a, 'b>(
        &'b mut self,
        name: &'a N,
    ) -> impl Iterator<Item = (usize, &'b mut I)> + 'a
    where
        'b: 'a,
        I: 'b,
    {
        self.parts_mut()
            .iter_mut()
            .enumerate()
            .filter_map(move |(i, (n, input))| (name == n).then_some((i, input)))
    }
}
