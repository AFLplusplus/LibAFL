//! Definitions for inputs which have multiple distinct subcomponents.
//!
//! Unfortunately, since both [`serde::de::Deserialize`] and [`Clone`] require [`Sized`], it is not
//! possible to dynamically define a single input with dynamic typing. As such, [`MultipartInput`]
//! requires that each subcomponent be the same subtype.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use arrayvec::ArrayVec;
use serde::{Deserialize, Serialize};

use crate::{corpus::CorpusId, inputs::Input};

/// An input composed of multiple parts. Use in situations where subcomponents are not necessarily
/// related, or represent distinct parts of the input.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultipartInput<I> {
    parts: Vec<I>,
    names: Vec<String>,
}

impl<I> Default for MultipartInput<I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I> MultipartInput<I> {
    /// Create a new multipart input.
    #[must_use]
    pub fn new() -> Self {
        Self {
            parts: Vec::new(),
            names: Vec::new(),
        }
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
    pub fn parts(&self) -> &[I] {
        &self.parts
    }

    /// Access multiple parts mutably.
    ///
    /// ## Panics
    ///
    /// Panics if idxs is not sorted, has duplicate elements, or any entry is out of bounds.
    #[must_use]
    pub fn parts_mut<const N: usize>(&mut self, mut idxs: [usize; N]) -> [&mut I; N] {
        Self::idxs_to_skips(&mut idxs);

        let mut parts = self.parts.iter_mut();
        if let Ok(arr) = idxs
            .into_iter()
            .map(|i| parts.nth(i).expect("idx had an out of bounds entry"))
            .collect::<ArrayVec<_, N>>()
            .into_inner()
        {
            arr
        } else {
            // avoid Debug trait requirement for expect/unwrap
            panic!("arrayvec collection failed somehow")
        }
    }

    /// Get a specific part of this input by index.
    pub fn part_mut(&mut self, idx: usize) -> Option<&mut I> {
        self.parts.get_mut(idx)
    }

    /// Get the names associated with the subparts of this input. Used to distinguish between the
    /// input components in the case where some parts may or may not be present, or in different
    /// orders.
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Gets a reference to each part with the provided name.
    pub fn parts_by_name<'a, 'b>(
        &'b self,
        name: &'a str,
    ) -> impl Iterator<Item = (usize, &'b I)> + 'a
    where
        'b: 'a,
    {
        self.names()
            .iter()
            .zip(&self.parts)
            .enumerate()
            .filter_map(move |(i, (s, item))| (s == name).then_some((i, item)))
    }

    /// Gets a mutable reference to each part with the provided name.
    pub fn parts_by_name_mut<'a, 'b>(
        &'b mut self,
        name: &'a str,
    ) -> impl Iterator<Item = (usize, &'b mut I)> + 'a
    where
        'b: 'a,
    {
        self.names
            .iter()
            .zip(&mut self.parts)
            .enumerate()
            .filter_map(move |(i, (s, item))| (s == name).then_some((i, item)))
    }

    /// Adds a part to this input, potentially with the same name as an existing part.
    pub fn add_part(&mut self, name: String, part: I) {
        self.parts.push(part);
        self.names.push(name);
    }

    /// Iterate over the parts of this input; no order is specified.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &I)> {
        self.names.iter().map(String::as_ref).zip(self.parts())
    }
}

impl<I, It, S> From<It> for MultipartInput<I>
where
    It: IntoIterator<Item = (S, I)>,
    S: AsRef<str>,
{
    fn from(parts: It) -> Self {
        let mut input = MultipartInput::new();
        for (name, part) in parts {
            input.add_part(name.as_ref().to_string(), part);
        }
        input
    }
}

impl<I> Input for MultipartInput<I>
where
    I: Input,
{
    fn generate_name(&self, id: Option<CorpusId>) -> String {
        if self.names().is_empty() {
            "empty_multipart_input".to_string() // empty strings cause issues with OnDiskCorpus
        } else {
            self.names
                .iter()
                .cloned()
                .zip(self.parts.iter().map(|i| i.generate_name(id)))
                .map(|(name, generated)| format!("{name}-{generated}"))
                .collect::<Vec<_>>()
                .join(",")
        }
    }
}
