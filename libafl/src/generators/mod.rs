//! Generators may generate bytes or, in general, data, for inputs.

use alloc::vec::Vec;
use core::{marker::PhantomData, num::NonZeroUsize};

use libafl_bolts::rands::Rand;

use crate::{inputs::bytes::BytesInput, nonzero, state::HasRand, Error};

pub mod gramatron;
use core::cmp::max;

pub use gramatron::*;

#[cfg(feature = "nautilus")]
pub mod nautilus;
#[cfg(feature = "nautilus")]
pub use nautilus::*;

/// Generators can generate ranges of bytes.
pub trait Generator<I, S> {
    /// Generate a new input
    fn generate(&mut self, state: &mut S) -> Result<I, Error>;
}

/// Iterators may be used as generators.
///
/// `generate` throws a [`Error::Empty`] if an input is requested but
/// [`Iterator::next`] returns `None`.
impl<T, I, S> Generator<I, S> for T
where
    T: Iterator<Item = I>,
{
    fn generate(&mut self, _state: &mut S) -> Result<I, Error> {
        match self.next() {
            Some(i) => Ok(i),
            None => Err(Error::empty(
                "No more items in iterator when generating inputs",
            )),
        }
    }
}

/// An [`Iterator`] built from a [`Generator`].
#[derive(Debug)]
pub struct GeneratorIter<'a, I, S, G> {
    gen: G,
    state: &'a mut S,
    phantom: PhantomData<I>,
}

impl<'a, I, S, G> GeneratorIter<'a, I, S, G> {
    /// Create a new [`GeneratorIter`]
    pub fn new(gen: G, state: &'a mut S) -> Self {
        Self {
            gen,
            state,
            phantom: PhantomData,
        }
    }
}

impl<I, S, G> Iterator for GeneratorIter<'_, I, S, G>
where
    G: Generator<I, S>,
{
    type Item = I;

    fn next(&mut self) -> Option<Self::Item> {
        self.gen.generate(self.state).ok()
    }
}

#[derive(Clone, Debug)]
/// Generates random bytes
pub struct RandBytesGenerator {
    max_size: NonZeroUsize,
}

impl<S> Generator<BytesInput, S> for RandBytesGenerator
where
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<BytesInput, Error> {
        let mut size = state.rand_mut().below(self.max_size);
        size = max(size, 1);
        let random_bytes: Vec<u8> = (0..size)
            .map(|_| state.rand_mut().below(nonzero!(256)) as u8)
            .collect();
        Ok(BytesInput::new(random_bytes))
    }
}

impl RandBytesGenerator {
    /// Returns a new [`RandBytesGenerator`], generating up to `max_size` random bytes.
    #[must_use]
    pub fn new(max_size: NonZeroUsize) -> Self {
        Self { max_size }
    }
}

#[derive(Clone, Debug)]
/// Generates random printable characters
pub struct RandPrintablesGenerator {
    max_size: NonZeroUsize,
}

impl<S> Generator<BytesInput, S> for RandPrintablesGenerator
where
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<BytesInput, Error> {
        let mut size = state.rand_mut().below(self.max_size);
        size = max(size, 1);
        let printables = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \t\n!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".as_bytes();
        let random_bytes: Vec<u8> = (0..size)
            .map(|_| *state.rand_mut().choose(printables).unwrap())
            .collect();
        Ok(BytesInput::new(random_bytes))
    }
}

impl RandPrintablesGenerator {
    /// Returns a new [`RandBytesGenerator`], generating up to `max_size` random bytes.
    #[must_use]
    pub fn new(max_size: NonZeroUsize) -> Self {
        Self { max_size }
    }
}
