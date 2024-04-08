//! Generators may generate bytes or, in general, data, for inputs.

use alloc::vec::Vec;
use core::marker::PhantomData;

use libafl_bolts::rands::Rand;

use crate::{
    inputs::{bytes::BytesInput, Input},
    state::HasRand,
    Error,
};

pub mod gramatron;
pub use gramatron::*;

#[cfg(feature = "nautilus")]
pub mod nautilus;
#[cfg(feature = "nautilus")]
pub use nautilus::*;

/// Generators can generate ranges of bytes.
pub trait Generator<I, S>
where
    I: Input,
{
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
    I: Input,
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
pub struct GeneratorIter<'a, I, S, G>
where
    I: Input,
    G: Generator<I, S>,
{
    gen: G,
    state: &'a mut S,
    phantom: PhantomData<I>,
}

impl<'a, I, S, G> GeneratorIter<'a, I, S, G>
where
    I: Input,
    G: Generator<I, S>,
{
    /// Create a new [`GeneratorIter`]
    pub fn new(gen: G, state: &'a mut S) -> Self {
        Self {
            gen,
            state,
            phantom: PhantomData,
        }
    }
}

impl<'a, I, S, G> Iterator for GeneratorIter<'a, I, S, G>
where
    I: Input,
    G: Generator<I, S>,
{
    type Item = I;

    fn next(&mut self) -> Option<Self::Item> {
        self.gen.generate(self.state).ok()
    }
}

#[derive(Clone, Debug)]
/// Generates random bytes
pub struct RandBytesGenerator<S>
where
    S: HasRand,
{
    max_size: usize,
    phantom: PhantomData<S>,
}

impl<S> Generator<BytesInput, S> for RandBytesGenerator<S>
where
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<BytesInput, Error> {
        let mut size = state.rand_mut().below(self.max_size as u64);
        if size == 0 {
            size = 1;
        }
        let random_bytes: Vec<u8> = (0..size)
            .map(|_| state.rand_mut().below(256) as u8)
            .collect();
        Ok(BytesInput::new(random_bytes))
    }
}

impl<S> RandBytesGenerator<S>
where
    S: HasRand,
{
    /// Returns a new [`RandBytesGenerator`], generating up to `max_size` random bytes.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            phantom: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
/// Generates random printable characters
pub struct RandPrintablesGenerator<S>
where
    S: HasRand,
{
    max_size: usize,
    phantom: PhantomData<S>,
}

impl<S> Generator<BytesInput, S> for RandPrintablesGenerator<S>
where
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<BytesInput, Error> {
        let mut size = state.rand_mut().below(self.max_size as u64);
        if size == 0 {
            size = 1;
        }
        let printables = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \t\n!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".as_bytes();
        let random_bytes: Vec<u8> = (0..size)
            .map(|_| *state.rand_mut().choose(printables))
            .collect();
        Ok(BytesInput::new(random_bytes))
    }
}

impl<S> RandPrintablesGenerator<S>
where
    S: HasRand,
{
    /// Creates a new [`RandPrintablesGenerator`], generating up to `max_size` random printable characters.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            phantom: PhantomData,
        }
    }
}
