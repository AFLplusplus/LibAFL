//! Generators may generate bytes or, in general, data, for inputs.

use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    num::{NonZero, NonZeroUsize},
};

use libafl_bolts::rands::Rand;

use crate::{inputs::bytes::BytesInput, state::HasRand, Error};

pub mod gramatron;
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
pub struct RandBytesGenerator<S> {
    max_size: NonZeroUsize,
    phantom: PhantomData<S>,
}

impl<S> Generator<BytesInput, S> for RandBytesGenerator<S>
where
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<BytesInput, Error> {
        let mut size = state.rand_mut().below(self.max_size);
        if size == 0 {
            size = 1;
        }
        let random_bytes: Vec<u8> = (0..size)
            .map(|_| state.rand_mut().below(NonZero::new(256).unwrap()) as u8)
            .collect();
        Ok(BytesInput::new(random_bytes))
    }
}

impl<S> RandBytesGenerator<S> {
    /// Returns a new [`RandBytesGenerator`], generating up to `max_size` random bytes.
    ///
    /// If you want to save one 0 check, use [`Self::from_nonzero`].
    pub fn new(max_size: usize) -> Result<Self, Error> {
        let Some(max_size) = NonZero::new(max_size) else {
            return Err(Error::illegal_argument("The max_size may not be 0."));
        };
        Ok(Self::from_nonzero(max_size))
    }

    /// Returns a new [`RandBytesGenerator`], generating up to `max_size` random bytes.
    #[must_use]
    pub fn from_nonzero(max_size: NonZeroUsize) -> Self {
        Self {
            max_size,
            phantom: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
/// Generates random printable characters
pub struct RandPrintablesGenerator<S> {
    max_size: NonZeroUsize,
    phantom: PhantomData<S>,
}

impl<S> Generator<BytesInput, S> for RandPrintablesGenerator<S>
where
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<BytesInput, Error> {
        let mut size = state.rand_mut().below(self.max_size);
        if size == 0 {
            size = 1;
        }
        let printables = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \t\n!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".as_bytes();
        let random_bytes: Vec<u8> = (0..size)
            .map(|_| *state.rand_mut().choose(printables).unwrap())
            .collect();
        Ok(BytesInput::new(random_bytes))
    }
}

impl<S> RandPrintablesGenerator<S> {
    /// Creates a new [`RandPrintablesGenerator`], generating up to `max_size` random printable characters.
    ///
    /// To skip the 0 `max_size` check, create this using [`Self::from_nonzero`] instead.
    pub fn new(max_size: usize) -> Result<Self, Error> {
        let Some(max_size) = NonZero::new(max_size) else {
            return Err(Error::illegal_argument("The max_size may not be 0."));
        };
        Ok(Self::from_nonzero(max_size))
    }

    /// Returns a new [`RandBytesGenerator`], generating up to `max_size` random bytes.
    #[must_use]
    pub fn from_nonzero(max_size: NonZeroUsize) -> Self {
        Self {
            max_size,
            phantom: PhantomData,
        }
    }
}
