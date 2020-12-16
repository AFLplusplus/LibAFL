use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;
use core::convert::Into;
use core::default::Default;
use core::option::Option;
use serde::{Deserialize, Serialize};

use crate::inputs::Input;
use crate::serde_anymap::{SerdeAny, SerdeAnyMap};
use crate::AflError;

// TODO PathBuf for no_std and change filename to PathBuf
//#[cfg(feature = "std")]
//use std::path::PathBuf;

/// An entry in the Testcase Corpus
#[derive(Default, Serialize, Deserialize)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct Testcase<I>
where
    I: Input,
{
    /// The input of this testcase
    input: Option<I>,
    /// Filename, if this testcase is backed by a file in the filesystem
    filename: Option<String>,
    /// Accumulated fitness from all the feedbacks
    fitness: u32,
    // TODO find a way to use TypeId
    /// Map of metadatas associated with this testcase
    metadatas: SerdeAnyMap,
}

impl<I> Into<Rc<RefCell<Self>>> for Testcase<I>
where
    I: Input,
{
    fn into(self) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(self))
    }
}

/// Impl of a testcase
impl<I> Testcase<I>
where
    I: Input,
{
    /// Returns this testcase with a loaded input
    pub fn load_input(&mut self) -> Result<&I, AflError> {
        if self.input.is_none() {
            self.input = Some(I::from_file(self.filename.as_ref().unwrap())?);
        }
        Ok(self.input.as_ref().unwrap())
    }

    /// Get the input, if any
    #[inline]
    pub fn input(&self) -> &Option<I> {
        &self.input
    }

    /// Get the input, if any (mutable)
    #[inline]
    pub fn input_mut(&mut self) -> &mut Option<I> {
        &mut self.input
    }

    /// Set the input
    #[inline]
    pub fn set_input(&mut self, input: I) {
        self.input = Some(input);
    }

    /// Get the filename, if any
    #[inline]
    pub fn filename(&self) -> &Option<String> {
        &self.filename
    }

    /// Get the filename, if any (mutable)
    #[inline]
    pub fn filename_mut(&mut self) -> &mut Option<String> {
        &mut self.filename
    }

    /// Set the filename
    #[inline]
    pub fn set_filename(&mut self, filename: String) {
        self.filename = Some(filename);
    }

    /// Get the fitness
    #[inline]
    pub fn fitness(&self) -> u32 {
        self.fitness
    }

    /// Get the fitness (mutable)
    #[inline]
    pub fn fitness_mut(&mut self) -> &mut u32 {
        &mut self.fitness
    }

    /// Set the fitness
    #[inline]
    pub fn set_fitness(&mut self, fitness: u32) {
        self.fitness = fitness;
    }

    /// Get all the metadatas into an HashMap (mutable)
    #[inline]
    pub fn metadatas(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadatas
    }

    /// Add a metadata
    #[inline]
    pub fn add_metadata<M>(&mut self, meta: M)
    where
        M: SerdeAny,
    {
        self.metadatas.insert(meta);
    }

    /// Create a new Testcase instace given an input
    #[inline]
    pub fn new<T>(input: T) -> Self
    where
        T: Into<I>,
    {
        Testcase {
            input: Some(input.into()),
            filename: None,
            fitness: 0,
            metadatas: SerdeAnyMap::new(),
        }
    }

    /// Create a new Testcase instace given an input and a filename
    #[inline]
    pub fn with_filename(input: I, filename: String) -> Self {
        Testcase {
            input: Some(input),
            filename: Some(filename),
            fitness: 0,
            metadatas: SerdeAnyMap::new(),
        }
    }

    #[inline]
    pub fn default() -> Self {
        Testcase {
            input: None,
            filename: None,
            fitness: 0,
            metadatas: SerdeAnyMap::new(),
        }
    }
}
