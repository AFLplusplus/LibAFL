//! UTF-8 string input

use alloc::{borrow::ToOwned, rc::Rc, string::String};
use core::{
    cell::RefCell,
    convert::From,
    hash::{BuildHasher, Hasher},
};
#[cfg(feature = "std")]
use std::{fs, path::Path};

use ahash::RandomState;
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use crate::{bolts::fs::write_file_atomic, Error};
use crate::{bolts::HasLen, inputs::Input};

/// A UTF-8 string
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Utf8Input {
    /// The raw input string
    pub(crate) string: String,
}

impl Input for Utf8Input {
    #[cfg(feature = "std")]
    /// Write this input to the file
    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        write_file_atomic(path, self.string.as_bytes())
    }

    /// Load the content of this input from a file
    #[cfg(feature = "std")]
    fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Ok(Utf8Input::new(fs::read_to_string(path)?))
    }

    /// Generate a name for this input
    fn generate_name(&self, _idx: usize) -> String {
        let mut hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
        hasher.write(self.string.as_bytes());
        format!("{:016x}", hasher.finish())
    }
}

/// Rc Ref-cell from Input
impl From<Utf8Input> for Rc<RefCell<Utf8Input>> {
    fn from(input: Utf8Input) -> Self {
        Rc::new(RefCell::new(input))
    }
}

impl HasLen for Utf8Input {
    #[inline]
    fn len(&self) -> usize {
        self.string.len()
    }
}

impl From<String> for Utf8Input {
    fn from(string: String) -> Self {
        Self::new(string)
    }
}

impl From<&str> for Utf8Input {
    fn from(string: &str) -> Self {
        Self::new(string.to_owned())
    }
}

impl From<Utf8Input> for String {
    fn from(value: Utf8Input) -> String {
        value.string
    }
}

impl Utf8Input {
    /// Creates a new string input using the given string
    #[must_use]
    pub fn new(string: String) -> Self {
        Self { string }
    }
}
