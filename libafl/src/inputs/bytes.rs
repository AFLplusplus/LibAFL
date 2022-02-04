//! The `BytesInput` is the "normal" input, a map of bytes, that can be sent directly to the client
//! (As opposed to other, more abstract, inputs, like an Grammar-Based AST Input)

use ahash::AHasher;
use alloc::{borrow::ToOwned, rc::Rc, string::String, vec::Vec};
use core::hash::Hasher;
use core::{cell::RefCell, convert::From};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::{fs::File, io::Read, path::Path};

#[cfg(feature = "std")]
use crate::{bolts::fs::write_file_atomic, Error};
use crate::{
    bolts::{ownedref::OwnedSlice, HasLen},
    inputs::{HasBytesVec, HasTargetBytes, Input},
};

/// A bytes input is the basic input
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct BytesInput {
    /// The raw input bytes
    bytes: Vec<u8>,
}

impl Input for BytesInput {
    #[cfg(feature = "std")]
    /// Write this input to the file
    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        write_file_atomic(path, &self.bytes)
    }

    /// Load the content of this input from a file
    #[cfg(feature = "std")]
    fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut file = File::open(path)?;
        let mut bytes: Vec<u8> = vec![];
        file.read_to_end(&mut bytes)?;
        Ok(BytesInput::new(bytes))
    }

    /// Generate a name for this input
    fn generate_name(&self, _idx: usize) -> String {
        let mut hasher = AHasher::new_with_keys(0, 0);
        hasher.write(self.bytes());
        format!("{:016x}", hasher.finish())
    }
}

/// Rc Ref-cell from Input
impl From<BytesInput> for Rc<RefCell<BytesInput>> {
    fn from(input: BytesInput) -> Self {
        Rc::new(RefCell::new(input))
    }
}

impl HasBytesVec for BytesInput {
    #[inline]
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[inline]
    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }
}

impl HasTargetBytes for BytesInput {
    #[inline]
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::from(&self.bytes)
    }
}

impl HasLen for BytesInput {
    #[inline]
    fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl From<Vec<u8>> for BytesInput {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for BytesInput {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_owned())
    }
}

impl BytesInput {
    /// Creates a new bytes input using the given bytes
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}
