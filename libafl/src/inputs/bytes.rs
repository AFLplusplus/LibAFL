//! The `BytesInput` is the "normal" input, a map of bytes, that can be sent directly to the client
//! (As opposed to other, more abstract, inputs, like an Grammar-Based AST Input)

use alloc::{borrow::ToOwned, rc::Rc, string::String, vec::Vec};
use core::{
    cell::RefCell,
    hash::{BuildHasher, Hasher},
};
#[cfg(feature = "std")]
use std::{fs::File, io::Read, path::Path};

use ahash::RandomState;
#[cfg(feature = "std")]
use libafl_bolts::{fs::write_file_atomic, Error};
use libafl_bolts::{ownedref::OwnedSlice, HasLen, Truncate};
use serde::{Deserialize, Serialize};

use crate::{
    corpus::CorpusId,
    inputs::{HasMutatorBytes, HasTargetBytes, Input},
};

/// A bytes input is the basic input
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct BytesInput {
    /// The raw input bytes
    pub(crate) bytes: Vec<u8>,
    /// The current actual length of this input
    len: usize,
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

    fn wrapped_as_testcase(&mut self) {
        self.bytes().truncate(self.len);
    }

    /// Generate a name for this input
    fn generate_name(&self, _id: Option<CorpusId>) -> String {
        let mut hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
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

impl HasMutatorBytes for BytesInput {
    #[inline]
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    #[inline]
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }

    fn resize(&mut self, new_len: usize, value: u8) {
        if new_len <= self.len {
            // We shrink. Keep the memory around for later use.
            self.len = new_len;
        } else if self.bytes.len() >= new_len {
            // We still have enough space.
            let old_len = self.len;
            self.bytes[old_len..new_len].fill(value);
            self.len = new_len;
        } else {
            self.len = new_len;
            self.bytes.resize(new_len, value);
        }
    }

    fn extend<'a, I: IntoIterator<Item = &'a u8>>(&mut self, iter: I) {
        self.bytes.truncate(self.len);
        Extend::extend(&mut self.bytes, iter);
    }

    fn splice<R, I>(&mut self, range: R, replace_with: I) -> alloc::vec::Splice<'_, I::IntoIter>
    where
        R: core::ops::RangeBounds<usize>,
        I: IntoIterator<Item = u8>,
    {
        self.bytes.truncate(self.len);
        self.bytes.splice(range, replace_with)
    }

    fn drain<R>(&mut self, range: R) -> alloc::vec::Drain<'_, u8>
    where
        R: core::ops::RangeBounds<usize>,
    {
        self.bytes.truncate(self.len);
        self.bytes.drain(range)
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
        self.len
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

impl From<BytesInput> for Vec<u8> {
    fn from(value: BytesInput) -> Vec<u8> {
        value.bytes
    }
}

impl BytesInput {
    /// Creates a new bytes input using the given bytes
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        Self { bytes, len }
    }
}
