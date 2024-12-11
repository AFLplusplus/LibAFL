//! The `BytesInput` is the "normal" input, a map of bytes, that can be sent directly to the client
//! (As opposed to other, more abstract, inputs, like an Grammar-Based AST Input)

use alloc::{borrow::ToOwned, rc::Rc, string::String, vec::Vec};
use core::cell::RefCell;

use ahash::RandomState;
use libafl_bolts::{ownedref::OwnedSlice, HasLen};
#[cfg(feature = "std")]
use {
    libafl_bolts::{fs::write_file_atomic, Error},
    std::{fs::File, io::Read, path::Path},
};

use super::{Input, WrappingInput};
use crate::{
    corpus::CorpusId,
    inputs::{HasMutatorBytes, HasTargetBytes},
};

/// A bytes input is the basic input
pub type BytesInput = WrappingInput<Vec<u8>>;

impl Input for BytesInput {
    fn generate_name(&self, _id: Option<CorpusId>) -> String {
        format!(
            "{:016x}",
            RandomState::with_seeds(0, 0, 0, 0).hash_one(self.as_ref())
        )
    }

    #[cfg(feature = "std")]
    /// Write this input to the file
    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        write_file_atomic(path, self.as_ref())
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
}

/// Rc Ref-cell from Input
impl From<BytesInput> for Rc<RefCell<BytesInput>> {
    fn from(input: BytesInput) -> Self {
        Rc::new(RefCell::new(input))
    }
}

impl HasMutatorBytes for BytesInput {
    fn bytes(&self) -> &[u8] {
        self.as_ref()
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }

    fn resize(&mut self, new_len: usize, value: u8) {
        self.as_mut().resize(new_len, value);
    }

    fn extend<'a, I: IntoIterator<Item = &'a u8>>(&mut self, iter: I) {
        self.as_mut().extend(iter);
    }

    fn splice<R, I>(&mut self, range: R, replace_with: I) -> std::vec::Splice<'_, I::IntoIter>
    where
        R: core::ops::RangeBounds<usize>,
        I: IntoIterator<Item = u8>,
    {
        self.as_mut().splice(range, replace_with)
    }

    fn drain<R>(&mut self, range: R) -> std::vec::Drain<'_, u8>
    where
        R: core::ops::RangeBounds<usize>,
    {
        self.as_mut().drain(range)
    }
}

impl HasTargetBytes for BytesInput {
    #[inline]
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::from(self.as_ref())
    }
}

impl HasLen for BytesInput {
    fn len(&self) -> usize {
        self.as_ref().len()
    }
}

impl From<&[u8]> for BytesInput {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_owned())
    }
}

impl From<BytesInput> for Vec<u8> {
    fn from(value: BytesInput) -> Vec<u8> {
        value.inner()
    }
}
