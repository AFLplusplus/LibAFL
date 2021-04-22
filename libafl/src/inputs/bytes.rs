//! The `BytesInput` is the "normal" input, a map of bytes, that can be sent directly to the client
//! (As opposed to other, more abstract, imputs, like an Grammar-Based AST Input)

use alloc::{borrow::ToOwned, rc::Rc, vec::Vec};
use core::{cell::RefCell, convert::From};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use crate::{
    inputs::{HasBytesVec, HasLen, HasTargetBytes, Input, TargetBytes},
    Error,
};

/// A bytes input is the basic input
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
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
        let mut file = File::create(path)?;
        file.write_all(&self.bytes)?;
        Ok(())
    }

    /// Load the contents of this input from a file
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
    fn target_bytes(&self) -> TargetBytes {
        TargetBytes::Ref(&self.bytes)
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
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::{Rand, StdRand};

    #[test]
    fn test_input() {
        let mut rand = StdRand::with_seed(0);
        assert_ne!(rand.next(), rand.next());
        assert!(rand.below(100) < 100);
        assert_eq!(rand.below(1), 0);
        assert_eq!(rand.between(10, 10), 10);
        assert!(rand.between(11, 20) > 10);
    }
}
