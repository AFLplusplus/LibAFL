
use alloc::borrow::ToOwned;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::convert::From;

use crate::inputs::{HasBytesVec, HasTargetBytes, Input};
use crate::AflError;

/// A bytes input is the basic input
#[derive(Clone, Debug, Default)]
pub struct BytesInput {
    pub bytes: Vec<u8>,
}

impl Input for BytesInput {
    fn serialize(&self) -> Result<&[u8], AflError> {
        Ok(&self.bytes)
    }

    fn deserialize(buf: &[u8]) -> Result<Self, AflError> {
        Ok(Self {
            bytes: buf.to_owned(),
        })
    }
}

/// Rc Ref-cell from Input
impl Into<Rc<RefCell<Self>>> for BytesInput {
    fn into(self) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(self))
    }
}

impl HasBytesVec for BytesInput {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }
}

impl HasTargetBytes for BytesInput {
    fn target_bytes(&self) -> &[u8] {
        &self.bytes
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
        BytesInput { bytes: bytes }
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::{next_pow2, DefaultRand, Rand};

    #[test]
    fn test_input() {
        let mut rand = DefaultRand::new(0);
        assert_ne!(rand.next(), rand.next());
        assert!(rand.below(100) < 100);
        assert_eq!(rand.below(1), 0);
        assert_eq!(rand.between(10, 10), 10);
        assert!(rand.between(11, 20) > 10);
    }

    #[test]
    fn test_next_pow2() {
        assert_eq!(next_pow2(0), 0);
        assert_eq!(next_pow2(1), 1);
        assert_eq!(next_pow2(2), 2);
        assert_eq!(next_pow2(3), 4);
        assert_eq!(next_pow2(1000), 1024);
    }
}
