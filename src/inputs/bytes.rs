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
    fn deserialize(&mut self, buf: &[u8]) -> Result<(), AflError> {
        self.bytes.truncate(0);
        self.bytes.extend_from_slice(buf);
        Ok(())
    }
}

impl HasBytesVec for BytesInput {
    fn bytes(&self) -> &Vec<u8> {
        &self.bytes
    }
    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }
}

impl HasTargetBytes for BytesInput {
    fn target_bytes(&self) -> &Vec<u8> {
        &self.bytes
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
    use crate::utils::{next_pow2, Rand, Xoshiro256StarRand};

    #[test]
    fn test_input() {
        let mut rand = Xoshiro256StarRand::new();
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
