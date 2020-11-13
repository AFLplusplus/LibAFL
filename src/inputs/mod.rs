extern crate alloc;

pub mod bytes;
pub use bytes::BytesInput;

use core::clone::Clone;
use std::io::Write;
use std::path::Path;
use std::{fs::File, io::Read};

use crate::AflError;

/// An input for the target
pub trait Input: Clone {
    /// Write this input to the file
    fn to_file<P>(&self, path: P) -> Result<(), AflError>
    where
        P: AsRef<Path>,
    {
        let mut file = File::create(path)?;
        file.write_all(self.serialize()?)?;
        Ok(())
    }

    /// Load the contents of this input from a file
    fn from_file<P>(path: P) -> Result<Self, AflError>
    where
        P: AsRef<Path>,
    {
        let mut file = File::open(path).map_err(AflError::File)?;
        let mut bytes: Vec<u8> = vec![];
        file.read_to_end(&mut bytes).map_err(AflError::File)?;
        Self::deserialize(&bytes)
    }

    /// Serialize this input, for later deserialization.
    /// This is not necessarily the representation to be used by the target
    /// Instead, to get bytes for a target, use [HasTargetBytes](afl::inputs::HasTargetBytes).
    fn serialize(&self) -> Result<&[u8], AflError>;

    /// Deserialize this input, using the bytes serialized before.
    fn deserialize(buf: &[u8]) -> Result<Self, AflError>;
}

/// Can be serialized to a bytes representation
/// This representation is not necessarily deserializable
/// Instead, it can be used as bytes input for a target
pub trait HasTargetBytes {
    /// Target bytes, that can be written to a target
    fn target_bytes(&self) -> &Vec<u8>;
}

/// Contains an internal bytes Vector
pub trait HasBytesVec {
    /// The internal bytes map
    fn bytes(&self) -> &Vec<u8>;
    /// The internal bytes map (as mutable borrow)
    fn bytes_mut(&mut self) -> &mut Vec<u8>;
}
