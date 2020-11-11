extern crate alloc;
pub mod bytes;
pub use bytes::BytesInput;

use std::clone::Clone;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;

use crate::AflError;

/// An input for the target
pub trait Input: Clone {
    /// Write this input to the file
    fn to_file(&self, path: &PathBuf) -> Result<(), AflError> {
        let mut file = File::create(path)?;
        file.write_all(self.serialize()?)?;
        Ok(())
    }

    /// Load the contents of this input from a file
    fn from_file(&mut self, path: &PathBuf) -> Result<(), AflError> {
        let mut file = File::create(path)?;
        let mut buf = vec![];
        file.read_to_end(&mut buf)?;
        self.deserialize(&buf)?;
        Ok(())
    }

    /// Serialize this input, for later deserialization.
    /// This is not necessarily the representation to be used by the target
    /// Instead, to get bytes for a target, use [HasTargetBytes](afl::inputs::HasTargetBytes).
    fn serialize(&self) -> Result<&[u8], AflError>;

    /// Deserialize this input, using the bytes serialized before.
    fn deserialize(&mut self, buf: &[u8]) -> Result<(), AflError>;
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
