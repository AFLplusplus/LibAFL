pub mod bytes;
pub use bytes::{BytesInput, HasBytesVec};

use std::clone::Clone;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;

use crate::AflError;

pub trait Input: Clone {
    fn to_file(&self, path: &PathBuf) -> Result<(), AflError> {
        let mut file = File::create(path)?;
        file.write_all(self.serialize()?)?;
        Ok(())
    }

    fn from_file(&mut self, path: &PathBuf) -> Result<(), AflError> {
        let mut file = File::create(path)?;
        let mut buf = vec![];
        file.read_to_end(&mut buf)?;
        self.deserialize(&buf)?;
        Ok(())
    }

    fn serialize(&self) -> Result<&[u8], AflError>;

    fn deserialize(&mut self, buf: &[u8]) -> Result<(), AflError>;
}
