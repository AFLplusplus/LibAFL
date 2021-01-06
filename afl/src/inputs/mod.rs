pub mod bytes;
pub use bytes::BytesInput;

use alloc::vec::Vec;
use core::{clone::Clone, fmt::Debug};
#[cfg(feature = "std")]
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::AflError;

/// An input for the target
pub trait Input: Clone + serde::Serialize + serde::de::DeserializeOwned + Debug {
    #[cfg(feature = "std")]
    /// Write this input to the file
    fn to_file<P>(&self, path: P) -> Result<(), AflError>
    where
        P: AsRef<Path>,
    {
        let mut file = File::create(path)?;
        let serialized = postcard::to_allocvec(self)?;
        file.write_all(&serialized)?;
        Ok(())
    }

    #[cfg(not(feature = "std"))]
    /// Write this input to the file
    fn to_file<P>(&self, _path: P) -> Result<(), AflError>
where {
        Err(AflError::NotImplemented("Not suppored in no_std".into()))
    }

    /// Load the contents of this input from a file
    #[cfg(feature = "std")]
    fn from_file<P>(path: P) -> Result<Self, AflError>
    where
        P: AsRef<Path>,
    {
        let mut file = File::open(path)?;
        let mut bytes: Vec<u8> = vec![];
        file.read_to_end(&mut bytes)?;
        Ok(postcard::from_bytes(&bytes)?)
    }

    /// Write this input to the file
    #[cfg(not(feature = "std"))]
    fn from_file<P>(_path: P) -> Result<Self, AflError>
where {
        Err(AflError::NotImplemented("Not suppored in no_std".into()))
    }
}

/// An input for tests, mainly. There is no real use much else.
#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
pub struct NopInput {}
impl Input for NopInput {}
impl HasTargetBytes for NopInput {
    fn target_bytes(&self) -> TargetBytes {
        TargetBytes::Owned(vec![0])
    }
}

pub enum TargetBytes<'a> {
    Ref(&'a [u8]),
    Owned(Vec<u8>),
}

impl<'a> TargetBytes<'a> {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            TargetBytes::Ref(r) => r,
            TargetBytes::Owned(v) => v.as_slice(),
        }
    }
}

/// Can be represented with a vector of bytes
/// This representation is not necessarily deserializable
/// Instead, it can be used as bytes input for a target
pub trait HasTargetBytes {
    /// Target bytes, that can be written to a target
    fn target_bytes(&self) -> TargetBytes;
}

/// Contains an internal bytes Vector
pub trait HasBytesVec {
    /// The internal bytes map
    fn bytes(&self) -> &[u8];
    /// The internal bytes map (as mutable borrow)
    fn bytes_mut(&mut self) -> &mut Vec<u8>;
}
