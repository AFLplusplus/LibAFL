//! Inputs are the actual contents sent to a target for each exeuction.

pub mod bytes;
pub use bytes::BytesInput;

pub mod encoded;
pub use encoded::*;

pub mod gramatron;
pub use gramatron::*;

#[cfg(feature = "nautilus")]
pub mod nautilus;
#[cfg(feature = "nautilus")]
pub use nautilus::*;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{clone::Clone, fmt::Debug};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::{fs::File, io::Read, path::Path};

#[cfg(feature = "std")]
use crate::bolts::fs::write_file_atomic;
use crate::{bolts::ownedref::OwnedSlice, Error};

/// An input for the target
pub trait Input: Clone + Serialize + serde::de::DeserializeOwned + Debug {
    #[cfg(feature = "std")]
    /// Write this input to the file
    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        write_file_atomic(path, &postcard::to_allocvec(self)?)
    }

    #[cfg(not(feature = "std"))]
    /// Write this input to the file
    fn to_file<P>(&self, _path: P) -> Result<(), Error> {
        Err(Error::NotImplemented("Not supported in no_std".into()))
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
        Ok(postcard::from_bytes(&bytes)?)
    }

    /// Write this input to the file
    #[cfg(not(feature = "std"))]
    fn from_file<P>(_path: P) -> Result<Self, Error> {
        Err(Error::NotImplemented("Not supprted in no_std".into()))
    }

    /// Generate a name for this input
    fn generate_name(&self, idx: usize) -> String;
}

/// An input for tests, mainly. There is no real use much else.
#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
pub struct NopInput {}
impl Input for NopInput {
    fn generate_name(&self, _idx: usize) -> String {
        "nop-input".to_string()
    }
}
impl HasTargetBytes for NopInput {
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::Owned(vec![0])
    }
}

/// Can be represented with a vector of bytes
/// This representation is not necessarily deserializable
/// Instead, it can be used as bytes input for a target
pub trait HasTargetBytes {
    /// Target bytes, that can be written to a target
    fn target_bytes(&self) -> OwnedSlice<u8>;
}

/// Contains an internal bytes Vector
pub trait HasBytesVec {
    /// The internal bytes map
    fn bytes(&self) -> &[u8];
    /// The internal bytes map (as mutable borrow)
    fn bytes_mut(&mut self) -> &mut Vec<u8>;
}
