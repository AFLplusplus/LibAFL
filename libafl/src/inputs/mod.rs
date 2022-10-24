//! Inputs are the actual contents sent to a target for each exeuction.

pub mod bytes;
pub use bytes::BytesInput;

pub mod encoded;
pub use encoded::*;

pub mod gramatron;
pub use gramatron::*;

pub mod generalized;
pub use generalized::*;

#[cfg(feature = "nautilus")]
pub mod nautilus;
use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    clone::Clone,
    fmt::{Debug, Formatter},
};
#[cfg(feature = "std")]
use std::{fs::File, hash::Hash, io::Read, path::Path};

#[cfg(feature = "input_conversion")]
use downcast_rs::{impl_downcast, Downcast};
#[cfg(feature = "nautilus")]
pub use nautilus::*;
use postcard::{de_flavors::Slice, Deserializer};
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use crate::bolts::fs::write_file_atomic;
use crate::{bolts::ownedref::OwnedSlice, Error};

/// An input for the target
#[cfg(not(feature = "std"))]
pub trait Input: Clone + Serialize + serde::de::DeserializeOwned + Debug {
    /// Name for this input type
    const NAME: &'static str;

    /// Write this input to the file
    fn to_file<P>(&self, _path: P) -> Result<(), Error> {
        Err(Error::not_implemented("Not supported in no_std"))
    }

    /// Write this input to the file
    fn from_file<P>(_path: P) -> Result<Self, Error> {
        Err(Error::not_implemented("Not supprted in no_std"))
    }

    /// Generate a name for this input
    fn generate_name(&self, idx: usize) -> String;

    /// An hook executed if the input is stored as `Testcase`
    fn wrapped_as_testcase(&mut self) {}
}

/// An input for the target
#[cfg(feature = "std")]
pub trait Input:
    Clone + ConvertibleInput + Serialize + serde::de::DeserializeOwned + Debug
{
    /// Name for this input type
    const NAME: &'static str;

    /// Write this input to the file
    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        write_file_atomic(path, &postcard::to_allocvec(self)?)
    }

    /// Load the content of this input from a file
    fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut file = File::open(path)?;
        let mut bytes: Vec<u8> = vec![];
        file.read_to_end(&mut bytes)?;
        Ok(postcard::from_bytes(&bytes)?)
    }

    /// Serializes this input to the dynamic serialisation format to pass between different fuzzers
    fn serialize_dynamic(&self, buf: &mut Vec<u8>) -> Result<(), postcard::Error> {
        buf.extend_from_slice(postcard::to_allocvec(Self::NAME)?.as_slice());
        buf.extend_from_slice(postcard::to_allocvec(self)?.as_slice());
        Ok(())
    }

    /// Deserializes this input type from the dynamic serialization format, if possible
    fn deserialize_dynamic(
        buf: &[u8],
    ) -> Result<Option<Self>, <&mut Deserializer<Slice> as serde::de::Deserializer>::Error> {
        convert_named(buf)
    }

    /// Generate a name for this input
    fn generate_name(&self, idx: usize) -> String;

    /// An hook executed if the input is stored as `Testcase`
    fn wrapped_as_testcase(&mut self) {}
}

/// Utility trait for downcasting inputs for conversion
#[cfg(feature = "input_conversion")]
pub trait ConvertibleInput: Downcast {}

#[cfg(feature = "input_conversion")]
impl_downcast!(ConvertibleInput);

#[cfg(feature = "input_conversion")]
impl<I: Input> ConvertibleInput for I {}

/// Function signature for conversion methods
#[cfg(feature = "input_conversion")]
pub type InputConversionFn = fn(
    &[u8],
) -> Result<
    Box<dyn ConvertibleInput>,
    <&mut Deserializer<Slice> as serde::de::Deserializer>::Error,
>;

/// Struct for converting between input types at deserialisation time
#[cfg(feature = "input_conversion")]
pub struct InputConversion {
    from: &'static str,
    to: &'static str,
    converter: InputConversionFn,
}

#[cfg(feature = "input_conversion")]
impl Debug for InputConversion {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InputConversion")
            .field("from", &self.from)
            .field("to", &self.to)
            .finish()
    }
}

#[cfg(feature = "input_conversion")]
impl InputConversion {
    /// Create a new input conversion to be registered
    pub const fn new(from: &'static str, to: &'static str, converter: InputConversionFn) -> Self {
        Self {
            from,
            to,
            converter,
        }
    }
}

#[cfg(feature = "input_conversion")]
inventory::collect!(InputConversion);

/// Converts from a serialisation-specified type to the intended type, if such a conversion exists
#[cfg(feature = "input_conversion")]
pub fn convert_named<T: Input>(
    bytes: &[u8],
) -> Result<Option<T>, <&mut Deserializer<Slice> as serde::de::Deserializer>::Error> {
    let mut deser = Deserializer::from_bytes(bytes);
    let from = String::deserialize(&mut deser)?;
    for conversion in inventory::iter::<InputConversion> {
        if conversion.from == from && conversion.to == T::NAME {
            return Ok((conversion.converter)(deser.finalize()?)?
                .downcast()
                .ok()
                .map(|boxed| *boxed));
        }
    }
    Ok(None)
}

/// An input for tests, mainly. There is no real use much else.
#[derive(Copy, Clone, Serialize, Deserialize, Debug, Hash)]
pub struct NopInput {}
impl Input for NopInput {
    const NAME: &'static str = "NopInput";

    fn generate_name(&self, _idx: usize) -> String {
        "nop-input".to_string()
    }
}
impl HasTargetBytes for NopInput {
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::from(vec![0])
    }
}

// TODO change this to fn target_bytes(&self, buffer: &mut Vec<u8>) -> &[u8];
/// Can be represented with a vector of bytes.
/// This representation is not necessarily deserializable.
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

/// Defines the input type shared across traits of the type.
/// Needed for consistency across HasCorpus/HasSolutions and friends.
pub trait UsesInput {
    /// Type which will be used throughout this state.
    type Input: Input;
}
