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
pub trait Input: Clone + serde::Serialize + serde::de::DeserializeOwned + Debug {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolts::current_nanos;

    #[cfg(feature = "nautilus")]
    use grammartec::{context::Context, tree::Tree};
    use uuid::Uuid;

    static TEST_INPUT: &str = "I'm a test case";

    #[test]
    /// create a `BytesInput` ensuring filename is a parseable uuid
    fn test_bytesinput_generate_name() {
        let bytes = BytesInput::new(Vec::from(TEST_INPUT));
        let name = bytes.generate_name(0);
        assert!(Uuid::parse_str(&name).is_ok());
    }

    #[test]
    /// create an `EncodedInput` ensuring filename is a parseable uuid
    fn test_encodedinput_generate_name() {
        let encoded = TEST_INPUT
            .to_string()
            .as_bytes()
            .iter()
            .map(|c| (*c).into())
            .collect();

        let encoded_input = EncodedInput::new(encoded);

        let name = encoded_input.generate_name(0);

        assert!(Uuid::parse_str(&name).is_ok());
    }

    #[test]
    /// create a `GramatronInput` ensuring filename is a parseable uuid
    fn test_gramatroninput_generate_name() {
        let term = Terminal::new(0, 0, String::from("terminal"));

        let gramatron_input = GramatronInput::new(vec![term]);

        let name = gramatron_input.generate_name(0);

        assert!(Uuid::parse_str(&name).is_ok());
    }

    #[test]
    #[cfg(feature = "nautilus")]
    /// create a `NautilusInput` ensuring filename is a parseable uuid
    ///
    /// invoked via
    ///   `cargo +nightly test test_nautilusinput_generate_name --features nautilus`
    fn test_nautilusinput_generate_name() {
        let mut ctx = Context::new();
        let _ = ctx.add_rule("E", b"({E}+{E})");
        let _ = ctx.add_rule("E", b"1");
        ctx.initialize(11);

        let tree = Tree::from_rule_vec(vec![], &ctx);

        let nautilus_input = NautilusInput::new(tree);

        let name = nautilus_input.generate_name(0);

        assert!(Uuid::parse_str(&name).is_ok());
    }
}
