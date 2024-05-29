//! Inputs are the actual contents sent to a target for each exeuction.

pub mod bytes;
pub use bytes::BytesInput;

pub mod encoded;
pub use encoded::*;

pub mod gramatron;
pub use gramatron::*;

pub mod generalized;
pub use generalized::*;

pub mod bytessub;
pub use bytessub::{BytesSubInput, BytesSubInputMut};

#[cfg(feature = "multipart_inputs")]
pub mod multi;
#[cfg(feature = "multipart_inputs")]
pub use multi::*;

#[cfg(feature = "nautilus")]
pub mod nautilus;

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::{Drain, Splice, Vec},
};
use core::{clone::Clone, fmt::Debug, marker::PhantomData, ops::RangeBounds};
#[cfg(feature = "std")]
use std::{fs::File, hash::Hash, io::Read, path::Path};

#[cfg(feature = "std")]
use libafl_bolts::fs::write_file_atomic;
use libafl_bolts::{ownedref::OwnedSlice, Error, HasLen};
#[cfg(feature = "nautilus")]
pub use nautilus::*;
use serde::{Deserialize, Serialize};

/// An input for the target
#[cfg(not(feature = "std"))]
pub trait Input: Clone + Serialize + serde::de::DeserializeOwned + Debug {
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
pub trait Input: Clone + Serialize + serde::de::DeserializeOwned + Debug {
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
        let mut bytes = vec![];
        file.read_to_end(&mut bytes)?;
        Ok(postcard::from_bytes(&bytes)?)
    }

    /// Generate a name for this input, the user is responsible for making each name of testcase unique.
    fn generate_name(&self, idx: usize) -> String;

    /// An hook executed if the input is stored as `Testcase`
    fn wrapped_as_testcase(&mut self) {}
}

/// Convert between two input types with a state
pub trait InputConverter: Debug {
    /// Source type
    type From: Input;
    /// Destination type
    type To: Input;

    /// Convert the src type to the dest
    fn convert(&mut self, input: Self::From) -> Result<Self::To, Error>;
}

/// `None` type to satisfy the type infearence in an `Option`
#[macro_export]
macro_rules! none_input_converter {
    () => {
        None::<$crate::inputs::ClosureInputConverter<_, _>>
    };
}

/// An input for tests, mainly. There is no real use much else.
#[derive(Copy, Clone, Serialize, Deserialize, Debug, Hash)]
pub struct NopInput {}
impl Input for NopInput {
    fn generate_name(&self, _idx: usize) -> String {
        "nop-input".to_string()
    }
}
impl HasTargetBytes for NopInput {
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::from(vec![0])
    }
}

/// Target bytes wrapper keeping track of the current read position.
/// Convenient wrapper when bytes must be split it in multiple subinputs.
#[derive(Debug)]
pub struct BytesReader<'a, I>
where
    I: HasTargetBytes + HasLen,
{
    parent_input: &'a I,
    pos: usize,
}

impl<'a, I> BytesReader<'a, I>
where
    I: HasTargetBytes + HasLen,
{
    /// Create a new [`BytesReader`].
    /// The position of the reader is initialized to 0.
    pub fn new(input: &'a I) -> Self {
        Self {
            parent_input: input,
            pos: 0,
        }
    }

    /// Read an immutable subinput from the parent input, from the current cursor position up to `limit` bytes.
    /// If the resulting slice would go beyond the end of the parent input, it will be limited to the length of the parent input.
    #[must_use]
    pub fn read_to_slice(&mut self, limit: usize) -> BytesSubInput<'a> {
        let sub_input = BytesSubInput::new(self.parent_input, self.pos..(self.pos + limit));

        self.pos += sub_input.len();

        sub_input
    }
}

impl<'a, I: HasTargetBytes + HasLen> From<&'a I> for BytesReader<'a, I> {
    fn from(input: &'a I) -> Self {
        Self::new(input)
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

/// Contains mutateable and resizable bytes
pub trait HasMutatorBytes: HasLen {
    /// The bytes
    fn bytes(&self) -> &[u8];

    /// The bytes to mutate
    fn bytes_mut(&mut self) -> &mut [u8];

    /// Resize the mutator bytes to a given new size.
    /// Use `value` to fill new slots in case the buffer grows.
    /// See [`alloc::vec::Vec::splice`].
    fn resize(&mut self, new_len: usize, value: u8);

    /// Extends the given buffer with an iterator. See [`alloc::vec::Vec::extend`]
    fn extend<'a, I: IntoIterator<Item = &'a u8>>(&mut self, iter: I);

    /// Splices the given target bytes according to [`alloc::vec::Vec::splice`]'s rules
    fn splice<R, I>(&mut self, range: R, replace_with: I) -> Splice<'_, I::IntoIter>
    where
        R: RangeBounds<usize>,
        I: IntoIterator<Item = u8>;

    /// Drains the given target bytes according to [`alloc::vec::Vec::drain`]'s rules
    fn drain<R>(&mut self, range: R) -> Drain<'_, u8>
    where
        R: RangeBounds<usize>;

    /// Creates a [`BytesSubInput`] from this input, that can be used for local mutations.
    fn sub_input<R>(&self, range: R) -> BytesSubInput
    where
        R: RangeBounds<usize>,
        Self: Sized,
    {
        BytesSubInput::new(self, range)
    }

    /// Creates a [`BytesSubInputMut`] from this input, that can be used for local mutations.
    fn sub_input_mut<R>(&mut self, range: R) -> BytesSubInputMut<Self>
    where
        R: RangeBounds<usize>,
        Self: Sized,
    {
        BytesSubInputMut::new(self, range)
    }
}

impl<I> HasTargetBytes for I
where
    I: HasMutatorBytes,
{
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::from(self.bytes())
    }
}

/// A wrapper type that allows us to use mutators for Mutators for `&mut `[`Vec`].
#[derive(Debug)]
pub struct MutVecInput<'a>(&'a mut Vec<u8>);

impl<'a> From<&'a mut Vec<u8>> for MutVecInput<'a> {
    fn from(value: &'a mut Vec<u8>) -> Self {
        Self(value)
    }
}

impl<'a> HasLen for MutVecInput<'a> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a> HasMutatorBytes for MutVecInput<'a> {
    fn bytes(&self) -> &[u8] {
        self.0
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.0
    }

    fn resize(&mut self, new_len: usize, value: u8) {
        self.0.resize(new_len, value);
    }

    fn extend<'b, I: IntoIterator<Item = &'b u8>>(&mut self, iter: I) {
        self.0.extend(iter);
    }

    fn splice<R, I>(&mut self, range: R, replace_with: I) -> Splice<'_, I::IntoIter>
    where
        R: RangeBounds<usize>,
        I: IntoIterator<Item = u8>,
    {
        self.0.splice::<R, I>(range, replace_with)
    }

    fn drain<R>(&mut self, range: R) -> Drain<'_, u8>
    where
        R: RangeBounds<usize>,
    {
        self.0.drain(range)
    }
}

/// Defines the input type shared across traits of the type.
/// Needed for consistency across HasCorpus/HasSolutions and friends.
pub trait UsesInput {
    /// Type which will be used throughout this state.
    type Input: Input;
}

#[derive(Debug)]
/// Basic `InputConverter` with just one type that is not converting
pub struct NopInputConverter<I> {
    phantom: PhantomData<I>,
}

impl<I> Default for NopInputConverter<I> {
    fn default() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<I> InputConverter for NopInputConverter<I>
where
    I: Input,
{
    type From = I;
    type To = I;

    fn convert(&mut self, input: Self::From) -> Result<Self::To, Error> {
        Ok(input)
    }
}

/// `InputConverter` that uses a closure to convert
pub struct ClosureInputConverter<F, T>
where
    F: Input,
    T: Input,
{
    convert_cb: Box<dyn FnMut(F) -> Result<T, Error>>,
}

impl<F, T> Debug for ClosureInputConverter<F, T>
where
    F: Input,
    T: Input,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClosureInputConverter")
            .finish_non_exhaustive()
    }
}

impl<F, T> ClosureInputConverter<F, T>
where
    F: Input,
    T: Input,
{
    /// Create a new converter using two closures, use None to forbid the conversion or the conversion back
    #[must_use]
    pub fn new(convert_cb: Box<dyn FnMut(F) -> Result<T, Error>>) -> Self {
        Self { convert_cb }
    }
}

impl<F, T> InputConverter for ClosureInputConverter<F, T>
where
    F: Input,
    T: Input,
{
    type From = F;
    type To = T;

    fn convert(&mut self, input: Self::From) -> Result<Self::To, Error> {
        (self.convert_cb)(input)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use crate::inputs::{BytesInput, BytesReader, HasTargetBytes};

    #[test]
    fn test_bytesreader() {
        let bytes_input = BytesInput::new(vec![1, 2, 3, 4, 5, 6, 7]);
        let mut bytes_reader = BytesReader::new(&bytes_input);

        let bytes_read = bytes_reader.read_to_slice(2);
        assert_eq!(bytes_read.target_bytes().deref(), &[1, 2]);

        let bytes_read = bytes_reader.read_to_slice(3);
        assert_eq!(bytes_read.target_bytes().deref(), &[3, 4, 5]);

        let bytes_read = bytes_reader.read_to_slice(8);
        assert_eq!(bytes_read.target_bytes().deref(), &[6, 7]);

        let bytes_read = bytes_reader.read_to_slice(8);
        let bytes_read_ref: &[u8] = &[];
        assert_eq!(bytes_read.target_bytes().deref(), bytes_read_ref);
    }
}
