//! Inputs are the actual contents sent to a target for each exeuction.

pub mod bytes;
pub use bytes::BytesInput;

pub mod value;
pub use value::ValueInput;

pub mod encoded;
pub use encoded::*;

pub mod gramatron;
pub use gramatron::*;

pub mod generalized;
pub use generalized::*;

pub mod bytessub;
pub use bytessub::BytesSubInput;

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
use core::{
    clone::Clone,
    fmt::Debug,
    marker::PhantomData,
    ops::{DerefMut, RangeBounds},
};
#[cfg(feature = "std")]
use std::{fs::File, hash::Hash, io::Read, path::Path};

#[cfg(feature = "std")]
use libafl_bolts::fs::write_file_atomic;
use libafl_bolts::{
    ownedref::{OwnedMutSlice, OwnedSlice},
    subrange::{SubRangeMutSlice, SubRangeSlice},
    Error, HasLen,
};
#[cfg(feature = "nautilus")]
pub use nautilus::*;
use serde::{Deserialize, Serialize};

use crate::corpus::CorpusId;

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
    fn generate_name(&self, id: Option<CorpusId>) -> String;
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
    fn generate_name(&self, id: Option<CorpusId>) -> String;
}

/// Convert between two input types with a state
pub trait InputConverter: Debug {
    /// Source type
    type From;
    /// Destination type
    type To;

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
#[derive(Copy, Clone, Serialize, Deserialize, Debug, Default, Hash)]
pub struct NopInput {}

impl NopInput {
    /// Creates a new [`NopInput`]
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl Input for NopInput {
    fn generate_name(&self, _id: Option<CorpusId>) -> String {
        "nop-input".to_string()
    }
}

impl HasTargetBytes for NopInput {
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::from(vec![0])
    }
}

impl HasLen for NopInput {
    fn len(&self) -> usize {
        0
    }
}

// TODO change this to fn target_bytes(&self, buffer: &mut Vec<u8>) -> &[u8];
/// Has a byte representation intended for the target.
/// Can be represented with a vector of bytes.
/// This representation is not necessarily deserializable.
/// Instead, it can be used as bytes input for a target
pub trait HasTargetBytes {
    /// Target bytes, that can be written to a target
    fn target_bytes(&self) -> OwnedSlice<u8>;
}

/// Contains mutable bytes
pub trait HasFixedMutatorBytes: HasLen {
    /// The bytes
    fn bytes(&self) -> &[u8];

    /// The bytes to mutate
    fn bytes_mut(&mut self) -> &mut [u8];

    /// Creates a [`SubRangeSlice`] from this input, that can be used to slice a byte array.
    fn sub_bytes<R>(&self, range: R) -> SubRangeSlice<u8>
    where
        R: RangeBounds<usize>,
    {
        SubRangeSlice::new(OwnedSlice::from(self.bytes()), range)
    }

    /// Creates a [`SubRangeMutSlice`] from this input, that can be used to slice a byte array.
    fn sub_bytes_mut<R>(&mut self, range: R) -> SubRangeMutSlice<u8>
    where
        R: RangeBounds<usize>,
    {
        SubRangeMutSlice::new(OwnedMutSlice::from(self.bytes_mut()), range)
    }

    /// Creates a [`BytesSubInput`] from this input, that can be used for local mutations.
    fn sub_input<R>(&mut self, range: R) -> BytesSubInput<Self>
    where
        R: RangeBounds<usize>,
    {
        BytesSubInput::new(self, range)
    }
}

impl HasFixedMutatorBytes for Vec<u8> {
    fn bytes(&self) -> &[u8] {
        self.as_ref()
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }
}

/// A wrapper type that allows us to use mutators for Mutators for `&mut `[`Vec`].
#[deprecated(since = "0.15.0", note = "Use &mut Vec<u8> directly")]
pub type MutVecInput<'a> = &'a mut Vec<u8>;

impl HasFixedMutatorBytes for &'_ mut Vec<u8> {
    fn bytes(&self) -> &[u8] {
        self
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self
    }
}

/// Contains mutable and resizable bytes
pub trait HasMutatorBytes: HasFixedMutatorBytes {
    /// Resize the mutator bytes to a given new size.
    /// Use `value` to fill new slots in case the buffer grows.
    /// See [`Vec::splice`].
    fn resize(&mut self, new_len: usize, value: u8);

    /// Extends the given buffer with an iterator. See [`alloc::vec::Vec::extend`]
    fn extend<'a, I: IntoIterator<Item = &'a u8>>(&mut self, iter: I);

    /// Splices the given target bytes according to [`Vec::splice`]'s rules
    fn splice<R, I>(&mut self, range: R, replace_with: I) -> Splice<'_, I::IntoIter>
    where
        R: RangeBounds<usize>,
        I: IntoIterator<Item = u8>;

    /// Drains the given target bytes according to [`Vec::drain`]'s rules
    fn drain<R>(&mut self, range: R) -> Drain<'_, u8>
    where
        R: RangeBounds<usize>;
}

impl HasMutatorBytes for Vec<u8> {
    fn resize(&mut self, new_len: usize, value: u8) {
        <Vec<u8>>::resize(self, new_len, value);
    }

    fn extend<'a, I: IntoIterator<Item = &'a u8>>(&mut self, iter: I) {
        <Vec<u8> as Extend<I::Item>>::extend(self, iter);
    }

    fn splice<R, I>(&mut self, range: R, replace_with: I) -> Splice<'_, I::IntoIter>
    where
        R: RangeBounds<usize>,
        I: IntoIterator<Item = u8>,
    {
        <Vec<u8>>::splice(self, range, replace_with)
    }

    fn drain<R>(&mut self, range: R) -> Drain<'_, u8>
    where
        R: RangeBounds<usize>,
    {
        <Vec<u8>>::drain(self, range)
    }
}

impl HasMutatorBytes for &mut Vec<u8> {
    fn resize(&mut self, new_len: usize, value: u8) {
        self.deref_mut().resize(new_len, value);
    }

    fn extend<'b, I: IntoIterator<Item = &'b u8>>(&mut self, iter: I) {
        <Vec<u8> as Extend<I::Item>>::extend(self, iter);
    }

    fn splice<R, I>(&mut self, range: R, replace_with: I) -> Splice<'_, I::IntoIter>
    where
        R: RangeBounds<usize>,
        I: IntoIterator<Item = u8>,
    {
        self.deref_mut().splice::<R, I>(range, replace_with)
    }

    fn drain<R>(&mut self, range: R) -> Drain<'_, u8>
    where
        R: RangeBounds<usize>,
    {
        self.deref_mut().drain(range)
    }
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

/// A converter that converts from `input` to target bytes
pub trait TargetBytesConverter<I> {
    /// Create target bytes
    fn to_target_bytes<'a>(&mut self, input: &'a I) -> OwnedSlice<'a, u8>;
}

/// Simply gets the target bytes out from a [`HasTargetBytes`] type.
#[derive(Debug)]
pub struct NopTargetBytesConverter<I> {
    phantom: PhantomData<I>,
}

impl<I> NopTargetBytesConverter<I> {
    /// Create a new [`NopTargetBytesConverter`]
    #[must_use]
    pub fn new() -> NopTargetBytesConverter<I> {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<I> Default for NopTargetBytesConverter<I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I> TargetBytesConverter<I> for NopTargetBytesConverter<I>
where
    I: HasTargetBytes,
{
    fn to_target_bytes<'a>(&mut self, input: &'a I) -> OwnedSlice<'a, u8> {
        input.target_bytes()
    }
}
