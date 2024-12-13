//! Newtype pattern style wrapper for [`super::Input`]s

use alloc::{string::String, vec::Vec};
use core::{
    fmt::Debug,
    hash::Hash,
    ops::{Deref, DerefMut},
};

use libafl_bolts::{generic_hash_std, rands::Rand};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use {
    libafl_bolts::{fs::write_file_atomic, Error},
    std::{fs::File, io::Read, path::Path},
};

use super::{Input, MappedInput};
use crate::{corpus::CorpusId, mutators::numeric::Numeric};

/// Newtype pattern wrapper around an underlying structure to implement inputs
///
/// This does not blanket implement [`super::Input`], because for certain inputs, writing them to disk does not make sense, because they don't own their data (like [`super::MutVecInput`])
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct ValueInput<I>(I);

impl<I> From<I> for ValueInput<I> {
    fn from(value: I) -> Self {
        Self(value)
    }
}

impl<I> ValueInput<I> {
    /// Create a new [`ValueInput`]
    pub const fn new(value: I) -> Self {
        Self(value)
    }

    /// Extract the inner value
    pub fn into_inner(self) -> I {
        self.0
    }
}

impl<I> AsRef<I> for ValueInput<I> {
    fn as_ref(&self) -> &I {
        &self.0
    }
}

impl<I> AsMut<I> for ValueInput<I> {
    fn as_mut(&mut self) -> &mut I {
        &mut self.0
    }
}

impl<I: Copy> Copy for ValueInput<I> {}

// Macro to implement the `Input` trait and create type aliases for `WrappingInput<T>`
macro_rules! impl_input_for_value_input {
    ($($t:ty => $name:ident),+ $(,)?) => {
        $(
            impl Input for ValueInput<$t> {
                fn generate_name(&self, _id: Option<CorpusId>) -> String {
                    format!("{:016x}", generic_hash_std(self))
                }
            }

            /// Input wrapping a <$t>
            pub type $name = ValueInput<$t>;
        )*
    };
}

// Invoke the macro with type-name pairs
impl_input_for_value_input!(
    u8 => U8Input,
    u16 => U16Input,
    u32 => U32Input,
    u64 => U64Input,
    u128 => U128Input,
    usize => UsizeInput,
    i8 => I8Input,
    i16 => I16Input,
    i32 => I32Input,
    i64 => I64Input,
    i128 => I128Input,
    isize => IsizeInput,
);

/// manually implemented because files can be written more efficiently
impl Input for ValueInput<Vec<u8>> {
    fn generate_name(&self, _id: Option<CorpusId>) -> String {
        format!("{:016x}", generic_hash_std(self))
    }

    /// Write this input to the file
    #[cfg(feature = "std")]
    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        write_file_atomic(path, self.as_ref())?;
        Ok(())
    }

    /// Load the content of this input from a file
    #[cfg(feature = "std")]
    fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut file = File::open(path)?;
        let mut data = vec![];
        file.read_to_end(&mut data)?;
        Ok(data.into())
    }
}

impl<I> Numeric for ValueInput<I>
where
    I: Numeric,
{
    fn flip_all_bits(&mut self) {
        self.as_mut().flip_all_bits();
    }

    fn flip_bit_at(&mut self, rhs: usize) {
        self.as_mut().flip_bit_at(rhs);
    }

    fn wrapping_inc(&mut self) {
        self.as_mut().wrapping_inc();
    }

    fn wrapping_dec(&mut self) {
        self.as_mut().wrapping_dec();
    }

    fn twos_complement(&mut self) {
        self.as_mut().twos_complement();
    }

    fn randomize<R: Rand>(&mut self, rand: &mut R) {
        self.as_mut().randomize(rand);
    }
}

/// Input type that holds a mutable reference to an inner value
#[derive(Debug)]
pub struct ValueMutRefInput<'a, I>(&'a mut I);

// Macro to implement the `Input` trait and create type aliases for `WrappingInput<T>`
macro_rules! impl_input_for_value_mut_ref_input {
    ($($t:ty => $name:ident),+ $(,)?) => {
        $(            /// Input wrapping a <$t>
            pub type $name<'a> = ValueMutRefInput<'a, $t>;
        )*
    };
}

// Invoke the macro with type-name pairs
impl_input_for_value_mut_ref_input!(
    u8 => MutU8Input,
    u16 => MutU16Input,
    u32 => MutU32Input,
    u64 => MutU64Input,
    u128 => MutU128Input,
    usize => MutUsizeInput,
    i8 => MutI8Input,
    i16 => MutI16Input,
    i32 => MutI32Input,
    i64 => MutI64Input,
    i128 => MutI128Input,
    isize => MutIsizeInput,
);

impl<I> Deref for ValueMutRefInput<'_, I> {
    type Target = I;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<I> DerefMut for ValueMutRefInput<'_, I> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl<'a, I> From<&'a mut I> for ValueMutRefInput<'a, I> {
    fn from(value: &'a mut I) -> Self {
        Self(value)
    }
}

impl<'a, I> From<&'a mut ValueInput<I>> for ValueMutRefInput<'a, I> {
    fn from(value: &'a mut ValueInput<I>) -> Self {
        Self(value.as_mut())
    }
}

impl<I> MappedInput for ValueMutRefInput<'_, I> {
    type Type<'a>
        = ValueMutRefInput<'a, I>
    where
        Self: 'a;
}

impl<I> Numeric for ValueMutRefInput<'_, I>
where
    I: Numeric,
{
    fn flip_all_bits(&mut self) {
        self.deref_mut().flip_all_bits();
    }

    fn flip_bit_at(&mut self, rhs: usize) {
        self.deref_mut().flip_bit_at(rhs);
    }

    fn wrapping_inc(&mut self) {
        self.deref_mut().wrapping_inc();
    }

    fn wrapping_dec(&mut self) {
        self.deref_mut().wrapping_dec();
    }

    fn twos_complement(&mut self) {
        self.deref_mut().twos_complement();
    }

    fn randomize<R: Rand>(&mut self, rand: &mut R) {
        self.deref_mut().randomize(rand);
    }
}

#[cfg(test)]
mod tests {
    use super::{ValueInput, ValueMutRefInput};
    use crate::mutators::numeric::Numeric;

    fn take_numeric<I: Numeric + Clone>(i: I) {
        i.clone().flip_all_bits();
        i.clone().flip_bit_at(0);
        i.clone().flip_bit_at(size_of::<I>() * 8 - 1);
        i.clone().twos_complement();
        i.clone().wrapping_dec();
        i.clone().wrapping_inc();

        ValueInput::from(i.clone()).flip_all_bits();
        ValueInput::from(i.clone()).flip_bit_at(0);
        ValueInput::from(i.clone()).flip_bit_at(size_of::<I>() * 8 - 1);
        ValueInput::from(i.clone()).twos_complement();
        ValueInput::from(i.clone()).wrapping_dec();
        ValueInput::from(i.clone()).wrapping_inc();

        ValueMutRefInput::from(&mut i.clone()).flip_all_bits();
        ValueMutRefInput::from(&mut i.clone()).flip_bit_at(0);
        ValueMutRefInput::from(&mut i.clone()).flip_bit_at(size_of::<I>() * 8 - 1);
        ValueMutRefInput::from(&mut i.clone()).twos_complement();
        ValueMutRefInput::from(&mut i.clone()).wrapping_dec();
        ValueMutRefInput::from(&mut i.clone()).wrapping_inc();
        drop(i);
    }

    #[test]
    fn impls_at_extremes() {
        take_numeric(u8::MIN);
        take_numeric(u16::MIN);
        take_numeric(u32::MIN);
        take_numeric(u64::MIN);
        take_numeric(u128::MIN);
        take_numeric(usize::MIN);
        take_numeric(i8::MIN);
        take_numeric(i16::MIN);
        take_numeric(i32::MIN);
        take_numeric(i64::MIN);
        take_numeric(i128::MIN);
        take_numeric(isize::MIN);
        take_numeric(u8::MAX);
        take_numeric(u16::MAX);
        take_numeric(u32::MAX);
        take_numeric(u64::MAX);
        take_numeric(u128::MAX);
        take_numeric(usize::MAX);
        take_numeric(i8::MAX);
        take_numeric(i16::MAX);
        take_numeric(i32::MAX);
        take_numeric(i64::MAX);
        take_numeric(i128::MAX);
        take_numeric(isize::MAX);
    }
}
