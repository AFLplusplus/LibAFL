//! Newtype pattern style wrapper for [`super::Input`]s

use alloc::{string::String, vec::Vec};
use core::{
    fmt::Debug,
    ops::{Add, BitOrAssign, BitXorAssign, Mul, Not, Shl, Sub},
};

use ahash::RandomState;
use num_traits::{One, WrappingAdd, WrappingSub, Zero};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use {
    libafl_bolts::{fs::write_file_atomic, Error},
    std::{fs::File, io::Read, path::Path},
};

use super::{Input, MappedInput};
use crate::corpus::CorpusId;

/// Newtype pattern wrapper around an underlying structure to implement inputs
///
/// This does not blanket implement [`super::Input`], because for certain inputs, writing them to disk does not make sense, because they don't own their data (like [`super::MutVecInput`])
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappingInput<I>(I);

impl<I> From<I> for WrappingInput<I> {
    fn from(value: I) -> Self {
        Self(value)
    }
}

impl<I> WrappingInput<I> {
    /// Create a new [`WrappingInput`]
    pub const fn new(value: I) -> Self {
        Self(value)
    }

    /// Extract the inner value
    pub fn inner(self) -> I {
        self.0
    }
}

impl<I> AsRef<I> for WrappingInput<I> {
    fn as_ref(&self) -> &I {
        &self.0
    }
}

impl<I> AsMut<I> for WrappingInput<I> {
    fn as_mut(&mut self) -> &mut I {
        &mut self.0
    }
}

impl<I> MappedInput for WrappingInput<&mut I> {
    type Type<'a>
        = WrappingInput<&'a mut I>
    where
        Self: 'a;
}

// Macro to implement the `Input` trait and create type aliases for `WrappingInput<T>`
macro_rules! impl_input_for_wrapping_input {
    ($($t:ty => $name:ident),+ $(,)?) => {
        $(
            impl Input for WrappingInput<$t> {
                fn generate_name(&self, _id: Option<CorpusId>) -> String {
                    format!(
                        "{:016x}",
                        RandomState::with_seeds(0, 0, 0, 0).hash_one(self.as_ref())
                    )
                }
            }

            /// Input wrapping a <$t>
            pub type $name = WrappingInput<$t>;
        )*
    };
}

// Invoke the macro with type-name pairs
impl_input_for_wrapping_input!(
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
impl Input for WrappingInput<Vec<u8>> {
    fn generate_name(&self, _id: Option<CorpusId>) -> String {
        format!(
            "{:016x}",
            RandomState::with_seeds(0, 0, 0, 0).hash_one(self.as_ref())
        )
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

/// Constants for numeric types
pub trait NumericConsts {
    /// The number of bits, used for limiting shift operations
    const BITS: u32;
    /// The min value
    const MIN: Self;
    /// The max value
    const MAX: Self;
}

macro_rules! impl_numeric_consts {
    ( $( $t:ty ),* $(,)? ) => {
        $(
            impl NumericConsts for $t {
                const BITS: u32 = <$t>::BITS;
                const MIN: Self = <$t>::MIN;
                const MAX: Self = <$t>::MAX;
            }
        )*
    };
}

impl_numeric_consts!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

impl<I, R> Shl<R> for WrappingInput<I>
where
    I: Shl<R>,
    I::Output: Into<Self>,
{
    type Output = Self;

    fn shl(self, rhs: R) -> Self::Output {
        self.inner().shl(rhs).into()
    }
}

impl<I> BitXorAssign for WrappingInput<I>
where
    I: BitXorAssign,
{
    fn bitxor_assign(&mut self, rhs: Self) {
        self.as_mut().bitxor_assign(rhs.inner());
    }
}
impl<I> BitOrAssign for WrappingInput<I>
where
    I: BitOrAssign,
{
    fn bitor_assign(&mut self, rhs: Self) {
        self.as_mut().bitor_assign(rhs.inner());
    }
}

impl<I> NumericConsts for WrappingInput<I>
where
    I: NumericConsts,
{
    const BITS: u32 = I::BITS;
    const MIN: Self = WrappingInput::new(I::MIN);
    const MAX: Self = WrappingInput::new(I::MAX);
}

impl<I> One for WrappingInput<I>
where
    I: One + Mul,
{
    fn one() -> Self {
        I::one().into()
    }
}

impl<I> Mul for WrappingInput<I>
where
    I: Mul,
    I::Output: Into<Self>,
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.inner().mul(rhs.inner()).into()
    }
}

impl<I> Zero for WrappingInput<I>
where
    I: Zero + Into<Self>,
{
    fn zero() -> Self {
        I::zero().into()
    }

    fn is_zero(&self) -> bool {
        self.as_ref().is_zero()
    }
}

impl<I> WrappingAdd for WrappingInput<I>
where
    I: WrappingAdd,
    I::Output: Into<Self>,
{
    fn wrapping_add(&self, v: &Self) -> Self {
        self.as_ref().wrapping_add(v.as_ref()).into()
    }
}

impl<I> Add for WrappingInput<I>
where
    I: Add,
    I::Output: Into<Self>,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.inner().add(rhs.inner()).into()
    }
}
impl<I> WrappingSub for WrappingInput<I>
where
    I: WrappingSub,
    I::Output: Into<Self>,
{
    fn wrapping_sub(&self, v: &Self) -> Self {
        self.as_ref().wrapping_sub(v.as_ref()).into()
    }
}

impl<I> Sub for WrappingInput<I>
where
    I: Sub,
    I::Output: Into<Self>,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.inner().sub(rhs.inner()).into()
    }
}

impl<I> Not for WrappingInput<I>
where
    I: Not,
    I::Output: Into<Self>,
{
    type Output = Self;

    fn not(self) -> Self::Output {
        self.inner().not().into()
    }
}

impl<I> Copy for WrappingInput<I> where I: Copy {}
