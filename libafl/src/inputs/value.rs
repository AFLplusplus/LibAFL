//! Newtype pattern style wrapper for [`super::Input`]s

use alloc::{string::String, vec::Vec};
use core::{fmt::Debug, hash::Hash};

use libafl_bolts::{generic_hash_std, rands::Rand};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use {
    libafl_bolts::{fs::write_file_atomic, Error},
    std::{fs::File, io::Read, path::Path},
};

use super::Input;
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use {
        super::ValueInput, crate::mutators::numeric::Numeric, alloc::fmt::Debug,
        std::any::type_name,
    };

    #[cfg(feature = "std")]
    macro_rules! apply_all_ops {
        ($prep:stmt, $value:expr, $type:ty, $check_twos_complement:expr) => {{
            $prep
            let mut j = $value;
            j.flip_all_bits();
            $prep
            assert_ne!(j, $value, "{:?}.flip_all_bits() for {}", j, type_name::<$type>());

            $prep
            let mut j = $value;
            j.wrapping_inc();
            $prep
            assert_ne!(j, $value, "{:?}.wrapping_inc() for {}", j, type_name::<$type>());

            $prep
            let mut j = $value;
            j.wrapping_dec();
            $prep
            assert_ne!(j, $value, "{:?}.wrapping_dec() for {}", j, type_name::<$type>());

            $prep
            let mut j = $value;
            j.twos_complement();
            if $check_twos_complement {
                $prep
                assert_ne!(j, $value, "{:?}.twos_complement() for {}", j, type_name::<$type>());
            }

            $prep
            let mut j = $value;
            j.flip_bit_at(0);
            $prep
            assert_ne!(j, $value, "{:?}.flip_bit_at(0) for {}", j, type_name::<$type>());

            $prep
            let mut j = $value;
            j.flip_bit_at(size_of::<I>() * 8 - 1);
            $prep
            assert_ne!(j, $value, "{:?}.flip_bit_at({}) for {}", j, size_of::<I>() * 8 - 1, type_name::<$type>());
        }};
    }

    #[cfg(feature = "std")]
    #[expect(unused_mut)]
    fn take_numeric<I: Numeric + Clone + PartialEq + Debug>(i: &I, check_twos_complement: bool) {
        apply_all_ops!({}, i.clone(), I, check_twos_complement);
        apply_all_ops!(
            {},
            ValueInput::from(i.clone()),
            ValueInput<I>,
            check_twos_complement
        );
        apply_all_ops!(
            let mut i_clone = i.clone(),
            &mut i_clone,
            &mut I,
            check_twos_complement
        );
    }

    #[test]
    #[cfg(feature = "std")] // type detection for better error messages, running with std is sufficient
    fn compiles() {
        // twos complement doesn't change anything on the min value of numeric types
        take_numeric(&u8::MIN, false);
        take_numeric(&u16::MIN, false);
        take_numeric(&u32::MIN, false);
        take_numeric(&u64::MIN, false);
        take_numeric(&u128::MIN, false);
        take_numeric(&usize::MIN, false);
        take_numeric(&i8::MIN, false);
        take_numeric(&i16::MIN, false);
        take_numeric(&i32::MIN, false);
        take_numeric(&i64::MIN, false);
        take_numeric(&i128::MIN, false);
        take_numeric(&isize::MIN, false);
        take_numeric(&u8::MAX, true);
        take_numeric(&u16::MAX, true);
        take_numeric(&u32::MAX, true);
        take_numeric(&u64::MAX, true);
        take_numeric(&u128::MAX, true);
        take_numeric(&usize::MAX, true);
        take_numeric(&i8::MAX, true);
        take_numeric(&i16::MAX, true);
        take_numeric(&i32::MAX, true);
        take_numeric(&i64::MAX, true);
        take_numeric(&i128::MAX, true);
        take_numeric(&isize::MAX, true);
    }
}
