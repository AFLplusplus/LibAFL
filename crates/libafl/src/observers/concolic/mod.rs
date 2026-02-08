//! # Concolic Tracing
#[cfg(feature = "std")]
use alloc::vec::Vec;
use core::{
    fmt::{Debug, Display, Error, Formatter},
    num::NonZeroUsize,
};

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

/// A `SymExprRef` identifies a [`SymExpr`] in a trace.
///
/// Reading a `SymExpr` from a trace will always also yield its
/// `SymExprRef`, which can be used later in the trace to identify the `SymExpr`.
/// It is also never zero, which allows for efficient use of `Option<SymExprRef>`.
///
/// In a trace, `SymExprRef`s are monotonically increasing and start at 1.
/// `SymExprRef`s are not valid across traces.
pub type SymExprRef = NonZeroUsize;

/// [`Location`]s are code locations encountered during concolic tracing
///
/// [`Location`]s are constructed from pointers, but not always in a meaningful way.
/// Therefore, a location is an opaque value that can only be compared against itself.
///
/// It is possible to get at the underlying value using [`Into::into`], should this restriction be too inflexible for your usecase.
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Location(usize);

impl Debug for Location {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        Debug::fmt(&self.0, f)
    }
}

impl Display for Location {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        Display::fmt(&self.0, f)
    }
}

impl From<Location> for usize {
    fn from(l: Location) -> Self {
        l.0
    }
}

impl From<usize> for Location {
    fn from(v: usize) -> Self {
        Self(v)
    }
}

/// `SymExpr` represents a message in the serialization format.
/// The messages in the format are a perfect mirror of the methods that are called on the runtime during execution.
#[cfg(feature = "std")]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum SymExpr {
    /// A byte from the input at a specific offset.
    InputByte {
        /// The offset in the input.
        offset: usize,
        /// The value of the byte.
        value: u8,
    },
    /// A constant integer value.
    Integer {
        /// The value.
        value: u64,
        /// The number of bits.
        bits: u8,
    },
    /// A constant 128-bit integer value.
    Integer128 {
        /// The high 64 bits.
        high: u64,
        /// The low 64 bits.
        low: u64,
    },
    /// An integer value derived from a buffer.
    IntegerFromBuffer {},
    /// A constant floating-point value.
    Float {
        /// The value.
        value: f64,
        /// Whether it is a double precision float.
        is_double: bool,
    },
    /// A null pointer constant.
    NullPointer,
    /// A true boolean constant.
    True,
    /// A false boolean constant.
    False,
    /// A boolean value.
    Bool {
        /// The value.
        value: bool,
    },

    /// Negation operation.
    Neg {
        /// The operand.
        op: SymExprRef,
    },
    /// Addition operation.
    Add {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Subtraction operation.
    Sub {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Multiplication operation.
    Mul {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Unsigned division operation.
    UnsignedDiv {
        /// The dividend.
        a: SymExprRef,
        /// The divisor.
        b: SymExprRef,
    },
    /// Signed division operation.
    SignedDiv {
        /// The dividend.
        a: SymExprRef,
        /// The divisor.
        b: SymExprRef,
    },
    /// Unsigned remainder operation.
    UnsignedRem {
        /// The dividend.
        a: SymExprRef,
        /// The divisor.
        b: SymExprRef,
    },
    /// Signed remainder operation.
    SignedRem {
        /// The dividend.
        a: SymExprRef,
        /// The divisor.
        b: SymExprRef,
    },
    /// Left shift operation.
    ShiftLeft {
        /// The value to shift.
        a: SymExprRef,
        /// The shift amount.
        b: SymExprRef,
    },
    /// Logical right shift operation.
    LogicalShiftRight {
        /// The value to shift.
        a: SymExprRef,
        /// The shift amount.
        b: SymExprRef,
    },
    /// Arithmetic right shift operation.
    ArithmeticShiftRight {
        /// The value to shift.
        a: SymExprRef,
        /// The shift amount.
        b: SymExprRef,
    },

    /// Signed less than comparison.
    SignedLessThan {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Signed less than or equal comparison.
    SignedLessEqual {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Signed greater than comparison.
    SignedGreaterThan {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Signed greater than or equal comparison.
    SignedGreaterEqual {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Unsigned less than comparison.
    UnsignedLessThan {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Unsigned less than or equal comparison.
    UnsignedLessEqual {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Unsigned greater than comparison.
    UnsignedGreaterThan {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Unsigned greater than or equal comparison.
    UnsignedGreaterEqual {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },

    /// Bitwise NOT operation.
    Not {
        /// The operand.
        op: SymExprRef,
    },
    /// Equality comparison.
    Equal {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Inequality comparison.
    NotEqual {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },

    /// Boolean AND operation.
    BoolAnd {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Boolean OR operation.
    BoolOr {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Boolean XOR operation.
    BoolXor {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },

    /// Bitwise AND operation.
    And {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Bitwise OR operation.
    Or {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Bitwise XOR operation.
    Xor {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },

    /// Ordered floating-point comparison.
    FloatOrdered {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Ordered floating-point greater than comparison.
    FloatOrderedGreaterThan {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Ordered floating-point greater than or equal comparison.
    FloatOrderedGreaterEqual {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Ordered floating-point less than comparison.
    FloatOrderedLessThan {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Ordered floating-point less than or equal comparison.
    FloatOrderedLessEqual {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Ordered floating-point equality comparison.
    FloatOrderedEqual {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Ordered floating-point inequality comparison.
    FloatOrderedNotEqual {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },

    /// Unordered floating-point comparison.
    FloatUnordered {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Unordered floating-point greater than comparison.
    FloatUnorderedGreaterThan {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Unordered floating-point greater than or equal comparison.
    FloatUnorderedGreaterEqual {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Unordered floating-point less than comparison.
    FloatUnorderedLessThan {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Unordered floating-point less than or equal comparison.
    FloatUnorderedLessEqual {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Unordered floating-point equality comparison.
    FloatUnorderedEqual {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Unordered floating-point inequality comparison.
    FloatUnorderedNotEqual {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Floating-point negation.
    FloatNeg {
        /// The operand.
        op: SymExprRef,
    },
    /// Floating-point absolute value.
    FloatAbs {
        /// The operand.
        op: SymExprRef,
    },
    /// Floating-point addition.
    FloatAdd {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Floating-point subtraction.
    FloatSub {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Floating-point multiplication.
    FloatMul {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Floating-point division.
    FloatDiv {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Floating-point remainder.
    FloatRem {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },

    /// If-then-else expression.
    Ite {
        /// The condition.
        cond: SymExprRef,
        /// The value if true.
        a: SymExprRef,
        /// The value if false.
        b: SymExprRef,
    },
    /// Sign extension.
    Sext {
        /// The operand.
        op: SymExprRef,
        /// The number of bits.
        bits: u8,
    },
    /// Zero extension.
    Zext {
        /// The operand.
        op: SymExprRef,
        /// The number of bits.
        bits: u8,
    },
    /// Truncation.
    Trunc {
        /// The operand.
        op: SymExprRef,
        /// The number of bits.
        bits: u8,
    },
    /// Integer to floating-point conversion.
    IntToFloat {
        /// The operand.
        op: SymExprRef,
        /// Whether the result is a double precision float.
        is_double: bool,
        /// Whether the input is signed.
        is_signed: bool,
    },
    /// Floating-point to floating-point conversion.
    FloatToFloat {
        /// The operand.
        op: SymExprRef,
        /// Whether the result is a double precision float.
        to_double: bool,
    },
    /// Bits to floating-point conversion.
    BitsToFloat {
        /// The operand.
        op: SymExprRef,
        /// Whether the result is a double precision float.
        to_double: bool,
    },
    /// Floating-point to bits conversion.
    FloatToBits {
        /// The operand.
        op: SymExprRef,
    },
    /// Floating-point to signed integer conversion.
    FloatToSignedInteger {
        /// The operand.
        op: SymExprRef,
        /// The number of bits.
        bits: u8,
    },
    /// Floating-point to unsigned integer conversion.
    FloatToUnsignedInteger {
        /// The operand.
        op: SymExprRef,
        /// The number of bits.
        bits: u8,
    },
    /// Boolean to bit conversion.
    BoolToBit {
        /// The operand.
        op: SymExprRef,
    },

    /// Concatenation.
    Concat {
        /// The first operand.
        a: SymExprRef,
        /// The second operand.
        b: SymExprRef,
    },
    /// Extraction of bits.
    Extract {
        /// The operand.
        op: SymExprRef,
        /// The first bit to extract.
        first_bit: usize,
        /// The last bit to extract.
        last_bit: usize,
    },
    /// Insertion of bits.
    Insert {
        /// The target.
        target: SymExprRef,
        /// The value to insert.
        to_insert: SymExprRef,
        /// The offset.
        offset: u64,
        /// Whether it is little endian.
        little_endian: bool,
    },

    /// A path constraint.
    PathConstraint {
        /// The constraint.
        constraint: SymExprRef,
        /// Whether the constraint was taken.
        taken: bool,
        /// The location.
        location: Location,
    },

    /// These expressions won't be referenced again
    ExpressionsUnreachable {
        /// The unreachable expressions.
        exprs: Vec<SymExprRef>,
    },

    /// Location information regarding a call. Tracing this information is optional.
    Call {
        /// The location.
        location: Location,
    },
    /// Location information regarding a return. Tracing this information is optional.
    Return {
        /// The location.
        location: Location,
    },
    /// Location information regarding a basic block. Tracing this information is optional.
    BasicBlock {
        /// The location.
        location: Location,
    },
}

#[cfg(feature = "std")]
/// Serialization format module
pub mod serialization_format;

/// The environment name used to identify the hitmap for the concolic runtime.
pub const HITMAP_ENV_NAME: &str = "LIBAFL_CONCOLIC_HITMAP";

/// The name of the environment variable that contains the byte offsets to be symbolized.
pub const SELECTIVE_SYMBOLICATION_ENV_NAME: &str = "LIBAFL_SELECTIVE_SYMBOLICATION";

/// The name of the environment variable that signals the runtime to concretize floating point operations.
pub const NO_FLOAT_ENV_NAME: &str = "LIBAFL_CONCOLIC_NO_FLOAT";

/// The name of the environment variable that signals the runtime to perform expression pruning.
pub const EXPRESSION_PRUNING: &str = "LIBAFL_CONCOLIC_EXPRESSION_PRUNING";

#[cfg(feature = "std")]
mod metadata;
#[cfg(feature = "std")]
pub use metadata::ConcolicMetadata;

#[cfg(feature = "std")]
mod observer;
#[cfg(feature = "std")]
pub use observer::ConcolicObserver;
