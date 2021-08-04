use core::num::NonZeroUsize;

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

pub type SymExprRef = NonZeroUsize;

#[cfg(feature = "std")]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum SymExpr {
    InputByte {
        offset: usize,
    },

    Integer {
        value: u64,
        bits: u8,
    },
    Integer128 {
        high: u64,
        low: u64,
    },
    Float {
        value: f64,
        is_double: bool,
    },
    NullPointer,
    True,
    False,
    Bool {
        value: bool,
    },

    Neg {
        op: SymExprRef,
    },
    Add {
        a: SymExprRef,
        b: SymExprRef,
    },
    Sub {
        a: SymExprRef,
        b: SymExprRef,
    },
    Mul {
        a: SymExprRef,
        b: SymExprRef,
    },
    UnsignedDiv {
        a: SymExprRef,
        b: SymExprRef,
    },
    SignedDiv {
        a: SymExprRef,
        b: SymExprRef,
    },
    UnsignedRem {
        a: SymExprRef,
        b: SymExprRef,
    },
    SignedRem {
        a: SymExprRef,
        b: SymExprRef,
    },
    ShiftLeft {
        a: SymExprRef,
        b: SymExprRef,
    },
    LogicalShiftRight {
        a: SymExprRef,
        b: SymExprRef,
    },
    ArithmeticShiftRight {
        a: SymExprRef,
        b: SymExprRef,
    },

    SignedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    SignedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    SignedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    SignedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    UnsignedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    UnsignedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    UnsignedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    UnsignedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    Not {
        op: SymExprRef,
    },
    Equal {
        a: SymExprRef,
        b: SymExprRef,
    },
    NotEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    BoolAnd {
        a: SymExprRef,
        b: SymExprRef,
    },
    BoolOr {
        a: SymExprRef,
        b: SymExprRef,
    },
    BoolXor {
        a: SymExprRef,
        b: SymExprRef,
    },

    And {
        a: SymExprRef,
        b: SymExprRef,
    },
    Or {
        a: SymExprRef,
        b: SymExprRef,
    },
    Xor {
        a: SymExprRef,
        b: SymExprRef,
    },

    FloatOrdered {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatOrderedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatOrderedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatOrderedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatOrderedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatOrderedEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatOrderedNotEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    FloatUnordered {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatUnorderedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatUnorderedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatUnorderedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatUnorderedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatUnorderedEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatUnorderedNotEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    FloatAbs {
        op: SymExprRef,
    },
    FloatAdd {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatSub {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatMul {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatDiv {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatRem {
        a: SymExprRef,
        b: SymExprRef,
    },

    Sext {
        op: SymExprRef,
        bits: u8,
    },
    Zext {
        op: SymExprRef,
        bits: u8,
    },
    Trunc {
        op: SymExprRef,
        bits: u8,
    },
    IntToFloat {
        op: SymExprRef,
        is_double: bool,
        is_signed: bool,
    },
    FloatToFloat {
        op: SymExprRef,
        to_double: bool,
    },
    BitsToFloat {
        op: SymExprRef,
        to_double: bool,
    },
    FloatToBits {
        op: SymExprRef,
    },
    FloatToSignedInteger {
        op: SymExprRef,
        bits: u8,
    },
    FloatToUnsignedInteger {
        op: SymExprRef,
        bits: u8,
    },
    BoolToBits {
        op: SymExprRef,
        bits: u8,
    },

    Concat {
        a: SymExprRef,
        b: SymExprRef,
    },
    Extract {
        op: SymExprRef,
        first_bit: usize,
        last_bit: usize,
    },
    Insert {
        target: SymExprRef,
        to_insert: SymExprRef,
        offset: u64,
        little_endian: bool,
    },

    PathConstraint {
        constraint: SymExprRef,
        taken: bool,
        site_id: usize,
    },

    /// These expressions won't be referenced again
    ExpressionsUnreachable {
        exprs: Vec<SymExprRef>,
    },
}

#[cfg(feature = "std")]
pub mod serialization_format;

/// The environment name used to identify the hitmap for the concolic runtime.
pub const HITMAP_ENV_NAME: &str = "LIBAFL_CONCOLIC_HITMAP";

/// The name of the environment variable that contains the byte offsets to be symbolized.
pub const SELECTIVE_SYMBOLICATION_ENV_NAME: &str = "LIBAFL_SELECTIVE_SYMBOLICATION";

/// The name of the environment variable that contains the byte offsets to be symbolized.
pub const NO_FLOAT_ENV_NAME: &str = "LIBAFL_CONCOLIC_NO_FLOAT";

/// The name of the environment variable that contains the byte offsets to be symbolized.
pub const EXPRESSION_PRUNING: &str = "LIBAFL_CONCOLIC_EXPRESSION_PRUNING";

#[cfg(feature = "std")]
mod metadata;
#[cfg(feature = "std")]
pub use metadata::ConcolicMetadata;

#[cfg(feature = "std")]
mod observer;
#[cfg(feature = "std")]
pub use observer::ConcolicObserver;
