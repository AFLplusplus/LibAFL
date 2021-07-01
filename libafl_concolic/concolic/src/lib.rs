use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;

pub type SymExprRef = NonZeroUsize;

#[derive(Serialize, Deserialize, Debug)]
pub enum SymExpr {
    GetInputByte {
        offset: usize,
    },

    BuildInteger {
        value: u64,
        bits: u8,
    },
    BuildInteger128 {
        high: u64,
        low: u64,
    },
    BuildFloat {
        value: f64,
        is_double: bool,
    },
    BuildNullPointer,
    BuildTrue,
    BuildFalse,
    BuildBool {
        value: bool,
    },

    BuildNeg {
        op: SymExprRef,
    },
    BuildAdd {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildSub {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildMul {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildUnsignedDiv {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildSignedDiv {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildUnsignedRem {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildSignedRem {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildShiftLeft {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildLogicalShiftRight {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildArithmeticShiftRight {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildSignedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildSignedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildSignedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildSignedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildUnsignedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildUnsignedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildUnsignedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildUnsignedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildNot {
        op: SymExprRef,
    },
    BuildEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildNotEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildBoolAnd {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildBoolOr {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildBoolXor {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildAnd {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildOr {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildXor {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildFloatOrdered {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatOrderedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatOrderedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatOrderedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatOrderedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatOrderedEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatOrderedNotEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildFloatUnordered {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatUnorderedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatUnorderedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatUnorderedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatUnorderedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatUnorderedEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatUnorderedNotEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildFloatAbs {
        op: SymExprRef,
    },
    BuildFloatAdd {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatSub {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatMul {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatDiv {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatRem {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildSext {
        op: SymExprRef,
        bits: u8,
    },
    BuildZext {
        op: SymExprRef,
        bits: u8,
    },
    BuildTrunc {
        op: SymExprRef,
        bits: u8,
    },
    BuildIntToFloat {
        op: SymExprRef,
        is_double: bool,
        is_signed: bool,
    },
    BuildFloatToFloat {
        op: SymExprRef,
        to_double: bool,
    },
    BuildBitsToFloat {
        op: SymExprRef,
        to_double: bool,
    },
    BuildFloatToBits {
        op: SymExprRef,
    },
    BuildFloatToSignedInteger {
        op: SymExprRef,
        bits: u8,
    },
    BuildFloatToUnsignedInteger {
        op: SymExprRef,
        bits: u8,
    },
    BuildBoolToBits {
        op: SymExprRef,
        bits: u8,
    },

    ConcatHelper {
        a: SymExprRef,
        b: SymExprRef,
    },
    ExtractHelper {
        op: SymExprRef,
        first_bit: usize,
        last_bit: usize,
    },
    BuildExtract {
        op: SymExprRef,
        offset: u64,
        length: u64,
        little_endian: bool,
    },
    BuildBswap {
        op: SymExprRef,
    },
    BuildInsert {
        target: SymExprRef,
        to_insert: SymExprRef,
        offset: u64,
        little_endian: bool
    },

    PushPathConstraint {
        constraint: SymExprRef,
        taken: bool,
        site_id: usize,
    },

    /// This marks the end of the trace.
    End,
}

pub mod serialization_format;

/// The environment name used to identify the hitmap for the concolic runtime.
pub const HITMAP_ENV_NAME: &str = "LIBAFL_CONCOLIC_HITMAP";

/// The name of the environment variable that contains the byte offsets to be symbolized.
pub const SELECTIVE_SYMBOLICATION_ENV_NAME: &str = "LIBAFL_SELECTIVE_SYMBOLICATION";