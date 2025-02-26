//! Tracing of expressions in a serialized form.
#![allow(no_mangle_generic_items)]

pub use libafl::observers::concolic::serialization_format::StdShMemMessageFileWriter;
use libafl::observers::concolic::SymExpr;
use libafl_bolts::shmem::ShMem;

use crate::{RSymExpr, Runtime};

/// Traces the expressions according to the format described in [`libafl::observers::concolic::serialization_format`].
///
/// The format can be read from elsewhere to perform processing of the expressions outside of the runtime.
pub struct TracingRuntime<SHM>
where
    SHM: ShMem,
{
    writer: StdShMemMessageFileWriter<SHM>,
    trace_locations: bool,
}

impl<SHM> TracingRuntime<SHM>
where
    SHM: ShMem,
{
    /// Creates the runtime, tracing using the given writer.
    /// When `trace_locations` is true, location information for calls, returns and basic blocks will also be part of the trace.
    /// Tracing location information can drastically increase trace size. It is therefore recommended to not active this if not needed.
    #[must_use]
    pub fn new(writer: StdShMemMessageFileWriter<SHM>, trace_locations: bool) -> Self {
        Self {
            writer,
            trace_locations,
        }
    }

    #[expect(clippy::unnecessary_wraps)]
    fn write_message(&mut self, message: SymExpr) -> Option<RSymExpr> {
        Some(self.writer.write_message(message).unwrap())
    }
}

/// A macro to generate the boilerplate for declaring a runtime function for `SymCC` that simply logs the function call
/// according to [`concolic::SymExpr`].
macro_rules! expression_builder {
    ($method_name:ident ( $($param_name:ident : $param_type:ty ),+ ) => $message:ident) => {
        // #[expect(clippy::missing_safety_doc)]
        #[unsafe(no_mangle)]
        fn $method_name(&mut self, $( $param_name : $param_type, )+ ) -> Option<RSymExpr> {
            self.write_message(SymExpr::$message { $($param_name,)+ })
        }
    };
    ($method_name:ident () => $message:ident) => {
        // #[expect(clippy::missing_safety_doc)]
        #[unsafe(no_mangle)]
        fn $method_name(&mut self) -> Option<RSymExpr> {
            self.write_message(SymExpr::$message)
        }
    };
}

macro_rules! unary_expression_builder {
    ($c_name:ident, $message:ident) => {
        expression_builder!($c_name(op: RSymExpr) => $message);
    };
}

macro_rules! binary_expression_builder {
    ($c_name:ident, $message:ident) => {
        expression_builder!($c_name(a: RSymExpr, b: RSymExpr) => $message);
    };
}

impl<SHM> Runtime for TracingRuntime<SHM>
where
    SHM: ShMem,
{
    #[unsafe(no_mangle)]
    fn build_integer_from_buffer(
        &mut self,
        _buffer: *mut core::ffi::c_void,
        _num_bits: core::ffi::c_uint,
    ) -> Option<RSymExpr> {
        // todo
        self.write_message(SymExpr::IntegerFromBuffer {})
    }

    expression_builder!(get_input_byte(offset: usize, value: u8) => InputByte);

    expression_builder!(build_integer(value: u64, bits: u8) => Integer);
    expression_builder!(build_integer128(high: u64, low: u64) => Integer128);
    expression_builder!(build_float(value: f64, is_double: bool) => Float);
    expression_builder!(build_null_pointer() => NullPointer);
    expression_builder!(build_true() => True);
    expression_builder!(build_false() => False);
    expression_builder!(build_bool(value: bool) => Bool);

    unary_expression_builder!(build_neg, Neg);

    binary_expression_builder!(build_add, Add);
    binary_expression_builder!(build_sub, Sub);
    binary_expression_builder!(build_mul, Mul);
    binary_expression_builder!(build_unsigned_div, UnsignedDiv);
    binary_expression_builder!(build_signed_div, SignedDiv);
    binary_expression_builder!(build_unsigned_rem, UnsignedRem);
    binary_expression_builder!(build_signed_rem, SignedRem);
    binary_expression_builder!(build_shift_left, ShiftLeft);
    binary_expression_builder!(build_logical_shift_right, LogicalShiftRight);
    binary_expression_builder!(build_arithmetic_shift_right, ArithmeticShiftRight);

    binary_expression_builder!(build_signed_less_than, SignedLessThan);
    binary_expression_builder!(build_signed_less_equal, SignedLessEqual);
    binary_expression_builder!(build_signed_greater_than, SignedGreaterThan);
    binary_expression_builder!(build_signed_greater_equal, SignedGreaterEqual);
    binary_expression_builder!(build_unsigned_less_than, UnsignedLessThan);
    binary_expression_builder!(build_unsigned_less_equal, UnsignedLessEqual);
    binary_expression_builder!(build_unsigned_greater_than, UnsignedGreaterThan);
    binary_expression_builder!(build_unsigned_greater_equal, UnsignedGreaterEqual);

    binary_expression_builder!(build_and, And);
    binary_expression_builder!(build_or, Or);
    binary_expression_builder!(build_xor, Xor);

    binary_expression_builder!(build_float_ordered, FloatOrdered);
    binary_expression_builder!(build_float_ordered_greater_than, FloatOrderedGreaterThan);
    binary_expression_builder!(build_float_ordered_greater_equal, FloatOrderedGreaterEqual);
    binary_expression_builder!(build_float_ordered_less_than, FloatOrderedLessThan);
    binary_expression_builder!(build_float_ordered_less_equal, FloatOrderedLessEqual);
    binary_expression_builder!(build_float_ordered_equal, FloatOrderedEqual);
    binary_expression_builder!(build_float_ordered_not_equal, FloatOrderedNotEqual);

    binary_expression_builder!(build_float_unordered, FloatUnordered);
    binary_expression_builder!(
        build_float_unordered_greater_than,
        FloatUnorderedGreaterThan
    );
    binary_expression_builder!(
        build_float_unordered_greater_equal,
        FloatUnorderedGreaterEqual
    );
    binary_expression_builder!(build_float_unordered_less_than, FloatUnorderedLessThan);
    binary_expression_builder!(build_float_unordered_less_equal, FloatUnorderedLessEqual);
    binary_expression_builder!(build_float_unordered_equal, FloatUnorderedEqual);
    binary_expression_builder!(build_float_unordered_not_equal, FloatUnorderedNotEqual);

    binary_expression_builder!(build_fp_add, FloatAdd);
    binary_expression_builder!(build_fp_sub, FloatSub);
    binary_expression_builder!(build_fp_mul, FloatMul);
    binary_expression_builder!(build_fp_div, FloatDiv);
    binary_expression_builder!(build_fp_rem, FloatRem);

    unary_expression_builder!(build_fp_abs, FloatAbs);
    unary_expression_builder!(build_fp_neg, FloatNeg);

    unary_expression_builder!(build_not, Not);
    binary_expression_builder!(build_equal, Equal);
    binary_expression_builder!(build_not_equal, NotEqual);
    binary_expression_builder!(build_bool_and, BoolAnd);
    binary_expression_builder!(build_bool_or, BoolOr);
    binary_expression_builder!(build_bool_xor, BoolXor);

    expression_builder!(build_ite(cond: RSymExpr, a: RSymExpr, b: RSymExpr) => Ite);
    expression_builder!(build_sext(op: RSymExpr, bits: u8) => Sext);
    expression_builder!(build_zext(op: RSymExpr, bits: u8) => Zext);
    expression_builder!(build_trunc(op: RSymExpr, bits: u8) => Trunc);
    expression_builder!(build_int_to_float(op: RSymExpr, is_double: bool, is_signed: bool) => IntToFloat);
    expression_builder!(build_float_to_float(op: RSymExpr, to_double: bool) => FloatToFloat);
    expression_builder!(build_bits_to_float(op: RSymExpr, to_double: bool) => BitsToFloat);
    expression_builder!(build_float_to_bits(op: RSymExpr) => FloatToBits);
    expression_builder!(build_float_to_signed_integer(op: RSymExpr, bits: u8) => FloatToSignedInteger);
    expression_builder!(build_float_to_unsigned_integer(op: RSymExpr, bits: u8) => FloatToUnsignedInteger);
    expression_builder!(build_bool_to_bit(op: RSymExpr) => BoolToBit);

    binary_expression_builder!(concat_helper, Concat);
    expression_builder!(extract_helper(op: RSymExpr, first_bit:usize, last_bit:usize) => Extract);

    fn notify_call(&mut self, site_id: usize) {
        if self.trace_locations {
            self.write_message(SymExpr::Call {
                location: site_id.into(),
            });
        }
    }

    fn notify_ret(&mut self, site_id: usize) {
        if self.trace_locations {
            self.write_message(SymExpr::Return {
                location: site_id.into(),
            });
        }
    }

    fn notify_basic_block(&mut self, site_id: usize) {
        if self.trace_locations {
            self.write_message(SymExpr::BasicBlock {
                location: site_id.into(),
            });
        }
    }

    fn expression_unreachable(&mut self, exprs: &[RSymExpr]) {
        self.write_message(SymExpr::ExpressionsUnreachable {
            exprs: exprs.to_owned(),
        });
    }

    fn push_path_constraint(&mut self, constraint: RSymExpr, taken: bool, site_id: usize) {
        self.write_message(SymExpr::PathConstraint {
            constraint,
            taken,
            location: site_id.into(),
        });
    }
}

impl<SHM> Drop for TracingRuntime<SHM>
where
    SHM: ShMem,
{
    fn drop(&mut self) {
        // manually end the writer to update the length prefix
        self.writer
            .update_trace_header()
            .expect("failed to shut down writer");
    }
}
