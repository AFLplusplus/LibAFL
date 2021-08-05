pub use libafl::observers::concolic::{
    serialization_format::shared_memory::StdShMemMessageFileWriter, SymExpr,
};

use crate::{RSymExpr, Runtime};

pub struct TracingRuntime {
    writer: StdShMemMessageFileWriter,
}

impl TracingRuntime {
    #[must_use]
    pub fn new(writer: StdShMemMessageFileWriter) -> Self {
        Self { writer }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn write_message(&mut self, message: SymExpr) -> Option<RSymExpr> {
        Some(self.writer.write_message(message).unwrap())
    }
}

/// A macro to generate the boilerplate for declaring a runtime function for SymCC that simply logs the function call
/// according to [`concolic::SymExpr`].
macro_rules! expression_builder {
    ($method_name:ident ( $($param_name:ident : $param_type:ty ),+ ) => $message:ident) => {
        #[allow(clippy::missing_safety_doc)]
        #[no_mangle]
        fn $method_name(&mut self, $( $param_name : $param_type, )+ ) -> Option<RSymExpr> {
            self.write_message(SymExpr::$message { $($param_name,)+ })
        }
    };
    ($method_name:ident () => $message:ident) => {
        #[allow(clippy::missing_safety_doc)]
        #[no_mangle]
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

impl Runtime for TracingRuntime {
    expression_builder!(get_input_byte(offset: usize) => GetInputByte);

    expression_builder!(build_integer(value: u64, bits: u8) => BuildInteger);
    expression_builder!(build_integer128(high: u64, low: u64) => BuildInteger128);
    expression_builder!(build_float(value: f64, is_double: bool) => BuildFloat);
    expression_builder!(build_null_pointer() => BuildNullPointer);
    expression_builder!(build_true() => BuildTrue);
    expression_builder!(build_false() => BuildFalse);
    expression_builder!(build_bool(value: bool) => BuildBool);

    unary_expression_builder!(build_neg, BuildNeg);

    binary_expression_builder!(build_add, BuildAdd);
    binary_expression_builder!(build_sub, BuildSub);
    binary_expression_builder!(build_mul, BuildMul);
    binary_expression_builder!(build_unsigned_div, BuildUnsignedDiv);
    binary_expression_builder!(build_signed_div, BuildSignedDiv);
    binary_expression_builder!(build_unsigned_rem, BuildUnsignedRem);
    binary_expression_builder!(build_signed_rem, BuildSignedRem);
    binary_expression_builder!(build_shift_left, BuildShiftLeft);
    binary_expression_builder!(build_logical_shift_right, BuildLogicalShiftRight);
    binary_expression_builder!(build_arithmetic_shift_right, BuildArithmeticShiftRight);

    binary_expression_builder!(build_signed_less_than, BuildSignedLessThan);
    binary_expression_builder!(build_signed_less_equal, BuildSignedLessEqual);
    binary_expression_builder!(build_signed_greater_than, BuildSignedGreaterThan);
    binary_expression_builder!(build_signed_greater_equal, BuildSignedGreaterEqual);
    binary_expression_builder!(build_unsigned_less_than, BuildUnsignedLessThan);
    binary_expression_builder!(build_unsigned_less_equal, BuildUnsignedLessEqual);
    binary_expression_builder!(build_unsigned_greater_than, BuildUnsignedGreaterThan);
    binary_expression_builder!(build_unsigned_greater_equal, BuildUnsignedGreaterEqual);

    binary_expression_builder!(build_and, BuildAnd);
    binary_expression_builder!(build_or, BuildOr);
    binary_expression_builder!(build_xor, BuildXor);

    binary_expression_builder!(build_float_ordered, BuildFloatOrdered);
    binary_expression_builder!(
        build_float_ordered_greater_than,
        BuildFloatOrderedGreaterThan
    );
    binary_expression_builder!(
        build_float_ordered_greater_equal,
        BuildFloatOrderedGreaterEqual
    );
    binary_expression_builder!(build_float_ordered_less_than, BuildFloatOrderedLessThan);
    binary_expression_builder!(build_float_ordered_less_equal, BuildFloatOrderedLessEqual);
    binary_expression_builder!(build_float_ordered_equal, BuildFloatOrderedEqual);
    binary_expression_builder!(build_float_ordered_not_equal, BuildFloatOrderedNotEqual);

    binary_expression_builder!(build_float_unordered, BuildFloatUnordered);
    binary_expression_builder!(
        build_float_unordered_greater_than,
        BuildFloatUnorderedGreaterThan
    );
    binary_expression_builder!(
        build_float_unordered_greater_equal,
        BuildFloatUnorderedGreaterEqual
    );
    binary_expression_builder!(build_float_unordered_less_than, BuildFloatUnorderedLessThan);
    binary_expression_builder!(
        build_float_unordered_less_equal,
        BuildFloatUnorderedLessEqual
    );
    binary_expression_builder!(build_float_unordered_equal, BuildFloatUnorderedEqual);
    binary_expression_builder!(build_float_unordered_not_equal, BuildFloatUnorderedNotEqual);

    binary_expression_builder!(build_fp_add, BuildFloatAdd);
    binary_expression_builder!(build_fp_sub, BuildFloatSub);
    binary_expression_builder!(build_fp_mul, BuildFloatMul);
    binary_expression_builder!(build_fp_div, BuildFloatDiv);
    binary_expression_builder!(build_fp_rem, BuildFloatRem);

    unary_expression_builder!(build_fp_abs, BuildFloatAbs);

    unary_expression_builder!(build_not, BuildNot);
    binary_expression_builder!(build_equal, BuildEqual);
    binary_expression_builder!(build_not_equal, BuildNotEqual);
    binary_expression_builder!(build_bool_and, BuildBoolAnd);
    binary_expression_builder!(build_bool_or, BuildBoolOr);
    binary_expression_builder!(build_bool_xor, BuildBoolXor);

    expression_builder!(build_sext(op: RSymExpr, bits: u8) => BuildSext);
    expression_builder!(build_zext(op: RSymExpr, bits: u8) => BuildZext);
    expression_builder!(build_trunc(op: RSymExpr, bits: u8) => BuildTrunc);
    expression_builder!(build_int_to_float(op: RSymExpr, is_double: bool, is_signed: bool) => BuildIntToFloat);
    expression_builder!(build_float_to_float(op: RSymExpr, to_double: bool) => BuildFloatToFloat);
    expression_builder!(build_bits_to_float(op: RSymExpr, to_double: bool) => BuildBitsToFloat);
    expression_builder!(build_float_to_bits(op: RSymExpr) => BuildFloatToBits);
    expression_builder!(build_float_to_signed_integer(op: RSymExpr, bits: u8) => BuildFloatToSignedInteger);
    expression_builder!(build_float_to_unsigned_integer(op: RSymExpr, bits: u8) => BuildFloatToUnsignedInteger);
    expression_builder!(build_bool_to_bits(op: RSymExpr, bits: u8) => BuildBoolToBits);

    binary_expression_builder!(concat_helper, ConcatHelper);
    expression_builder!(extract_helper(op: RSymExpr, first_bit:usize, last_bit:usize) => ExtractHelper);

    fn notify_call(&mut self, _site_id: usize) {}

    fn notify_ret(&mut self, _site_id: usize) {}

    fn notify_basic_block(&mut self, _site_id: usize) {}

    fn expression_unreachable(&mut self, exprs: &[RSymExpr]) {
        self.write_message(SymExpr::ExpressionsUnreachable {
            exprs: exprs.to_owned(),
        });
    }

    fn push_path_constraint(&mut self, constraint: RSymExpr, taken: bool, site_id: usize) {
        self.write_message(SymExpr::PushPathConstraint {
            constraint,
            taken,
            site_id,
        });
    }
}

impl Drop for TracingRuntime {
    fn drop(&mut self) {
        self.writer.end().expect("failed to shut down writer");
    }
}
