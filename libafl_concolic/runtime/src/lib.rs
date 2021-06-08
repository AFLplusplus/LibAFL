use ctor::{ctor, dtor};

use concolic::{Message, MessageFileWriter, SymExprRef, StdShMemMessageFileWriter};

struct State {
    writer: StdShMemMessageFileWriter,
}

impl State {
    fn new() -> Self {
        let writer = MessageFileWriter::new_from_stdshmem_env("SHARED_MEMORY_MESSAGES");
        Self { writer }
    }

    fn log_message(&mut self, message: Message) -> SymExprRef {
        self.writer.write_message(message)
    }

    fn unwrap(&self, expr: Option<SymExprRef>) -> SymExprRef {
        expr.unwrap()
    }
}

static mut GLOBAL_DATA: Option<State> = None;

#[ctor]
fn init() {
    unsafe { GLOBAL_DATA = Some(State::new()) }
}
#[dtor]
fn fini() {
    // drops the global data object
    unsafe { GLOBAL_DATA = None }
}

fn with_state<R>(cb: impl FnOnce(&mut State) -> R) -> R {
    use unchecked_unwrap::UncheckedUnwrap;
    let s = unsafe { GLOBAL_DATA.as_mut().unchecked_unwrap() };
    cb(s)
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn _sym_push_path_constraint(
    constraint: Option<SymExprRef>,
    taken: bool,
    site_id: usize,
) {
    with_state(|s| {
        s.log_message(Message::PushPathConstraint {
            constraint: constraint.unwrap(),
            taken,
            site_id,
        });
    })
}

macro_rules! expression_builder {
    ($c_name:ident ( $($param_name:ident : $param_type:ty $( => $param_expr:tt)? ),+ ) => $message:ident) => {
        #[allow(clippy::missing_safety_doc)]
        #[no_mangle]
        pub unsafe extern "C" fn $c_name( $( $param_name : $param_type, )+ ) -> SymExprRef {
            with_state(|s| {
                s.log_message(Message::$message { $($param_name $(: s.$param_expr($param_name))? ,)+ })
            })
        }
    };
    ($c_name:ident ( ) => $message:ident) => {
        #[allow(clippy::missing_safety_doc)]
        #[no_mangle]
        pub unsafe extern "C" fn $c_name( ) -> SymExprRef {
            with_state(|s| {
                s.log_message(Message::$message)
            })
        }
    };
}

expression_builder!(_sym_get_input_byte(offset: usize) => GetInputByte);

expression_builder!(_sym_build_integer(value: u64, bits: u8) => BuildInteger);
expression_builder!(_sym_build_integer128(high: u64, low: u64) => BuildInteger128);
expression_builder!(_sym_build_float(value: f64, is_double: bool) => BuildFloat);
expression_builder!(_sym_build_null_pointer() => BuildNullPointer);
expression_builder!(_sym_build_true() => BuildTrue);
expression_builder!(_sym_build_false() => BuildFalse);
expression_builder!(_sym_build_bool(value: bool) => BuildBool);

macro_rules! unary_expression_builder {
    ($c_name:ident, $message:ident) => {
        expression_builder!($c_name(op: Option<SymExprRef> => unwrap) => $message);
    };
}

macro_rules! binary_expression_builder {
    ($c_name:ident, $message:ident) => {
        expression_builder!($c_name(a: Option<SymExprRef> => unwrap, b: Option<SymExprRef> => unwrap) => $message);
    };
}

unary_expression_builder!(_sym_build_neg, BuildNeg);

binary_expression_builder!(_sym_build_add, BuildAdd);
binary_expression_builder!(_sym_build_sub, BuildSub);
binary_expression_builder!(_sym_build_mul, BuildMul);
binary_expression_builder!(_sym_build_unsigned_div, BuildUnsignedDiv);
binary_expression_builder!(_sym_build_signed_div, BuildSignedDiv);
binary_expression_builder!(_sym_build_unsigned_rem, BuildUnsignedRem);
binary_expression_builder!(_sym_build_signed_rem, BuildSignedRem);
binary_expression_builder!(_sym_build_shift_left, BuildShiftLeft);
binary_expression_builder!(_sym_build_logical_shift_right, BuildLogicalShiftRight);
binary_expression_builder!(_sym_build_arithmetic_shift_right, BuildArithmeticShiftRight);

binary_expression_builder!(_sym_build_signed_less_than, BuildSignedLessThan);
binary_expression_builder!(_sym_build_signed_less_equal, BuildSignedLessEqual);
binary_expression_builder!(_sym_build_signed_greater_than, BuildSignedGreaterThan);
binary_expression_builder!(_sym_build_signed_greater_equal, BuildSignedGreaterEqual);
binary_expression_builder!(_sym_build_unsigned_less_than, BuildUnsignedLessThan);
binary_expression_builder!(_sym_build_unsigned_less_equal, BuildUnsignedLessEqual);
binary_expression_builder!(_sym_build_unsigned_greater_than, BuildUnsignedGreaterThan);
binary_expression_builder!(_sym_build_unsigned_greater_equal, BuildUnsignedGreaterEqual);

binary_expression_builder!(_sym_build_and, BuildAnd);
binary_expression_builder!(_sym_build_or, BuildOr);
binary_expression_builder!(_sym_build_xor, BuildXor);

binary_expression_builder!(_sym_build_float_ordered, BuildFloatOrdered);
binary_expression_builder!(
    _sym_build_float_ordered_greater_than,
    BuildFloatOrderedGreaterThan
);
binary_expression_builder!(
    _sym_build_float_ordered_greater_equal,
    BuildFloatOrderedGreaterEqual
);
binary_expression_builder!(
    _sym_build_float_ordered_less_than,
    BuildFloatOrderedLessThan
);
binary_expression_builder!(
    _sym_build_float_ordered_less_equal,
    BuildFloatOrderedLessEqual
);
binary_expression_builder!(_sym_build_float_ordered_equal, BuildFloatOrderedEqual);
binary_expression_builder!(
    _sym_build_float_ordered_not_equal,
    BuildFloatOrderedNotEqual
);

binary_expression_builder!(_sym_build_float_unordered, BuildFloatUnordered);
binary_expression_builder!(
    _sym_build_float_unordered_greater_than,
    BuildFloatUnorderedGreaterThan
);
binary_expression_builder!(
    _sym_build_float_unordered_greater_equal,
    BuildFloatUnorderedGreaterEqual
);
binary_expression_builder!(
    _sym_build_float_unordered_less_than,
    BuildFloatUnorderedLessThan
);
binary_expression_builder!(
    _sym_build_float_unordered_less_equal,
    BuildFloatUnorderedLessEqual
);
binary_expression_builder!(_sym_build_float_unordered_equal, BuildFloatUnorderedEqual);
binary_expression_builder!(
    _sym_build_float_unordered_not_equal,
    BuildFloatUnorderedNotEqual
);

binary_expression_builder!(_sym_build_fp_add, BuildFloatAdd);
binary_expression_builder!(_sym_build_fp_sub, BuildFloatSub);
binary_expression_builder!(_sym_build_fp_mul, BuildFloatMul);
binary_expression_builder!(_sym_build_fp_div, BuildFloatDiv);
binary_expression_builder!(_sym_build_fp_rem, BuildFloatRem);

unary_expression_builder!(_sym_build_fp_abs, BuildFloatAbs);

unary_expression_builder!(_sym_build_not, BuildNot);
binary_expression_builder!(_sym_build_equal, BuildEqual);
binary_expression_builder!(_sym_build_not_equal, BuildNotEqual);
binary_expression_builder!(_sym_build_bool_and, BuildBoolAnd);
binary_expression_builder!(_sym_build_bool_or, BuildBoolOr);
binary_expression_builder!(_sym_build_bool_xor, BuildBoolXor);

expression_builder!(_sym_build_sext(op: Option<SymExprRef> => unwrap, bits: u8) => BuildSext);
expression_builder!(_sym_build_zext(op: Option<SymExprRef> => unwrap, bits: u8) => BuildZext);
expression_builder!(_sym_build_trunc(op: Option<SymExprRef> => unwrap, bits: u8) => BuildTrunc);
expression_builder!(_sym_build_int_to_float(op: Option<SymExprRef> => unwrap, is_double: bool, is_signed: bool) => BuildIntToFloat);
expression_builder!(_sym_build_float_to_float(op: Option<SymExprRef> => unwrap, to_double: bool) => BuildFloatToFloat);
expression_builder!(_sym_build_bits_to_float(op: Option<SymExprRef> => unwrap, to_double: bool) => BuildBitsToFloat);
expression_builder!(_sym_build_float_to_bits(op: Option<SymExprRef> => unwrap) => BuildFloatToBits);
expression_builder!(_sym_build_float_to_signed_integer(op: Option<SymExprRef> => unwrap, bits: u8) => BuildFloatToSignedInteger);
expression_builder!(_sym_build_float_to_unsigned_integer(op: Option<SymExprRef> => unwrap, bits: u8) => BuildFloatToUnsignedInteger);
expression_builder!(_sym_build_bool_to_bits(op: Option<SymExprRef> => unwrap, bits: u8) => BuildBoolToBits);

binary_expression_builder!(_sym_concat_helper, ConcatHelper);
expression_builder!(_sym_extract_helper(op: Option<SymExprRef> => unwrap, first_bit:usize, last_bit:usize) => ExtractHelper);
expression_builder!(_sym_build_extract(op: Option<SymExprRef> => unwrap, offset:u64, length:u64, little_endian:bool) => BuildExtract);
unary_expression_builder!(_sym_build_bswap, BuildBswap);
