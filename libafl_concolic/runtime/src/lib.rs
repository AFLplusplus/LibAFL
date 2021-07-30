use std::{
    collections::{hash_map::DefaultHasher, HashSet},
    env,
    hash::BuildHasherDefault,
    io, slice,
};

#[cfg(not(test))]
use ctor::ctor;

use expression_filters::{
    coverage::{CallStackCoverage, HitmapFilter},
    AndOpt, ExpressionFilterExt, NoFloat, Nop, SelectiveSymbolication,
};
use libafl::{
    bolts::shmem::{ShMemProvider, StdShMemProvider},
    observers::concolic::{
        serialization_format::{self, shared_memory::StdShMemMessageFileWriter, MessageFileWriter},
        SymExpr, SymExprRef, EXPRESSION_PRUNING, HITMAP_ENV_NAME, NO_FLOAT_ENV_NAME,
        SELECTIVE_SYMBOLICATION_ENV_NAME,
    },
};

mod expression_filters;

use crate::expression_filters::ExpressionFilter;

pub struct Runtime<Filter: ExpressionFilter> {
    writer: StdShMemMessageFileWriter,
    filter: Filter,
}

type DefaultExpressionFilter = AndOpt<
    AndOpt<
        AndOpt<AndOpt<Nop, SelectiveSymbolication>, NoFloat>,
        CallStackCoverage<DefaultHasher, BuildHasherDefault<DefaultHasher>>,
    >,
    HitmapFilter<<StdShMemProvider as ShMemProvider>::Mem, BuildHasherDefault<DefaultHasher>>,
>;

impl Runtime<DefaultExpressionFilter> {
    fn parse_env_bool(env_name: &str) -> bool {
        env::var(env_name)
            .ok()
            .map(|str| str.is_empty() || str.trim() == "1")
            .unwrap_or_default()
    }

    #[allow(unused)]
    fn new() -> Self {
        let filter = Nop
            .and_optionally(
                env::var(SELECTIVE_SYMBOLICATION_ENV_NAME)
                    .ok()
                    .map(|str| {
                        str.split(',')
                            .map(|s| s.trim().parse::<usize>())
                            .collect::<Result<HashSet<usize>, _>>()
                            .expect("failed parsing selective symbolication arguments.")
                    })
                    .map(SelectiveSymbolication::new),
            )
            .and_optionally(Self::parse_env_bool(NO_FLOAT_ENV_NAME).then(|| NoFloat))
            .and_optionally(
                Self::parse_env_bool(EXPRESSION_PRUNING).then(CallStackCoverage::default),
            )
            .and_optionally(
                StdShMemProvider::new()
                    .unwrap()
                    .existing_from_env(HITMAP_ENV_NAME)
                    .ok()
                    .map(HitmapFilter::new),
            );

        let writer =
            MessageFileWriter::from_stdshmem_default_env().expect("unable to initialise writer");
        Self { writer, filter }
    }
}

impl<Filter: ExpressionFilter> Runtime<Filter> {
    /// Logs the message to the trace. This is a convenient place to debug the expressions if necessary.
    fn log_message(&mut self, message: SymExpr) -> Option<SymExprRef> {
        if self.filter.symbolize(&message) {
            match self.writer.write_message(message) {
                Ok(id) => Some(id),
                Err(err) => {
                    match &*err {
                        serialization_format::ErrorKind::Io(io_err) => match io_err.kind() {
                            io::ErrorKind::WriteZero => {
                                // our buffer is full. exit the process gracefully
                                std::process::exit(0)
                            }
                            _ => panic!("IO Error serializing message: {:?}", io_err),
                        },
                        e => panic!("Error serializing message: {}", e),
                    }
                }
            }
        } else {
            None
        }
    }

    fn notify_call(&mut self, location_id: usize) {
        self.filter.notify_call(location_id)
    }

    fn notify_return(&mut self, location_id: usize) {
        self.filter.notify_return(location_id)
    }

    fn notify_basic_block(&mut self, location_id: usize) {
        self.filter.notify_basic_block(location_id)
    }

    /// This is called at the end of the process, giving us the opprtunity to signal the end of the trace.
    #[allow(unused)]
    fn end(mut self) {
        self.log_message(SymExpr::End);
        self.writer
            .end()
            .expect("unable to end message file writer");
    }
}

// We are creating a piece of shared mutable state here for our runtime, which is used unsafely.
// The correct solution here would be to either use a mutex or have per-thread state,
// however, this is not really supported in SymCC yet.
// Therefore we make the assumption that there is only ever a single thread, which should
// mean that this is 'safe'.
static mut GLOBAL_DATA: Option<Runtime<DefaultExpressionFilter>> = None;

#[cfg(not(test))]
#[ctor]
fn init() {
    // See comment on GLOBAL_DATA declaration.
    unsafe {
        GLOBAL_DATA = Some(Runtime::new());
        libc::atexit(fini);
    }
}

#[cfg(not(test))]
/// [`libc::atexit`] handler
extern "C" fn fini() {
    // drops the global data object
    unsafe {
        if let Some(state) = GLOBAL_DATA.take() {
            state.end()
        }
    }
}

/// A little helper function that encapsulates access to the shared mutable state.
fn with_state<R>(cb: impl FnOnce(&mut Runtime<DefaultExpressionFilter>) -> R) -> R {
    use unchecked_unwrap::UncheckedUnwrap;
    let s = unsafe { GLOBAL_DATA.as_mut().unchecked_unwrap() };
    cb(s)
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn _rsym_push_path_constraint(
    constraint: Option<SymExprRef>,
    taken: bool,
    site_id: usize,
) {
    if let Some(constraint) = constraint {
        with_state(|s| {
            s.log_message(SymExpr::PushPathConstraint {
                constraint,
                taken,
                site_id,
            });
        })
    }
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn _rsym_expression_unreachable(
    expressions_ptr: *const SymExprRef,
    expressions_len: usize,
) {
    let slice = slice::from_raw_parts(expressions_ptr, expressions_len);
    with_state(|s| {
        s.log_message(SymExpr::ExpressionsUnreachable {
            exprs: slice.to_owned(),
        });
    })
}

// Call stack tracing
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn _rsym_notify_call(location_id: usize) {
    with_state(|s| s.notify_call(location_id))
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn _rsym_notify_ret(location_id: usize) {
    with_state(|s| s.notify_return(location_id))
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn _rsym_notify_basic_block(location_id: usize) {
    with_state(|s| s.notify_basic_block(location_id))
}

/// A macro to generate the boilerplate for declaring a runtime function for SymCC that simply logs the function call
/// according to [`concolic::SymExpr`].
macro_rules! expression_builder {
    ($c_name:ident ( $($param_name:ident : $param_type:ty $(=> $param_name2:ident ?)? ),+ ) => $message:ident) => {
        #[allow(clippy::missing_safety_doc)]
        #[no_mangle]
        pub unsafe extern "C" fn $c_name( $( $param_name : $param_type, )+ ) -> Option<SymExprRef> {
            with_state(|s| {
                s.log_message(SymExpr::$message { $($param_name $(: $param_name2?)? ,)+ })
            })
        }
    };
    ($c_name:ident ( ) => $message:ident) => {
        #[allow(clippy::missing_safety_doc)]
        #[no_mangle]
        pub unsafe extern "C" fn $c_name( ) -> Option<SymExprRef> {
            with_state(|s| {
                s.log_message(SymExpr::$message)
            })
        }
    };
}

expression_builder!(_rsym_get_input_byte(offset: usize) => GetInputByte);

expression_builder!(_rsym_build_integer(value: u64, bits: u8) => BuildInteger);
expression_builder!(_rsym_build_integer128(high: u64, low: u64) => BuildInteger128);
expression_builder!(_rsym_build_float(value: f64, is_double: bool) => BuildFloat);
expression_builder!(_rsym_build_null_pointer() => BuildNullPointer);
expression_builder!(_rsym_build_true() => BuildTrue);
expression_builder!(_rsym_build_false() => BuildFalse);
expression_builder!(_rsym_build_bool(value: bool) => BuildBool);

macro_rules! unary_expression_builder {
    ($c_name:ident, $message:ident) => {
        expression_builder!($c_name(op: Option<SymExprRef> => op?) => $message);
    };
}

macro_rules! binary_expression_builder {
    ($c_name:ident, $message:ident) => {
        expression_builder!($c_name(a: Option<SymExprRef> => a?, b: Option<SymExprRef> => b?) => $message);
    };
}

unary_expression_builder!(_rsym_build_neg, BuildNeg);

binary_expression_builder!(_rsym_build_add, BuildAdd);
binary_expression_builder!(_rsym_build_sub, BuildSub);
binary_expression_builder!(_rsym_build_mul, BuildMul);
binary_expression_builder!(_rsym_build_unsigned_div, BuildUnsignedDiv);
binary_expression_builder!(_rsym_build_signed_div, BuildSignedDiv);
binary_expression_builder!(_rsym_build_unsigned_rem, BuildUnsignedRem);
binary_expression_builder!(_rsym_build_signed_rem, BuildSignedRem);
binary_expression_builder!(_rsym_build_shift_left, BuildShiftLeft);
binary_expression_builder!(_rsym_build_logical_shift_right, BuildLogicalShiftRight);
binary_expression_builder!(
    _rsym_build_arithmetic_shift_right,
    BuildArithmeticShiftRight
);

binary_expression_builder!(_rsym_build_signed_less_than, BuildSignedLessThan);
binary_expression_builder!(_rsym_build_signed_less_equal, BuildSignedLessEqual);
binary_expression_builder!(_rsym_build_signed_greater_than, BuildSignedGreaterThan);
binary_expression_builder!(_rsym_build_signed_greater_equal, BuildSignedGreaterEqual);
binary_expression_builder!(_rsym_build_unsigned_less_than, BuildUnsignedLessThan);
binary_expression_builder!(_rsym_build_unsigned_less_equal, BuildUnsignedLessEqual);
binary_expression_builder!(_rsym_build_unsigned_greater_than, BuildUnsignedGreaterThan);
binary_expression_builder!(
    _rsym_build_unsigned_greater_equal,
    BuildUnsignedGreaterEqual
);

binary_expression_builder!(_rsym_build_and, BuildAnd);
binary_expression_builder!(_rsym_build_or, BuildOr);
binary_expression_builder!(_rsym_build_xor, BuildXor);

binary_expression_builder!(_rsym_build_float_ordered, BuildFloatOrdered);
binary_expression_builder!(
    _rsym_build_float_ordered_greater_than,
    BuildFloatOrderedGreaterThan
);
binary_expression_builder!(
    _rsym_build_float_ordered_greater_equal,
    BuildFloatOrderedGreaterEqual
);
binary_expression_builder!(
    _rsym_build_float_ordered_less_than,
    BuildFloatOrderedLessThan
);
binary_expression_builder!(
    _rsym_build_float_ordered_less_equal,
    BuildFloatOrderedLessEqual
);
binary_expression_builder!(_rsym_build_float_ordered_equal, BuildFloatOrderedEqual);
binary_expression_builder!(
    _rsym_build_float_ordered_not_equal,
    BuildFloatOrderedNotEqual
);

binary_expression_builder!(_rsym_build_float_unordered, BuildFloatUnordered);
binary_expression_builder!(
    _rsym_build_float_unordered_greater_than,
    BuildFloatUnorderedGreaterThan
);
binary_expression_builder!(
    _rsym_build_float_unordered_greater_equal,
    BuildFloatUnorderedGreaterEqual
);
binary_expression_builder!(
    _rsym_build_float_unordered_less_than,
    BuildFloatUnorderedLessThan
);
binary_expression_builder!(
    _rsym_build_float_unordered_less_equal,
    BuildFloatUnorderedLessEqual
);
binary_expression_builder!(_rsym_build_float_unordered_equal, BuildFloatUnorderedEqual);
binary_expression_builder!(
    _rsym_build_float_unordered_not_equal,
    BuildFloatUnorderedNotEqual
);

binary_expression_builder!(_rsym_build_fp_add, BuildFloatAdd);
binary_expression_builder!(_rsym_build_fp_sub, BuildFloatSub);
binary_expression_builder!(_rsym_build_fp_mul, BuildFloatMul);
binary_expression_builder!(_rsym_build_fp_div, BuildFloatDiv);
binary_expression_builder!(_rsym_build_fp_rem, BuildFloatRem);

unary_expression_builder!(_rsym_build_fp_abs, BuildFloatAbs);

unary_expression_builder!(_rsym_build_not, BuildNot);
binary_expression_builder!(_rsym_build_equal, BuildEqual);
binary_expression_builder!(_rsym_build_not_equal, BuildNotEqual);
binary_expression_builder!(_rsym_build_bool_and, BuildBoolAnd);
binary_expression_builder!(_rsym_build_bool_or, BuildBoolOr);
binary_expression_builder!(_rsym_build_bool_xor, BuildBoolXor);

expression_builder!(_rsym_build_sext(op: Option<SymExprRef> => op?, bits: u8) => BuildSext);
expression_builder!(_rsym_build_zext(op: Option<SymExprRef> => op?, bits: u8) => BuildZext);
expression_builder!(_rsym_build_trunc(op: Option<SymExprRef> => op?, bits: u8) => BuildTrunc);
expression_builder!(_rsym_build_int_to_float(op: Option<SymExprRef> => op?, is_double: bool, is_signed: bool) => BuildIntToFloat);
expression_builder!(_rsym_build_float_to_float(op: Option<SymExprRef> => op?, to_double: bool) => BuildFloatToFloat);
expression_builder!(_rsym_build_bits_to_float(op: Option<SymExprRef> => op?, to_double: bool) => BuildBitsToFloat);
expression_builder!(_rsym_build_float_to_bits(op: Option<SymExprRef> => op?) => BuildFloatToBits);
expression_builder!(_rsym_build_float_to_signed_integer(op: Option<SymExprRef> => op?, bits: u8) => BuildFloatToSignedInteger);
expression_builder!(_rsym_build_float_to_unsigned_integer(op: Option<SymExprRef> => op?, bits: u8) => BuildFloatToUnsignedInteger);
expression_builder!(_rsym_build_bool_to_bits(op: Option<SymExprRef> => op?, bits: u8) => BuildBoolToBits);

binary_expression_builder!(_rsym_concat_helper, ConcatHelper);
expression_builder!(_rsym_extract_helper(op: Option<SymExprRef> => op?, first_bit:usize, last_bit:usize) => ExtractHelper);
