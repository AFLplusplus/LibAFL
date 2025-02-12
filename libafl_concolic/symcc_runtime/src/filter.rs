//! [`Filter`]s are ergonomic abstractions over [`Runtime`] that facilitate filtering expressions.

use std::collections::HashSet;

// required for the import the macro `invoke_macro_with_rust_runtime_exports` that is dynamically generated in build.rs
#[allow(clippy::wildcard_imports)]
use crate::*;

mod coverage;
pub use coverage::{CallStackCoverage, HitmapFilter};

// creates the method declaration and default implementations for the filter trait
macro_rules! rust_filter_function_declaration {
    // expression_unreachable is not supported for filters
    (pub fn expression_unreachable(expressions: *mut RSymExpr, num_elements: usize), $c_name:ident;) => {
    };

    // push_path_constraint is not caught by the following case (because it has not return value),
    // but still needs to return something
    (pub fn push_path_constraint($( $arg:ident : $type:ty ),*$(,)?), $c_name:ident;) => {
        #[allow(unused_variables)] // only unused for some macro invocations
        fn push_path_constraint(&mut self, $($arg : $type),*) -> bool {
            true
        }
    };

    (pub fn $name:ident($( $arg:ident : $type:ty ),*$(,)?) -> $ret:ty, $c_name:ident;) => {
        #[allow(unused_variables)] // only unused for some macro invocations
        fn $name(&mut self, $( $arg : $type),*) -> bool {true}
    };

    (pub fn $name:ident($( $arg:ident : $type:ty ),*$(,)?), $c_name:ident;) => {
        #[allow(unused_variables)] // only unused for some macro invocations
        fn $name(&mut self, $( $arg : $type),*) {}
    };
}

/// A [`Filter`] can decide for each expression whether the expression should be traced symbolically or be
/// concretized.
///
/// This allows us to implement filtering mechanisms that reduce the amount of traced expressions by
/// concretizing uninteresting expressions.
/// If a filter concretizes an expression that would have later been used as part of another expression that
/// is still symbolic, a concrete instead of a symbolic value is received.
///
/// The interface for a filter matches [`Runtime`] with all methods returning `bool` instead of returning [`Option<RSymExpr>`].
/// Returning `true` indicates that the expression should _continue_ to be processed.
/// Returning `false` indicates that the expression should _not_ be processed any further and its result should be _concretized_.
///
/// For example:
/// Suppose there are symbolic expressions `a` and `b`. Expression `a` is concretized, `b` is still symbolic. If an add
/// operation between `a` and `b` is encountered, it will receive `a`'s concrete value and `b` as a symbolic expression.
///
/// An expression filter also receives code locations (`visit_*` methods) as they are visited in between operations
/// and these code locations are typically used to decide whether an expression should be concretized.
///
/// ## How to use
/// To create your own filter, implement this trait for a new struct.
/// All methods of this trait have default implementations, so you can just implement those methods which you may want
/// to filter.
///
/// Use a [`FilterRuntime`] to compose your filter with a [`Runtime`].
/// ## Example
/// As an example, the following filter concretizes all variables (and, therefore, expressions based on these variables) that are not part of a predetermined set of variables.
/// It is also available to use as [`SelectiveSymbolication`].
/// ```no_run
/// # use symcc_runtime::filter::Filter;
/// # use std::collections::HashSet;
/// struct SelectiveSymbolication {
///     bytes_to_symbolize: HashSet<usize>,
/// }
///
/// impl Filter for SelectiveSymbolication {
///     fn get_input_byte(&mut self, offset: usize, value: u8) -> bool {
///         self.bytes_to_symbolize.contains(&offset)
///     }
///     // Note: No need to implement methods that we are not interested in!
/// }
/// ```
pub trait Filter {
    invoke_macro_with_rust_runtime_exports!(rust_filter_function_declaration;);
}

/// A `FilterRuntime` wraps a [`Runtime`] with a [`Filter`].
///
/// It applies the filter before passing expressions to the inner runtime.
/// It also implements [`Runtime`], allowing for composing multiple [`Filter`]'s in a chain.
#[expect(clippy::module_name_repetitions)]
pub struct FilterRuntime<F, RT> {
    filter: F,
    runtime: RT,
}

impl<F, RT> FilterRuntime<F, RT> {
    pub fn new(filter: F, runtime: RT) -> Self {
        Self { filter, runtime }
    }
}

macro_rules! rust_filter_function_implementation {
    (pub fn expression_unreachable(expressions: *mut RSymExpr, num_elements: usize), $c_name:ident;) => {
        fn expression_unreachable(&mut self, exprs: &[RSymExpr]) {
            self.runtime.expression_unreachable(exprs)
        }
    };

    (pub fn push_path_constraint($( $arg:ident : $type:ty ),*$(,)?), $c_name:ident;) => {
        fn push_path_constraint(&mut self, $($arg : $type),*) {
            if self.filter.push_path_constraint($($arg),*) {
                self.runtime.push_path_constraint($($arg),*)
            }
        }
    };

    (pub fn $name:ident($( $arg:ident : $type:ty ),*$(,)?) -> $ret:ty, $c_name:ident;) => {
        fn $name(&mut self, $($arg : $type),*) -> Option<$ret> {
            if self.filter.$name($($arg),*) {
                self.runtime.$name($($arg),*)
            } else {
                None
            }
        }
    };

    (pub fn $name:ident($( $arg:ident : $type:ty ),*$(,)?), $c_name:ident;) => {
        fn $name(&mut self, $( $arg : $type),*) {
            self.filter.$name($($arg),*);
            self.runtime.$name($($arg),*);
        }
    };
}

impl<F, RT> Runtime for FilterRuntime<F, RT>
where
    F: Filter,
    RT: Runtime,
{
    invoke_macro_with_rust_runtime_exports!(rust_filter_function_implementation;);
}

/// A [`Filter`] that concretizes all input byte expressions that are not included in a predetermined set of
/// of input byte offsets.
pub struct SelectiveSymbolication {
    bytes_to_symbolize: HashSet<usize>,
}

impl SelectiveSymbolication {
    #[must_use]
    pub fn new(offset: HashSet<usize>) -> Self {
        Self {
            bytes_to_symbolize: offset,
        }
    }
}

impl Filter for SelectiveSymbolication {
    fn get_input_byte(&mut self, offset: usize, _value: u8) -> bool {
        self.bytes_to_symbolize.contains(&offset)
    }
}

/// Concretizes all floating point operations.
pub struct NoFloat;

impl Filter for NoFloat {
    fn build_float(&mut self, _value: f64, _is_double: bool) -> bool {
        false
    }
    fn build_float_ordered(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_float_ordered_equal(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_float_ordered_greater_equal(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_float_ordered_greater_than(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_float_ordered_less_equal(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_float_ordered_less_than(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_float_ordered_not_equal(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_float_to_bits(&mut self, _expr: RSymExpr) -> bool {
        false
    }
    fn build_float_to_float(&mut self, _expr: RSymExpr, _to_double: bool) -> bool {
        false
    }
    fn build_float_to_signed_integer(&mut self, _expr: RSymExpr, _bits: u8) -> bool {
        false
    }
    fn build_float_to_unsigned_integer(&mut self, _expr: RSymExpr, _bits: u8) -> bool {
        false
    }
    fn build_float_unordered(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_float_unordered_equal(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_float_unordered_greater_equal(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_float_unordered_greater_than(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_float_unordered_less_equal(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_float_unordered_less_than(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_float_unordered_not_equal(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_int_to_float(&mut self, _value: RSymExpr, _is_double: bool, _is_signed: bool) -> bool {
        false
    }
    fn build_bits_to_float(&mut self, _expr: RSymExpr, _to_double: bool) -> bool {
        false
    }
    fn build_fp_abs(&mut self, _a: RSymExpr) -> bool {
        false
    }
    fn build_fp_add(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_fp_sub(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_fp_mul(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_fp_div(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_fp_rem(&mut self, _a: RSymExpr, _b: RSymExpr) -> bool {
        false
    }
    fn build_fp_neg(&mut self, _a: RSymExpr) -> bool {
        false
    }
}
