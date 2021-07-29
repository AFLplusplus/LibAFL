pub mod filter;
pub mod tracing;

#[doc(hidden)]
#[cfg(target_os = "linux")]
pub mod cpp_runtime {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[doc(hidden)]
pub use ctor::ctor;
#[doc(hidden)]
pub use libc::atexit;
#[doc(hidden)]
pub use unchecked_unwrap;

#[doc(hidden)]
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! export_c_symbol {
    (pub fn $name:ident($( $arg:ident : $type:ty ),*$(,)?) -> $ret:ty) => {
        use $crate::cpp_runtime::*;
        #[no_mangle]
        pub unsafe extern "C" fn $name($( $arg : $type),*) -> $ret {
            $crate::cpp_runtime::$name($( $arg ),*)
        }
    };
    (pub fn $name:ident($( $arg:ident : $type:ty ),* $(,)?)) => {
        $crate::export_c_symbol!(pub fn $name($( $arg : $type),*) -> ());
    }
}

#[cfg(target_os = "linux")]
include!(concat!(env!("OUT_DIR"), "/cpp_exports_macro.rs"));

include!(concat!(env!("OUT_DIR"), "/rust_exports_macro.rs"));

macro_rules! rust_runtime_function_declaration {
    (pub fn expression_unreachable(expressions: *mut RSymExpr, num_elements: usize), $c_name:ident;) => {
        fn expression_unreachable(&mut self, exprs: &[RSymExpr]);
    };

    (pub fn $name:ident($( $arg:ident : $type:ty ),*$(,)?)$( -> $ret:ty)?, $c_name:ident;) => {
        fn $name(&mut self, $( $arg : $type),*)$( -> Option<$ret>)?;
    };
}

pub type RSymExpr = concolic::SymExprRef;

pub trait Runtime {
    invoke_macro_with_rust_runtime_exports!(rust_runtime_function_declaration;);
}

#[doc(hidden)]
#[macro_export]
macro_rules! make_symexpr_optional {
    (RSymExpr) => {Option<RSymExpr>};
    ($($type:tt)+) => {$($type)+};
}

#[doc(hidden)]
#[macro_export]
macro_rules! unwrap_option {
    ($param_name:ident: RSymExpr) => {
        $param_name?
    };
    ($param_name:ident: $($type:tt)+) => {
        $param_name
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! export_rust_runtime_fn {
    (pub fn expression_unreachable(expressions: *mut RSymExpr, num_elements: usize), $c_name:ident; $rt_cb:path) => {
        #[allow(clippy::missing_safety_doc)]
        #[no_mangle]
        pub unsafe extern "C" fn _rsym_expression_unreachable(expressions: *mut RSymExpr, num_elements: usize) {
            let slice = core::slice::from_raw_parts(expressions, num_elements);
            $rt_cb(|rt| {
                rt.expression_unreachable(slice);
            })
        }
    };
    (pub fn push_path_constraint(constraint: RSymExpr, taken: bool, site_id: usize), $c_name:ident; $rt_cb:path) => {
        #[allow(clippy::missing_safety_doc)]
        #[no_mangle]
        pub unsafe extern "C" fn _rsym_push_path_constraint(constraint: Option<RSymExpr>, taken: bool, site_id: usize) {
            if let Some(constraint) = constraint {
                $rt_cb(|rt| {
                    rt.push_path_constraint(constraint, taken, site_id);
                })
            }
        }
    };
    (pub fn $name:ident($( $arg:ident : $(::)?$($type:ident)::+ ),*$(,)?)$( -> $($ret:ident)::+)?, $c_name:ident; $rt_cb:path) => {
        #[allow(clippy::missing_safety_doc)]
        #[no_mangle]
        pub unsafe extern "C" fn $c_name( $($arg: $crate::make_symexpr_optional!($($type)::+),)* )$( -> $crate::make_symexpr_optional!($($ret)::+))? {
            $rt_cb(|rt| {
                $(let $arg = $crate::unwrap_option!($arg: $($type)::+);)*
                rt.$name($($arg,)*)
            })
        }
    };
}

macro_rules! impl_nop_runtime_fn {
    (pub fn expression_unreachable(expressions: *mut RSymExpr, num_elements: usize), $c_name:ident;) => {
        #[allow(clippy::default_trait_access)]
        fn expression_unreachable(&mut self, _exprs: &[RSymExpr]) {std::default::Default::default()}
    };

    (pub fn $name:ident($( $arg:ident : $type:ty ),*$(,)?)$( -> $ret:ty)?, $c_name:ident;) => {
        #[allow(clippy::default_trait_access)]
        fn $name(&mut self, $( _ : $type),*)$( -> Option<$ret>)? {std::default::Default::default()}
    };
}

pub struct NopRuntime;

impl Runtime for NopRuntime {
    invoke_macro_with_rust_runtime_exports!(impl_nop_runtime_fn;);
}

#[macro_export]
macro_rules! export_runtime {
    ($filter_constructor:expr => $filter:ty ; $($constructor:expr => $rt:ty);+) => {
        export_runtime!(@final export_runtime!(@combine_constructor $filter_constructor; $($constructor);+) => export_runtime!(@combine_type $filter; $($rt);+));
    };

    ($constructor:expr => $rt:ty) => {
        export_runtime!(@final $constructor => $rt);
    };

    (@combine_constructor $filter_constructor:expr ; $($constructor:expr);+) => {
        $crate::filter::FilterRuntime::new($filter_constructor, export_runtime!(@combine_constructor $($constructor);+))
    };
    (@combine_constructor $constructor:expr) => {
        $constructor
    };

    (@combine_type $filter:ty ; $($rt:ty);+) => {
        $crate::filter::FilterRuntime<$filter, export_runtime!(@combine_type $($rt);+)>
    };
    (@combine_type $rt:ty) => {
        $rt
    };

    (@final $constructor:expr => $rt:ty) => {
        // We are creating a piece of shared mutable state here for our runtime, which is used unsafely.
        // The correct solution here would be to either use a mutex or have per-thread state,
        // however, this is not really supported in SymCC yet.
        // Therefore we make the assumption that there is only ever a single thread, which should
        // mean that this is 'safe'.
        static mut GLOBAL_DATA: Option<$rt> = None;

        #[cfg(not(test))]
        #[$crate::ctor]
        fn init() {
            // See comment on GLOBAL_DATA declaration.
            unsafe {
                GLOBAL_DATA = Some($constructor);
                $crate::atexit(fini);
            }
        }

        /// [`libc::atexit`] handler
        extern "C" fn fini() {
            // drops the global data object
            unsafe {
                if let Some(state) = GLOBAL_DATA.take() {
                }
            }
        }

        use $crate::RSymExpr;

        /// A little helper function that encapsulates access to the shared mutable state.
        fn with_state<R>(cb: impl FnOnce(&mut $rt) -> R) -> R {
            use $crate::unchecked_unwrap::UncheckedUnwrap;
            let s = unsafe { GLOBAL_DATA.as_mut().unchecked_unwrap() };
            cb(s)
        }

        $crate::invoke_macro_with_rust_runtime_exports!($crate::export_rust_runtime_fn;with_state);
        #[cfg(target_os="linux")]
        $crate::export_cpp_runtime_functions!();
    };
}
