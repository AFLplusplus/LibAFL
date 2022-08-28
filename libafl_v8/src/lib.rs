//! libafl executors, observers, and other necessary components for fuzzing JavaScript targets.

// lints directly from main libafl
#![allow(incomplete_features)]
// For `type_eq`
#![cfg_attr(unstable_feature, feature(specialization))]
// For `type_id` and owned things
#![cfg_attr(unstable_feature, feature(intrinsics))]
// For `std::simd`
#![cfg_attr(unstable_feature, feature(portable_simd))]
#![warn(clippy::cargo)]
#![deny(clippy::cargo_common_metadata)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(
    clippy::unreadable_literal,
    clippy::type_repetition_in_bounds,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::used_underscore_binding,
    clippy::ptr_as_ptr,
    clippy::missing_panics_doc,
    clippy::missing_docs_in_private_items,
    clippy::module_name_repetitions,
    clippy::unreadable_literal
)]
#![cfg_attr(debug_assertions, warn(
missing_debug_implementations,
missing_docs,
//trivial_casts,
trivial_numeric_casts,
unused_extern_crates,
unused_import_braces,
unused_qualifications,
//unused_results
))]
#![cfg_attr(not(debug_assertions), deny(
missing_debug_implementations,
missing_docs,
//trivial_casts,
trivial_numeric_casts,
unused_extern_crates,
unused_import_braces,
unused_qualifications,
unused_must_use,
missing_docs,
//unused_results
))]
#![cfg_attr(
    not(debug_assertions),
    deny(
        bad_style,
        const_err,
        dead_code,
        improper_ctypes,
        non_shorthand_field_patterns,
        no_mangle_generic_items,
        overflowing_literals,
        path_statements,
        patterns_in_fns_without_body,
        private_in_public,
        unconditional_recursion,
        unused,
        unused_allocation,
        unused_comparisons,
        unused_parens,
        while_true
    )
)]
// Till they fix this buggy lint in clippy
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::borrow_deref_ref)]

pub mod executors;
pub mod loader;
pub mod observers;
pub mod values;

pub use deno_core::{self, v8};
pub use deno_runtime;
pub use executors::*;
pub use loader::*;
pub use observers::*;
pub use tokio::{runtime, sync::Mutex};
pub use values::*;

pub(crate) fn forbid_deserialization<T>() -> T {
    unimplemented!(
        "Deserialization is forbidden for this type; cannot cross a serialization boundary"
    )
}
