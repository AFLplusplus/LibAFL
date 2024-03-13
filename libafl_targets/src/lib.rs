//! `libafl_targets` contains runtime code, injected in the target itself during compilation.
#![no_std]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![cfg_attr(nightly, feature(portable_simd))]
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
    clippy::pub_underscore_fields
)]
#![cfg_attr(not(test), warn(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    //unused_results
))]
#![cfg_attr(test, deny(
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
    test,
    deny(
        bad_style,
        dead_code,
        improper_ctypes,
        non_shorthand_field_patterns,
        no_mangle_generic_items,
        overflowing_literals,
        path_statements,
        patterns_in_fns_without_body,
        unconditional_recursion,
        unused,
        unused_allocation,
        unused_comparisons,
        unused_parens,
        while_true
    )
)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;
#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

include!(concat!(env!("OUT_DIR"), "/constants.rs"));

#[cfg(any(
    feature = "sancov_pcguard_edges",
    feature = "sancov_pcguard_hitcounts",
    feature = "sancov_ngram4",
    feature = "sancov_ctx"
))]
pub mod sancov_pcguard;
#[cfg(any(
    feature = "sancov_pcguard_edges",
    feature = "sancov_pcguard_hitcounts",
    feature = "sancov_ngram4",
    feature = "sancov_ctx"
))]
pub use sancov_pcguard::*;

#[cfg(any(feature = "sancov_cmplog", feature = "sancov_value_profile"))]
pub mod sancov_cmp;
#[cfg(any(feature = "sancov_cmplog", feature = "sancov_value_profile"))]
pub use sancov_cmp::*;

/// Module containing bindings to the various sanitizer interface headers
#[cfg(feature = "sanitizer_interfaces")]
#[allow(clippy::mixed_attributes_style)]
pub mod sanitizer_ifaces {
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]
    #![allow(improper_ctypes)]
    #![allow(clippy::unreadable_literal)]
    #![allow(missing_docs)]
    #![allow(missing_debug_implementations)]
    #![allow(unused_qualifications)]
    include!(concat!(env!("OUT_DIR"), "/sanitizer_interfaces.rs"));
}

#[cfg(feature = "libfuzzer")]
pub mod libfuzzer;
#[cfg(feature = "libfuzzer")]
pub use libfuzzer::*;

#[cfg(feature = "sancov_8bit")]
pub mod sancov_8bit;
#[cfg(feature = "sancov_8bit")]
pub use sancov_8bit::*;

#[cfg(feature = "coverage")]
pub mod coverage;
#[cfg(feature = "coverage")]
pub use coverage::*;

pub mod value_profile;
pub use value_profile::*;

/// runtime related to comparisons
pub mod cmps;
pub use cmps::*;

#[cfg(feature = "std")]
pub mod drcov;

#[cfg(all(windows, feature = "std", feature = "windows_asan"))]
pub mod windows_asan;
#[cfg(all(windows, feature = "std", feature = "windows_asan"))]
pub use windows_asan::*;

#[cfg(all(unix, feature = "forkserver"))]
pub mod forkserver;
#[cfg(all(unix, feature = "forkserver"))]
pub use forkserver::*;
