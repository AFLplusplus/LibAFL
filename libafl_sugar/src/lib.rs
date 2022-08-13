//! Sugar API to simplify the life of the naive user of `LibAFL`

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

pub mod inmemory;
pub use inmemory::InMemoryBytesCoverageSugar;

#[cfg(target_os = "linux")]
pub mod qemu;
#[cfg(target_os = "linux")]
pub use qemu::QemuBytesCoverageSugar;

#[cfg(target_family = "unix")]
pub mod forkserver;
#[cfg(target_family = "unix")]
pub use forkserver::ForkserverBytesCoverageSugar;

/// Default timeout for a run
pub const DEFAULT_TIMEOUT_SECS: u64 = 1200;
/// Default cache size for the corpus in memory.
/// Anything else will be on disk.
pub const CORPUS_CACHE_SIZE: usize = 4096;

#[cfg(feature = "python")]
use pyo3::prelude::*;

/// The sugar python module
#[cfg(feature = "python")]
#[pymodule]
#[pyo3(name = "libafl_sugar")]
pub fn python_module(py: Python, m: &PyModule) -> PyResult<()> {
    inmemory::pybind::register(py, m)?;
    #[cfg(target_os = "linux")]
    {
        qemu::pybind::register(py, m)?;
    }
    #[cfg(unix)]
    {
        forkserver::pybind::register(py, m)?;
    }
    Ok(())
}
