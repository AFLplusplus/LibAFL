//! Sugar API to simplify the life of users of `LibAFL` that just want to fuzz.
/*! */
#![cfg_attr(feature = "document-features", doc = document_features::document_features!())]
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
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_must_use,
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
pub fn python_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    inmemory::pybind::register(m)?;
    #[cfg(target_os = "linux")]
    {
        qemu::pybind::register(m)?;
    }
    #[cfg(unix)]
    {
        forkserver::pybind::register(m)?;
    }
    Ok(())
}
