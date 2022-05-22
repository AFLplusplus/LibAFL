/*!
Welcome to `LibAFL`
*/

#![allow(incomplete_features)]
#![no_std]
// For `type_eq`
#![cfg_attr(unstable_feature, feature(specialization))]
// For `type_id` and owned things
#![cfg_attr(unstable_feature, feature(intrinsics))]
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

#[cfg(feature = "std")]
#[macro_use]
extern crate std;
#[macro_use]
extern crate alloc;
#[macro_use]
extern crate static_assertions;
#[cfg(feature = "std")]
pub use ctor::ctor;

// Re-export derive(SerdeAny)
#[cfg(feature = "libafl_derive")]
#[allow(unused_imports)]
#[macro_use]
extern crate libafl_derive;
#[cfg(feature = "libafl_derive")]
#[doc(hidden)]
pub use libafl_derive::*;

pub mod bolts;
pub mod corpus;
pub mod events;
pub mod executors;
pub mod feedbacks;
pub mod generators;
pub mod inputs;
pub mod monitors;
pub mod mutators;
pub mod observers;
pub mod schedulers;
pub mod stages;
pub mod state;

pub mod fuzzer;
use alloc::string::{FromUtf8Error, String};
use core::{array::TryFromSliceError, fmt, num::ParseIntError, num::TryFromIntError};
pub use fuzzer::*;

#[cfg(feature = "std")]
use std::{env::VarError, io};

#[cfg(feature = "errors_backtrace")]
/// Error Backtrace type when `errors_backtrace` feature is enabled (== [`backtrace::Backtrace`])
pub type ErrorBacktrace = backtrace::Backtrace;

#[cfg(not(feature = "errors_backtrace"))]
#[derive(Debug, Default)]
/// Empty struct to use when `errors_backtrace` is disabled
pub struct ErrorBacktrace {}
#[cfg(not(feature = "errors_backtrace"))]
impl ErrorBacktrace {
    /// Nop
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(feature = "errors_backtrace")]
fn display_error_backtrace(f: &mut fmt::Formatter, err: &ErrorBacktrace) -> fmt::Result {
    write!(f, "\nBacktrace: {:?}", err)
}
#[cfg(not(feature = "errors_backtrace"))]
fn display_error_backtrace(_f: &mut fmt::Formatter, _err: &ErrorBacktrace) -> fmt::Result {
    fmt::Result::Ok(())
}

/// Main error struct for `LibAFL`
#[derive(Debug)]
pub enum Error {
    /// Serialization error
    Serialize(String, ErrorBacktrace),
    /// Compression error
    #[cfg(feature = "llmp_compression")]
    Compression(ErrorBacktrace),
    /// File related error
    #[cfg(feature = "std")]
    File(io::Error, ErrorBacktrace),
    /// Optional val was supposed to be set, but isn't.
    EmptyOptional(String, ErrorBacktrace),
    /// Key not in Map
    KeyNotFound(String, ErrorBacktrace),
    /// No elements in the current item
    Empty(String, ErrorBacktrace),
    /// End of iteration
    IteratorEnd(String, ErrorBacktrace),
    /// This is not supported (yet)
    NotImplemented(String, ErrorBacktrace),
    /// You're holding it wrong
    IllegalState(String, ErrorBacktrace),
    /// The argument passed to this method or function is not valid
    IllegalArgument(String, ErrorBacktrace),
    /// Shutting down, not really an error.
    ShuttingDown,
    /// Something else happened
    Unknown(String, ErrorBacktrace),
}

impl Error {
    /// Serialization error
    #[must_use]
    pub fn serialize<S>(arg: S) -> Self
    where
        S: Into<String>,
    {
        Error::Serialize(arg.into(), ErrorBacktrace::new())
    }
    #[cfg(feature = "llmp_compression")]
    /// Compression error
    #[must_use]
    pub fn compression() -> Self {
        Error::Compression(ErrorBacktrace::new())
    }
    #[cfg(feature = "std")]
    /// File related error
    #[must_use]
    pub fn file(arg: io::Error) -> Self {
        Error::File(arg, ErrorBacktrace::new())
    }
    /// Optional val was supposed to be set, but isn't.
    #[must_use]
    pub fn empty_optional<S>(arg: S) -> Self
    where
        S: Into<String>,
    {
        Error::EmptyOptional(arg.into(), ErrorBacktrace::new())
    }
    /// Key not in Map
    #[must_use]
    pub fn key_not_found<S>(arg: S) -> Self
    where
        S: Into<String>,
    {
        Error::KeyNotFound(arg.into(), ErrorBacktrace::new())
    }
    /// No elements in the current item
    #[must_use]
    pub fn empty<S>(arg: S) -> Self
    where
        S: Into<String>,
    {
        Error::Empty(arg.into(), ErrorBacktrace::new())
    }
    /// End of iteration
    #[must_use]
    pub fn iterator_end<S>(arg: S) -> Self
    where
        S: Into<String>,
    {
        Error::IteratorEnd(arg.into(), ErrorBacktrace::new())
    }
    /// This is not supported (yet)
    #[must_use]
    pub fn not_implemented<S>(arg: S) -> Self
    where
        S: Into<String>,
    {
        Error::NotImplemented(arg.into(), ErrorBacktrace::new())
    }
    /// You're holding it wrong
    #[must_use]
    pub fn illegal_state<S>(arg: S) -> Self
    where
        S: Into<String>,
    {
        Error::IllegalState(arg.into(), ErrorBacktrace::new())
    }
    /// The argument passed to this method or function is not valid
    #[must_use]
    pub fn illegal_argument<S>(arg: S) -> Self
    where
        S: Into<String>,
    {
        Error::IllegalArgument(arg.into(), ErrorBacktrace::new())
    }
    /// Shutting down, not really an error.
    #[must_use]
    pub fn shutting_down() -> Self {
        Error::ShuttingDown
    }
    /// Something else happened
    #[must_use]
    pub fn unknown<S>(arg: S) -> Self
    where
        S: Into<String>,
    {
        Error::Unknown(arg.into(), ErrorBacktrace::new())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Serialize(s, b) => {
                write!(f, "Error in Serialization: `{0}`", &s)?;
                display_error_backtrace(f, b)
            }
            #[cfg(feature = "llmp_compression")]
            Self::Compression(b) => {
                write!(f, "Error in decompression")?;
                display_error_backtrace(f, b)
            }
            #[cfg(feature = "std")]
            Self::File(err, b) => {
                write!(f, "File IO failed: {:?}", &err)?;
                display_error_backtrace(f, b)
            }
            Self::EmptyOptional(s, b) => {
                write!(f, "Optional value `{0}` was not set", &s)?;
                display_error_backtrace(f, b)
            }
            Self::KeyNotFound(s, b) => {
                write!(f, "Key `{0}` not in Corpus", &s)?;
                display_error_backtrace(f, b)
            }
            Self::Empty(s, b) => {
                write!(f, "No items in {0}", &s)?;
                display_error_backtrace(f, b)
            }
            Self::IteratorEnd(s, b) => {
                write!(f, "All elements have been processed in {0} iterator", &s)?;
                display_error_backtrace(f, b)
            }
            Self::NotImplemented(s, b) => {
                write!(f, "Not implemented: {0}", &s)?;
                display_error_backtrace(f, b)
            }
            Self::IllegalState(s, b) => {
                write!(f, "Illegal state: {0}", &s)?;
                display_error_backtrace(f, b)
            }
            Self::IllegalArgument(s, b) => {
                write!(f, "Illegal argument: {0}", &s)?;
                display_error_backtrace(f, b)
            }
            Self::ShuttingDown => write!(f, "Shutting down!"),
            Self::Unknown(s, b) => {
                write!(f, "Unknown error: {0}", &s)?;
                display_error_backtrace(f, b)
            }
        }
    }
}

/// Stringify the postcard serializer error
impl From<postcard::Error> for Error {
    fn from(err: postcard::Error) -> Self {
        Self::serialize(format!("{:?}", err))
    }
}

/// Stringify the json serializer error
#[cfg(feature = "std")]
impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::serialize(format!("{:?}", err))
    }
}

#[cfg(all(unix, feature = "std"))]
impl From<nix::Error> for Error {
    fn from(err: nix::Error) -> Self {
        Self::unknown(format!("Unix error: {:?}", err))
    }
}

/// Create an AFL Error from io Error
#[cfg(feature = "std")]
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::file(err)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Self {
        Self::unknown(format!("Could not convert byte / utf-8: {:?}", err))
    }
}

#[cfg(feature = "std")]
impl From<VarError> for Error {
    fn from(err: VarError) -> Self {
        Self::empty(format!("Could not get env var: {:?}", err))
    }
}

impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Self {
        Self::unknown(format!("Failed to parse Int: {:?}", err))
    }
}

impl From<TryFromIntError> for Error {
    fn from(err: TryFromIntError) -> Self {
        Self::illegal_state(format!("Expected conversion failed: {:?}", err))
    }
}

impl From<TryFromSliceError> for Error {
    fn from(err: TryFromSliceError) -> Self {
        Self::illegal_argument(format!("Could not convert slice: {:?}", err))
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

// TODO: no_std test
#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use crate::{
        bolts::{rands::StdRand, tuples::tuple_list},
        corpus::{Corpus, InMemoryCorpus, Testcase},
        executors::{ExitKind, InProcessExecutor},
        inputs::BytesInput,
        monitors::SimpleMonitor,
        mutators::{mutations::BitFlipMutator, StdScheduledMutator},
        schedulers::RandScheduler,
        stages::StdMutationalStage,
        state::{HasCorpus, StdState},
        Fuzzer, StdFuzzer,
    };

    #[cfg(feature = "std")]
    use crate::events::SimpleEventManager;

    #[test]
    #[allow(clippy::similar_names)]
    fn test_fuzzer() {
        let rand = StdRand::with_seed(0);

        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(vec![0; 4]);
        corpus.add(testcase).unwrap();

        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::<BytesInput>::new(),
            tuple_list!(),
        );

        let monitor = SimpleMonitor::new(|s| {
            println!("{}", s);
        });
        let mut event_manager = SimpleEventManager::new(monitor);

        let scheduler = RandScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, (), ());

        let mut harness = |_buf: &BytesInput| ExitKind::Ok;
        let mut executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(),
            &mut fuzzer,
            &mut state,
            &mut event_manager,
        )
        .unwrap();

        let mutator = StdScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        for i in 0..1000 {
            fuzzer
                .fuzz_one(&mut stages, &mut executor, &mut state, &mut event_manager)
                .unwrap_or_else(|_| panic!("Error in iter {}", i));
        }

        let state_serialized = postcard::to_allocvec(&state).unwrap();
        let state_deserialized: StdState<
            InMemoryCorpus<BytesInput>,
            (),
            BytesInput,
            StdRand,
            InMemoryCorpus<BytesInput>,
        > = postcard::from_bytes(state_serialized.as_slice()).unwrap();
        assert_eq!(state.corpus().count(), state_deserialized.corpus().count());

        let corpus_serialized = postcard::to_allocvec(state.corpus()).unwrap();
        let corpus_deserialized: InMemoryCorpus<BytesInput> =
            postcard::from_bytes(corpus_serialized.as_slice()).unwrap();
        assert_eq!(state.corpus().count(), corpus_deserialized.count());
    }
}

#[cfg(all(test, not(feature = "std")))]
/// Provide custom time in `no_std` tests.
#[no_mangle]
pub extern "C" fn external_current_millis() -> u64 {
    // TODO: use "real" time here
    1000
}

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pymodule]
#[pyo3(name = "libafl")]
/// Register the classes to the python module
pub fn python_module(py: Python, m: &PyModule) -> PyResult<()> {
    observers::map::pybind::register(py, m)?;
    feedbacks::map::pybind::register(py, m)?;
    state::pybind::register(py, m)?;
    monitors::pybind::register(py, m)?;
    events::pybind::register(py, m)?;
    events::simple::pybind::register(py, m)?;
    fuzzer::pybind::register(py, m)?;
    executors::pybind::register(py, m)?;
    executors::inprocess::pybind::register(py, m)?;
    generators::pybind::register(py, m)?;
    corpus::pybind::register(py, m)?;
    corpus::ondisk::pybind::register(py, m)?;
    corpus::inmemory::pybind::register(py, m)?;
    corpus::cached::pybind::register(py, m)?;
    bolts::rands::pybind::register(py, m)?;
    stages::pybind::register(py, m)?;
    stages::owned::pybind::register(py, m)?;
    stages::mutational::pybind::register(py, m)?;
    Ok(())
}
