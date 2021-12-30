/*!
Welcome to `LibAFL`
*/

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "RUSTC_IS_NIGHTLY", feature(min_specialization))]
#![deny(rustdoc::broken_intra_doc_links)]
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
#![deny(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    //unused_results
)]

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
pub mod stages;
pub mod state;

pub mod fuzzer;
pub use fuzzer::*;

/// The `stats` module got renamed to [`monitors`].
/// It monitors and displays the statistics of the fuzzing process.
#[deprecated(since = "0.7.0", note = "The `stats` module got renamed to `monitors`")]
pub mod stats {
    #[deprecated(
        since = "0.7.0",
        note = "Use monitors::MultiMonitor instead of stats::MultiStats!"
    )]
    pub use crate::monitors::MultiMonitor as MultiStats;
    #[deprecated(
        since = "0.7.0",
        note = "Use monitors::SimpleMonitor instead of stats::SimpleStats!"
    )]
    pub use crate::monitors::SimpleMonitor as SimpleStats;
    #[deprecated(
        since = "0.7.0",
        note = "Use monitors::UserMonitor instead of stats::SimpleStats!"
    )]
    pub use crate::monitors::UserStats;
}

use alloc::string::String;
use core::fmt;

#[cfg(feature = "std")]
use std::{env::VarError, io, num::ParseIntError, num::TryFromIntError, string::FromUtf8Error};

/// Main error struct for AFL
#[derive(Debug)]
pub enum Error {
    /// Serialization error
    Serialize(String),
    /// Compression error
    #[cfg(feature = "llmp_compression")]
    Compression,
    /// File related error
    #[cfg(feature = "std")]
    File(io::Error),
    /// Optional val was supposed to be set, but isn't.
    EmptyOptional(String),
    /// Key not in Map
    KeyNotFound(String),
    /// No elements in the current item
    Empty(String),
    /// End of iteration
    IteratorEnd(String),
    /// This is not supported (yet)
    NotImplemented(String),
    /// You're holding it wrong
    IllegalState(String),
    /// The argument passed to this method or function is not valid
    IllegalArgument(String),
    /// Forkserver related Error
    Forkserver(String),
    /// MOpt related Error
    MOpt(String),
    /// Shutting down, not really an error.
    ShuttingDown,
    /// Something else happened
    Unknown(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Serialize(s) => write!(f, "Error in Serialization: `{0}`", &s),
            #[cfg(feature = "llmp_compression")]
            Self::Compression => write!(f, "Error in decompression"),
            #[cfg(feature = "std")]
            Self::File(err) => write!(f, "File IO failed: {:?}", &err),
            Self::EmptyOptional(s) => write!(f, "Optional value `{0}` was not set", &s),
            Self::KeyNotFound(s) => write!(f, "Key `{0}` not in Corpus", &s),
            Self::Empty(s) => write!(f, "No items in {0}", &s),
            Self::IteratorEnd(s) => {
                write!(f, "All elements have been processed in {0} iterator", &s)
            }
            Self::NotImplemented(s) => write!(f, "Not implemented: {0}", &s),
            Self::IllegalState(s) => write!(f, "Illegal state: {0}", &s),
            Self::IllegalArgument(s) => write!(f, "Illegal argument: {0}", &s),
            Self::Forkserver(s) => write!(f, "Forkserver : {0}", &s),
            Self::MOpt(s) => write!(f, "MOpt: {0}", &s),
            Self::ShuttingDown => write!(f, "Shutting down!"),
            Self::Unknown(s) => write!(f, "Unknown error: {0}", &s),
        }
    }
}

/// Stringify the postcard serializer error
impl From<postcard::Error> for Error {
    fn from(err: postcard::Error) -> Self {
        Self::Serialize(format!("{:?}", err))
    }
}

/// Stringify the json serializer error
#[cfg(feature = "std")]
impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialize(format!("{:?}", err))
    }
}

#[cfg(all(unix, feature = "std"))]
impl From<nix::Error> for Error {
    fn from(err: nix::Error) -> Self {
        Self::Unknown(format!("{:?}", err))
    }
}

/// Create an AFL Error from io Error
#[cfg(feature = "std")]
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::File(err)
    }
}

#[cfg(feature = "std")]
impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Self {
        Self::Unknown(format!("Could not convert byte to utf-8: {:?}", err))
    }
}

#[cfg(feature = "std")]
impl From<VarError> for Error {
    fn from(err: VarError) -> Self {
        Self::Empty(format!("Could not get env var: {:?}", err))
    }
}

#[cfg(feature = "std")]
impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Self {
        Self::Unknown(format!("Failed to parse Int: {:?}", err))
    }
}

#[cfg(feature = "std")]
impl From<TryFromIntError> for Error {
    fn from(err: TryFromIntError) -> Self {
        Self::IllegalState(format!("Expected conversion failed: {:?}", err))
    }
}

// TODO: no_std test
#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use crate::{
        bolts::{rands::StdRand, tuples::tuple_list},
        corpus::{Corpus, InMemoryCorpus, RandCorpusScheduler, Testcase},
        executors::{ExitKind, InProcessExecutor},
        inputs::BytesInput,
        monitors::SimpleMonitor,
        mutators::{mutations::BitFlipMutator, StdScheduledMutator},
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

        let scheduler = RandCorpusScheduler::new();
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
