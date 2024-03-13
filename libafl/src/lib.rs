/*!
Welcome to `LibAFL`
*/
#![doc = include_str!("../README.md")]
/*! */
#![cfg_attr(feature = "document-features", doc = document_features::document_features!())]
#![allow(incomplete_features)]
#![no_std]
// For `type_eq`
#![cfg_attr(nightly, feature(specialization))]
// For `std::simd`
#![cfg_attr(nightly, feature(portable_simd))]
#![warn(clippy::cargo)]
#![allow(ambiguous_glob_reexports)]
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
    clippy::ptr_cast_constness,
    clippy::unsafe_derive_deserialize,
    clippy::similar_names,
    clippy::too_many_lines
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
// Till they fix this buggy lint in clippy
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::borrow_deref_ref)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;
#[macro_use]
#[doc(hidden)]
pub extern crate alloc;

// Re-export derive(SerdeAny)
#[cfg(feature = "derive")]
#[allow(unused_imports)]
#[macro_use]
extern crate libafl_derive;
/// Dummy export that will warn with a deprecation note on usage.
/// Use the `libafl_bolts` crate instead.
#[deprecated(
    since = "0.11.0",
    note = "All LibAFL bolts have moved to the libafl_bolts crate."
)]
pub mod bolts {}
#[cfg(feature = "derive")]
#[doc(hidden)]
pub use libafl_derive::*;

pub mod corpus;
pub mod events;
pub mod executors;
pub mod feedbacks;
pub mod fuzzer;
pub mod generators;
pub mod inputs;
pub mod monitors;
pub mod mutators;
pub mod observers;
pub mod schedulers;
pub mod stages;
pub mod state;

pub use fuzzer::*;
pub use libafl_bolts::Error;

/// The purpose of this module is to alleviate imports of many components by adding a glob import.
#[cfg(feature = "prelude")]
pub mod prelude {
    pub use super::{
        corpus::*, events::*, executors::*, feedbacks::*, fuzzer::*, generators::*, inputs::*,
        monitors::*, mutators::*, observers::*, schedulers::*, stages::*, state::*, *,
    };
}

#[cfg(all(any(doctest, test), not(feature = "std")))]
/// Provide custom time in `no_std` tests.
#[no_mangle]
pub unsafe extern "C" fn external_current_millis() -> u64 {
    // TODO: use "real" time here
    1000
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    #[cfg(miri)]
    use libafl_bolts::serdeany::RegistryBuilder;
    use libafl_bolts::{rands::StdRand, tuples::tuple_list};

    #[cfg(miri)]
    use crate::stages::ExecutionCountRestartHelperMetadata;
    use crate::{
        corpus::{Corpus, InMemoryCorpus, Testcase},
        events::NopEventManager,
        executors::{ExitKind, InProcessExecutor},
        feedbacks::ConstFeedback,
        fuzzer::Fuzzer,
        inputs::BytesInput,
        monitors::SimpleMonitor,
        mutators::{mutations::BitFlipMutator, StdScheduledMutator},
        schedulers::RandScheduler,
        stages::StdMutationalStage,
        state::{HasCorpus, StdState},
        StdFuzzer,
    };

    #[test]
    #[allow(clippy::similar_names)]
    fn test_fuzzer() {
        // # Safety
        // No concurrency per testcase
        #[cfg(miri)]
        unsafe {
            RegistryBuilder::register::<ExecutionCountRestartHelperMetadata>();
        }

        let rand = StdRand::with_seed(0);

        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(vec![0; 4].into());
        corpus.add(testcase).unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::<BytesInput>::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let _monitor = SimpleMonitor::new(|s| {
            println!("{s}");
        });
        let mut event_manager = NopEventManager::new();

        let feedback = ConstFeedback::new(false);
        let objective = ConstFeedback::new(false);

        let scheduler = RandScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

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
                .unwrap_or_else(|_| panic!("Error in iter {i}"));
            if cfg!(miri) {
                break;
            }
        }

        let state_serialized = postcard::to_allocvec(&state).unwrap();
        let state_deserialized: StdState<
            _,
            InMemoryCorpus<BytesInput>,
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

#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use pyo3::prelude::*;

    use super::{
        corpus, events, executors, feedbacks, fuzzer, generators, monitors, mutators, observers,
        stages, state,
    };

    #[derive(Debug, Clone)]
    pub struct PythonMetadata {
        pub map: PyObject,
    }

    libafl_bolts::impl_serde_pyobjectwrapper!(PythonMetadata, map);
    libafl_bolts::impl_serdeany!(PythonMetadata);

    impl PythonMetadata {
        #[must_use]
        pub fn new(map: PyObject) -> Self {
            Self { map }
        }
    }

    #[pymodule]
    #[pyo3(name = "libafl")]
    /// Register the classes to the python module
    pub fn python_module(py: Python, m: &PyModule) -> PyResult<()> {
        libafl_bolts::rands::pybind::register(py, m)?;
        observers::map::pybind::register(py, m)?;
        observers::pybind::register(py, m)?;
        feedbacks::map::pybind::register(py, m)?;
        feedbacks::pybind::register(py, m)?;
        state::pybind::register(py, m)?;
        monitors::pybind::register(py, m)?;
        events::pybind::register(py, m)?;
        events::simple::pybind::register(py, m)?;
        fuzzer::pybind::register(py, m)?;
        executors::pybind::register(py, m)?;
        executors::inprocess::pybind::register(py, m)?;
        generators::pybind::register(py, m)?;
        mutators::pybind::register(py, m)?;
        mutators::scheduled::pybind::register(py, m)?;
        corpus::pybind::register(py, m)?;
        corpus::testcase::pybind::register(py, m)?;
        corpus::ondisk::pybind::register(py, m)?;
        corpus::inmemory::pybind::register(py, m)?;
        corpus::cached::pybind::register(py, m)?;
        stages::pybind::register(py, m)?;
        stages::mutational::pybind::register(py, m)?;
        Ok(())
    }
}
