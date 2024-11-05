/*!
Welcome to `LibAFL`
*/
#![doc = include_str!("../README.md")]
/*! */
#![cfg_attr(feature = "document-features", doc = document_features::document_features!())]
#![no_std]
// For `type_eq`
#![cfg_attr(nightly, feature(specialization))]
// For `std::simd`
#![cfg_attr(nightly, feature(portable_simd))]
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
#[cfg(feature = "derive")]
#[doc(hidden)]
pub use libafl_derive::*;

pub mod common;
pub use common::*;
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
pub use libafl_bolts::{nonzero, Error};

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
    use libafl_bolts::{
        rands::{RomuDuoJrRand, StdRand},
        tuples::tuple_list,
    };

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
        > = postcard::from_bytes::<
            StdState<
                BytesInput,
                InMemoryCorpus<BytesInput>,
                RomuDuoJrRand,
                InMemoryCorpus<BytesInput>,
            >,
        >(state_serialized.as_slice())
        .unwrap();
        assert_eq!(state.corpus().count(), state_deserialized.corpus().count());

        let corpus_serialized = postcard::to_allocvec(state.corpus()).unwrap();
        let corpus_deserialized: InMemoryCorpus<BytesInput> =
            postcard::from_bytes(corpus_serialized.as_slice()).unwrap();
        assert_eq!(state.corpus().count(), corpus_deserialized.count());
    }
}
