#![allow(unexpected_cfgs)] // the wasm_bindgen introduces these on nightly only
mod utils;

use libafl::{
    corpus::{Corpus, InMemoryCorpus},
    events::SimpleEventManager,
    executors::{ExitKind, InProcessExecutor},
    feedbacks::{CrashFeedback, MapFeedbackMetadata, MaxMapFeedback},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::{RetryCountRestartHelper, StdMutationalStage},
    state::{HasSolutions, StdState},
    Fuzzer, StdFuzzer,
};
use libafl_bolts::{
    nonzero, rands::StdRand, serdeany::RegistryBuilder, tuples::tuple_list, AsSlice,
};
use wasm_bindgen::prelude::*;
use web_sys::{Performance, Window};

use crate::utils::set_panic_hook;

// Defined for internal use by LibAFL
#[no_mangle]
#[expect(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc
)]
pub extern "C" fn external_current_millis() -> u64 {
    let window: Window = web_sys::window().expect("should be in browser to run this demo");
    let performance: Performance = window
        .performance()
        .expect("should be in browser to run this demo");
    performance.now() as u64
}

#[allow(clippy::missing_panics_doc)] // expect does not work, likely because of `wasm_bindgen`
#[wasm_bindgen]
pub fn fuzz() {
    set_panic_hook();

    // We need to register the types as LibAFL doesn't support `SerdeAny`
    // auto registration in non-standard environments.
    //
    // # Safety
    // No concurrency in WASM so these accesses are not racing.
    unsafe {
        RegistryBuilder::register::<MapFeedbackMetadata<u8>>();
        RegistryBuilder::register::<RetryCountRestartHelper>();
    }

    let mut signals = [0u8; 64];
    let signals_ptr = signals.as_mut_ptr();
    let signals_set = |i: usize| unsafe {
        *signals_ptr.add(i) += 1;
    };

    // The closure that we want to fuzz
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        signals_set(0);
        if !buf.is_empty() && buf[0] == b'a' {
            signals_set(1);
            if buf.len() > 1 && buf[1] == b'b' {
                signals_set(2);
                if buf.len() > 2 && buf[2] == b'c' {
                    // WASM cannot handle traps: https://webassembly.github.io/spec/core/intro/overview.html
                    // in a "real" fuzzing campaign, you should prefer to setup trap handling in JS,
                    // but we do not do this for demonstration purposes
                    return ExitKind::Crash;
                }
            }
        }
        ExitKind::Ok
    };

    // Create an observation channel using the signals map
    // TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
    #[allow(static_mut_refs)] // only a problem in nightly
    let observer =
        unsafe { StdMapObserver::from_mut_ptr("signals", signals.as_mut_ptr(), signals.len()) };

    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::new(),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // In a "real" fuzzing campaign, you should stash solutions in a JS array instead
        InMemoryCorpus::new(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are reported to the user
    let monitor = SimpleMonitor::new(|s| {
        web_sys::console::log_1(&s.into());
    });

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(nonzero!(32));

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    while state.solutions().is_empty() {
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");
    }
}
