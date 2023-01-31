#![no_main]

#[cfg(windows)]
use std::ptr::write_volatile;
use std::{ffi::c_int, path::PathBuf};

#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;
#[cfg(not(feature = "tui"))]
use libafl::monitors::SimpleMonitor;
use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice},
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    mutators::{
        scheduled::{havoc_mutations, StdScheduledMutator},
        BytesInsertMutator,
    },
    observers::{HitcountsMapObserver, StdMapObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasSolutions, StdState},
};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use libafl_targets::{
    create_dfsan_harness, DataflowCmplogTracingStage, DataflowI2SMutator, DataflowMapFeedback,
    DataflowObserver, EDGES_MAP, MAX_EDGES_NUM,
};

#[allow(non_snake_case)]
extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, len: usize) -> c_int;
}

#[allow(clippy::similar_names)]
#[allow(clippy::too_many_lines)]
#[no_mangle]
pub fn main() {
    // The closure that we want to fuzz
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let slice: &[u8] = target.as_slice();

        unsafe {
            LLVMFuzzerTestOneInput(slice.as_ptr(), slice.len());
        }

        ExitKind::Ok
    };
    let edges_observer = HitcountsMapObserver::new(unsafe {
        StdMapObserver::from_mut_ptr("edges", EDGES_MAP.as_mut_ptr(), MAX_EDGES_NUM)
    });

    // Feedback to rate the interestingness of an input
    let mut feedback = feedback_or!(MaxMapFeedback::new(&edges_observer));

    // A feedback to choose if an input is a solution or not
    // Crash here means "both crashed", which is our objective
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are displayed to the user
    #[cfg(not(feature = "tui"))]
    let mon = SimpleMonitor::new(|s| println!("{s}"));
    #[cfg(feature = "tui")]
    let mon = TuiMonitor::new(String::from("Baby Fuzzer"), false);

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcases from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(edges_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandBytesGenerator::new(32);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let i2s = StdScheduledMutator::new(tuple_list!(DataflowI2SMutator::new()));
    let mutator = StdScheduledMutator::new(tuple_list!(BytesInsertMutator::new()));

    let cmplog = DataflowCmplogTracingStage::new();
    let mut stages = tuple_list!(
        cmplog,
        StdMutationalStage::new(mutator),
        StdMutationalStage::new(i2s)
    );

    while state.solutions().is_empty() {
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");
    }
}
