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
    corpus::{CachedOnDiskCorpus, Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind, ShadowExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    mutators::{
        scheduled::{havoc_mutations, StdScheduledMutator},
        token_mutations::I2SRandReplace,
        tokens_mutations, BytesDeleteMutator,
    },
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    prelude::Merge,
    schedulers::QueueScheduler,
    stages::{mutational::StdMutationalStage, ShadowTracingStage},
    state::{HasSolutions, StdState},
};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use libafl_targets::{
    create_dfsan_harness, CmpLogObserver, DataflowCmplogTracingStage, DataflowI2SMutator,
    DataflowMapFeedback, DataflowObserver, EDGES_MAP, MAX_EDGES_NUM,
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

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new_tracking(&edges_observer, true, false),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::with_observer(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    // Crash here means "both crashed", which is our objective
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        CachedOnDiskCorpus::<BytesInput>::new(PathBuf::from("./fuzzer_generated"), 1 << 8).unwrap(),
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
    // Create the executor for an in-process function with just one observer for edge coverage
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .unwrap();

    // Generate 8 initial inputs
    // state
    //     .load_initial_inputs(
    //         &mut fuzzer,
    //         &mut executor,
    //         &mut mgr,
    //         &[PathBuf::from("corpus")],
    //     )
    //     .expect("Failed to generate the initial corpus");
    let mut generator = RandBytesGenerator::new(32);
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 16)
        .unwrap();

    // Setup a mutational stage with a basic bytes mutator
    let dfi2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(
        DataflowI2SMutator::new()
    )));
    let mutations = StdMutationalStage::new(StdScheduledMutator::new(
        havoc_mutations().merge(tokens_mutations()),
    ));

    let dataflow = DataflowCmplogTracingStage::new();
    let mut stages = tuple_list!(dataflow, dfi2s, mutations);

    while state.solutions().is_empty() {
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");
    }
}
