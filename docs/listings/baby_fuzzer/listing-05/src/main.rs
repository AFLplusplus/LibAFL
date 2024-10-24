/* ANCHOR: use */
extern crate libafl;
extern crate libafl_bolts;

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::StdFuzzer,
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    state::StdState,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list, AsSlice, nonzero};
use std::path::PathBuf;
/* ANCHOR_END: use */

/* ANCHOR: signals */
// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];

fn signals_set(idx: usize) {
    unsafe { SIGNALS[idx] = 1 };
}

fn main() {
    // The closure that we want to fuzz
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        signals_set(0); // set SIGNALS[0]
        if buf.len() > 0 && buf[0] == 'a' as u8 {
            signals_set(1); // set SIGNALS[1]
            if buf.len() > 1 && buf[1] == 'b' as u8 {
                signals_set(2); // set SIGNALS[2]
                if buf.len() > 2 && buf[2] == 'c' as u8 {
                    panic!("=)");
                }
            }
        }
        ExitKind::Ok
    };
    /* ANCHOR_END: signals */
    // To test the panic:
    let input = BytesInput::new(Vec::from("abc"));
    #[cfg(feature = "panic")]
    harness(&input);

    /* ANCHOR: observer */
    // Create an observation channel using the signals map
    let observer = unsafe { StdMapObserver::new("signals", &mut SIGNALS) };
    /* ANCHOR_END: observer */

    /* ANCHOR: state_with_feedback_and_objective */
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
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();
    /* ANCHOR_END: state_with_feedback_and_objective */

    // The Monitor trait defines how the fuzzer stats are displayed to the user
    let mon = SimpleMonitor::new(|s| println!("{s}"));

    // The event manager handles the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();
    /* ANCHOR: state_with_feedback_and_objective */

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    /* ANCHOR_END: state_with_feedback_and_objective */

    /* ANCHOR: executor_with_observer */
    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");
    /* ANCHOR_END: executor_with_observer */

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(nonzero!(32));

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");
    /* ANCHOR: signals */
}
/* ANCHOR_END: signals */
