/* ANCHOR: use */
extern crate libafl;
extern crate libafl_bolts;

use std::path::PathBuf;
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    fuzzer::StdFuzzer,
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    schedulers::QueueScheduler,
    state::StdState,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list, AsSlice, nonzero};
/* ANCHOR_END: use */

fn main() {
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        if buf.len() > 0 && buf[0] == 'a' as u8 {
            if buf.len() > 1 && buf[1] == 'b' as u8 {
                if buf.len() > 2 && buf[2] == 'c' as u8 {
                    panic!("=)");
                }
            }
        }
        ExitKind::Ok
    };
    // To test the panic:
    let input = BytesInput::new(Vec::from("abc"));
    #[cfg(feature = "panic")]
    harness(&input);

    /* ANCHOR: state */
    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::new(),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut (),
        &mut (),
    )
    .unwrap();
    /* ANCHOR_END: state */

    /* ANCHOR: event_manager */
    // The Monitor trait defines how the fuzzer stats are displayed to the user
    let mon = SimpleMonitor::new(|s| println!("{s}"));

    // The event manager handles the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);
    /* ANCHOR_END: event_manager */

    /* ANCHOR: scheduler_fuzzer */
    // A queue policy to get testcases from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, (), ());
    /* ANCHOR_END: scheduler_fuzzer */

    /* ANCHOR: executor */
    // Create the executor for an in-process function
    let mut executor = InProcessExecutor::new(&mut harness, (), &mut fuzzer, &mut state, &mut mgr)
        .expect("Failed to create the Executor");
    /* ANCHOR_END: executor */

    /* ANCHOR: generator */
    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(nonzero!(32));

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");
    /* ANCHOR_END: generator */
}
