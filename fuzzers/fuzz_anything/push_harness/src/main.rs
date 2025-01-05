//! [`Klo-routines`](https://github.com/andreafioraldi/klo-routines/) based fuzzer.
//! The target loops and the harness pulls inputs out of `LibAFL`, instead of being called by `LibAFL`.
use std::path::PathBuf;

use klo_routines::{yield_, KloRoutine};
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{current_nanos, nonzero, rands::StdRand, tuples::tuple_list, AsSlice};

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];

/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { SIGNALS[idx] = 1 };
}

/// This generates the input, using klo-routines.
fn input_generator() {
    // The closure that produced the input for the generator
    let mut harness = |input: &BytesInput| {
        // The `yield_` switches execution context back to the loop in `main`.
        // When `resume` is called, we return to this function.
        yield_(input);
        ExitKind::Ok
    };

    let signals_ptr = &raw mut SIGNALS;
    let signals_len = unsafe { *signals_ptr }.len();

    // Create an observation channel using the signals map

    let observer =
        unsafe { StdMapObserver::from_mut_ptr("signals", &raw mut SIGNALS as _, signals_len) };

    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
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

    // The Monitor trait define how the fuzzer stats are reported to the user
    let monitor = SimpleMonitor::new(|s| println!("{s}"));

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

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}

/// the main function loops independently of the fuzzer.
/// `Klo` internally switches between the `LibAFL` and harness coroutines to generate the inputs.
#[expect(clippy::manual_assert)]
pub fn main() {
    // Set up the Klo-routines harness
    let mut input_generator = input_generator;
    let mut klo =
        KloRoutine::<_, &BytesInput>::with_stack_size(&mut input_generator, 512 * 1024 * 1024);

    // Loop, calling `klo.resume` repeatedly. This will switch execution to the loop in the `input_generator` function.
    while let Some(input) = klo.resume() {
        let target = input.target_bytes();
        let buf = target.as_slice();
        signals_set(0);
        if !buf.is_empty() && buf[0] == b'a' {
            signals_set(1);
            if buf.len() > 1 && buf[1] == b'b' {
                signals_set(2);
                if buf.len() > 2 && buf[2] == b'c' {
                    panic!("=)");
                }
            }
        }
    }
    println!("Flushed klo");
}
