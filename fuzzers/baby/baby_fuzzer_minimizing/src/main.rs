#[cfg(windows)]
use std::ptr::write_volatile;
use std::{path::PathBuf, ptr::write};

use libafl::prelude::*;
use libafl_bolts::prelude::*;

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];
static mut SIGNALS_PTR: *mut u8 = unsafe { SIGNALS.as_mut_ptr() };

/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { write(SIGNALS_PTR.add(idx), 1) };
}

#[allow(clippy::similar_names)]
pub fn main() -> Result<(), Error> {
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
                    return ExitKind::Crash;
                }
            }
        }
        ExitKind::Ok
    };

    // Create an observation channel using the signals map
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, SIGNALS.len()) };

    let factory = MapEqualityFactory::new(&observer);

    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // The Monitor trait define how the fuzzer stats are displayed to the user
    let mon = SimpleMonitor::new(|s| println!("{s}"));

    let mut mgr = SimpleEventManager::new(mon);

    let corpus_dir = PathBuf::from("./corpus");
    let solution_dir = PathBuf::from("./solutions");

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::new(),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryOnDiskCorpus::new(corpus_dir).unwrap(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(&solution_dir).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

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
    let minimizer = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(
        StdMutationalStage::new(mutator),
        StdTMinMutationalStage::new(minimizer, factory, 128)
    );

    while state.solutions().is_empty() {
        fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)?;
    }

    let minimized_dir = PathBuf::from("./minimized");

    let mut state = StdState::new(
        StdRand::new(),
        InMemoryOnDiskCorpus::new(minimized_dir).unwrap(),
        InMemoryCorpus::new(),
        &mut (),
        &mut (),
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are displayed to the user
    let mon = SimpleMonitor::new(|s| println!("{s}"));

    let mut mgr = SimpleEventManager::new(mon);

    let minimizer = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdTMinMutationalStage::new(
        minimizer,
        CrashFeedback::new(),
        1 << 10,
    ));

    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, (), ());

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::new(&mut harness, (), &mut fuzzer, &mut state, &mut mgr)?;

    state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[solution_dir])?;

    let first_id = state.corpus().first().expect("Empty corpus");
    state.set_corpus_id(first_id)?;

    stages.perform_all(&mut fuzzer, &mut executor, &mut state, &mut mgr)?;

    Ok(())
}
