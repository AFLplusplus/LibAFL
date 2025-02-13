#[cfg(windows)]
use std::ptr::write_volatile;
use std::{path::PathBuf, ptr::write};

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{ExitKind, InProcessForkExecutor},
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
use libafl_bolts::{
    nonzero,
    rands::StdRand,
    shmem::{unix_shmem, ShMemProvider},
    tuples::tuple_list,
    AsSlice, AsSliceMut,
};

pub fn main() {
    let mut shmem_provider = unix_shmem::UnixShMemProvider::new().unwrap();
    let mut signals = shmem_provider.new_shmem(16).unwrap();

    let signals_len = signals.as_slice().len();
    let signals_ptr = signals.as_slice_mut().as_mut_ptr();

    let signals_set = |idx: usize| {
        unsafe { write(signals_ptr.add(idx), 1) };
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
                    // removed the windows panic for simplicity, will add later
                    #[cfg(unix)]
                    panic!("panic 1");
                }
                if buf.len() > 2 && buf[2] == b'd' {
                    #[cfg(unix)]
                    panic!("panic 2");
                }
                if buf.len() > 2 && buf[2] == b'e' {
                    #[cfg(unix)]
                    panic!("panic 3");
                }
            }
        }
        ExitKind::Ok
    };

    // Create an observation channel using the signals map

    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", signals_ptr, signals_len) };
    // Create a stacktrace observer to add the observers tuple

    // Feedback to rate the interestingness of an input, obtained by ANDing the interestingness of both feedbacks
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
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are displayed to the user
    let mon = SimpleMonitor::new(|s| println!("{s}"));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessForkExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        core::time::Duration::from_millis(5000),
        shmem_provider,
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
