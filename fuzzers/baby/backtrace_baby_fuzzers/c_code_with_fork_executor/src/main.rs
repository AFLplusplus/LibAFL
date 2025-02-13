use std::{path::PathBuf, ptr::NonNull, time::Duration};

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::InProcessForkExecutor,
    feedback_and,
    feedbacks::{CrashFeedback, MaxMapFeedback, NewHashFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::StdScheduledMutator},
    observers::{BacktraceObserver, ConstMapObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{
    nonzero,
    ownedref::OwnedRefMut,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
    AsSlice,
};
use libc::{c_int, c_uchar};
extern crate libc;

extern "C" {
    fn c_harness(input: *const c_uchar);
    fn create_shmem_array() -> c_int;
    fn get_ptr() -> *mut u8;

}

pub fn main() {
    let mut shmem_provider = StdShMemProvider::new().unwrap();
    unsafe { create_shmem_array() };
    let map_ptr = unsafe { get_ptr() };
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        unsafe { c_harness(buf.as_ptr()) }
        libafl::executors::ExitKind::Ok
    };
    // Create an observation channel using the signals map
    let observer = unsafe {
        ConstMapObserver::from_mut_ptr(
            "signals",
            NonNull::new(map_ptr)
                .expect("map ptr is null.")
                .cast::<[u8; 3]>(),
        )
    };
    // Create a stacktrace observer
    let mut bt = shmem_provider.new_on_shmem::<Option<u64>>(None).unwrap();
    let bt_observer = BacktraceObserver::new(
        "BacktraceObserver",
        unsafe { OwnedRefMut::from_shmem(&mut bt) },
        libafl::observers::HarnessType::Child,
    );

    // Feedback to rate the interestingness of an input, obtained by ANDing the interestingness of both feedbacks
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_and!(CrashFeedback::new(), NewHashFeedback::new(&bt_observer));

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
        tuple_list!(observer, bt_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        Duration::from_millis(5000),
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
