use std::path::PathBuf;

use libafl::bolts::shmem::ShMemProvider;
use libafl::bolts::AsSlice;
use libafl::observers::ConstMapObserver;
use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        shmem::{ShMem, StdShMemProvider},
        tuples::tuple_list,
    },
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::InProcessForkExecutor,
    feedback_and,
    feedbacks::{
        CrashFeedback, MapFeedbackState, MaxMapFeedback, NewHashFeedback, NewHashFeedbackState,
    },
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::BacktraceObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libc::c_int;
use libc::c_uchar;
extern crate libc;

extern "C" {
    fn c_harness(input: *const c_uchar);
    fn create_shmem_array() -> c_int;
    fn get_ptr() -> *mut u8;

}

#[allow(clippy::similar_names)]
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
    let observer = unsafe { ConstMapObserver::<u8, 3>::new_from_ptr("signals", map_ptr) };
    // Create a stacktrace observer
    let mut bt = shmem_provider.new_shmem_object::<Option<u64>>().unwrap();
    let bt_observer = BacktraceObserver::new(
        "BacktraceObserver",
        unsafe { bt.as_object_mut::<Option<u64>>() },
        libafl::observers::HarnessType::Child,
    );

    // The state of the edges feedback.
    let feedback_state = MapFeedbackState::with_observer(&observer);
    let st_feedback_state = NewHashFeedbackState::<u64>::with_observer(&bt_observer);

    // Feedback to rate the interestingness of an input, obtained by ANDing the interestingness of both feedbacks
    let feedback = MaxMapFeedback::new(&feedback_state, &observer);

    // A feedback to choose if an input is a solution or not
    let objective = feedback_and!(
        CrashFeedback::new(),
        NewHashFeedback::<BacktraceObserver>::new_with_observer("BacktraceObserver", &bt_observer)
    );

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
        // They are the data related to the feedbacks that you want to persist in the State.
        tuple_list!(feedback_state, st_feedback_state),
    );

    // The Monitor trait define how the fuzzer stats are displayed to the user
    let mon = SimpleMonitor::new(|s| println!("{}", s));

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
        shmem_provider,
    )
    .expect("Failed to create the Executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(32);

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
