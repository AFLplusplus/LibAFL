use std::path::PathBuf;

use libafl::inputs::{BytesInput, HasTargetBytes};
use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list, shmem::{ShMemProvider, StdShMemProvider, ShMem}},
    corpus::{InMemoryCorpus, OnDiskCorpus, QueueCorpusScheduler},
    events::SimpleEventManager,
    executors::{forkserver::ForkserverExecutor},
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    stages::mutational::StdMutationalStage,
    state::StdState,
    stats::SimpleStats,
};


#[allow(clippy::similar_names)]
pub fn main() {

    const MAP_SIZE: i32 = 65536;
    //Coverage map shared between observer and executor
    let mut shmem = StdShMemProvider::new().unwrap().new_map(MAP_SIZE as usize).unwrap();
    //let the forkserver know the shmid
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let mut shmem_map = shmem.map_mut();

    // Create an observation channel using the signals map
    let observer = StdMapObserver::new("signals", unsafe { &mut shmem_map });

    // The state of the edges feedback.
    let feedback_state = MapFeedbackState::with_observer(&observer);

    // Feedback to rate the interestingness of an input
    let feedback = MaxMapFeedback::new(&feedback_state, &observer);

    // A feedback to choose if an input is a solution or not
    let objective = CrashFeedback::new();

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
        tuple_list!(feedback_state),
    );

    // The Stats trait define how the fuzzer stats are reported to the user
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(stats);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueCorpusScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the executor for an in-process function with just one observer



    
    let mut executor = ForkserverExecutor::new(
        "../../libafl_tests/src/forkserver_test.o".to_string(),
        vec![],
        tuple_list!(observer),
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
