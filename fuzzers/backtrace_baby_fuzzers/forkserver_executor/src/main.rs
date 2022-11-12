use std::path::PathBuf;

#[cfg(not(target_vendor = "apple"))]
use libafl::bolts::shmem::StdShMemProvider;
#[cfg(target_vendor = "apple")]
use libafl::bolts::shmem::UnixShMemProvider;
use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        shmem::{ShMem, ShMemProvider},
        tuples::tuple_list,
        AsMutSlice,
    },
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::forkserver::ForkserverExecutor,
    feedback_and,
    feedbacks::{CrashFeedback, MaxMapFeedback, NewHashFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{AsanBacktraceObserver, ConstMapObserver, HitcountsMapObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};

#[allow(clippy::similar_names)]
pub fn main() {
    const MAP_SIZE: usize = 65536;

    //Coverage map shared between observer and executor
    #[cfg(target_vendor = "apple")]
    let mut shmem_provider = UnixShMemProvider::new().unwrap();

    #[cfg(not(target_vendor = "apple"))]
    let mut shmem_provider = StdShMemProvider::new().unwrap();

    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    //let the forkserver know the shmid
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let shmem_map = shmem.as_mut_slice();

    // Create an observation channel using the signals map
    let edges_observer = HitcountsMapObserver::new(ConstMapObserver::<_, MAP_SIZE>::new(
        "shared_mem",
        shmem_map,
    ));

    let bt_observer = AsanBacktraceObserver::new("AsanBacktraceObserver");

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = MaxMapFeedback::new_tracking(&edges_observer, true, false);

    // A feedback to choose if an input is a solution or not
    // We want to do the same crash deduplication that AFL does
    let mut objective = feedback_and!(CrashFeedback::new(), NewHashFeedback::new(&bt_observer));

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::<BytesInput>::new(),
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
    let monitor = SimpleMonitor::new(|s| println!("{}", s));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = ForkserverExecutor::builder()
        .program("./target/release/program")
        .arg_input_file_std()
        .shmem_provider(&mut shmem_provider)
        .build(tuple_list!(bt_observer, edges_observer))
        .unwrap();

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(3);

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
