use std::path::PathBuf;

use libafl::{
    bolts::tuples::tuple_list,
    corpus::{InMemoryCorpus, OnDiskCorpus, QueueCorpusScheduler},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    stages::mutational::StdMutationalStage,
    state::State,
    stats::SimpleStats,
    utils::{current_nanos, StdRand},
};

static mut SIGNALS: [u8; 16] = [0; 16];

pub fn main() {
    // The closure that we want to fuzz
    let mut harness = |buf: &[u8]| {
        unsafe { SIGNALS[0] = 1 };
        if buf.len() > 0 && buf[0] == 'a' as u8 {
            unsafe { SIGNALS[1] = 1 };
            if buf.len() > 1 && buf[1] == 'b' as u8 {
                unsafe { SIGNALS[2] = 1 };
                if buf.len() > 2 && buf[2] == 'c' as u8 {
                    panic!("=)");
                }
            }
        }
        ExitKind::Ok
    };

    // The Stats trait define how the fuzzer stats are reported to the user
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(stats);

    // Create an observation channel using the siganls map
    let observer =
        StdMapObserver::new("signals", unsafe { &mut SIGNALS }, unsafe { SIGNALS.len() });

    // create a State from scratch
    let mut state = State::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Feedbacks to rate the interestingness of an input
        tuple_list!(MaxMapFeedback::new(&observer)),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // Feedbacks to recognize an input as solution
        tuple_list!(CrashFeedback::new()),
    );

    // Setup a basic mutator with a mutational stage
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let stage = StdMutationalStage::new(mutator);

    // A fuzzer with just one stage
    let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueCorpusScheduler::new();

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::new(
        "in-process(signals)",
        &mut harness,
        tuple_list!(observer),
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor".into());

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(32);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut executor, &mut generator, &mut mgr, &scheduler, 8)
        .expect("Failed to generate the initial corpus".into());

    fuzzer
        .fuzz_loop(&mut state, &mut executor, &mut mgr, &scheduler)
        .expect("Error in the fuzzing loop".into());
}
