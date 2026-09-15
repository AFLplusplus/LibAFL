#[cfg(windows)]
use std::ptr::write_volatile;
use std::{
    fs,
    io::{BufReader, Read},
    path::{Path, PathBuf},
};

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::StdFuzzer,
    generators::{Automaton, GramatronGenerator},
    inputs::GramatronInput,
    monitors::SimpleMonitor,
    mutators::{
        GramatronRandomMutator, GramatronRecursionMutator, GramatronSpliceMutator,
        HavocScheduledMutator,
    },
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list};

/// Coverage map with explicit assignments due to the lack of instrumentation
const SIGNALS_LEN: usize = 16;
static mut SIGNALS: [u8; SIGNALS_LEN] = [0; SIGNALS_LEN];
static mut SIGNALS_PTR: *mut u8 = &raw mut SIGNALS as _;
/*
/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { std::ptr::write(SIGNALS_PTR.add(idx), 1) };
}
*/

fn read_automaton_from_file<P: AsRef<Path>>(path: P) -> Automaton {
    let file = fs::File::open(path).unwrap();
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).unwrap();
    postcard::from_bytes(&buffer).unwrap()
}

pub fn main() {
    let mut bytes = vec![];

    // The closure that we want to fuzz
    let mut harness = |input: &GramatronInput| {
        input.unparse(&mut bytes);
        unsafe {
            println!(">>> {}", std::str::from_utf8_unchecked(&bytes));
        }
        ExitKind::Ok
    };

    // Create an observation channel using the signals map

    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, SIGNALS_LEN) };

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

    let automaton = read_automaton_from_file(PathBuf::from("auto.postcard"));
    let generator = GramatronGenerator::new(&automaton);
    let mut initial_generator = GramatronGenerator::new(&automaton);

    // Setup a mutational stage with a basic bytes mutator
    let mutator = HavocScheduledMutator::with_max_stack_pow(
        tuple_list!(
            GramatronRandomMutator::new(&generator),
            GramatronRandomMutator::new(&generator),
            GramatronRandomMutator::new(&generator),
            GramatronSpliceMutator::new(),
            GramatronSpliceMutator::new(),
            GramatronRecursionMutator::new()
        ),
        2,
    );
    let stages = tuple_list!(StdMutationalStage::new(mutator));

    // A fuzzer with feedbacks, a corpus scheduler, and stages
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective, stages);

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::builder()
        .harness(&mut harness)
        .observers(tuple_list!(observer))
        .fuzzer(&mut fuzzer)
        .state(&mut state)
        .event_mgr(&mut mgr)
        .build()
        .expect("Failed to create the Executor");

    // Generate 8 initial inputs
    state
        .generate_initial_inputs_forced(
            &mut fuzzer,
            &mut executor,
            &mut initial_generator,
            &mut mgr,
            8,
        )
        .expect("Failed to generate the initial corpus");

    fuzzer
        .fuzz_loop(&mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
