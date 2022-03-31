use std::io::Read;
use std::{
    fs,
    io::BufReader,
    path::{Path, PathBuf},
};

#[cfg(windows)]
use std::ptr::write_volatile;

use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list},
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{Automaton, GramatronGenerator},
    inputs::GramatronInput,
    monitors::SimpleMonitor,
    mutators::{
        GramatronRandomMutator, GramatronRecursionMutator, GramatronSpliceMutator,
        StdScheduledMutator,
    },
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];
/*
/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { SIGNALS[idx] = 1 };
}
*/

fn read_automaton_from_file<P: AsRef<Path>>(path: P) -> Automaton {
    let file = fs::File::open(path).unwrap();
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).unwrap();
    postcard::from_bytes(&buffer).unwrap()
}

#[allow(clippy::similar_names)]
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
    let observer = StdMapObserver::new("signals", unsafe { &mut SIGNALS });

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

    // The Monitor trait define how the fuzzer stats are reported to the user
    let monitor = SimpleMonitor::new(|s| println!("{}", s));

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

    let automaton = read_automaton_from_file(PathBuf::from("auto.postcard"));
    let mut generator = GramatronGenerator::new(&automaton);

    // Use this code to profile the generator performance
    /*
    use libafl::generators::Generator;
    use std::collections::HashSet;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    let mut set = HashSet::new();
    let st = libafl::bolts::current_milliseconds();
    let mut b = vec![];
    let mut c = 0;
    for _ in 0..100000 {
        let i = generator.generate(&mut state).unwrap();
        i.unparse(&mut b);
        set.insert(calculate_hash(&b));
        c += b.len();
    }
    println!("{} / {}", c, libafl::bolts::current_milliseconds() - st);
    println!("{} / 100000", set.len());

    return;
    */

    // Generate 8 initial inputs
    state
        .generate_initial_inputs_forced(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::with_max_stack_pow(
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
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
