use std::path::PathBuf;

#[cfg(windows)]
use std::ptr::write_volatile;

use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list},
    corpus::{InMemoryCorpus, OnDiskCorpus, QueueCorpusScheduler},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{NautilusContext, NautilusGenerator},
    inputs::NautilusInput,
    mutators::{NautilusRandomMutator, StdScheduledMutator},
    observers::StdMapObserver,
    stages::mutational::StdMutationalStage,
    state::StdState,
    stats::SimpleStats,
};

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];
/*
/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { SIGNALS[idx] = 1 };
}
*/

#[allow(clippy::similar_names)]
pub fn main() {
    let context = NautilusContext::from_file(15, "grammar.json");
    let mut bytes = vec![];

    // The closure that we want to fuzz
    let mut harness = |input: &NautilusInput| {
        input.unparse(&context, &mut bytes);
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
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    let mut generator = NautilusGenerator::new(&context);

    // Use this code to profile the generator performance
    /*
    use libafl::generators::Generator;
    use std::collections::hash_map::DefaultHasher;
    use std::collections::HashSet;
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
        i.unparse(&context, &mut b);
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
    let mutator = StdScheduledMutator::with_max_iterations(
        tuple_list!(NautilusRandomMutator::new(&context)),
        2,
    );
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
