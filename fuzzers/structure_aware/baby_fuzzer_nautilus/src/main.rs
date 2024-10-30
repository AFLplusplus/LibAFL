use std::path::PathBuf;
#[cfg(windows)]
use std::ptr::write_volatile;

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, NautilusChunksMetadata, NautilusFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{NautilusContext, NautilusGenerator},
    inputs::NautilusInput,
    monitors::SimpleMonitor,
    mutators::{
        NautilusRandomMutator, NautilusRecursionMutator, NautilusSpliceMutator, StdScheduledMutator,
    },
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
    HasMetadata,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list};

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];
static mut SIGNALS_PTR: *mut u8 = unsafe { SIGNALS.as_mut_ptr() };
/*
/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { str::ptr::write(SIGNALS_PTR.add(idx), 1) };
}
*/

#[allow(clippy::similar_names)]
pub fn main() {
    let context = NautilusContext::from_file(15, "grammar.json").unwrap();
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
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, SIGNALS.len()) };

    // Feedback to rate the interestingness of an input
    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&observer),
        NautilusFeedback::new(&context)
    );

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

    let _ = state.metadata_or_insert_with::<NautilusChunksMetadata>(|| {
        NautilusChunksMetadata::new("/tmp/".into())
    });

    // The Monitor trait define how the fuzzer stats are reported to the user
    let monitor = SimpleMonitor::new(|s| println!("{s}"));

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
    let st = libafl_bolts::current_milliseconds();
    let mut b = vec![];
    let mut c = 0;
    for _ in 0..100000 {
        let i = generator.generate(&mut state).unwrap();
        i.unparse(&context, &mut b);
        set.insert(calculate_hash(&b));
        c += b.len();
    }
    println!("{} / {}", c, libafl_bolts::current_milliseconds() - st);
    println!("{} / 100000", set.len());

    return;
    */

    // Generate 8 initial inputs
    if state.must_load_initial_inputs() {
        state
            .generate_initial_inputs_forced(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
            .expect("Failed to generate the initial corpus");
    }

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::with_max_stack_pow(
        tuple_list!(
            NautilusRandomMutator::new(&context),
            NautilusRandomMutator::new(&context),
            NautilusRandomMutator::new(&context),
            NautilusRandomMutator::new(&context),
            NautilusRandomMutator::new(&context),
            NautilusRandomMutator::new(&context),
            NautilusRecursionMutator::new(&context),
            NautilusSpliceMutator::new(&context),
            NautilusSpliceMutator::new(&context),
            NautilusSpliceMutator::new(&context),
        ),
        2,
    );
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
