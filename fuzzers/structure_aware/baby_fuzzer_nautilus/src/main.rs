use std::path::PathBuf;
#[cfg(windows)]
use std::ptr::write_volatile;

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, NautilusChunksMetadata, NautilusFeedback},
    fuzzer::StdFuzzer,
    generators::{NautilusContext, NautilusGenerator},
    inputs::{NautilusBytesConverter, NautilusInput},
    monitors::SimpleMonitor,
    mutators::{
        HavocScheduledMutator, NautilusRandomMutator, NautilusRecursionMutator,
        NautilusSpliceMutator,
    },
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::StdMutationalStage,
    state::StdState,
    HasMetadata,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list};

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];
// TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
#[allow(static_mut_refs)] // only a problem in nightly
static mut SIGNALS_PTR: *mut u8 = unsafe { SIGNALS.as_mut_ptr() };
/*
/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { str::ptr::write(SIGNALS_PTR.add(idx), 1) };
}
*/

pub fn main() {
    let ctx = NautilusContext::from_file(15, "grammar.json").unwrap();
    let mut bytes = vec![];

    // The closure that we want to fuzz
    let mut harness = |input: &NautilusInput| {
        input.unparse(&ctx, &mut bytes);
        unsafe {
            println!(">>> {}", std::str::from_utf8_unchecked(&bytes));
        }
        ExitKind::Ok
    };

    // Create an observation channel using the signals map
    // TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
    #[allow(static_mut_refs)] // only a problem in nightly
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, SIGNALS.len()) };

    // Feedback to rate the interestingness of an input
    let mut feedback = feedback_or!(MaxMapFeedback::new(&observer), NautilusFeedback::new(&ctx));

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

    // Setup a mutational stage with a basic bytes mutator
    let mutator = HavocScheduledMutator::with_max_stack_pow(
        tuple_list!(
            NautilusRandomMutator::new(&ctx),
            NautilusRandomMutator::new(&ctx),
            NautilusRandomMutator::new(&ctx),
            NautilusRandomMutator::new(&ctx),
            NautilusRandomMutator::new(&ctx),
            NautilusRandomMutator::new(&ctx),
            NautilusRecursionMutator::new(&ctx),
            NautilusSpliceMutator::new(&ctx),
            NautilusSpliceMutator::new(&ctx),
            NautilusSpliceMutator::new(&ctx),
        ),
        2,
    );
    let stages = tuple_list!(StdMutationalStage::new(mutator));

    // A fuzzer with feedbacks, a corpus scheduler, and stages
    let mut fuzzer = StdFuzzer::builder()
        .scheduler(scheduler)
        .feedback(feedback)
        .objective(objective)
        .target_bytes_converter(NautilusBytesConverter::new(&ctx))
        .build_with_stages(stages);

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::builder()
        .harness(&mut harness)
        .observers(tuple_list!(observer))
        .fuzzer(&mut fuzzer)
        .state(&mut state)
        .event_mgr(&mut mgr)
        .build()
        .expect("Failed to create the Executor");

    let mut generator = NautilusGenerator::new(&ctx);

    // Generate 8 initial inputs
    if state.must_load_initial_inputs() {
        state
            .generate_initial_inputs_forced(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
            .expect("Failed to generate the initial corpus");
    }

    fuzzer
        .fuzz_loop(&mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
