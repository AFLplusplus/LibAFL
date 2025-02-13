#[cfg(windows)]
use std::ptr::write_volatile;
use std::{fs, io::Read, path::PathBuf, ptr::write};

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Evaluator, Fuzzer, StdFuzzer},
    inputs::{BytesInput, GeneralizedInputMetadata, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{
        havoc_mutations, scheduled::StdScheduledMutator, GrimoireExtensionMutator,
        GrimoireRandomDeleteMutator, GrimoireRecursiveReplacementMutator,
        GrimoireStringReplacementMutator, Tokens,
    },
    observers::{CanTrack, StdMapObserver},
    schedulers::QueueScheduler,
    stages::{mutational::StdMutationalStage, GeneralizationStage},
    state::StdState,
    HasMetadata,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list, AsSlice};

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];
// TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
#[allow(static_mut_refs)] // only a problem in nightly
static mut SIGNALS_PTR: *mut u8 = unsafe { SIGNALS.as_mut_ptr() };
/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { write(SIGNALS_PTR.add(idx), 1) };
}

fn is_sub<T: PartialEq>(mut haystack: &[T], needle: &[T]) -> bool {
    if needle.is_empty() {
        return true;
    }
    while !haystack.is_empty() {
        if haystack.starts_with(needle) {
            return true;
        }
        haystack = &haystack[1..];
    }
    false
}

pub fn main() {
    let mut initial_inputs = vec![];
    for entry in fs::read_dir("./corpus").unwrap() {
        let path = entry.unwrap().path();
        let attr = fs::metadata(&path);
        if attr.is_err() {
            continue;
        }
        let attr = attr.unwrap();

        if attr.is_file() && attr.len() > 0 {
            println!("Loading file {:?} ...", &path);
            let mut file = fs::File::open(path).expect("no file found");
            let mut buffer = vec![];
            file.read_to_end(&mut buffer).expect("buffer overflow");
            let input = BytesInput::new(buffer);
            initial_inputs.push(input);
        }
    }

    // The closure that we want to fuzz
    let mut harness = |input: &BytesInput| {
        let target_bytes = input.target_bytes();
        let bytes = target_bytes.as_slice();

        if is_sub(bytes, "fn".as_bytes()) {
            signals_set(2);
        }

        if is_sub(bytes, "pippopippo".as_bytes()) {
            signals_set(3);
        }

        signals_set(1);
        ExitKind::Ok
    };

    // Create an observation channel using the signals map
    // TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
    #[allow(static_mut_refs)] // only a problem in nightly
    let observer = unsafe {
        StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, SIGNALS.len()).track_novelties()
    };
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

    if state.metadata_map().get::<Tokens>().is_none() {
        state.add_metadata(Tokens::from([b"FOO".to_vec(), b"BAR".to_vec()]));
    }

    // The Monitor trait define how the fuzzer stats are reported to the user
    let monitor = SimpleMonitor::new(|s| println!("{s}"));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let generalization = GeneralizationStage::new(&observer);

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::with_max_stack_pow(havoc_mutations(), 2);
    let grimoire_mutator = StdScheduledMutator::with_max_stack_pow(
        tuple_list!(
            GrimoireExtensionMutator::new(),
            GrimoireRecursiveReplacementMutator::new(),
            GrimoireStringReplacementMutator::new(),
            // give more probability to avoid large inputs
            GrimoireRandomDeleteMutator::new(),
            GrimoireRandomDeleteMutator::new(),
        ),
        3,
    );
    let mut stages = tuple_list!(
        generalization,
        StdMutationalStage::new(mutator),
        StdMutationalStage::<_, _, GeneralizedInputMetadata, BytesInput, _, _, _>::transforming(
            grimoire_mutator
        )
    );

    for input in initial_inputs {
        fuzzer
            .evaluate_input(&mut state, &mut executor, &mut mgr, &input)
            .unwrap();
    }

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
