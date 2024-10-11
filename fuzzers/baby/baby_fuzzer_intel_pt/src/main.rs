use std::{hint::black_box, path::PathBuf, time::Duration};

#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;
#[cfg(not(feature = "tui"))]
use libafl::monitors::SimpleMonitor;
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{
        hooks::intel_pt::{IntelPT, IntelPTHook},
        inprocess::GenericInProcessExecutor,
        ExitKind,
    },
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    mutators::{havoc_mutations::havoc_mutations, scheduled::StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice};

/// Coverage map
static mut SIGNALS: [u8; 1024] = [0; 1024];
static mut SIGNALS_PTR: *mut u8 = unsafe { SIGNALS.as_mut_ptr() };

#[allow(clippy::similar_names, clippy::manual_assert)]
pub fn main() {
    // Check that IntelPT is available
    // TODO: call availability if try_new fails in the lib?
    IntelPT::availability().expect("Intel PT check failed");

    // The closure that we want to fuzz
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        if !buf.is_empty() && buf[0] == b'a' {
            let _do_something = black_box(0);
            if buf.len() > 1 && buf[1] == b'b' {
                let _do_something = black_box(0);
                if buf.len() > 2 && buf[2] == b'c' {
                    panic!("Artificial bug triggered =)");
                }
            }
        }
        ExitKind::Ok
    };

    // Create an observation channel using the signals map
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, SIGNALS.len()) };

    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

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
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are displayed to the user
    #[cfg(not(feature = "tui"))]
    let mon = SimpleMonitor::new(|s| println!("{s}"));
    #[cfg(feature = "tui")]
    let mon = TuiMonitor::builder()
        .title("Baby Fuzzer Intel PT")
        .enhanced_graphics(false)
        .build();

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcases from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Intel PT hook that will handle the setup of Intel PT for each execution and fill the map
    let pt_hook = unsafe { IntelPTHook::new(SIGNALS_PTR, SIGNALS.len()) };

    type PTInProcessExecutor<'a, H, OT, S> =
        GenericInProcessExecutor<H, &'a mut H, (IntelPTHook, ()), OT, S>;
    // Create the executor for an in-process function with just one observer
    let mut executor = PTInProcessExecutor::with_timeout_generic(
        tuple_list!(pt_hook),
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        Duration::from_millis(5000),
    )
    .expect("Failed to create the Executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(32).unwrap();

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Set up a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
