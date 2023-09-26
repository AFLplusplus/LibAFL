#[cfg(windows)]
use std::ptr::write_volatile;
use std::{path::PathBuf, ptr::write};

#[cfg(feature = "tui")]
use libafl::monitors::tui::{ui::TuiUI, TuiMonitor};
#[cfg(not(feature = "tui"))]
use libafl::monitors::SimpleMonitor;
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    mutators::{StdScheduledMutator, StringCategoryRandMutator, StringSubcategoryRandMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::{mutational::StdMutationalStage, StringIdentificationStage},
    state::StdState,
    Evaluator,
};
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice};

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 64] = [0; 64];
static mut SIGNALS_PTR: *mut u8 = unsafe { SIGNALS.as_mut_ptr() };

/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { write(SIGNALS_PTR.add(idx), 1) };
}

#[allow(clippy::similar_names, clippy::manual_assert)]
pub fn main() {
    // The closure that we want to fuzz
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        let goal = b"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";
        let mut i = 0;
        for _ in buf.iter().zip(goal).take_while(|(b, c)| b == c) {
            signals_set(i);
            i += 1;
        }
        if i == goal.len() {
            #[cfg(unix)]
            panic!("Artificial bug triggered =)");

            #[cfg(windows)]
            unsafe {
                write_volatile(0 as *mut u32, 0);
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
    let ui = TuiUI::with_version(String::from("Baby Fuzzer"), String::from("0.0.1"), false);
    #[cfg(feature = "tui")]
    let mon = TuiMonitor::new(ui);

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

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

    // Generate 8 initial inputs
    fuzzer
        .evaluate_input(
            &mut state,
            &mut executor,
            &mut mgr,
            BytesInput::new(vec![b'a']),
        )
        .unwrap();

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(tuple_list!(
        StringCategoryRandMutator,
        StringSubcategoryRandMutator,
        StringSubcategoryRandMutator,
        StringSubcategoryRandMutator,
        StringSubcategoryRandMutator
    ));
    let mut stages = tuple_list!(
        StringIdentificationStage::new(),
        StdMutationalStage::transforming(mutator)
    );

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
