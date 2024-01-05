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
    feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, MinMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes, MultipartInput},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
    Evaluator,
};
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice};

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 128] = [0; 128];
static mut SIGNALS_PTR: *mut u8 = unsafe { SIGNALS.as_mut_ptr() };

/// "Coverage" map for count, just to help things along
static mut LAST_COUNT: [usize; 1] = [usize::MAX];
static mut LAST_COUNT_PTR: *mut usize = unsafe { LAST_COUNT.as_mut_ptr() };

/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { write(SIGNALS_PTR.add(idx), 1) };
}

/// Assign a count to the count "map"
fn count_set(count: usize) {
    unsafe { LAST_COUNT[0] = count };
}

#[allow(clippy::similar_names, clippy::manual_assert)]
pub fn main() {
    // The closure that we want to fuzz
    let mut harness = |input: &MultipartInput<BytesInput>| {
        let mut count = input.parts().len();
        for (i, input) in input.parts().iter().enumerate() {
            let target = input.target_bytes();
            let buf = target.as_slice();
            signals_set(i * 8);
            if !buf.is_empty() && buf[0] == b'a' {
                signals_set(1 + i * 8);
                if buf.len() > 1 && buf[1] == b'b' {
                    signals_set(2 + i * 8);
                    if buf.len() > 2 && buf[2] == b'c' {
                        count -= 1;
                    }
                }
            }
        }
        if count == 0 {
            #[cfg(unix)]
            panic!("Artificial bug triggered =)");

            // panic!() raises a STATUS_STACK_BUFFER_OVERRUN exception which cannot be caught by the exception handler.
            // Here we make it raise STATUS_ACCESS_VIOLATION instead.
            // Extending the windows exception handler is a TODO. Maybe we can refer to what winafl code does.
            // https://github.com/googleprojectzero/winafl/blob/ea5f6b85572980bb2cf636910f622f36906940aa/winafl.c#L728
            #[cfg(windows)]
            unsafe {
                write_volatile(0 as *mut u32, 0);
            }
        }

        // without this, artificial bug is not found
        // maybe interesting to try to auto-derive this, researchers! :)
        count_set(count);

        ExitKind::Ok
    };

    // Create an observation channel using the signals map
    let signals_observer =
        unsafe { StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, SIGNALS.len()) };
    let mut count_observer =
        unsafe { StdMapObserver::from_mut_ptr("count", LAST_COUNT_PTR, LAST_COUNT.len()) };
    *count_observer.initial_mut() = usize::MAX; // we are minimising!

    // Feedback to rate the interestingness of an input
    let signals_feedback = MaxMapFeedback::new(&signals_observer);
    let count_feedback = MinMapFeedback::new(&count_observer);

    let mut feedback = feedback_or_fast!(count_feedback, signals_feedback);

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
        tuple_list!(signals_observer, count_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // a generator here is not generalisable
    let initial = MultipartInput::from([
        ("part", BytesInput::new(vec![b'h', b'e', b'l', b'l', b'o'])),
        ("part", BytesInput::new(vec![b'h', b'e', b'l', b'l', b'o'])),
        ("part", BytesInput::new(vec![b'h', b'e', b'l', b'l', b'o'])),
        ("part", BytesInput::new(vec![b'h', b'e', b'l', b'l', b'o'])),
    ]);

    fuzzer
        .evaluate_input(&mut state, &mut executor, &mut mgr, initial)
        .unwrap();

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
