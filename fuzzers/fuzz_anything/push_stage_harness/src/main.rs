//! A fuzzer that uses a `PushStage`, generating input to be subsequently executed,
//! instead of executing input iteslf in a loop.
//! Using this method, we can add `LibAFL`, for example, into an emulation loop
//! or use its mutations for another fuzzer.
//! This is a less hacky alternative to the `KloRoutines` based fuzzer, that will also work on non-`Unix`.

use core::cell::{Cell, RefCell};
use std::{path::PathBuf, rc::Rc};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    executors::ExitKind,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::{QueueScheduler, Scheduler},
    stages::push::{PushStageSharedState, StdMutationalPushStage},
    state::{HasCorpus, StdState},
};
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice};

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];

/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { SIGNALS[idx] = 1 };
}

#[expect(clippy::manual_assert)]
pub fn main() {
    // Create an observation channel using the signals map
    // TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
    #[allow(static_mut_refs)] // only a problem in nightly
    let observer =
        unsafe { StdMapObserver::from_mut_ptr("signals", SIGNALS.as_mut_ptr(), SIGNALS.len()) };

    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::<BytesInput>::new(),
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
    let mgr = SimpleEventManager::new(monitor);

    // A queue policy to get testcasess from the corpus
    let mut scheduler = QueueScheduler::new();

    // Create the executor for an in-process function with just one observer
    //let mut executor = InProcessExecutor::new(tuple_list!(), &mut harness, &mut fuzzer, &mut state, &mut mgr)
    //    .expect("Failed to create the Executor");

    let testcase = Testcase::new(BytesInput::new(b"aaaa".to_vec()));
    //self.feedback_mut().append_metadata(state, &mut testcase)?;
    let idx = state.corpus_mut().add(testcase).unwrap();
    <QueueScheduler as Scheduler<BytesInput, _>>::on_add(&mut scheduler, &mut state, idx).unwrap();

    // A fuzzer with feedbacks and a corpus scheduler
    let fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Generate 8 initial inputs
    //state.generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8);
    //    .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());

    let exit_kind = Rc::new(Cell::new(None));

    let observers = tuple_list!(observer);

    let shared_state = PushStageSharedState::new(fuzzer, state, observers, mgr);

    // All fuzzer elements are hidden behind Rc<RefCell>>, so we can reuse them for multiple stages.
    let push_stage = StdMutationalPushStage::new(
        mutator,
        Rc::new(RefCell::new(Some(shared_state))),
        exit_kind.clone(),
    );

    // Loop, the input, getting a new entry from the push stage each iteration.
    for input in push_stage {
        let input = input.unwrap();
        let target = input.target_bytes();
        let buf = target.as_slice();
        signals_set(0);
        if !buf.is_empty() && buf[0] == b'a' {
            signals_set(1);
            if buf.len() > 1 && buf[1] == b'b' {
                signals_set(2);
                if buf.len() > 2 && buf[2] == b'c' {
                    panic!("=)");
                }
            }
        }
        (*exit_kind).replace(Some(ExitKind::Ok));
    }

    println!("One iteration done.");
}
