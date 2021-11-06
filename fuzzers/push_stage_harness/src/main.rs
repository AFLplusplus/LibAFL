//! A fuzzer that uses a `PushStage`, generating input to be subsequently executed,
//! instead of executing input iteslf in a loop.
//! Using this method, we can add LibAFL, for example, into an emulation loop
//! or use its mutations for another fuzzer.
//! This is a less hacky alternative to the `KloRoutines` based fuzzer, that will also work on non-`Unix`.

use core::cell::{Cell, RefCell};
use std::{path::PathBuf, rc::Rc};

use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list},
    corpus::{
        Corpus, CorpusScheduler, InMemoryCorpus, OnDiskCorpus, QueueCorpusScheduler, Testcase,
    },
    events::SimpleEventManager,
    executors::ExitKind,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback},
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    stages::push::StdMutationalPushStage,
    state::{HasCorpus, StdState},
    stats::SimpleStats,
};

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];

/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { SIGNALS[idx] = 1 };
}

#[allow(clippy::similar_names)]
pub fn main() {
    // Create an observation channel using the signals map
    let observer = StdMapObserver::new("signals", unsafe { &mut SIGNALS });

    // The state of the edges feedback.
    let feedback_state = MapFeedbackState::with_observer(&observer);

    // Feedback to rate the interestingness of an input
    let feedback = MaxMapFeedback::<_, BytesInput, _, _, _>::new(&feedback_state, &observer);

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
    let mgr = SimpleEventManager::new(stats);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueCorpusScheduler::new();

    // Create the executor for an in-process function with just one observer
    //let mut executor = InProcessExecutor::new(&mut harness, &mut fuzzer, &mut state, &mut mgr)
    //    .expect("Failed to create the Executor");

    let testcase = Testcase::new(BytesInput::new(b"aaaa".to_vec()));
    //self.feedback_mut().append_metadata(state, &mut testcase)?;
    let idx = state.corpus_mut().add(testcase).unwrap();
    scheduler.on_add(&mut state, idx).unwrap();

    // A fuzzer with feedbacks and a corpus scheduler
    let fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Generate 8 initial inputs
    //state.generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8);
    //    .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());

    let exit_kind = Rc::new(Cell::new(None));

    let stage_idx = 0;

    let observers = tuple_list!(observer);

    // All fuzzer elements are hidden behind Rc<RefCell>>, so we can reuse them for multiple stages.
    let push_stage = StdMutationalPushStage::new(
        mutator,
        Rc::new(RefCell::new(fuzzer)),
        Rc::new(RefCell::new(state)),
        Rc::new(RefCell::new(mgr)),
        Rc::new(RefCell::new(observers)),
        exit_kind.clone(),
        stage_idx,
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
