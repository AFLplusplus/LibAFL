use std::path::PathBuf;

#[cfg(windows)]
use std::ptr::write_volatile;

use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        shmem::{unix_shmem, ShMem, ShMemProvider},
        tuples::tuple_list,
        AsMutSlice, AsSlice,
    },
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{ExitKind, InProcessForkExecutor},
    feedback_and,
    feedbacks::{
        CrashFeedback, MapFeedbackState, MaxMapFeedback, NewHashFeedback, NewHashFeedbackState,
    },
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{BacktraceObserver, StdMapObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};

#[allow(clippy::similar_names)]
pub fn main() {
    let mut shmem_provider = unix_shmem::UnixShMemProvider::new().unwrap();
    let mut signals = shmem_provider.new_shmem(16).unwrap();
    let mut signals_clone = signals.clone();
    let mut bt = shmem_provider.new_shmem_object::<Option<u64>>().unwrap();

    let mut signals_set = |idx: usize| {
        let a = signals.as_mut_slice();
        a[idx] = 1;
    };

    // The closure that we want to fuzz
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        signals_set(0);
        if !buf.is_empty() && buf[0] == b'a' {
            signals_set(1);
            if buf.len() > 1 && buf[1] == b'b' {
                signals_set(2);
                if buf.len() > 2 && buf[2] == b'c' {
                    #[cfg(unix)]
                    panic!("panic 1");
                }
                if buf.len() > 2 && buf[2] == b'd' {
                    #[cfg(unix)]
                    panic!("panic 2");
                }
                if buf.len() > 2 && buf[2] == b'e' {
                    #[cfg(unix)]
                    panic!("panic 3");
                }
            }
        }
        ExitKind::Ok
    };

    // Create an observation channel using the signals map
    let observer = StdMapObserver::new("signals", signals_clone.as_mut_slice());
    // Create a stacktrace observer
    let bt_observer = BacktraceObserver::new(
        "BacktraceObserver",
        unsafe { bt.as_object_mut::<Option<u64>>() },
        libafl::observers::HarnessType::Child,
    );

    // The state of the edges feedback.
    let feedback_state = MapFeedbackState::with_observer(&observer);
    let bt_feedback_state = NewHashFeedbackState::<u64>::with_observer(&bt_observer);

    // Feedback to rate the interestingness of an input, obtained by ANDing the interestingness of both feedbacks
    let feedback = MaxMapFeedback::new(&feedback_state, &observer);

    // A feedback to choose if an input is a solution or not
    let objective = feedback_and!(
        CrashFeedback::new(),
        NewHashFeedback::<BacktraceObserver>::new_with_observer("BacktraceObserver", &bt_observer)
    );

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
        tuple_list!(feedback_state, bt_feedback_state),
    );

    // The Monitor trait define how the fuzzer stats are displayed to the user
    let mon = SimpleMonitor::new(|s| println!("{}", s));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessForkExecutor::new(
        &mut harness,
        tuple_list!(observer, bt_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        shmem_provider,
    )
    .expect("Failed to create the Executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(32);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
