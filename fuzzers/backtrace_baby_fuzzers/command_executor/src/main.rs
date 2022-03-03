use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        shmem::{unix_shmem, ShMem, ShMemId, ShMemProvider},
        tuples::tuple_list,
        AsMutSlice, AsSlice,
    },
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::command::CommandConfigurator,
    feedback_and,
    feedbacks::{
        CrashFeedback, MapFeedbackState, MaxMapFeedback, NewHashFeedback, NewHashFeedbackState,
    },
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{HasTargetBytes, Input},
    monitors::SimpleMonitor,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{get_asan_runtime_flags, ASANBacktraceObserver, StdMapObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
    Error,
};
#[cfg(windows)]
use std::ptr::write_volatile;
use std::{
    io::Write,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

#[allow(clippy::similar_names)]
pub fn main() {
    let mut shmem_provider = unix_shmem::UnixShMemProvider::new().unwrap();
    let mut signals = shmem_provider.new_shmem(3).unwrap();
    let shmem_id = signals.id();

    // Create an observation channel using the signals map
    let observer = StdMapObserver::new("signals", signals.as_mut_slice());
    // Create a stacktrace observer
    let bt_observer = ASANBacktraceObserver::new("ASANBacktraceObserver");

    // The state of the edges feedback.
    let feedback_state = MapFeedbackState::with_observer(&observer);
    let bt_feedback_state = NewHashFeedbackState::<u64>::with_observer(&bt_observer);

    // Feedback to rate the interestingness of an input, obtained by ANDing the interestingness of both feedbacks
    let feedback = MaxMapFeedback::new(&feedback_state, &observer);

    // A feedback to choose if an input is a solution or not
    let objective = feedback_and!(
        CrashFeedback::new(),
        NewHashFeedback::<ASANBacktraceObserver>::new_with_observer(
            "ASANBacktraceObserver",
            &bt_observer
        )
    );
    // let objective = CrashFeedback::new();

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
    #[derive(Debug)]
    struct MyExecutor {
        shmem_id: ShMemId,
    }

    impl CommandConfigurator for MyExecutor {
        fn spawn_child<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<Child, Error> {
            let mut command = Command::new("./test_command");

            let command = command
                .args(&[self.shmem_id.as_str()])
                .env("ASAN_OPTIONS", get_asan_runtime_flags());

            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            let child = command.spawn().expect("failed to start process");
            let mut stdin = child.stdin.as_ref().unwrap();
            stdin.write_all(input.target_bytes().as_slice())?;
            Ok(child)
        }
    }

    let mut executor = MyExecutor { shmem_id }.into_executor(tuple_list!(observer, bt_observer));

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
