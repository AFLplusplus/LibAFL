use core::time::Duration;
use std::path::PathBuf;

use clap::Parser;
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{forkserver::ForkserverExecutor, HasObservers},
    feedback_and_fast, feedback_or,
    feedbacks::{
        CrashFeedback, MaxMapFeedback, NautilusChunksMetadata, NautilusFeedback, TimeFeedback,
    },
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{NautilusContext, NautilusGenerator},
    inputs::{NautilusInput, NautilusTargetBytesConverter},
    monitors::SimpleMonitor,
    mutators::{
        NautilusRandomMutator, NautilusRecursionMutator, NautilusSpliceMutator,
        StdScheduledMutator, Tokens,
    },
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::StdState,
    HasMetadata,
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::{tuple_list, Handled},
    AsSliceMut, Truncate,
};
use nix::sys::signal::Signal;

/// The commandline args this fuzzer accepts
#[derive(Debug, Parser)]
#[command(
    name = "forkserver_simple",
    about = "This is a simple example fuzzer to fuzz a executable instrumented by afl-cc, using Nautilus grammar.",
    author = "tokatoka <tokazerkje@outlook.com>, dmnk <domenukk@gmail.com>"
)]
struct Opt {
    #[arg(
        help = "The instrumented binary we want to fuzz",
        name = "EXEC",
        required = true
    )]
    executable: String,

    #[arg(
        help = "Timeout for each individual execution, in milliseconds",
        short = 't',
        long = "timeout",
        default_value = "1200"
    )]
    timeout: u64,

    #[arg(
        help = "If not set, the child's stdout and stderror will be redirected to /dev/null",
        short = 'd',
        long = "debug-child",
        default_value = "false"
    )]
    debug_child: bool,

    #[arg(
        help = "Arguments passed to the target",
        name = "arguments",
        num_args(1..),
        allow_hyphen_values = true,
    )]
    arguments: Vec<String>,

    #[arg(
        help = "Signal used to stop child",
        short = 's',
        long = "signal",
        value_parser = str::parse::<Signal>,
        default_value = "SIGKILL"
    )]
    signal: Signal,

    #[arg(help = "The nautilus grammar file", short)]
    grammar: PathBuf,
}

pub fn main() {
    env_logger::init();
    const MAP_SIZE: usize = 65536;

    let opt = Opt::parse();

    let mut shmem_provider = UnixShMemProvider::new().unwrap();

    // The coverage map shared between observer and executor
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();

    unsafe {
        // let the forkserver know the shmid
        shmem.write_to_env("__AFL_SHM_ID").unwrap();
    }

    let shmem_buf = shmem.as_slice_mut();

    // Create an observation channel using the signals map
    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)).track_indices()
    };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let context = NautilusContext::from_file(15, opt.grammar).unwrap();

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new(&edges_observer),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer),
        // Nautilus context
        NautilusFeedback::new(&context),
    );

    // A feedback to choose if an input is a solution or not
    // We want to do the same crash deduplication that AFL does
    let mut objective = feedback_and_fast!(
        // Must be a crash
        CrashFeedback::new(),
        // Take it only if trigger new coverage over crashes
        // Uses `with_name` to create a different history from the `MaxMapFeedback` in `feedback` above
        MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
    );

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::<NautilusInput>::new(),
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

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // If we should debug the child
    let debug_child = opt.debug_child;

    // Create the executor for the forkserver
    let args = opt.arguments;

    let observer_ref = edges_observer.handle();

    let mut tokens = Tokens::new();
    let mut executor = ForkserverExecutor::builder()
        .program(opt.executable)
        .debug_child(debug_child)
        .shmem_provider(&mut shmem_provider)
        .autotokens(&mut tokens)
        .parse_afl_cmdline(args)
        .coverage_map_size(MAP_SIZE)
        .timeout(Duration::from_millis(opt.timeout))
        .kill_signal(opt.signal)
        .target_bytes_converter(NautilusTargetBytesConverter::new(&context))
        .build(tuple_list!(time_observer, edges_observer))
        .unwrap();

    if let Some(dynamic_map_size) = executor.coverage_map_size() {
        executor.observers_mut()[&observer_ref]
            .as_mut()
            .truncate(dynamic_map_size);
    }

    let mut generator = NautilusGenerator::new(&context);

    if state.must_load_initial_inputs() {
        state
            .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
            .expect("Failed to generate inputs");
    }

    state.add_metadata(tokens);

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
