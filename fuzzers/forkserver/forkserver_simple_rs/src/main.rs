use core::time::Duration;
use std::path::PathBuf;

use clap::Parser;
use libafl::{
    corpus::{Corpus, InMemoryCorpus},
    events::SimpleEventManager,
    executors::{forkserver::ForkserverExecutor, HasObservers, StdChildArgs},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, HavocScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::{tuple_list, Handled},
    AsSliceMut, StdTargetArgs, Truncate,
};
use nix::sys::signal::Signal;

#[derive(Debug, Parser)]
#[command(
    name = "forkserver_simple_rs",
    about = "A simple forkserver fuzzer with a Rust target binary."
)]
struct Opt {
    #[arg(
        help = "Timeout for each individual execution, in milliseconds",
        short = 't',
        long = "timeout",
        default_value = "1200"
    )]
    timeout: u64,

    #[arg(
        help = "If set, the child's stdout and stderr will be printed",
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

    #[arg(
        help = "Run the target in persistent mode",
        short = 'p',
        long = "persistent",
        default_value = "false"
    )]
    persistent: bool,
}

pub fn main() {
    env_logger::init();
    const MAP_SIZE: usize = 65536;

    let opt = Opt::parse();

    let mut shmem_provider = UnixShMemProvider::new().unwrap();

    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    unsafe {
        shmem.write_to_env("__AFL_SHM_ID").unwrap();
    }
    let shmem_buf = shmem.as_slice_mut();

    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)).track_indices()
    };

    let time_observer = TimeObserver::new("time");

    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::new(&time_observer)
    );

    let mut objective = feedback_and_fast!(
        CrashFeedback::new(),
        MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
    );

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<BytesInput>::new(),
        InMemoryCorpus::new(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);

    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let observer_ref = edges_observer.handle();

    let target_bin = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("target");
    let mut executor = ForkserverExecutor::builder()
        .program(target_bin)
        .debug_child(opt.debug_child)
        .shmem_provider(&mut shmem_provider)
        .parse_afl_cmdline(opt.arguments)
        .coverage_map_size(MAP_SIZE)
        .timeout(Duration::from_millis(opt.timeout))
        .kill_signal(opt.signal)
        .is_persistent(opt.persistent)
        .build(tuple_list!(time_observer, edges_observer))
        .unwrap();

    if let Some(dynamic_map_size) = executor.coverage_map_size() {
        executor.observers_mut()[&observer_ref]
            .as_mut()
            .truncate(dynamic_map_size);
    }

    // Add some initial inputs so the fuzzer has something to mutate
    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs_forced(
                &mut fuzzer,
                &mut executor,
                &mut mgr,
                &[PathBuf::from("./corpus")],
            )
            .expect("Failed to load initial inputs");
    }
    if state.must_load_initial_inputs() {
        // No inputs on disk, seed with a random byte
        state
            .corpus_mut()
            .add(BytesInput::new(vec![0x00]).into())
            .unwrap();
    }

    let mutator = HavocScheduledMutator::with_max_stack_pow(havoc_mutations(), 6);
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
