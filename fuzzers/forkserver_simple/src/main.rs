use clap::{App, Arg};
use core::time::Duration;
use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        shmem::{ShMem, ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge},
        AsMutSlice,
    },
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::forkserver::{ForkserverExecutor, TimeoutForkserverExecutor},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{scheduled::havoc_mutations, tokens_mutations, StdScheduledMutator, Tokens},
    observers::{ConstMapObserver, HitcountsMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, StdState},
};
use nix::sys::signal::Signal;
use std::path::PathBuf;

#[allow(clippy::similar_names)]
pub fn main() {
    let res = App::new("forkserver_simple")
        .about("Example Forkserver fuzer")
        .arg(
            Arg::new("executable")
                .help("The instrumented binary we want to fuzz")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("in")
                .help("The directory to read initial inputs from ('seeds')")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("timeout")
                .help("Timeout for each individual execution, in milliseconds")
                .short('t')
                .long("timeout")
                .default_value("1200"),
        )
        .arg(
            Arg::new("debug_child")
                .help("If not set, the child's stdout and stderror will be redirected to /dev/null")
                .short('d')
                .long("debug-child"),
        )
        .arg(
            Arg::new("arguments")
                .help("Arguments passed to the target")
                .setting(clap::ArgSettings::MultipleValues)
                .takes_value(true),
        )
        .arg(
            Arg::new("signal")
                .help("Signal used to stop child")
                .short('s')
                .long("signal")
                .default_value("SIGKILL"),
        )
        .get_matches();

    let corpus_dirs = vec![PathBuf::from(res.value_of("in").unwrap().to_string())];

    const MAP_SIZE: usize = 65536;

    // The default, OS-specific privider for shared memory
    let mut shmem_provider = StdShMemProvider::new().unwrap();
    // The coverage map shared between observer and executor
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // let the forkserver know the shmid
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let shmem_buf = shmem.as_mut_slice();

    // Create an observation channel using the signals map
    let edges_observer = HitcountsMapObserver::new(ConstMapObserver::<_, MAP_SIZE>::new(
        "shared_mem",
        shmem_buf,
    ));

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // The state of the edges feedback.
    let feedback_state = MapFeedbackState::with_observer(&edges_observer);

    // The state of the edges feedback for crashes.
    let objective_state = MapFeedbackState::new("crash_edges", MAP_SIZE);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, false),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new_with_observer(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    // We want to do the same crash deduplication that AFL does
    let objective = feedback_and_fast!(
        // Must be a crash
        CrashFeedback::new(),
        // Take it onlt if trigger new coverage over crashes
        MaxMapFeedback::new(&objective_state, &edges_observer)
    );

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
        // They are the data related to the feedbacks that you want to persist in the State.
        tuple_list!(feedback_state, objective_state),
    );

    // The Monitor trait define how the fuzzer stats are reported to the user
    let monitor = SimpleMonitor::new(|s| println!("{}", s));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // If we should debug the child
    let debug_child = res.is_present("debug_child");

    // Create the executor for the forkserver
    let args = match res.values_of("arguments") {
        Some(vec) => vec.map(|s| s.to_string()).collect::<Vec<String>>().to_vec(),
        None => [].to_vec(),
    };

    let mut tokens = Tokens::new();
    let forkserver = ForkserverExecutor::builder()
        .program(res.value_of("executable").unwrap().to_string())
        .debug_child(debug_child)
        .shmem_provider(&mut shmem_provider)
        .autotokens(&mut tokens)
        .parse_afl_cmdline(args)
        .build(tuple_list!(time_observer, edges_observer))
        .unwrap();

    let mut executor = TimeoutForkserverExecutor::with_signal(
        forkserver,
        Duration::from_millis(
            res.value_of("timeout")
                .unwrap()
                .to_string()
                .parse()
                .expect("Could not parse timeout in milliseconds"),
        ),
        res.value_of("signal").unwrap().parse::<Signal>().unwrap(),
    )
    .expect("Failed to create the executor.");

    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to load initial corpus at {:?}: {:?}",
                    &corpus_dirs, err
                )
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    state.add_metadata(tokens);

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
