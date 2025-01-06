//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
//! In this example, you will see the use of the `launcher` feature.
//! The `launcher` will spawn new processes for each cpu core.
use core::{ptr::addr_of, time::Duration};
use std::{env, net::SocketAddr, path::PathBuf};

use clap::Parser;
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{EventConfig, Launcher},
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{
        havoc_mutations::havoc_mutations,
        scheduled::{tokens_mutations, StdScheduledMutator},
        token_mutations::Tokens,
    },
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{CoverageAccountingScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
    Error, HasMetadata,
};
use libafl_bolts::{
    core_affinity::Cores,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Merge},
    AsSlice,
};
use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, ACCOUNTING_MEMOP_MAP, EDGES_MAP,
    MAX_EDGES_FOUND,
};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Parse a millis string to a [`Duration`]. Used for arg parsing.
fn timeout_from_millis_str(time: &str) -> Result<Duration, Error> {
    Ok(Duration::from_millis(time.parse()?))
}

/// The commandline args this fuzzer accepts
#[derive(Debug, Parser)]
#[command(
    name = "libfuzzer_libpng_launcher",
    about = "A libfuzzer-like fuzzer for libpng with llmp-multithreading support and a launcher",
    author = "Andrea Fioraldi <andreafioraldi@gmail.com>, Dominik Maier <domenukk@gmail.com>"
)]
struct Opt {
    #[arg(
    short,
    long,
    value_parser = Cores::from_cmdline,
    help = "Spawn a client in each of the provided cores. Broker runs in the 0th core. 'all' to select all available cores. 'none' to run a client without binding to any core. eg: '1,2-4,6' selects the cores 1,2,3,4,6.",
    name = "CORES"
    )]
    cores: Cores,

    #[arg(
        short = 'p',
        long,
        help = "Choose the broker TCP port, default is 1337",
        name = "PORT",
        default_value = "1337"
    )]
    broker_port: u16,

    #[arg(short = 'a', long, help = "Specify a remote broker", name = "REMOTE")]
    remote_broker_addr: Option<SocketAddr>,

    #[arg(
        short,
        long,
        help = "Set an initial corpus directory",
        name = "INPUT",
        required = true
    )]
    input: Vec<PathBuf>,

    #[arg(
        short,
        long,
        help = "Set the output directory, default is ./out",
        name = "OUTPUT",
        default_value = "./out"
    )]
    output: PathBuf,

    #[arg(
    value_parser = timeout_from_millis_str,
    short,
    long,
    help = "Set the execution timeout in milliseconds, default is 10000",
    name = "TIMEOUT",
    default_value = "10000"
    )]
    timeout: Duration,
    /*
    /// This fuzzer has hard-coded tokens
    #[arg(

        short = "x",
        long,
        help = "Feed the fuzzer with an user-specified list of tokens (often called \"dictionary\"",
        name = "TOKENS",
        multiple = true
    )]
    tokens: Vec<PathBuf>,
    */
}

/// The main fn, `no_mangle` as it is a C symbol
#[no_mangle]
pub extern "C" fn libafl_main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    // unsafe { RegistryBuilder::register::<Tokens>(); }
    let opt = Opt::parse();

    let broker_port = opt.broker_port;
    let cores = opt.cores;

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let monitor = MultiMonitor::new(|s| println!("{s}"));

    let mut run_client = |state: Option<_>, mut restarting_mgr, _client_description| {
        // Create an observation channel using the coverage map
        // TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
        #[allow(static_mut_refs)] // only a problem on nightly
        let edges_observer = HitcountsMapObserver::new(unsafe {
            StdMapObserver::from_mut_ptr("edges", EDGES_MAP.as_mut_ptr(), MAX_EDGES_FOUND)
        })
        .track_indices();

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new(&edges_observer),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::new(),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(&opt.output).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });

        println!("We're a client, let's fuzz :)");

        // Create a PNG dictionary if not existing
        if state.metadata_map().get::<Tokens>().is_none() {
            state.add_metadata(Tokens::from(vec![
                vec![137, 80, 78, 71, 13, 10, 26, 10], // PNG header
                "IHDR".as_bytes().to_vec(),
                "IDAT".as_bytes().to_vec(),
                "PLTE".as_bytes().to_vec(),
                "IEND".as_bytes().to_vec(),
            ]));
        }

        // Setup a basic mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = CoverageAccountingScheduler::new(
            &edges_observer,
            &mut state,
            QueueScheduler::new(),
            unsafe { &*addr_of!(ACCOUNTING_MEMOP_MAP) },
        );

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            unsafe {
                libfuzzer_test_one_input(buf);
            }
            ExitKind::Ok
        };

        // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
        let mut executor = InProcessExecutor::with_timeout(
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut restarting_mgr,
            opt.timeout,
        )?;

        // The actual target run starts here.
        // Call LLVMFUzzerInitialize() if present.
        let args: Vec<String> = env::args().collect();
        if unsafe { libfuzzer_initialize(&args) } == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1");
        }

        // In case the corpus is empty (on first run), reset
        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut restarting_mgr, &opt.input)
                .unwrap_or_else(|e| {
                    panic!("Failed to load initial corpus at {:?} {:?}", &opt.input, e)
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
        Ok(())
    };

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("default"))
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(broker_port)
        .remote_broker_addr(opt.remote_broker_addr)
        //.stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
