use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[cfg(windows)]
use std::ptr::write_volatile;
use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

use clap::Parser;
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::{launcher::Launcher, llmp::LlmpEventConverter, EventConfig},
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, NautilusChunksMetadata, NautilusFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{NautilusContext, NautilusGenerator},
    inputs::{NautilusInput, NautilusToBytesInputConverter},
    monitors::SimpleMonitor,
    mutators::{
        NautilusRandomMutator, NautilusRecursionMutator, NautilusSpliceMutator, StdScheduledMutator,
    },
    none_input_converter,
    schedulers::QueueScheduler,
    stages::{mutational::StdMutationalStage, sync::SyncFromBrokerStage},
    state::StdState,
    Error, HasMetadata,
};
use libafl_bolts::{
    core_affinity::Cores,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer};

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
        default_value = "1338"
    )]
    broker_port: u16,

    #[arg(
        short = 'b',
        long,
        help = "Specify a BytesInput broker TCP port",
        name = "BYTESPORT"
    )]
    bytes_broker_port: Option<u16>,

    #[arg(short = 'a', long, help = "Specify a remote broker", name = "REMOTE")]
    remote_broker_addr: Option<SocketAddr>,

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
        help = "Set the exeucution timeout in milliseconds, default is 10000",
        name = "TIMEOUT",
        default_value = "10000"
    )]
    timeout: Duration,
}

/// The main fn, `no_mangle` as it is a C symbol
#[no_mangle]
#[allow(clippy::missing_panics_doc, clippy::too_many_lines)]
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

    // The Monitor trait define how the fuzzer stats are reported to the user
    let monitor = SimpleMonitor::new(|s| println!("{s}"));

    let context = NautilusContext::from_file(15, "grammar.json").unwrap();

    let mut event_converter = opt.bytes_broker_port.map(|port| {
        LlmpEventConverter::builder()
            .build_on_port(
                shmem_provider.clone(),
                port,
                Some(NautilusToBytesInputConverter::new(&context)),
                none_input_converter!(),
            )
            .unwrap()
    });

    // to disconnect the event coverter from the broker later
    // call detach_from_broker( port)

    let mut run_client = |state: Option<_>, mut mgr, _client_description| {
        let mut bytes = vec![];

        // The closure that we want to fuzz
        let mut harness = |input: &NautilusInput| {
            input.unparse(&context, &mut bytes);
            unsafe {
                libfuzzer_test_one_input(&bytes);
            }
            ExitKind::Ok
        };

        // Create an observation channel using the coverage map
        let observer = unsafe { std_edges_map_observer("edges") };

        // Feedback to rate the interestingness of an input
        let mut feedback = feedback_or!(
            MaxMapFeedback::new(&observer),
            NautilusFeedback::new(&context)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = CrashFeedback::new();

        // create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::new(),
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
            .unwrap()
        });

        if state
            .metadata_map()
            .get::<NautilusChunksMetadata>()
            .is_none()
        {
            state.add_metadata(NautilusChunksMetadata::new("/tmp/".into()));
        }

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

        // The actual target run starts here.
        // Call LLVMFUzzerInitialize() if present.
        let args: Vec<String> = env::args().collect();
        if unsafe { libfuzzer_initialize(&args) } == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1");
        }

        let mut generator = NautilusGenerator::new(&context);

        // Generate 8 initial inputs
        state
            .generate_initial_inputs_forced(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
            .expect("Failed to generate the initial corpus");

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

        if let Some(conv) = event_converter.take() {
            let mut stages = tuple_list!(
                StdMutationalStage::new(mutator),
                SyncFromBrokerStage::new(conv)
            );

            fuzzer
                .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                .expect("Error in the fuzzing loop");
        } else {
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            fuzzer
                .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                .expect("Error in the fuzzing loop");
        }

        Ok(())
    };

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("nautilus"))
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(broker_port)
        .remote_broker_addr(opt.remote_broker_addr)
        .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
