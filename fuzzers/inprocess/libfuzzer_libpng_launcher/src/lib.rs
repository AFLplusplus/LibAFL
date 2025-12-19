//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
//! In this example, you will see the use of the `launcher` feature.
//! The `launcher` will spawn new processes for each cpu core.
use core::time::Duration;
use std::{env, net::SocketAddr, path::PathBuf};

use clap::{self, Parser};
#[cfg(feature = "statsd")]
use libafl::monitors::statsd::StatsdMonitorTagFlavor;
#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{
        launcher::Launcher, ClientDescription, EventConfig, EventFirer, EventReceiver,
        EventRestarter, EventWithStats, HasEventManagerId, ProgressReporter, SendExiting,
    },
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::{
        stats::{user_stats::TAG_CORE_ID, AggregatorOps, UserStats, UserStatsValue},
        MultiMonitor, OnDiskTomlMonitor,
    },
    mutators::{
        havoc_mutations::havoc_mutations,
        scheduled::{tokens_mutations, HavocScheduledMutator},
        token_mutations::Tokens,
    },
    observers::{CanTrack, HitcountsMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{
        afl_stats::AflStatsStage, calibrate::CalibrationStage, mutational::StdMutationalStage,
    },
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
use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

type FuzzerState =
    StdState<InMemoryCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;

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
    help = "Spawn clients in each of the provided cores. Broker runs in the 0th core. 'all' to select all available cores. 'none' to run a client without binding to any core. eg: '1,2-4,6' selects the cores 1,2,3,4,6.",
    name = "CORES"
    )]
    cores: Cores,

    #[arg(
        long,
        help = "Spawn n clients on each core, this is useful if clients don't fully load a client, e.g. because they `sleep` often.",
        name = "OVERCOMMIT",
        default_value = "1"
    )]
    overcommit: usize,

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
    help = "Set the exeucution timeout in milliseconds, default is 10000",
    name = "TIMEOUT",
    default_value = "10000"
    )]
    timeout: Duration,
    #[cfg(feature = "statsd")]
    #[arg(
        long,
        help = "Host for StatsD",
        name = "STATSD_HOST",
        default_value = "127.0.0.1"
    )]
    statsd_host: String,

    #[cfg(feature = "statsd")]
    #[arg(
        long,
        help = "Port for StatsD",
        name = "STATSD_PORT",
        default_value = "8125"
    )]
    statsd_port: u16,

    #[cfg(feature = "statsd")]
    #[arg(long, help = "Enable StatsD", name = "STATSD", default_value = "false")]
    statsd: bool,

    #[cfg(feature = "tui")]
    #[arg(long, help = "Enable TUI", name = "TUI", default_value = "false")]
    tui: bool,
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
    #[arg(long, help = "Use fork mode (Launcher fork)")]
    fork: bool,
    #[arg(long, help = "Crash after this many iterations")]
    crash_after: Option<u64>,
    #[cfg(feature = "tcp_manager")]
    #[arg(
        long,
        help = "Use TCP event manager for IPC instead of LLMP (slower, but might have its benefits?)"
    )]
    tcp: bool,
}

fn print_fmt(s: &str) {
    println!("{s}");
}

/// The main fn, `no_mangle` as it is a C symbol
#[no_mangle]
pub extern "C" fn libafl_main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    // unsafe { RegistryBuilder::register::<Tokens>(); }
    let opt = Opt::parse();
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    libafl_bolts::SimpleStdoutLogger::set_logger().unwrap();
    log::set_max_level(log::LevelFilter::Info);

    // for testing purposes in CI only. No need to do this for normal fuzzing
    if let Some(iters) = opt.crash_after {
        env::set_var("LIBAFL_CRASH_AFTER", iters.to_string());
    }

    let broker_port = opt.broker_port;
    let cores = opt.cores.clone();

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    #[cfg(feature = "statsd")]
    let statsd = libafl::monitors::OptionalMonitor::new(if opt.statsd {
        Some(
            libafl::monitors::StatsdMonitor::new(
                opt.statsd_host.clone(),
                opt.statsd_port,
                StatsdMonitorTagFlavor::default(),
            )
            .with_per_client_stats(true),
        )
    } else {
        None
    });

    let m_ondisk = OnDiskTomlMonitor::new("./fuzzer_stats.toml");
    let m_multi = libafl::monitors::OptionalMonitor::new(
        #[cfg(feature = "tui")]
        if !opt.tui {
            Some(MultiMonitor::new(print_fmt))
        } else {
            None
        },
        #[cfg(not(feature = "tui"))]
        Some(MultiMonitor::new(print_fmt)),
    );

    #[cfg(feature = "tui")]
    let m_tui = libafl::monitors::OptionalMonitor::new(if opt.tui {
        Some(
            TuiMonitor::builder()
                .title("libfuzzer_libpng")
                .enhanced_graphics(true)
                .build(),
        )
    } else {
        None
    });

    #[cfg(all(not(feature = "tui"), not(feature = "statsd")))]
    let monitor = (m_ondisk, (m_multi, ()));

    #[cfg(all(feature = "tui", not(feature = "statsd")))]
    let monitor = (m_ondisk, (m_multi, (m_tui, ())));

    #[cfg(all(not(feature = "tui"), feature = "statsd"))]
    let monitor = (m_ondisk, (m_multi, (statsd, ())));

    #[cfg(all(feature = "tui", feature = "statsd"))]
    let monitor = (m_ondisk, (m_multi, (m_tui, (statsd, ()))));

    fn run_client<EM>(
        state: Option<FuzzerState>,
        mut restarting_mgr: EM,
        client_description: ClientDescription,
        opt: &Opt,
    ) -> Result<(), Error>
    where
        EM: EventFirer<BytesInput, FuzzerState>
            + EventRestarter<FuzzerState>
            + HasEventManagerId
            + ProgressReporter<FuzzerState>
            + EventReceiver<BytesInput, FuzzerState>
            + SendExiting,
    {
        println!(
            "DEBUG: run_client started for client {:?}",
            client_description
        );
        // Send the core_id to the monitor
        let core_id = client_description.core_id();

        // Create an observation channel using the signals map
        let map_observer = unsafe { std_edges_map_observer("edges") };
        let map_ptr = map_observer.as_slice().as_ptr();
        let map_len = map_observer.as_slice().len();
        println!("DEBUG: Edges map ptr: {:p}, len: {}", map_ptr, map_len);
        let edges_observer = HitcountsMapObserver::new(map_observer).track_indices();
        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let map_feedback = MaxMapFeedback::new(&edges_observer);
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            map_feedback.clone(),
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

        restarting_mgr.fire(
            &mut state,
            EventWithStats::with_current_time(
                libafl::events::Event::UpdateUserStats {
                    name: "core_id".to_string().into(),
                    value: UserStats::with_tag(
                        UserStatsValue::String(core_id.0.to_string().into()),
                        AggregatorOps::None,
                        TAG_CORE_ID,
                    ),
                    phantom: Default::default(),
                },
                0,
            ),
        )?;

        // Create a PNG dictionary if not existing
        if state.metadata_map().get::<Tokens>().is_none() {
            state.add_metadata(Tokens::from([
                vec![137, 80, 78, 71, 13, 10, 26, 10], // PNG header
                "IHDR".as_bytes().to_vec(),
                "IDAT".as_bytes().to_vec(),
                "PLTE".as_bytes().to_vec(),
                "IEND".as_bytes().to_vec(),
            ]));
        }

        // Setup a basic mutator with a mutational stage
        let mutator = HavocScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
        let calibration = CalibrationStage::new(&map_feedback);
        let afl_stats = AflStatsStage::builder()
            .map_feedback(&map_feedback)
            .stats_file(opt.output.join("fuzzer_stats"))
            .report_interval(Duration::from_millis(1000))
            .core_id(core_id)
            .banner("libfuzzer_libpng".into())
            .version("0.16.0".into())
            .target_mode("LibFuzzer".into())
            .build()
            .unwrap();

        let mut stages = tuple_list!(calibration, StdMutationalStage::new(mutator), afl_stats);

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

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
                .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", &opt.input));
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        let result = fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr);
        result?;
        restarting_mgr.on_restart(&mut state)?;
        Ok(())
    }

    #[cfg(feature = "tcp_manager")]
    if opt.tcp {
        println!("Running in TCP mode");
        let builder = Launcher::builder()
            .shmem_provider(shmem_provider)
            .configuration(EventConfig::from_name("default"))
            .monitor(monitor)
            .run_client(|s, m, c| run_client(s, m, c, &opt))
            .cores(&cores)
            .overcommit(opt.overcommit)
            .broker_port(broker_port)
            .remote_broker_addr(opt.remote_broker_addr);

        #[cfg(unix)]
        let builder = builder.fork(opt.fork);

        builder
            .build()
            .launch_tcp(tuple_list!())
            .expect("Failed to launch TCP manager");
        return;
    }

    let builder = Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("default"))
        .monitor(monitor)
        .run_client(|s, m, c| run_client(s, m, c, &opt))
        .cores(&cores)
        .overcommit(opt.overcommit)
        .broker_port(broker_port)
        .remote_broker_addr(opt.remote_broker_addr);

    #[cfg(unix)]
    let builder = builder.fork(opt.fork);

    match builder.build().launch() {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
