//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use clap::{self, StructOpt};
use frida_gum::Gum;
use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use libafl::{
    bolts::{
        current_nanos,
        launcher::Launcher,
        os::Cores,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge},
        AsSlice,
    },
    corpus::{
        ondisk::OnDiskMetadataFormat, CachedOnDiskCorpus, Corpus,
        IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus, QueueCorpusScheduler,
    },
    events::{llmp::LlmpRestartingEventManager, EventConfig},
    executors::{inprocess::InProcessExecutor, ExitKind, ShadowExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{
        scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
        token_mutations::I2SRandReplace,
        token_mutations::Tokens,
    },
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    stages::{ShadowTracingStage, StdMutationalStage},
    state::{HasCorpus, HasMetadata, StdState},
    Error,
};

use libafl_frida::{
    coverage_rt::CoverageRuntime, coverage_rt::MAP_SIZE, executor::FridaInProcessExecutor,
    helper::FridaInstrumentationHelper, FridaOptions,
};
use libafl_targets::cmplog::{CmpLogObserver, CMPLOG_MAP};

#[cfg(unix)]
use libafl_frida::asan::errors::{AsanErrorsFeedback, AsanErrorsObserver, ASAN_ERRORS};

#[derive(Debug, StructOpt)]
#[clap(
    name = "libafl_frida",
    version = "0.1.0",
    about = "A frida-based binary-only libfuzzer-style fuzzer for with llmp-multithreading support",
    author = "s1341 <github@shmarya.net>,
    Dongjia Zhang <toka@aflplus.plus>, Andrea Fioraldi <andreafioraldi@gmail.com>, Dominik Maier <domenukk@gmail.com>"
)]
struct Opt {
    #[clap(
        short,
        long,
        parse(try_from_str = Cores::from_cmdline),
        help = "Spawn a client in each of the provided cores. Broker runs in the 0th core. 'all' to select all available cores. 'none' to run a client without binding to any core. eg: '1,2-4,6' selects the cores 1,2,3,4,6.",
        name = "CORES"
    )]
    cores: Cores,

    #[clap(
        short = 'p',
        long,
        help = "Choose the broker TCP port, default is 1337",
        name = "PORT",
        default_value = "1337"
    )]
    broker_port: u16,

    #[clap(
        parse(try_from_str),
        short = 'a',
        long,
        help = "Specify a remote broker",
        name = "REMOTE"
    )]
    remote_broker_addr: Option<SocketAddr>,

    #[clap(
        parse(try_from_str),
        short,
        long,
        help = "Set an initial corpus directory",
        name = "INPUT"
    )]
    input: Vec<PathBuf>,

    #[clap(
        short,
        long,
        parse(try_from_str),
        help = "Set the output directory, default is ./out",
        name = "OUTPUT",
        default_value = "./out"
    )]
    output: PathBuf,

    #[clap(
        long,
        help = "The configuration this fuzzer runs with, for multiprocessing",
        name = "CONF",
        default_value = "default launcher"
    )]
    configuration: String,

    #[clap(
        long,
        help = "The file to redirect stdout input to (/dev/null if unset)"
    )]
    stdout_file: Option<String>,

    #[clap(help = "The harness")]
    harness: String,

    #[clap(help = "The symbol name to look up and hook")]
    symbol: String,

    #[clap(help = "The modules to instrument, separated by colons")]
    modules_to_instrument: String,
}

/// The main fn, usually parsing parameters, and starting the fuzzer
pub fn main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

    let opt = Opt::parse();
    color_backtrace::install();

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    unsafe {
        match fuzz(
            &opt.harness,
            &opt.symbol,
            &opt.modules_to_instrument.split(':').collect::<Vec<_>>(),
            //modules_to_instrument,
            &opt.input,
            &opt.output,
            opt.broker_port,
            &opt.cores,
            opt.stdout_file.as_deref(),
            opt.remote_broker_addr,
            opt.configuration,
        ) {
            Ok(()) | Err(Error::ShuttingDown) => println!("\nFinished fuzzing. Good bye."),
            Err(e) => panic!("Error during fuzzing: {:?}", e),
        }
    }
}

/// The actual fuzzer
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
unsafe fn fuzz(
    module_name: &str,
    symbol_name: &str,
    modules_to_instrument: &[&str],
    corpus_dirs: &[PathBuf],
    objective_dir: &Path,
    broker_port: u16,
    cores: &Cores,
    stdout_file: Option<&str>,
    broker_addr: Option<SocketAddr>,
    configuration: String,
) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let monitor = MultiMonitor::new(|s| println!("{}", s));

    let shmem_provider = StdShMemProvider::new()?;

    let mut run_client = |state: Option<StdState<_, _, _, _, _>>,
                          mut mgr: LlmpRestartingEventManager<_, _, _, _>,
                          _core_id| {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.

        // println!("{:?}", mgr.mgr_id());

        let lib = libloading::Library::new(module_name).unwrap();
        let target_func: libloading::Symbol<
            unsafe extern "C" fn(data: *const u8, size: usize) -> i32,
        > = lib.get(symbol_name.as_bytes()).unwrap();

        let mut frida_harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            (target_func)(buf.as_ptr(), buf.len());
            ExitKind::Ok
        };

        let gum = Gum::obtain();
        let frida_options = FridaOptions::parse_env_options();
        let coverage = CoverageRuntime::new();
        let mut frida_helper = FridaInstrumentationHelper::new(
            &gum,
            &frida_options,
            module_name,
            modules_to_instrument,
            tuple_list!(coverage),
        );

        // Create an observation channel using the coverage map
        let edges_observer = HitcountsMapObserver::new(StdMapObserver::new_from_ptr(
            "edges",
            frida_helper.map_ptr_mut(),
            MAP_SIZE,
        ));

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        let feedback_state = MapFeedbackState::with_observer(&edges_observer);
        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, false),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new_with_observer(&time_observer)
        );

        // Feedbacks to recognize an input as solution

        #[cfg(unix)]
        let objective = feedback_or_fast!(
            CrashFeedback::new(),
            TimeoutFeedback::new(),
            AsanErrorsFeedback::new()
        );

        #[cfg(windows)]
        let objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                CachedOnDiskCorpus::new(PathBuf::from("./corpus_discovered"), 64).unwrap(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new_save_meta(
                    objective_dir.to_path_buf(),
                    Some(OnDiskMetadataFormat::JsonPretty),
                )
                .unwrap(),
                // States of the feedbacks.
                // They are the data related to the feedbacks that you want to persist in the State.
                tuple_list!(feedback_state),
            )
        });

        println!("We're a client, let's fuzz :)");

        // Create a PNG dictionary if not existing
        if state.metadata().get::<Tokens>().is_none() {
            state.add_metadata(Tokens::new(vec![
                vec![137, 80, 78, 71, 13, 10, 26, 10], // PNG header
                b"IHDR".to_vec(),
                b"IDAT".to_vec(),
                b"PLTE".to_vec(),
                b"IEND".to_vec(),
            ]));
        }

        // Setup a basic mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // Create the executor for an in-process function with just one observer for edge coverage
        #[cfg(unix)]
        let mut executor = FridaInProcessExecutor::new(
            &gum,
            InProcessExecutor::new(
                &mut frida_harness,
                tuple_list!(
                    edges_observer,
                    time_observer,
                    AsanErrorsObserver::new(&ASAN_ERRORS)
                ),
                &mut fuzzer,
                &mut state,
                &mut mgr,
            )?,
            &mut frida_helper,
        );

        #[cfg(windows)]
        let mut executor = FridaInProcessExecutor::new(
            &gum,
            InProcessExecutor::new(
                &mut frida_harness,
                tuple_list!(edges_observer, time_observer,),
                &mut fuzzer,
                &mut state,
                &mut mgr,
            )?,
            &mut frida_helper,
        );

        // In case the corpus is empty (on first run), reset
        if state.corpus().count() < 1 {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, corpus_dirs)
                .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", &corpus_dirs));
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        if frida_options.cmplog_enabled() {
            // Create an observation channel using cmplog map
            let cmplog_observer = CmpLogObserver::new("cmplog", &mut CMPLOG_MAP, true);

            let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

            let tracing = ShadowTracingStage::new(&mut executor);

            // Setup a randomic Input2State stage
            let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(
                I2SRandReplace::new()
            )));

            // Setup a basic mutator
            let mutational = StdMutationalStage::new(mutator);

            // The order of the stages matter!
            let mut stages = tuple_list!(tracing, i2s, mutational);

            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        } else {
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        };
        Ok(())
    };

    Launcher::builder()
        .configuration(EventConfig::from_name(&configuration))
        .shmem_provider(shmem_provider)
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(cores)
        .broker_port(broker_port)
        .stdout_file(stdout_file)
        .remote_broker_addr(broker_addr)
        .build()
        .launch()
}
