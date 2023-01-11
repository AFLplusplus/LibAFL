// LibJIF provides a rust static library which can get linked into chrome (or another browser that meets
// the contract of LibJIF) and implements a feedback driven XSS fuzzer using grimoire and cmplog.

use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use core::time::Duration;
use libafl::events::EventRestarter;
use libafl::prelude::Cores;
use libafl::prelude::GeneralizationStage;
use libafl::prelude::GeneralizedInput;
use libafl::prelude::LlmpRestartingEventManager;
use libafl::prelude::SkippableStage;
use libafl::prelude::TokenInsert;
use libafl::Evaluator;
use libafl::{
    bolts::{
        current_nanos,
        launcher::Launcher,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
        AsSlice,
    },
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::EventConfig,
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or,
    feedbacks::MaxMapFeedback,
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::HasTargetBytes,
    monitors::MultiMonitor,
    mutators::mutations::{
        BytesDeleteMutator, CrossoverInsertMutator, CrossoverReplaceMutator, SpliceMutator,
    },
    mutators::{
        scheduled::StdScheduledMutator,
        token_mutations::{I2SRandReplace, Tokens},
        GrimoireExtensionMutator, GrimoireRandomDeleteMutator, GrimoireRecursiveReplacementMutator,
        GrimoireStringReplacementMutator,
    },
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::QueueScheduler,
    stages::{calibrate::CalibrationStage, StdMutationalStage, TracingStage},
    state::{HasCorpus, HasMaxSize, HasMetadata, StdState},
    Error,
};
use std::{env, fs, io::Read, net::SocketAddr, path::PathBuf};
use structopt::StructOpt;

use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, CmpLogObserver, CMPLOG_MAP, EDGES_MAP,
    MAX_EDGES_NUM,
};

mod js;
mod mutators;
mod rvf;
use crate::js::JSFeedback;
use crate::js::JSMapState;
use crate::js::JSObserver;
use crate::rvf::ReturnValueFeedback;
use mutators::TagCopyMutator;
use mutators::TagCrossoverMutator;
use mutators::TagDeleteMutator;
use mutators::TagTokenMutator;

use atomic_counter::AtomicCounter;
use atomic_counter::RelaxedCounter;

const NUM_ITERATIONS: usize = 10_000;

/// Parses a millseconds int into a [`Duration`], used for commandline arg parsing
fn timeout_from_millis_str(time: &str) -> Result<Duration, Error> {
    Ok(Duration::from_millis(time.parse()?))
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "jif",
    about = "JIF: Javascript Injection Fuzzer",
    author = "jhertz"
)]
struct Opt {
    #[structopt(
        short,
        long,
        parse(try_from_str = Cores::from_cmdline),
        help = "Spawn a client in each of the provided cores. Broker runs in the 0th core. 'all' to select all available cores. 'none' to run a client without binding to any core. eg: '1,2-4,6' selects the cores 1,2,3,4,6.",
        name = "CORES"
    )]
    cores: Cores,

    #[structopt(
        short = "p",
        long,
        help = "Choose the broker TCP port, default is 1337",
        name = "PORT"
    )]
    broker_port: u16,

    #[structopt(
        parse(try_from_str),
        short = "a",
        long,
        help = "Specify a remote broker",
        name = "REMOTE"
    )]
    remote_broker_addr: Option<SocketAddr>,

    #[structopt(
        parse(try_from_str),
        short,
        long,
        help = "Set an initial corpus directory",
        name = "INPUT"
    )]
    input: PathBuf,

    #[structopt(
        short,
        long,
        parse(try_from_str),
        help = "Set the output directory, default is ./out",
        name = "OUTPUT",
        default_value = "./out"
    )]
    output: PathBuf,

    #[structopt(
        help = "Path for the JS file with the harness to run inputs through",
        name = "HARNESS",
        long = "harness",
        parse(from_os_str)
    )]
    harness: PathBuf,

    #[structopt(
        parse(try_from_str = timeout_from_millis_str),
        short,
        long,
        help = "Set the exeucution timeout in milliseconds, default is 1000",
        name = "TIMEOUT",
        default_value = "1000"
    )]
    timeout: Duration,

    #[structopt(
        parse(from_os_str),
        short = "x",
        long,
        help = "Feed the fuzzer with an user-specified list of tokens (often called \"dictionary\"",
        name = "TOKENS",
        multiple = true
    )]
    tokens: Vec<PathBuf>,

    #[structopt(
        help = "File to run instead of doing fuzzing loop",
        name = "REPRO",
        long = "repro",
        parse(from_os_str)
    )]
    repro_file: Option<PathBuf>,

    // several new flags, -g for grimoire -b for bytes -t for tags
    #[structopt(
        help = "Use grimoire mutator",
        name = "GRIMOIRE",
        long = "grimoire",
        short = "g"
    )]
    grimoire: bool,

    #[structopt(
        help = "Use bytes mutator",
        name = "BYTES",
        long = "bytes",
        short = "b"
    )]
    bytes: bool,

    #[structopt(help = "Use tags mutator", name = "TAGS", long = "tags", short = "t")]
    tags: bool,

    #[structopt(
        help = "Use cmplog mutator",
        name = "CMPLOG",
        long = "cmplog",
        short = "c"
    )]
    cmplog: bool,
}

/// The main fn, `no_mangle` as it is a C symbol
#[allow(clippy::too_many_lines)]
#[no_mangle]
pub extern "C" fn main() {
    let _args: Vec<String> = env::args().collect();
    let workdir = env::current_dir().unwrap();
    let opt = Opt::from_args();
    let cores = opt.cores;
    let broker_port = opt.broker_port;
    let remote_broker_addr = opt.remote_broker_addr;
    let input_dir = opt.input;
    let output_dir = opt.output;
    let token_files = opt.tokens;
    let timeout_ms = opt.timeout;
    let repro_file = opt.repro_file;

    let use_grimoire = opt.grimoire;
    let use_bytes = opt.bytes;
    let use_tags = opt.tags;
    let use_cmplog = opt.cmplog;

    if !use_grimoire && !use_bytes && !use_tags && !use_cmplog {
        panic!("Must specify at least one mutator");
    }

    println!("Workdir: {:?}", workdir.to_string_lossy().to_string());

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let monitor = MultiMonitor::new(|s| println!("{}", s));

    let iteration_counter = RelaxedCounter::new(0);

    let mut run_client = |state: Option<StdState<_, _, _, _>>,
                          mut mgr: LlmpRestartingEventManager<_, _>,
                          _core_id| {
        let repro_file = repro_file.clone();

        // Create an observation channel using the coverage map
        let edges = unsafe { &mut EDGES_MAP[0..MAX_EDGES_NUM] };
        let edges_observer = HitcountsMapObserver::new(StdMapObserver::new("edges", edges));

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Create the Cmp observer
        let cmplog_observer = CmpLogObserver::new("cmplog", true);

        // feedback from js
        let js_observer = JSObserver::new("js");
        let js_feedback = JSFeedback::new("js");
        let _js_mapstate = JSMapState::new("js");

        // Feedback to rate the interestingness of an input
        let mut feedback = feedback_or!(
            MaxMapFeedback::new_tracking(&edges_observer, true, true),
            js_feedback
        );

        // A feedback to choose if an input is a solution or not

        let mut objective = ReturnValueFeedback::new();

        let mut crashdir = output_dir.clone();
        crashdir.push("solutions");
        let mut corpdir = output_dir.clone();
        corpdir.push("corpus");

        let generalization = GeneralizationStage::new(&edges_observer); //TODO: investigate using a multimapobserver
        let generalization = SkippableStage::new(generalization, |_s| use_grimoire.into());
        let mut state = match state {
            Some(state) => state,
            None => StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we use a cached disk version
                CachedOnDiskCorpus::new(corpdir, 40_000).unwrap(),
                // Corpus in which we store solutions (XSS)
                OnDiskCorpus::new(crashdir).unwrap(),
                // States of the feedbacks.
                // They are the data related to the feedbacks that you want to persist in the State.
                &mut feedback,
                &mut objective,
            )
            .unwrap(),
        };

        //set max size of a test case to 1024
        state.set_max_size(1024);

        // Create a dictionary if not existing
        if state.metadata().get::<Tokens>().is_none() {
            for tokens_file in &token_files {
                state.add_metadata(Tokens::from_file(tokens_file)?);
            }
        }

        // The actual target run starts here.
        // Call LLVMFUzzerInitialize() if present.
        let args: Vec<String> = env::args().collect();
        assert_ne!(
            libfuzzer_initialize(&args),
            -1,
            "Error: LLVMFuzzerInitialize failed with -1"
        );

        // if repro_file isnt empty, read the file to a buf
        // and then run the input through libfuzzer_test_one_input
        // and return
        if let Some(repro_file) = repro_file {
            println!("Running repro file: {:?}", repro_file);
            let repro_file = repro_file.to_str().unwrap();
            let repro_buf = fs::read(repro_file).unwrap();
            println!("Repro file size: {}", repro_buf.len());
            if libfuzzer_test_one_input(&repro_buf) == 42 {
                println!("XSS Detected in repro file");
            }
            println!("Done running repro file, exiting");
            return Ok(());
        }

        let max_map_feedback = MaxMapFeedback::new_tracking(&edges_observer, true, false);
        let calibration = CalibrationStage::new(&max_map_feedback);

        // Setup a randomic Input2State stage
        let i2s = SkippableStage::new(
            StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new()))),
            |_s| use_cmplog.into(),
        );

        // mutations
        let byte_mutations = tuple_list!(
            SpliceMutator::new(),
            CrossoverInsertMutator::new(),
            CrossoverReplaceMutator::new(),
            BytesDeleteMutator::new(),
            BytesDeleteMutator::new(),
            BytesDeleteMutator::new(),
            BytesDeleteMutator::new(),
            BytesDeleteMutator::new(),
            TokenInsert::new(),
        );

        let tag_mutations = tuple_list!(
            TagCopyMutator::new(),
            TagDeleteMutator::new(),
            TagDeleteMutator::new(),
            TagDeleteMutator::new(),
            TagDeleteMutator::new(),
            TagCrossoverMutator::new(),
            TagTokenMutator::new(),
        );

        // note: right now if you dont use byte or tag mutations, you wont get any default tokens inserted?
        let grimoire_mutations = StdScheduledMutator::new(tuple_list!(
            GrimoireExtensionMutator::new(),
            GrimoireRecursiveReplacementMutator::new(),
            GrimoireStringReplacementMutator::new(),
            // give more probability to avoid large inputs
            GrimoireRandomDeleteMutator::new(),
            GrimoireRandomDeleteMutator::new(),
        ));

        let byte_mutational_stage = SkippableStage::new(
            StdMutationalStage::new(StdScheduledMutator::new(byte_mutations)),
            |_s| use_bytes.into(),
        );
        let tag_mutational_stage = SkippableStage::new(
            StdMutationalStage::new(StdScheduledMutator::new(tag_mutations)),
            |_s| use_tags.into(),
        );

        let grim_mutational_stage =
            SkippableStage::new(StdMutationalStage::new(grimoire_mutations), |_s| {
                use_grimoire.into()
            });

        // A minimization+queue policy to get testcases from the corpus
        let scheduler = QueueScheduler::new();

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |input: &GeneralizedInput| {
            iteration_counter.inc();
            let target = input.target_bytes();
            let buf = target.as_slice();
            let rv = libfuzzer_test_one_input(buf);
            if rv == 42 {
                return ExitKind::Oom;
            } // for now, use OOM to mean XSS, this is a hack
            ExitKind::Ok
        };

        // TODO: try without timeout executor
        // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
        let mut executor = TimeoutExecutor::new(
            InProcessExecutor::new(
                &mut harness,
                tuple_list!(edges_observer, time_observer, js_observer),
                &mut fuzzer,
                &mut state,
                &mut mgr,
            )?,
            timeout_ms,
        );

        // Secondary harness due to mut ownership
        let mut harness = |input: &GeneralizedInput| {
            iteration_counter.inc();
            let target = input.target_bytes();
            let buf = target.as_slice();
            let rv = libfuzzer_test_one_input(buf);
            if rv == 42 {
                return ExitKind::Oom;
            } // for now, use OOM to mean XSS, this is a hack
            ExitKind::Ok
        };

        // Setup a tracing stage in which we log comparisons
        let tracing = SkippableStage::new(
            TracingStage::new(InProcessExecutor::new(
                &mut harness,
                tuple_list!(cmplog_observer),
                &mut fuzzer,
                &mut state,
                &mut mgr,
            )?),
            |_s| use_cmplog.into(),
        );

        // The order of the stages matter!
        let mut stages = tuple_list!(
            calibration,
            tracing,
            i2s,
            byte_mutational_stage,
            tag_mutational_stage,
            generalization, // should this be in a different position?
            grim_mutational_stage,
        );

        // In case the corpus is empty (on first run), reset
        if state.corpus().count() < 1 {
            println!("Loading from {:?}", &input_dir);
            let mut initial_inputs = vec![];
            for entry in fs::read_dir(input_dir.as_path()).unwrap() {
                let path = entry.unwrap().path();
                let attr = fs::metadata(&path);
                if attr.is_err() {
                    continue;
                }
                let attr = attr.unwrap();

                if attr.is_file() && attr.len() > 0 {
                    println!("Loading file {:?} ...", &path);
                    let mut file = fs::File::open(path).expect("no file found");
                    let mut buffer = vec![];
                    file.read_to_end(&mut buffer).expect("buffer overflow");
                    let input = GeneralizedInput::new(buffer);
                    initial_inputs.push(input);
                }
            }
            assert!(
                !initial_inputs.is_empty(),
                "Failed to load any inputs from {:?}",
                &input_dir
            );

            for input in initial_inputs {
                fuzzer
                    .evaluate_input(&mut state, &mut executor, &mut mgr, input)
                    .unwrap();
            }
        }

        // run the fuzzer for NUM_ITERATIONS
        while iteration_counter.get() < NUM_ITERATIONS {
            fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)?;
        }

        println!("restarting fuzzer");
        // save state
        mgr.on_restart(&mut state)?;
        std::process::exit(0);
    };

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("default"))
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(broker_port)
        .remote_broker_addr(remote_broker_addr)
        .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(_) | Err(Error::ShuttingDown) => (),
        Err(e) => panic!("{:?}", e),
    };
}
