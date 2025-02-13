//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The `launcher` will spawn new processes for each cpu core.
//! This is the drop-in replacement for libfuzzer, to be used together with [`Atheris`](https://github.com/google/atheris)
//! for python instrumentation and fuzzing.

use core::time::Duration;
use std::{
    env,
    os::raw::{c_char, c_int},
    path::PathBuf,
};

use clap::{Arg, ArgAction, Command};
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{launcher::Launcher, EventConfig},
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{
        havoc_mutations::havoc_mutations,
        scheduled::{tokens_mutations, StdScheduledMutator},
        token_mutations::{I2SRandReplace, Tokens},
    },
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{StdMutationalStage, TracingStage},
    state::{HasCorpus, StdState},
    Error, HasMetadata,
};
use libafl_bolts::{
    core_affinity::Cores,
    nonzero,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Merge},
    AsSlice,
};
use libafl_targets::{extra_counters, CmpLogObserver};

/// It's called by Atheris after the fuzzer has been initialized.
/// The main entrypoint to our fuzzer, which will be called by `Atheris` when fuzzing starts.
/// The `harness_fn` parameter is the function that will be called by `LibAFL` for each iteration
/// and jumps back into `Atheris'` instrumented python code.
#[no_mangle]
pub extern "C" fn LLVMFuzzerRunDriver(
    _argc: *const c_int,
    _argv: *const *const c_char,
    harness_fn: Option<extern "C" fn(*const u8, usize) -> c_int>,
) {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    // unsafe { RegistryBuilder::register::<Tokens>(); }

    assert!(harness_fn.is_some(), "No harness callback provided");
    let harness_fn = harness_fn.unwrap();

    println!("Args: {:?}", std::env::args());

    let matches = Command::new("libafl_atheris")
        .version("0.1.0")
        .allow_external_subcommands(true)
        .arg(Arg::new("script")) // The python script is the first arg
        .arg(Arg::new("cores").short('c').long("cores").required(true))
        .arg(
            Arg::new("broker_port")
                .short('p')
                .long("broker-port")
                .required(false),
        )
        .arg(Arg::new("output").short('o').long("output").required(false))
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .required(true)
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("remote_broker_addr")
                .short('B')
                .long("remote-broker-addr")
                .required(false),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .required(false),
        )
        .get_matches();

    let workdir = env::current_dir().unwrap();
    println!("{}", env::current_dir().unwrap().to_string_lossy());

    let cores = Cores::from_cmdline(matches.get_one::<String>("cores").unwrap())
        .expect("No valid core count given!");
    let broker_port = matches
        .get_one::<String>("broker_port")
        .map_or(1337, |s| s.parse().expect("Invalid broker port"));
    let remote_broker_addr = matches
        .get_one::<String>("remote_broker_addr")
        .map(|s| s.parse().expect("Invalid broker address"));
    let input_dirs: Vec<PathBuf> = matches
        .get_many::<String>("input")
        .map(|v| v.map(PathBuf::from).collect())
        .unwrap_or_default();
    let output_dir = matches
        .get_one::<String>("output")
        .map_or_else(|| workdir.clone(), PathBuf::from);
    let token_files: Vec<PathBuf> = matches
        .get_many::<PathBuf>("tokens")
        .map(|v| v.map(PathBuf::from).collect())
        .unwrap_or_default();
    let timeout_ms = matches
        .get_one::<String>("timeout")
        .map_or(10000, |s| s.parse().expect("Invalid timeout"));
    // let cmplog_enabled = matches.is_present("cmplog");

    println!("Workdir: {:?}", workdir.to_string_lossy().to_string());

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let monitor = MultiMonitor::new(|s| println!("{s}"));

    // TODO: we need to handle Atheris calls to `exit` on errors somhow.

    let mut run_client = |state: Option<_>, mut mgr, _client_description| {
        // Create an observation channel using the coverage map
        let edges = unsafe { extra_counters() };
        println!("edges: {:?}", edges);
        let edges_observer = HitcountsMapObserver::new(StdMapObserver::from_mut_slice(
            "edges",
            edges.into_iter().next().unwrap(),
        ))
        .track_indices();

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Create the Cmp observer
        let cmplog_observer = CmpLogObserver::new("cmplog", true);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new(&edges_observer),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::new(),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(output_dir.clone()).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });

        // Create a dictionary if not existing
        state.metadata_or_insert_with(|| {
            Tokens::new()
                .add_from_files(&token_files)
                .expect("Could not read tokens files.")
        });

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            harness_fn(buf.as_ptr(), buf.len());
            ExitKind::Ok
        };

        // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
        let mut executor = InProcessExecutor::with_timeout(
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            Duration::from_millis(timeout_ms),
        )?;

        // Secondary harness due to mut ownership
        let mut harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            harness_fn(buf.as_ptr(), buf.len());
            ExitKind::Ok
        };

        // Setup a tracing stage in which we log comparisons
        let tracing = TracingStage::new(InProcessExecutor::new(
            &mut harness,
            tuple_list!(cmplog_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )?);

        // Setup a randomic Input2State stage
        let i2s =
            StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));

        // Setup a basic mutator
        let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
        let mutational = StdMutationalStage::new(mutator);

        // The order of the stages matter!
        let mut stages = tuple_list!(tracing, i2s, mutational);

        // In case the corpus is empty (on first run), reset
        if state.must_load_initial_inputs() {
            if input_dirs.is_empty() {
                // Generator of printable bytearrays of max size 32
                let mut generator = RandBytesGenerator::new(nonzero!(32));

                // Generate 8 initial inputs
                state
                    .generate_initial_inputs(
                        &mut fuzzer,
                        &mut executor,
                        &mut generator,
                        &mut mgr,
                        8,
                    )
                    .expect("Failed to generate the initial corpus");
                println!(
                    "We imported {} inputs from the generator.",
                    state.corpus().count()
                );
            } else {
                println!("Loading from {:?}", &input_dirs);
                // Load from disk
                // we used _forced since some Atheris testcases don't touch the map at all, hence, would not load any data.
                state
                    .load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &input_dirs)
                    .unwrap_or_else(|_| {
                        panic!("Failed to load initial corpus at {:?}", &input_dirs)
                    });
                println!("We imported {} inputs from disk.", state.corpus().count());
            }
        }

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    // Let's go. Python fuzzing ftw!
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("default"))
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(broker_port)
        .remote_broker_addr(remote_broker_addr)
        // remove this comment to silence the target.
        // .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(_) | Err(Error::ShuttingDown) => (),
        Err(e) => panic!("Error in fuzzer: {e}"),
    };
}
