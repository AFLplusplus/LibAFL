//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The `launcher` will spawn new processes for each cpu core.

use clap::{load_yaml, App};
use core::time::Duration;
use std::{env, path::PathBuf};

use libafl::{
    bolts::{
        current_nanos,
        launcher::Launcher,
        os::parse_core_bind_arg,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge},
    },
    corpus::{
        Corpus, InMemoryCorpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
        QueueCorpusScheduler,
    },
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    mutators::scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
    mutators::token_mutations::{I2SRandReplace, Tokens},
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    stages::{StdMutationalStage, TracingStage},
    state::{HasCorpus, HasMetadata, StdState},
    stats::MultiStats,
};

use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, CmpLogObserver, CMPLOG_MAP, EDGES_MAP,
    MAX_EDGES_NUM,
};

/// The main fn, `no_mangle` as it is a C main
#[no_mangle]
pub fn main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();
    
    let workdir = env::current_dir().unwrap();

    let yaml = load_yaml!("clap-config.yaml");
    let matches = App::from(yaml).get_matches();

    let cores = parse_core_bind_arg(&matches.value_of("cores").unwrap())
        .expect("No valid core count given!");
    let broker_port = matches
        .value_of("broker_port")
        .map(|s| s.parse().expect("Invalid broker port".into()))
        .unwrap_or(1337);
    let remote_broker_addr = matches
        .value_of("remote_broker_addr")
        .map(|s| s.parse().expect("Invalid broker address".into()));
    let input_dirs: Vec<PathBuf> = matches
        .values_of("input")
        .map(|v| v.map(|s| PathBuf::from(s)).collect())
        .unwrap_or(vec![]);
    let output_dir = matches
        .value_of("output")
        .map(|s| PathBuf::from(s))
        .unwrap_or(workdir.clone());
    let dicts: Vec<&str> = matches
        .values_of("dict")
        .map(|v| v.collect())
        .unwrap_or(vec![]);
    let timeout_ms = matches
        .value_of("timeout")
        .map(|s| s.parse().expect("Invalid timeout".into()))
        .unwrap_or(10000);
    // let cmplog_enabled = matches.is_present("cmplog");

    println!("Workdir: {:?}", workdir.to_string_lossy().to_string());

    #[cfg(target_os = "android")]
    AshmemService::start().expect("Failed to start Ashmem service");
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let stats = MultiStats::new(|s| println!("{}", s));

    let mut run_client = |state: Option<StdState<_, _, _, _, _>>, mut mgr| {
        // Create an observation channel using the coverage map
        let edges = unsafe { &mut EDGES_MAP[0..MAX_EDGES_NUM] };
        let edges_observer = HitcountsMapObserver::new(StdMapObserver::new("edges", edges));

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Create the Cmp observer
        let cmplog = unsafe { &mut CMPLOG_MAP };
        let cmplog_observer = CmpLogObserver::new("cmplog", cmplog, true);

        // The state of the edges feedback.
        let feedback_state = MapFeedbackState::with_observer(&edges_observer);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, false),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new_with_observer(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let objective = feedback_or!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(output_dir.clone()).unwrap(),
                // States of the feedbacks.
                // They are the data related to the feedbacks that you want to persist in the State.
                tuple_list!(feedback_state),
            )
        });

        // Create a PNG dictionary if not existing
        if state.metadata().get::<Tokens>().is_none() {
            for dict in &dicts {
                state.add_metadata(Tokens::from_tokens_file(dict)?);
            }
        }

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            libfuzzer_test_one_input(buf);
            ExitKind::Ok
        };

        // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
        let mut executor = TimeoutExecutor::new(
            InProcessExecutor::new(
                &mut harness,
                tuple_list!(edges_observer, time_observer),
                &mut fuzzer,
                &mut state,
                &mut mgr,
            )?,
            Duration::from_millis(timeout_ms),
        );

        // Secondary harness due to mut ownership
        let mut harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            libfuzzer_test_one_input(buf);
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

        // The actual target run starts here.
        // Call LLVMFUzzerInitialize() if present.
        let args: Vec<String> = env::args().collect();
        if libfuzzer_initialize(&args) == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1")
        }

        // In case the corpus is empty (on first run), reset
        if state.corpus().count() < 1 {
            if input_dirs.len() == 0 {
                // Generator of printable bytearrays of max size 32
                let mut generator = RandBytesGenerator::new(32);

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
                state
                    .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &input_dirs)
                    .unwrap_or_else(|_| {
                        panic!("Failed to load initial corpus at {:?}", &input_dirs)
                    });
                println!("We imported {} inputs from disk.", state.corpus().count());
            }
        }

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    Launcher::builder()
        .shmem_provider(shmem_provider)
        .stats(stats)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(broker_port)
        .remote_broker_addr(remote_broker_addr)
        //.stdout_file(Some("/dev/null"))
        .build()
        .launch()
        .expect("Launcher failed");
}
