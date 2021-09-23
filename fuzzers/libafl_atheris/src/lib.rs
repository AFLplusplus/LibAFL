//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The `launcher` will spawn new processes for each cpu core.

use clap::{load_yaml, App};
use core::{convert::TryInto, ffi::c_void, slice, time::Duration};
use std::{
    env,
    os::raw::{c_char, c_int},
    path::PathBuf,
};

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
    events::EventConfig,
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
    Error,
};

use libafl_targets::{CmpLogObserver, CMPLOG_MAP, EDGES_MAP_PTR, MAX_EDGES_NUM};

extern "C" {
    pub fn __sanitizer_cov_trace_cmp1(v0: u8, v1: u8);
    pub fn __sanitizer_cov_trace_cmp2(v0: u16, v1: u16);
    pub fn __sanitizer_cov_trace_cmp4(v0: u32, v1: u32);
    pub fn __sanitizer_cov_trace_cmp8(v0: u64, v1: u64);
}

/// This seems to be unused by atheris, so we can ignore it.
#[no_mangle]
pub fn __sanitizer_cov_pcs_init(_pcs_beg: *mut u8, _pcs_end: *mut u8) {
    // noop
}

/// Set up our coverage map.
#[no_mangle]
pub fn __sanitizer_cov_8bit_counters_init(start: *mut u8, stop: *mut u8) {
    unsafe {
        EDGES_MAP_PTR = start;
        MAX_EDGES_NUM = (stop as usize - start as usize) / 8;
    }
}

/// There must be a better way to `cmplog` this, but for now this should be fine(?)
#[no_mangle]
pub fn __sanitizer_weak_hook_memcmp(
    _caller_pc: *const c_void,
    s1: *const c_void,
    s2: *const c_void,
    n: usize,
    _result: c_int,
) {
    unsafe {
        let s1 = slice::from_raw_parts(s1 as *const u8, n);
        let s2 = slice::from_raw_parts(s2 as *const u8, n);
        match n {
            0 => (),
            1 => __sanitizer_cov_trace_cmp1(
                u8::from_ne_bytes(s1.try_into().unwrap()),
                u8::from_ne_bytes(s2.try_into().unwrap()),
            ),
            2..=3 => __sanitizer_cov_trace_cmp2(
                u16::from_ne_bytes(s1.try_into().unwrap()),
                u16::from_ne_bytes(s2.try_into().unwrap()),
            ),
            4..=7 => __sanitizer_cov_trace_cmp4(
                u32::from_ne_bytes(s1.try_into().unwrap()),
                u32::from_ne_bytes(s2.try_into().unwrap()),
            ),
            _ => __sanitizer_cov_trace_cmp8(
                u64::from_ne_bytes(s1.try_into().unwrap()),
                u64::from_ne_bytes(s2.try_into().unwrap()),
            ),
        }
    }
}

/// The main fn, `no_mangle` as it is a C symbol
/// It's called by Atheris after the fuzzer has been initialized.
#[no_mangle]
#[allow(non_snake_case)]
pub fn LLVMFuzzerRunDriver(
    _argc: *const c_int,
    _argv: *const c_char,
    harness_fn: Option<extern "C" fn(*const u8, usize) -> c_int>,
) {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

    if harness_fn.is_none() {
        panic!("No harness callback provided");
    }
    let harness_fn = harness_fn.unwrap();

    if unsafe { EDGES_MAP_PTR.is_null() } {
        panic!(
            "Edges map was never initialized - __sanitizer_cov_8bit_counters_init never got called"
        );
    }

    let workdir = env::current_dir().unwrap();

    let yaml = load_yaml!("clap-config.yaml");
    let matches = App::from(yaml).get_matches();

    let cores = parse_core_bind_arg(matches.value_of("cores").unwrap())
        .expect("No valid core count given!");
    let broker_port = matches
        .value_of("broker_port")
        .map(|s| s.parse().expect("Invalid broker port"))
        .unwrap_or(1337);
    let remote_broker_addr = matches
        .value_of("remote_broker_addr")
        .map(|s| s.parse().expect("Invalid broker address"));
    let input_dirs: Vec<PathBuf> = matches
        .values_of("input")
        .map(|v| v.map(PathBuf::from).collect())
        .unwrap_or_default();
    let output_dir = matches
        .value_of("output")
        .map(PathBuf::from)
        .unwrap_or_else(|| workdir.clone());
    let token_files: Vec<&str> = matches
        .values_of("tokens")
        .map(|v| v.collect())
        .unwrap_or_default();
    let timeout_ms = matches
        .value_of("timeout")
        .map(|s| s.parse().expect("Invalid timeout"))
        .unwrap_or(10000);
    // let cmplog_enabled = matches.is_present("cmplog");

    println!("Workdir: {:?}", workdir.to_string_lossy().to_string());

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let stats = MultiStats::new(|s| println!("{}", s));

    let mut run_client = |state: Option<StdState<_, _, _, _, _>>, mut mgr, _core_id| {
        // Create an observation channel using the coverage map
        let edges = unsafe { slice::from_raw_parts_mut(EDGES_MAP_PTR, MAX_EDGES_NUM) };
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

        // Create a dictionary if not existing
        if state.metadata().get::<Tokens>().is_none() {
            for tokens_file in &token_files {
                state.add_metadata(Tokens::from_tokens_file(tokens_file)?);
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
            harness_fn(buf.as_ptr(), buf.len());
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
        if state.corpus().count() < 1 {
            if input_dirs.is_empty() {
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

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("default"))
        .stats(stats)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(broker_port)
        .remote_broker_addr(remote_broker_addr)
        //.stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(_) | Err(Error::ShuttingDown) => (),
        Err(e) => panic!("Error in fuzzer: {}", e),
    };
}
