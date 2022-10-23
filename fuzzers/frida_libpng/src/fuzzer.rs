//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::path::PathBuf;

use frida_gum::Gum;
use libafl::{
    bolts::{
        cli::{parse_args, FuzzerOptions},
        current_nanos,
        launcher::Launcher,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge},
        AsSlice,
    },
    corpus::{ondisk::OnDiskMetadataFormat, CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{llmp::LlmpRestartingEventManager, EventConfig},
    executors::{inprocess::InProcessExecutor, ExitKind, ShadowExecutor},
    feedback_and_fast, feedback_or, feedback_or_fast,
    feedbacks::{ConstFeedback, CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{
        scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
        token_mutations::{I2SRandReplace, Tokens},
    },
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{ShadowTracingStage, StdMutationalStage},
    state::{HasCorpus, HasMetadata, StdState},
    Error,
};
#[cfg(unix)]
use libafl_frida::asan::asan_rt::AsanRuntime;
#[cfg(unix)]
use libafl_frida::asan::errors::{AsanErrorsFeedback, AsanErrorsObserver, ASAN_ERRORS};
use libafl_frida::{
    cmplog_rt::CmpLogRuntime,
    coverage_rt::{CoverageRuntime, MAP_SIZE},
    executor::FridaInProcessExecutor,
    helper::FridaInstrumentationHelper,
};
use libafl_targets::cmplog::{CmpLogObserver, CMPLOG_MAP};

/// The main fn, usually parsing parameters, and starting the fuzzer
pub fn main() {
    color_backtrace::install();

    let options = parse_args();

    unsafe {
        match fuzz(options) {
            Ok(()) | Err(Error::ShuttingDown) => println!("\nFinished fuzzing. Good bye."),
            Err(e) => panic!("Error during fuzzing: {:?}", e),
        }
    }
}

/// The actual fuzzer
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
unsafe fn fuzz(options: FuzzerOptions) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let monitor = MultiMonitor::new(|s| println!("{}", s));

    let shmem_provider = StdShMemProvider::new()?;

    let mut run_client = |state: Option<_>, mgr: LlmpRestartingEventManager<_, _>, core_id| {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.

        // println!("{:?}", mgr.mgr_id());

        let lib = libloading::Library::new(options.clone().harness.unwrap()).unwrap();
        let target_func: libloading::Symbol<
            unsafe extern "C" fn(data: *const u8, size: usize) -> i32,
        > = lib.get(options.harness_function.as_bytes()).unwrap();

        let mut frida_harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            (target_func)(buf.as_ptr(), buf.len());
            ExitKind::Ok
        };

        if options.asan && options.asan_cores.contains(core_id) {
            (|state: Option<_>, mut mgr: LlmpRestartingEventManager<_, _>, _core_id| {
                let gum = Gum::obtain();

                let coverage = CoverageRuntime::new();
                #[cfg(unix)]
                let asan = AsanRuntime::new(options.clone());

                #[cfg(unix)]
                let mut frida_helper =
                    FridaInstrumentationHelper::new(&gum, &options, tuple_list!(coverage, asan));
                #[cfg(windows)]
                let mut frida_helper =
                    FridaInstrumentationHelper::new(&gum, &options, tuple_list!(coverage));

                // Create an observation channel using the coverage map
                let edges_observer = HitcountsMapObserver::new(StdMapObserver::new_from_ptr(
                    "edges",
                    frida_helper.map_ptr_mut().unwrap(),
                    MAP_SIZE,
                ));

                // Create an observation channel to keep track of the execution time
                let time_observer = TimeObserver::new("time");

                // Feedback to rate the interestingness of an input
                // This one is composed by two Feedbacks in OR
                let mut feedback = feedback_or!(
                    // New maximization map feedback linked to the edges observer and the feedback state
                    MaxMapFeedback::new_tracking(&edges_observer, true, false),
                    // Time feedback, this one does not need a feedback state
                    TimeFeedback::new_with_observer(&time_observer)
                );

                // Feedbacks to recognize an input as solution
                #[cfg(unix)]
                let mut objective = feedback_or_fast!(
                    CrashFeedback::new(),
                    TimeoutFeedback::new(),
                    // true enables the AsanErrorFeedback
                    feedback_and_fast!(ConstFeedback::from(true), AsanErrorsFeedback::new())
                );
                #[cfg(windows)]
                let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

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
                            options.output.to_path_buf(),
                            Some(OnDiskMetadataFormat::JsonPretty),
                        )
                        .unwrap(),
                        &mut feedback,
                        &mut objective,
                    )
                    .unwrap()
                });

                println!("We're a client, let's fuzz :)");

                // Create a PNG dictionary if not existing
                if state.metadata().get::<Tokens>().is_none() {
                    state.add_metadata(Tokens::from([
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
                let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

                // A fuzzer with feedbacks and a corpus scheduler
                let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

                #[cfg(unix)]
                let observers = tuple_list!(
                    edges_observer,
                    time_observer,
                    AsanErrorsObserver::new(&ASAN_ERRORS)
                );
                #[cfg(windows)]
                let observers = tuple_list!(edges_observer, time_observer);

                // Create the executor for an in-process function with just one observer for edge coverage
                let mut executor = FridaInProcessExecutor::new(
                    &gum,
                    InProcessExecutor::new(
                        &mut frida_harness,
                        observers,
                        &mut fuzzer,
                        &mut state,
                        &mut mgr,
                    )?,
                    &mut frida_helper,
                );

                // In case the corpus is empty (on first run), reset
                if state.corpus().count() < 1 {
                    state
                        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &options.input)
                        .unwrap_or_else(|_| {
                            panic!("Failed to load initial corpus at {:?}", &options.input)
                        });
                    println!("We imported {} inputs from disk.", state.corpus().count());
                }

                let mut stages = tuple_list!(StdMutationalStage::new(mutator));

                fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

                Ok(())
            })(state, mgr, core_id)
        } else if options.cmplog && options.cmplog_cores.contains(core_id) {
            (|state: Option<_>, mut mgr: LlmpRestartingEventManager<_, _>, _core_id| {
                let gum = Gum::obtain();

                let coverage = CoverageRuntime::new();
                let cmplog = CmpLogRuntime::new();

                let mut frida_helper =
                    FridaInstrumentationHelper::new(&gum, &options, tuple_list!(coverage, cmplog));

                // Create an observation channel using the coverage map
                let edges_observer = HitcountsMapObserver::new(StdMapObserver::new_from_ptr(
                    "edges",
                    frida_helper.map_ptr_mut().unwrap(),
                    MAP_SIZE,
                ));

                // Create an observation channel to keep track of the execution time
                let time_observer = TimeObserver::new("time");

                // Feedback to rate the interestingness of an input
                // This one is composed by two Feedbacks in OR
                let mut feedback = feedback_or!(
                    // New maximization map feedback linked to the edges observer and the feedback state
                    MaxMapFeedback::new_tracking(&edges_observer, true, false),
                    // Time feedback, this one does not need a feedback state
                    TimeFeedback::new_with_observer(&time_observer)
                );

                #[cfg(unix)]
                let mut objective = feedback_or_fast!(
                    CrashFeedback::new(),
                    TimeoutFeedback::new(),
                    feedback_and_fast!(ConstFeedback::from(false), AsanErrorsFeedback::new())
                );
                #[cfg(windows)]
                let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

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
                            options.output.to_path_buf(),
                            Some(OnDiskMetadataFormat::JsonPretty),
                        )
                        .unwrap(),
                        &mut feedback,
                        &mut objective,
                    )
                    .unwrap()
                });

                println!("We're a client, let's fuzz :)");

                // Create a PNG dictionary if not existing
                if state.metadata().get::<Tokens>().is_none() {
                    state.add_metadata(Tokens::from([
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
                let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

                // A fuzzer with feedbacks and a corpus scheduler
                let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

                #[cfg(unix)]
                let observers = tuple_list!(
                    edges_observer,
                    time_observer,
                    AsanErrorsObserver::new(&ASAN_ERRORS)
                );
                #[cfg(windows)]
                let observers = tuple_list!(edges_observer, time_observer,);

                // Create the executor for an in-process function with just one observer for edge coverage
                let mut executor = FridaInProcessExecutor::new(
                    &gum,
                    InProcessExecutor::new(
                        &mut frida_harness,
                        observers,
                        &mut fuzzer,
                        &mut state,
                        &mut mgr,
                    )?,
                    &mut frida_helper,
                );

                // In case the corpus is empty (on first run), reset
                if state.corpus().count() < 1 {
                    state
                        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &options.input)
                        .unwrap_or_else(|_| {
                            panic!("Failed to load initial corpus at {:?}", &options.input)
                        });
                    println!("We imported {} inputs from disk.", state.corpus().count());
                }

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

                Ok(())
            })(state, mgr, core_id)
        } else {
            (|state: Option<_>, mut mgr: LlmpRestartingEventManager<_, _>, _core_id| {
                let gum = Gum::obtain();

                let coverage = CoverageRuntime::new();

                let mut frida_helper =
                    FridaInstrumentationHelper::new(&gum, &options, tuple_list!(coverage));

                // Create an observation channel using the coverage map
                let edges_observer = HitcountsMapObserver::new(StdMapObserver::new_from_ptr(
                    "edges",
                    frida_helper.map_ptr_mut().unwrap(),
                    MAP_SIZE,
                ));

                // Create an observation channel to keep track of the execution time
                let time_observer = TimeObserver::new("time");

                // Feedback to rate the interestingness of an input
                // This one is composed by two Feedbacks in OR
                let mut feedback = feedback_or!(
                    // New maximization map feedback linked to the edges observer and the feedback state
                    MaxMapFeedback::new_tracking(&edges_observer, true, false),
                    // Time feedback, this one does not need a feedback state
                    TimeFeedback::new_with_observer(&time_observer)
                );

                #[cfg(unix)]
                let mut objective = feedback_or_fast!(
                    CrashFeedback::new(),
                    TimeoutFeedback::new(),
                    feedback_and_fast!(ConstFeedback::from(false), AsanErrorsFeedback::new())
                );
                #[cfg(windows)]
                let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

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
                            options.output.to_path_buf(),
                            Some(OnDiskMetadataFormat::JsonPretty),
                        )
                        .unwrap(),
                        &mut feedback,
                        &mut objective,
                    )
                    .unwrap()
                });

                println!("We're a client, let's fuzz :)");

                // Create a PNG dictionary if not existing
                if state.metadata().get::<Tokens>().is_none() {
                    state.add_metadata(Tokens::from([
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
                let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

                // A fuzzer with feedbacks and a corpus scheduler
                let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

                #[cfg(unix)]
                let observers = tuple_list!(
                    edges_observer,
                    time_observer,
                    AsanErrorsObserver::new(&ASAN_ERRORS)
                );
                #[cfg(windows)]
                let observers = tuple_list!(edges_observer, time_observer,);

                // Create the executor for an in-process function with just one observer for edge coverage
                let mut executor = FridaInProcessExecutor::new(
                    &gum,
                    InProcessExecutor::new(
                        &mut frida_harness,
                        observers,
                        &mut fuzzer,
                        &mut state,
                        &mut mgr,
                    )?,
                    &mut frida_helper,
                );

                // In case the corpus is empty (on first run), reset
                if state.corpus().count() < 1 {
                    state
                        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &options.input)
                        .unwrap_or_else(|_| {
                            panic!("Failed to load initial corpus at {:?}", &options.input)
                        });
                    println!("We imported {} inputs from disk.", state.corpus().count());
                }

                let mut stages = tuple_list!(StdMutationalStage::new(mutator));

                fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

                Ok(())
            })(state, mgr, core_id)
        }
    };

    Launcher::builder()
        .configuration(EventConfig::AlwaysUnique)
        .shmem_provider(shmem_provider)
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&options.cores)
        .broker_port(options.broker_port)
        .stdout_file(Some(&options.stdout))
        .remote_broker_addr(options.remote_broker_addr)
        .build()
        .launch()
}
