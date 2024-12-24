//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
use std::path::PathBuf;

use frida_gum::Gum;
use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{
        launcher::Launcher, llmp::LlmpRestartingEventManager, ClientDescription, EventConfig,
    },
    executors::{inprocess::InProcessExecutor, ExitKind, ShadowExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{
        havoc_mutations::havoc_mutations,
        scheduled::{tokens_mutations, StdScheduledMutator},
        token_mutations::{I2SRandReplace, Tokens},
    },
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{ShadowTracingStage, StdMutationalStage},
    state::{HasCorpus, StdState},
    Error, HasMetadata,
};
#[cfg(unix)]
use libafl::{feedback_and_fast, feedbacks::ConstFeedback};
use libafl_bolts::{
    cli::{parse_args, FuzzerOptions},
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Merge},
    AsSlice,
};
#[cfg(unix)]
use libafl_frida::asan::{
    asan_rt::AsanRuntime,
    errors::{AsanErrorsFeedback, AsanErrorsObserver},
};
use libafl_frida::{
    cmplog_rt::CmpLogRuntime,
    coverage_rt::{CoverageRuntime, MAP_SIZE},
    executor::FridaInProcessExecutor,
    helper::{FridaInstrumentationHelper, FridaRuntimeVec},
};
use libafl_targets::cmplog::CmpLogObserver;
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// The main fn, usually parsing parameters, and starting the fuzzer
pub fn main() {
    env_logger::init();
    color_backtrace::install();
    let options = parse_args();

    unsafe {
        match fuzz(&options) {
            Ok(()) | Err(Error::ShuttingDown) => println!("\nFinished fuzzing. Good bye."),
            Err(e) => panic!("Error during fuzzing: {e:?}"),
        }
    }
}

/// The actual fuzzer
#[expect(clippy::too_many_lines)]
unsafe fn fuzz(options: &FuzzerOptions) -> Result<(), Error> {
    log::info!("Frida fuzzer starting up.");

    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    let shmem_provider = StdShMemProvider::new()?;

    let mut run_client = |state: Option<_>,
                          mut mgr: LlmpRestartingEventManager<_, _, _>,
                          client_description: ClientDescription| {
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

        let gum = Gum::obtain();
        let coverage = CoverageRuntime::new();

        let mut enable_asan_error_callbacks = false;

        let runtimes = if options.asan && options.asan_cores.contains(client_description.core_id())
        {
            #[cfg(unix)]
            {
                enable_asan_error_callbacks = true;
                let asan = AsanRuntime::new(options);
                FridaRuntimeVec(vec![Box::new(coverage), Box::new(asan)])
            }
            #[cfg(windows)]
            {
                FridaRuntimeVec(vec![Box::new(coverage)])
            }
        } else if options.cmplog && options.cmplog_cores.contains(client_description.core_id()) {
            let cmplog = CmpLogRuntime::new();
            println!("cmplog runtime created");
            FridaRuntimeVec(vec![Box::new(coverage), Box::new(cmplog)])
        } else {
            FridaRuntimeVec(vec![Box::new(coverage)])
        };

        let mut frida_helper = FridaInstrumentationHelper::new(&gum, options, runtimes);

        // Create an observation channel using the coverage map
        let edges_observer = HitcountsMapObserver::new(StdMapObserver::from_mut_ptr(
            "edges",
            frida_helper.map_mut_ptr().unwrap(),
            MAP_SIZE,
        ))
        .track_indices();

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");
        #[cfg(unix)]
        let asan_observer = AsanErrorsObserver::from_static_asan_errors();

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new(&edges_observer),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new(&time_observer)
        );

        // Feedbacks to recognize an input as solution
        #[cfg(unix)]
        let mut objective = feedback_or_fast!(
            CrashFeedback::new(),
            TimeoutFeedback::new(),
            feedback_and_fast!(
                ConstFeedback::from(enable_asan_error_callbacks),
                AsanErrorsFeedback::new(&asan_observer)
            )
        );
        #[cfg(windows)]
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::new(),
                // Corpus that will be evolved, we keep it in memory for performance
                CachedOnDiskCorpus::no_meta(PathBuf::from("./corpus_discovered"), 64).unwrap(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(options.output.clone()).unwrap(),
                &mut feedback,
                &mut objective,
            )
            .unwrap()
        });

        println!("We're a client, let's fuzz :)");

        // Create a PNG dictionary if not existing
        if state.metadata_map().get::<Tokens>().is_none() {
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
        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // let observers = ObserversVec(vec![Box::new(edges_observer), Box::new(time_observer)]);
        #[cfg(unix)]
        let observers = tuple_list!(edges_observer, time_observer, asan_observer);
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
        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &options.input)
                .unwrap_or_else(|_| {
                    panic!("Failed to load initial corpus at {:?}", &options.input)
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        if options.asan && options.asan_cores.contains(client_description.core_id()) {
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

            Ok(())
        } else if options.cmplog && options.cmplog_cores.contains(client_description.core_id()) {
            // Create an observation channel using cmplog map
            let cmplog_observer = CmpLogObserver::new("cmplog", true);

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
        } else {
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

            Ok(())
        }
    };

    Launcher::builder()
        .configuration(EventConfig::AlwaysUnique)
        .shmem_provider(shmem_provider)
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&options.cores)
        .broker_port(options.broker_port)
        // .stdout_file(Some(&options.stdout))
        .remote_broker_addr(options.remote_broker_addr)
        .build()
        .launch()
}
