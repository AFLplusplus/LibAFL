//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
use std::{cell::RefCell, path::PathBuf, rc::Rc};

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
    stages::{IfElseStage, ShadowTracingStage, StdMutationalStage},
    state::{HasCorpus, StdState},
    Error, HasMetadata,
};
use libafl_bolts::{
    cli::{parse_args, FuzzerOptions},
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Merge},
    AsSlice,
};
use libafl_frida::{
    asan::{
        asan_rt::AsanRuntime,
        errors::{AsanErrorsFeedback, AsanErrorsObserver},
    },
    cmplog_rt::CmpLogRuntime,
    coverage_rt::{CoverageRuntime, MAP_SIZE},
    executor::FridaInProcessExecutor,
    frida_helper_shutdown_observer::FridaHelperObserver,
    helper::{FridaInstrumentationHelper, IfElseRuntime},
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

    log::info!("Frida fuzzer starting up.");
    match fuzz(&options) {
        Ok(()) | Err(Error::ShuttingDown) => println!("\nFinished fuzzing. Good bye."),
        Err(e) => panic!("Error during fuzzing: {e:?}"),
    }
}

/// The actual fuzzer
#[expect(clippy::too_many_lines)]
fn fuzz(options: &FuzzerOptions) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    let shmem_provider = StdShMemProvider::new()?;
    let is_asan = |options: &FuzzerOptions, client_description: &ClientDescription| {
        options.asan && options.asan_cores.contains(client_description.core_id())
    };
    let is_cmplog = |options: &FuzzerOptions, client_description: &ClientDescription| {
        options.cmplog && options.cmplog_cores.contains(client_description.core_id())
    };

    let mut run_client = |state: Option<_>,
                          mut mgr: LlmpRestartingEventManager<_, _, _, _, _>,
                          client_description: ClientDescription| {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.

        // println!("{:?}", mgr.mgr_id());

        let lib = unsafe { libloading::Library::new(options.clone().harness.unwrap()).unwrap() };
        let target_func: libloading::Symbol<
            unsafe extern "C" fn(data: *const u8, size: usize) -> i32,
        > = unsafe { lib.get(options.harness_function.as_bytes()).unwrap() };

        let mut frida_harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            unsafe { (target_func)(buf.as_ptr(), buf.len()) };
            ExitKind::Ok
        };

        let gum = Gum::obtain();

        let coverage = CoverageRuntime::new();
        let asan = AsanRuntime::new(options);
        let cmplog = CmpLogRuntime::new();

        let client_description_clone = client_description.clone();
        let options_clone = options.clone();
        let client_description_clone2 = client_description.clone();
        let options_clone2 = options.clone();
        let frida_helper = Rc::new(RefCell::new(FridaInstrumentationHelper::new(
            &gum,
            options,
            tuple_list!(
                IfElseRuntime::new(
                    move || Ok(is_asan(&options_clone, &client_description_clone)),
                    tuple_list!(asan),
                    tuple_list!()
                ),
                IfElseRuntime::new(
                    move || Ok(is_cmplog(&options_clone2, &client_description_clone2)),
                    tuple_list!(cmplog),
                    tuple_list!()
                ),
                coverage
            ),
        )));

        // Create an observation channel using the coverage map
        let edges_observer = HitcountsMapObserver::new(unsafe {
            StdMapObserver::from_mut_ptr(
                "edges",
                frida_helper.borrow_mut().map_mut_ptr().unwrap(),
                MAP_SIZE,
            )
        })
        .track_indices();

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");
        let asan_observer = AsanErrorsObserver::from_static_asan_errors();
        let frida_helper_observer = FridaHelperObserver::new(Rc::clone(&frida_helper));

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new(&edges_observer),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new(&time_observer)
        );

        // Feedbacks to recognize an input as solution
        let mut objective = feedback_or_fast!(
            CrashFeedback::new(),
            AsanErrorsFeedback::new(&asan_observer),
            TimeoutFeedback::new(),
        );

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

        let observers = tuple_list!(
            frida_helper_observer,
            edges_observer,
            time_observer,
            asan_observer
        );

        // Create the executor for an in-process function with just one observer for edge coverage
        let executor = FridaInProcessExecutor::new(
            &gum,
            InProcessExecutor::with_timeout(
                &mut frida_harness,
                observers,
                &mut fuzzer,
                &mut state,
                &mut mgr,
                options.timeout,
            )?,
            Rc::clone(&frida_helper),
        );
        // Create an observation channel using cmplog map
        let cmplog_observer = CmpLogObserver::new("cmplog", true);

        let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

        let tracing = ShadowTracingStage::new(&mut executor);

        // Setup a randomic Input2State stage
        let i2s =
            StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));

        // In case the corpus is empty (on first run), reset
        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs_multicore(
                    &mut fuzzer,
                    &mut executor,
                    &mut mgr,
                    &options.input,
                    &client_description.core_id(),
                    &options.cores,
                )
                .unwrap_or_else(|_| {
                    panic!("Failed to load initial corpus at {:?}", &options.input)
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        let mut stages = tuple_list!(
            IfElseStage::new(
                |_, _, _, _| Ok(is_cmplog(&options, &client_description)),
                tuple_list!(tracing, i2s),
                tuple_list!()
            ),
            StdMutationalStage::new(mutator)
        );

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

        Ok(())
    };

    let builder = Launcher::builder()
        .configuration(EventConfig::AlwaysUnique)
        .shmem_provider(shmem_provider)
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&options.cores)
        .broker_port(options.broker_port)
        .remote_broker_addr(options.remote_broker_addr);

    #[cfg(not(windows))]
    let builder = builder.stdout_file(Some(&options.stdout));

    builder.build().launch()
}
