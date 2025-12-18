//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
use core::time::Duration;
#[cfg(feature = "crash")]
use std::ptr;
use std::{env, path::PathBuf};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{
        tcp::TcpEventManager, EventConfig, EventRestarter, Launcher, RestartingEventManager,
        ShouldSaveState,
    },
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{
        havoc_mutations::havoc_mutations,
        scheduled::{tokens_mutations, HavocScheduledMutator},
        token_mutations::Tokens,
    },
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::{calibrate::CalibrationStage, power::StdPowerMutationalStage},
    state::{HasCorpus, StdState},
    HasMetadata,
};
use libafl_bolts::{
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Merge},
    AsSlice,
};
use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, EDGES_MAP, MAX_EDGES_FOUND};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// The main fn, `no_mangle` as it is a C main
#[no_mangle]
pub extern "C" fn libafl_main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    // unsafe { RegistryBuilder::register::<Tokens>(); }

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    libafl_bolts::SimpleStdoutLogger::set_logger().unwrap();
    log::set_max_level(log::LevelFilter::Info);

    let mut run_client =
        |state: Option<StdState<_, _, _, _>>,
         mut restarting_mgr: RestartingEventManager<TcpEventManager<_, _, _>, StdShMemProvider>,
         _client_description| {
            // Create an observation channel using the coverage map
            #[allow(static_mut_refs)] // only a problem on nightly
            let edges_observer = unsafe {
                HitcountsMapObserver::new(StdMapObserver::from_mut_ptr(
                    "edges",
                    EDGES_MAP.as_mut_ptr(),
                    MAX_EDGES_FOUND,
                ))
                .track_indices()
            };

            // Create an observation channel to keep track of the execution time
            let time_observer = TimeObserver::new("time");

            let map_feedback = MaxMapFeedback::new(&edges_observer);

            let calibration = CalibrationStage::new(&map_feedback);

            // Feedback to rate the interestingness of an input
            let mut feedback = feedback_or!(map_feedback, TimeFeedback::new(&time_observer));

            // A feedback to choose if an input is a solution or not
            let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

            // If not restarting, create a State from scratch
            let mut state = state.unwrap_or_else(|| {
                StdState::new(
                    StdRand::new(),
                    InMemoryCorpus::new(),
                    OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
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
                    "IHDR".as_bytes().to_vec(),
                    "IDAT".as_bytes().to_vec(),
                    "PLTE".as_bytes().to_vec(),
                    "IEND".as_bytes().to_vec(),
                ]));
            }

            // Setup a basic mutator with a mutational stage
            let mutator = HavocScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
            let power = StdPowerMutationalStage::new(mutator);
            let mut stages = tuple_list!(calibration, power);

            // A minimization+queue policy to get testcasess from the corpus
            let scheduler = IndexesLenTimeMinimizerScheduler::new(
                &edges_observer,
                StdWeightedScheduler::with_schedule(
                    &mut state,
                    &edges_observer,
                    Some(PowerSchedule::fast()),
                ),
            );

            // A fuzzer with feedbacks and a corpus scheduler
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

            // The wrapped harness function, calling out to the LLVM-style harness
            let mut harness = |input: &BytesInput| {
                let target = input.target_bytes();
                let buf = target.as_slice();
                #[cfg(feature = "crash")]
                if buf.len() > 4 && buf[4] == 0 {
                    unsafe {
                        eprintln!("Crashing (for testing purposes)");
                        let addr = ptr::null_mut();
                        *addr = 1;
                    }
                }
                unsafe {
                    libfuzzer_test_one_input(buf);
                }
                ExitKind::Ok
            };

            // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
            let mut executor = InProcessExecutor::with_timeout(
                &mut harness,
                tuple_list!(edges_observer, time_observer),
                &mut fuzzer,
                &mut state,
                &mut restarting_mgr,
                Duration::new(10, 0),
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
                    .load_initial_inputs(
                        &mut fuzzer,
                        &mut executor,
                        &mut restarting_mgr,
                        &[PathBuf::from("./corpus")],
                    )
                    .unwrap_or_else(|_| panic!("Failed to load initial corpus"));
                println!("We imported {} inputs from disk.", state.corpus().count());
            }

            fuzzer.fuzz_loop_for(
                &mut stages,
                &mut executor,
                &mut state,
                &mut restarting_mgr,
                1_000_000,
            )?;

            restarting_mgr.on_restart(&mut state)?;

            Ok(())
        };

    Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(1338)
        .configuration(EventConfig::AlwaysUnique)
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&libafl_bolts::core_affinity::Cores::from_cmdline("0-1").unwrap())
        .serialize_state(ShouldSaveState::OOMSafeNever)
        .build()
        .launch_tcp(tuple_list!())
        .expect("Failed to launch TCP manager");
}
