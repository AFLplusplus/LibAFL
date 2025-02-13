//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libmozjpeg.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::{env, path::PathBuf};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{setup_restarting_mgr_std, EventConfig},
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{
        havoc_mutations::havoc_mutations,
        scheduled::{tokens_mutations, StdScheduledMutator},
        token_mutations::Tokens,
    },
    observers::StdMapObserver,
    schedulers::RandScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
    Error, HasMetadata,
};
use libafl_bolts::{
    rands::StdRand,
    tuples::{tuple_list, Merge},
    AsSlice,
};
use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer, CMP_MAP,
};

const ALLOC_MAP_SIZE: usize = 16 * 1024;
extern "C" {
    static mut libafl_alloc_map: [usize; ALLOC_MAP_SIZE];
}

/// The main fn, usually parsing parameters, and starting the fuzzer
#[no_mangle]
pub extern "C" fn libafl_main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    // unsafe { RegistryBuilder::register::<Tokens>(); }

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );
    fuzz(
        &[PathBuf::from("./corpus")],
        PathBuf::from("./crashes"),
        1337,
    )
    .expect("An error occurred while fuzzing");
}

/// The actual fuzzer
fn fuzz(corpus_dirs: &[PathBuf], objective_dir: PathBuf, broker_port: u16) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let monitor = SimpleMonitor::new(|s| println!("{s}"));

    // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    let (state, mut restarting_mgr) =
        match setup_restarting_mgr_std(monitor, broker_port, EventConfig::from_name("default")) {
            Ok(tuple) => tuple,
            Err(Error::ShuttingDown) => {
                println!("\nFinished fuzzing. Good bye.");
                return Ok(());
            }
            Err(err) => {
                panic!("Failed to setup the restarter: {err:?}");
            }
        };

    // Create an observation channel using the coverage map
    let edges_observer = unsafe { std_edges_map_observer("edges") };

    // Create an observation channel using the cmp map
    // TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
    #[allow(static_mut_refs)] // only a problem on nightly
    let cmps_observer =
        unsafe { StdMapObserver::from_mut_ptr("cmps", CMP_MAP.as_mut_ptr(), CMP_MAP.len()) };

    // Create an observation channel using the allocations map
    // TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
    #[allow(static_mut_refs)] // only a problem on nightly
    let allocs_observer = unsafe {
        StdMapObserver::from_mut_ptr(
            "allocs",
            libafl_alloc_map.as_mut_ptr(),
            libafl_alloc_map.len(),
        )
    };

    // Feedback to rate the interestingness of an input
    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        MaxMapFeedback::new(&cmps_observer),
        MaxMapFeedback::new(&allocs_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::new(),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryCorpus::new(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )
        .unwrap()
    });

    println!("We're a client, let's fuzz :)");

    // Add the JPEG tokens if not existing
    if state.metadata_map().get::<Tokens>().is_none() {
        state.add_metadata(Tokens::from_file("./jpeg.dict")?);
    }

    // Setup a basic mutator with a mutational stage
    let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // A random policy to get testcasess from the corpus
    let scheduler = RandScheduler::new();

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

    // Create the executor for an in-process function with observers for edge coverage, value-profile and allocations sizes
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(edges_observer, cmps_observer, allocs_observer),
        &mut fuzzer,
        &mut state,
        &mut restarting_mgr,
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
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut restarting_mgr, corpus_dirs)
            .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", &corpus_dirs));
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;

    // Never reached
    Ok(())
}
