//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.

use std::{env, path::PathBuf};

#[cfg(unix)]
use libafl::{
    bolts::{shmem::UnixShMem, tuples::tuple_list},
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, RandCorpusScheduler},
    events::setup_restarting_mgr,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    mutators::token_mutations::Tokens,
    observers::{HitcountsMapObserver, StdMapObserver},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, State},
    stats::SimpleStats,
    utils::{current_nanos, StdRand},
    Error,
};

#[cfg(unix)]
const MAP_SIZE: usize = 16 * 1024;

/// We will interact with a C++ target, so use external c functionality
#[cfg(unix)]
extern "C" {
    /// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;

    // afl_libfuzzer_init calls LLVMFUzzerInitialize()
    fn afl_libfuzzer_init() -> i32;

    static __lafl_edges_map: *mut u8;
    static __lafl_cmp_map: *mut u8;
    static __lafl_alloc_map: *mut usize;
    static __lafl_max_edges_size: u32;
}

/// The main fn, usually parsing parameters, and starting the fuzzer
pub fn main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );
    fuzz(
        vec![PathBuf::from("./corpus")],
        PathBuf::from("./crashes"),
        1337,
    )
    .expect("An error occurred while fuzzing");
}

/// Not supported on windows right now
#[cfg(windows)]
fn fuzz(_corpus_dirs: Vec<PathBuf>, _objective_dir: PathBuf, _broker_port: u16) -> Result<(), ()> {
    todo!("Example not supported on Windows");
}

/// The actual fuzzer
#[cfg(unix)]
fn fuzz(corpus_dirs: Vec<PathBuf>, objective_dir: PathBuf, broker_port: u16) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    let (state, mut restarting_mgr) =
        match setup_restarting_mgr::<_, _, UnixShMem, _>(stats, broker_port) {
            Ok(res) => res,
            Err(err) => match err {
                Error::ShuttingDown => {
                    return Ok(());
                }
                _ => {
                    panic!("Failed to setup the restarter: {}", err);
                }
            },
        };

    // Create an observation channel using the coverage map
    let edges_observer = HitcountsMapObserver::new(unsafe {
        StdMapObserver::new_from_ptr("edges", __lafl_edges_map, __lafl_max_edges_size as usize)
    });

    // Create an observation channel using the cmp map
    let cmps_observer = unsafe { StdMapObserver::new_from_ptr("cmps", __lafl_cmp_map, MAP_SIZE) };

    // Create an observation channel using the allocations map
    let allocs_observer =
        unsafe { StdMapObserver::new_from_ptr("allocs", __lafl_alloc_map, MAP_SIZE) };

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        State::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryCorpus::new(),
            // Feedbacks to rate the interestingness of an input
            tuple_list!(
                MaxMapFeedback::new_with_observer_track(&edges_observer, true, false),
                MaxMapFeedback::new_with_observer(&cmps_observer),
                MaxMapFeedback::new_with_observer(&allocs_observer),
            ),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // Feedbacks to recognize an input as solution
            tuple_list!(CrashFeedback::new()),
        )
    });

    println!("We're a client, let's fuzz :)");

    // Create a PNG dictionary if not existing
    if state.metadata().get::<Tokens>().is_none() {
        state.add_metadata(Tokens::new(vec![
            vec![137, 80, 78, 71, 13, 10, 26, 10], // PNG header
            "IHDR".as_bytes().to_vec(),
            "IDAT".as_bytes().to_vec(),
            "PLTE".as_bytes().to_vec(),
            "IEND".as_bytes().to_vec(),
        ]));
    }

    // Setup a basic mutator with a mutational stage
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let stage = StdMutationalStage::new(mutator);

    let scheduler = RandCorpusScheduler::new();
    // A fuzzer with just one stage and a random policy to get testcasess from the corpus
    let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |buf: &[u8]| {
        unsafe { LLVMFuzzerTestOneInput(buf.as_ptr(), buf.len()) };
        ExitKind::Ok
    };

    // Create the executor for an in-process function with just one observer for edge coverage
    let mut executor = InProcessExecutor::new(
        "in-process(edges)",
        &mut harness,
        tuple_list!(edges_observer, cmps_observer, allocs_observer),
        &mut state,
        &mut restarting_mgr,
    )?;

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    unsafe {
        if afl_libfuzzer_init() == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1")
        }
    }

    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut executor, &mut restarting_mgr, &scheduler, &corpus_dirs)
            .expect(&format!(
                "Failed to load initial corpus at {:?}",
                &corpus_dirs
            ));
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    fuzzer.fuzz_loop(&mut state, &mut executor, &mut restarting_mgr, &scheduler)?;

    // Never reached
    Ok(())
}
