//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.

use std::{env, path::PathBuf};

#[cfg(unix)]
use libafl::{
    bolts::{shmem::UnixShMem, tuples::tuple_list},
    corpus::{
        Corpus, InMemoryCorpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
        QueueCorpusScheduler,
    },
    events::setup_restarting_mgr,
    executors::{inprocess::InProcessExecutor, Executor, ExitKind, inprocess::TimeoutExecutor},
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, HasCorpusScheduler, StdFuzzer},
    inputs::Input,
    mutators::{scheduled::HavocBytesMutator, token_mutations::Tokens},
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, State},
    stats::SimpleStats,
    utils::{current_nanos, StdRand},
    Error,
};

/// We will interact with a C++ target, so use external c functionality
#[cfg(unix)]
extern "C" {
    /// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;

    // afl_libfuzzer_init calls LLVMFUzzerInitialize()
    fn afl_libfuzzer_init() -> i32;

    static __lafl_edges_map: *mut u8;
    static __lafl_cmp_map: *mut u8;
    static __lafl_max_edges_size: u32;
}

/// The wrapped harness function, calling out to the LLVM-style harness
#[cfg(unix)]
fn harness<E, I>(_executor: &E, buf: &[u8]) -> ExitKind
where
    E: Executor<I>,
    I: Input,
{
    // println!("{:?}", buf);
    unsafe {
        LLVMFuzzerTestOneInput(buf.as_ptr(), buf.len());
    }
    ExitKind::Ok
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
                TimeFeedback::new()
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
    let mutator = HavocBytesMutator::default();
    let stage = StdMutationalStage::new(mutator);

    // A fuzzer with just one stage and a minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());
    let fuzzer = StdFuzzer::new(scheduler, tuple_list!(stage));

    // Create the executor for an in-process function with just one observer for edge coverage
    let mut executor = InProcessExecutor::new(
        "in-process(edges)",
        harness,
        tuple_list!(edges_observer, TimeObserver::new("time")),
        &mut state,
        &mut restarting_mgr,
    )?;
    let mut tmexecutor = TimeoutExecutor::new(executor, 2);
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
            .load_initial_inputs(
                &mut tmexecutor,
                &mut restarting_mgr,
                fuzzer.scheduler(),
                &corpus_dirs,
            )
            .expect(&format!(
                "Failed to load initial corpus at {:?}",
                &corpus_dirs
            ));
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    fuzzer.fuzz_loop(&mut state, &mut tmexecutor, &mut restarting_mgr)?;

    // Never reached
    Ok(())
}
