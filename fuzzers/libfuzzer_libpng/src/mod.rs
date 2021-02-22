//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.

use std::{env, path::PathBuf};

use libafl::{
    bolts::{shmem::UnixShMem, tuples::tuple_list},
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, RandCorpusScheduler},
    events::setup_restarting_mgr,
    executors::{inprocess::InProcessExecutor, Executor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::Input,
    mutators::scheduled::HavocBytesMutator,
    mutators::token_mutations::TokensMetadata,
    observers::StdMapObserver,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, State},
    stats::SimpleStats,
    utils::{current_nanos, StdRand},
    Error,
};

/// The name of the coverage map observer, to find it again in the observer list
const NAME_COV_MAP: &str = "cov_map";

/// We will interact with a c++ target, so use external c functionality
extern "C" {
    /// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;

    // afl_libfuzzer_init calls LLVMFUzzerInitialize()
    fn afl_libfuzzer_init() -> i32;

    static __lafl_edges_map: *mut u8;
    static __lafl_cmp_map: *mut u8;
    static __lafl_max_edges_size: u32;
}

/// The wrapped harness function, calling out to the llvm-style libfuzzer harness
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

/// The main fn, parsing parameters, and starting the fuzzer
pub fn main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<TokensMetadata>();

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

/// The actual fuzzer
fn fuzz(corpus_dirs: Vec<PathBuf>, objective_dir: PathBuf, broker_port: u16) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    let (state, mut restarting_mgr) =
        setup_restarting_mgr::<_, _, UnixShMem, _>(stats, broker_port)
            .expect("Failed to setup the restarter".into());

    // Create an observation channel using the coverage map
    let edges_observer =
        StdMapObserver::new_from_ptr(&NAME_COV_MAP, unsafe { __lafl_edges_map }, unsafe {
            __lafl_max_edges_size as usize
        });

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or(State::new(
        StdRand::new(current_nanos()),
        InMemoryCorpus::new(),
        tuple_list!(MaxMapFeedback::new_with_observer(
            &NAME_COV_MAP,
            &edges_observer
        )),
        OnDiskCorpus::new(objective_dir),
        tuple_list!(CrashFeedback::new()),
    ));

    println!("We're a client, let's fuzz :)");

    // Create a PNG dictionary if not existing
    if state.metadata().get::<TokensMetadata>().is_none() {
        state.add_metadata(TokensMetadata::new(vec![
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
    let fuzzer = StdFuzzer::new(RandCorpusScheduler::new(), tuple_list!(stage));

    // Create the executor
    let mut executor = InProcessExecutor::new(
        "Libfuzzer",
        harness,
        tuple_list!(edges_observer),
        &mut state,
        &mut restarting_mgr,
    );

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    unsafe {
        if afl_libfuzzer_init() == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1")
        }
    }

    // in case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut executor, &mut restarting_mgr, &corpus_dirs)
            .expect(&format!(
                "Failed to load initial corpus at {:?}",
                &corpus_dirs
            ));
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    fuzzer.fuzz_loop(&mut state, &mut executor, &mut restarting_mgr)?;

    Ok(())
}
