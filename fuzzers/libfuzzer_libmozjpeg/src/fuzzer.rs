//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libmozjpeg.

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

/// We will interact with a C++ target, so use external c functionality
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
        StdMapObserver::new_from_ptr("edges", unsafe { __lafl_edges_map }, unsafe {
            __lafl_max_edges_size as usize
        });

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        State::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryCorpus::new(),
            // Feedbacks to rate the interestingness of an input
            tuple_list!(MaxMapFeedback::new_with_observer(&edges_observer)),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir),
            // Feedbacks to recognize an input as solution
            tuple_list!(CrashFeedback::new()),
        )
    });

    println!("We're a client, let's fuzz :)");

    // Create a JPEG dictionary if not existing
    if state.metadata().get::<TokensMetadata>().is_none() {
        state.add_metadata(TokensMetadata::new(vec![
            vec![0xff, 0xd8, 0xff], // JPEG header
            vec![0xff, 0xc0],
            vec![0xff, 0xc2],
            vec![0xff, 0xc4],
            vec![0xff, 0xd0],
            vec![0xff, 0xd8],
            vec![0xff, 0xd9],
            vec![0xff, 0xda],
            vec![0xff, 0xdb],
            vec![0xff, 0xdd],
            vec![0xff, 0xe0],
            vec![0xff, 0xe1],
            vec![0xff, 0xfe],
        ]));
    }

    // Setup a basic mutator with a mutational stage
    let mutator = HavocBytesMutator::default();
    let stage = StdMutationalStage::new(mutator);

    // A fuzzer with just one stage and a random policy to get testcasess from the corpus
    let fuzzer = StdFuzzer::new(RandCorpusScheduler::new(), tuple_list!(stage));

    // Create the executor for an in-process function with just one observer for edge coverage
    let mut executor = InProcessExecutor::new(
        "in-process(edges)",
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

    // In case the corpus is empty (on first run), reset
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

    // Never reached
    Ok(())
}
