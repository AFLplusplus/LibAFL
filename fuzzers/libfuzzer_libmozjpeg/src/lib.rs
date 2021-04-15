//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libmozjpeg.

use std::{env, path::PathBuf};

use libafl::{
    bolts::{shmem::StdShMemProvider, tuples::tuple_list},
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, RandCorpusScheduler},
    events::setup_restarting_mgr,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    mutators::token_mutations::Tokens,
    observers::StdMapObserver,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, State},
    stats::SimpleStats,
    utils::{current_nanos, StdRand},
    Error,
};

use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, EDGES_MAP, MAX_EDGES_NUM, CMP_MAP, CMP_MAP_SIZE};

const ALLOC_MAP_SIZE: usize = 16*1024;
extern "C" {
    static mut libafl_alloc_map: [usize; ALLOC_MAP_SIZE];
}

/// The main fn, usually parsing parameters, and starting the fuzzer
#[no_mangle]
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

/// The actual fuzzer
fn fuzz(corpus_dirs: Vec<PathBuf>, objective_dir: PathBuf, broker_port: u16) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    let (state, mut restarting_mgr) =
        setup_restarting_mgr(StdShMemProvider::new(), stats, broker_port)
            .expect("Failed to setup the restarter".into());

    // Create an observation channel using the coverage map
    let edges_observer = StdMapObserver::new("edges", unsafe { &mut EDGES_MAP }, unsafe { MAX_EDGES_NUM });

    // Create an observation channel using the cmp map
    let cmps_observer = StdMapObserver::new("cmps", unsafe { &mut CMP_MAP }, CMP_MAP_SIZE);

    // Create an observation channel using the allocations map
    let allocs_observer = StdMapObserver::new("allocs", unsafe { &mut libafl_alloc_map }, ALLOC_MAP_SIZE);

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
            OnDiskCorpus::new(objective_dir).unwrap(),
            // Feedbacks to recognize an input as solution
            tuple_list!(CrashFeedback::new()),
        )
    });

    println!("We're a client, let's fuzz :)");

    // Add the JPEG tokens if not existing
    if state.metadata().get::<Tokens>().is_none() {
        state.add_metadata(Tokens::from_tokens_file("./jpeg.dict")?);
    }

    // Setup a basic mutator with a mutational stage
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let stage = StdMutationalStage::new(mutator);

    let scheduler = RandCorpusScheduler::new();
    // A fuzzer with just one stage and a random policy to get testcasess from the corpus
    let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |buf: &[u8]| {
        libfuzzer_test_one_input(buf);
        ExitKind::Ok
    };

    // Create the executor for an in-process function with just one observer for edge coverage
    let mut executor = InProcessExecutor::new(
        "in-process(edges,cmp,alloc)",
        &mut harness,
        tuple_list!(edges_observer, cmps_observer, allocs_observer),
        &mut state,
        &mut restarting_mgr,
    )?;

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if libfuzzer_initialize(&args) == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1")
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
