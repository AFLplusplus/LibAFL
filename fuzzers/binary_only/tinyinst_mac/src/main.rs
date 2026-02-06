//! TinyInst-based fuzzer for macOS Apple Silicon
//!
//! This fuzzer targets Apple's ImageIO framework using TinyInst for coverage collection.
//! It demonstrates LibAFL + TinyInst integration on macOS with:
//! - MmapShMemProvider for POSIX shared memory compatibility
//! - Persistent mode fuzzing with the `_fuzz` entry point
//! - Coverage-guided fuzzing with cumulative offset tracking
//!
//! # Building the harness
//! ```bash
//! cd imageio && make
//! ```
//!
//! # Running
//! ```bash
//! sudo ./target/debug/tinyinst_mac
//! ```
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    feedbacks::{CrashFeedback, ListFeedback},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, HavocScheduledMutator},
    observers::ListObserver,
    schedulers::RandScheduler,
    stages::StdMutationalStage,
    state::{HasCorpus, StdState},
    Fuzzer, StdFuzzer,
};
use libafl_bolts::{ownedref::OwnedMutPtr, rands::StdRand, tuples::tuple_list};
use libafl_tinyinst::executor::TinyInstExecutor;
#[cfg(target_vendor = "apple")]
use shmem_providers::MmapShMemProvider;

static mut COVERAGE: Vec<u64> = vec![];
static CUMULATIVE_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(not(target_vendor = "apple"))]
fn main() {
    eprintln!("This fuzzer only works on macOS Apple Silicon");
    eprintln!("Please run on a macOS system with TinyInst support");
}

#[cfg(target_vendor = "apple")]
fn main() {
    env_logger::init();

    println!("=== TinyInst ImageIO Fuzzer for macOS ===\n");

    // TinyInst instrumentation args - instrument ImageIO framework
    let tinyinst_args = vec![
        "-instrument_module".to_string(),
        "ImageIO".to_string(),
        "-generate_unwind".to_string(),
    ];

    // Program args - use shmem to pass testcases
    let args = vec![
        "imageio/imageio".to_string(),
        "-m".to_string(),
        "@@".to_string(),
    ];

    let coverage = OwnedMutPtr::Ptr(&raw mut COVERAGE);
    let observer = ListObserver::new("cov", coverage);
    let mut feedback = ListFeedback::new(&observer);

    // Use MmapShMemProvider for macOS POSIX shared memory compatibility
    let mut shmem_provider = MmapShMemProvider::with_filename_as_id();

    // Load seed images from seeds directory
    let seed_dir = PathBuf::from("../../../seeds/pngs");
    let rand = StdRand::new();
    let mut corpus = CachedOnDiskCorpus::new(PathBuf::from("./corpus"), 64).unwrap();

    if seed_dir.exists() {
        for entry in fs::read_dir(&seed_dir).expect("Failed to read seeds directory") {
            let entry = entry.expect("Failed to read entry");
            let path = entry.path();
            if path.is_file() {
                match fs::read(&path) {
                    Ok(data) => {
                        println!("Loading seed: {} ({} bytes)", path.display(), data.len());
                        let input = BytesInput::new(data);
                        corpus
                            .add(Testcase::new(input))
                            .expect("error in adding corpus");
                    }
                    Err(e) => eprintln!("Failed to read {}: {}", path.display(), e),
                }
            }
        }
    }

    println!("Corpus size: {}", corpus.count());
    let solutions = OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap();

    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();
    let scheduler = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let monitor = SimpleMonitor::new(|x| {
        let cov_count = CUMULATIVE_COUNT.load(Ordering::Relaxed);
        println!("{x}");
        println!("  >> Cumulative coverage offsets: {}", cov_count);
    });

    let mut mgr = SimpleEventManager::new(monitor);
    let mut executor = TinyInstExecutor::builder()
        .tinyinst_args(tinyinst_args)
        .program_args(args)
        .use_shmem()
        // Note: macOS mangles C function names with underscore prefix
        .persistent("imageio".to_string(), "_fuzz".to_string(), 1, 10000)
        .timeout(Duration::new(5, 0))
        .shmem_provider(&mut shmem_provider)
        .coverage_ptr(&raw mut COVERAGE)
        .build(tuple_list!(observer))
        .unwrap();

    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    println!("\nStarting ImageIO fuzzer...");
    println!("Press Ctrl+C to stop\n");

    // Run fuzzing loop with coverage tracking
    let start = Instant::now();
    let mut last_cov_print = Instant::now();
    let mut executions: u64 = 0;

    loop {
        match fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
            Ok(_) => {}
            Err(e) => {
                println!("Fuzzer error: {:?}", e);
                break;
            }
        }

        executions += 1;

        // Update cumulative coverage
        let current_cov = executor.cumulative_coverage_count() as u64;
        CUMULATIVE_COUNT.store(current_cov, Ordering::Relaxed);

        // Print coverage stats every 10 seconds
        if last_cov_print.elapsed() >= Duration::from_secs(10) {
            let elapsed = start.elapsed().as_secs();
            let exec_per_sec = if elapsed > 0 {
                executions as f64 / elapsed as f64
            } else {
                0.0
            };
            println!("\n=== Coverage Report ({}s) ===", elapsed);
            println!("  Executions: {} ({:.2}/sec)", executions, exec_per_sec);
            println!("  Cumulative unique offsets: {}", current_cov);
            println!("  Corpus size: {}", state.corpus().count());

            // Print sample offsets
            let offsets = executor.cumulative_coverage();
            if !offsets.is_empty() {
                let sample: Vec<String> = offsets
                    .iter()
                    .take(10)
                    .map(|x| format!("0x{:x}", x))
                    .collect();
                println!("  Sample offsets: {:?}", sample);
            }
            println!();

            last_cov_print = Instant::now();
        }
    }
}
