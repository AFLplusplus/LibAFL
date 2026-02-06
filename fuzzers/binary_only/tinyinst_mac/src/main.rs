//! TinyInst-based fuzzer for macOS Apple Silicon
//!
//! This fuzzer targets Apple's ImageIO framework using TinyInst for coverage collection.
//! It demonstrates LibAFL + TinyInst integration on macOS with:
//! - MmapShMemProvider for POSIX shared memory compatibility
//! - Persistent mode fuzzing with the `_fuzz` entry point
//! - Coverage-guided fuzzing with cumulative offset tracking
//! - Multi-process fuzzing with shared corpus
//!
//! # Building the harness
//! ```bash
//! cd imageio && make
//! ```
//!
//! # Running
//! ```bash
//! # Single process
//! sudo ./target/debug/tinyinst_mac
//!
//! # Multi-process (4 workers)
//! sudo ./target/debug/tinyinst_mac --workers 4
//! ```
use std::{
    env,
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use libafl::{
    Fuzzer, StdFuzzer,
    corpus::{Corpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    feedbacks::{CrashFeedback, ListFeedback},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{HavocScheduledMutator, havoc_mutations},
    observers::ListObserver,
    schedulers::RandScheduler,
    stages::StdMutationalStage,
    state::{HasCorpus, StdState},
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

    // Check if we're a worker process
    let args: Vec<String> = env::args().collect();
    let worker_id = args
        .iter()
        .position(|arg| arg == "--worker-id")
        .and_then(|pos| args.get(pos + 1))
        .and_then(|id| id.parse::<usize>().ok());

    if let Some(id) = worker_id {
        // We're a worker - run fuzzer
        println!("=== Worker {} starting ===", id);
        run_worker(id);
        return;
    }

    // Check if we should spawn multiple workers
    let num_workers = args
        .iter()
        .position(|arg| arg == "--workers")
        .and_then(|pos| args.get(pos + 1))
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(1);

    if num_workers > 1 {
        println!("=== TinyInst ImageIO Fuzzer for macOS ===");
        println!("Spawning {} worker processes...\n", num_workers);
        spawn_workers(num_workers);
    } else {
        println!("=== TinyInst ImageIO Fuzzer for macOS (single process) ===\n");
        run_worker(0);
    }
}

#[cfg(target_vendor = "apple")]
fn spawn_workers(num_workers: usize) {
    let exe_path = env::current_exe().expect("Failed to get executable path");
    let mut children = Vec::new();

    for worker_id in 0..num_workers {
        let child = Command::new(&exe_path)
            .arg("--worker-id")
            .arg(worker_id.to_string())
            .spawn()
            .expect("Failed to spawn worker");

        println!("Spawned worker {} (PID: {})", worker_id, child.id());
        children.push(child);

        // Small delay between spawns
        thread::sleep(Duration::from_millis(500));
    }

    println!("\nAll workers started. Press Ctrl+C to stop all workers.\n");

    // Wait for all workers
    for (id, mut child) in children.into_iter().enumerate() {
        match child.wait() {
            Ok(status) => println!("Worker {} exited with status: {}", id, status),
            Err(e) => eprintln!("Worker {} error: {}", id, e),
        }
    }
}

#[cfg(target_vendor = "apple")]
fn run_worker(worker_id: usize) {

    // TinyInst instrumentation args - instrument ImageIO framework
    // Note: -coverage_module enables coverage collection for the specified module
    let tinyinst_args = vec![
        "-instrument_module".to_string(),
        "ImageIO".to_string(),
        "-coverage_module".to_string(),
        "ImageIO".to_string(),
        "-coverage_type".to_string(),
        "edge".to_string(),
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

    // Shared corpus directory (all workers share the same corpus)
    let corpus_dir = PathBuf::from("./corpus");
    let mut corpus = OnDiskCorpus::new(corpus_dir).unwrap();

    // Load seed images from seeds directory (only if corpus is empty)
    if corpus.count() == 0 {
        let seed_dir = PathBuf::from("../../../seeds/pngs");
        if seed_dir.exists() {
            println!("[Worker {}] Loading seeds...", worker_id);
            for entry in fs::read_dir(&seed_dir).expect("Failed to read seeds directory") {
                let entry = entry.expect("Failed to read entry");
                let path = entry.path();
                if path.is_file() {
                    match fs::read(&path) {
                        Ok(data) => {
                            println!(
                                "[Worker {}] Loading seed: {} ({} bytes)",
                                worker_id,
                                path.display(),
                                data.len()
                            );
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
    }

    println!("[Worker {}] Corpus size: {}", worker_id, corpus.count());
    let solutions = OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap();

    let mut objective = CrashFeedback::new();
    let rand = StdRand::new();
    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();
    let scheduler = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let monitor = SimpleMonitor::new(move |x| {
        let cov_count = CUMULATIVE_COUNT.load(Ordering::Relaxed);
        println!("[Worker {}] {}", worker_id, x);
        println!("[Worker {}]   >> Cumulative coverage offsets: {}", worker_id, cov_count);
    });

    let mut mgr = SimpleEventManager::new(monitor);
    // Check if persistent mode is enabled via environment variable
    let use_persistent = env::var("PERSISTENT").is_ok();
    
    let mut executor = if use_persistent {
        println!("[Worker {}] Using persistent mode", worker_id);
        TinyInstExecutor::builder()
            .tinyinst_args(tinyinst_args)
            .program_args(args)
            .use_shmem()
            // Note: macOS mangles C function names with underscore prefix
            .persistent("imageio".to_string(), "_fuzz".to_string(), 1, 10000)
            .timeout(Duration::new(5, 0))
            .shmem_provider(&mut shmem_provider)
            .coverage_ptr(&raw mut COVERAGE)
            .build(tuple_list!(observer))
            .unwrap()
    } else {
        println!("[Worker {}] Using normal mode (set PERSISTENT=1 for persistent mode)", worker_id);
        TinyInstExecutor::builder()
            .tinyinst_args(tinyinst_args)
            .program_args(args)
            .use_shmem()
            .timeout(Duration::new(5, 0))
            .shmem_provider(&mut shmem_provider)
            .coverage_ptr(&raw mut COVERAGE)
            .build(tuple_list!(observer))
            .unwrap()
    };

    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    println!("[Worker {}] Starting ImageIO fuzzer...", worker_id);
    println!("[Worker {}] Press Ctrl+C to stop\n", worker_id);

    // Run fuzzing loop with coverage tracking
    let start = Instant::now();
    let mut last_cov_print = Instant::now();
    let mut last_corpus_sync = Instant::now();
    let mut executions: u64 = 0;
    let mut known_corpus_files: std::collections::HashSet<String> = std::collections::HashSet::new();
    
    // Track existing corpus files
    let corpus_dir = PathBuf::from("./corpus");
    if corpus_dir.exists() {
        if let Ok(entries) = fs::read_dir(&corpus_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    known_corpus_files.insert(name.to_string());
                }
            }
        }
    }

    loop {
        match fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
            Ok(_) => {}
            Err(e) => {
                println!("[Worker {}] Fuzzer error: {:?}", worker_id, e);
                break;
            }
        }

        executions += 1;

        // Update cumulative coverage
        let current_cov = executor.cumulative_coverage_count() as u64;
        CUMULATIVE_COUNT.store(current_cov, Ordering::Relaxed);

        // Sync corpus from other workers every 30 seconds
        if last_corpus_sync.elapsed() >= Duration::from_secs(30) {
            if let Ok(entries) = fs::read_dir(&corpus_dir) {
                let mut new_inputs = 0;
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        if !known_corpus_files.contains(name) {
                            // New file from another worker
                            if let Ok(data) = fs::read(entry.path()) {
                                let input = BytesInput::new(data);
                                if state.corpus_mut().add(Testcase::new(input)).is_ok() {
                                    new_inputs += 1;
                                }
                                known_corpus_files.insert(name.to_string());
                            }
                        }
                    }
                }
                if new_inputs > 0 {
                    println!(
                        "[Worker {}] Synced {} new inputs from other workers",
                        worker_id, new_inputs
                    );
                }
            }
            last_corpus_sync = Instant::now();
        }

        // Print coverage stats every 10 seconds
        if last_cov_print.elapsed() >= Duration::from_secs(10) {
            let elapsed = start.elapsed().as_secs();
            let exec_per_sec = if elapsed > 0 {
                executions as f64 / elapsed as f64
            } else {
                0.0
            };
            println!(
                "\n[Worker {}] === Coverage Report ({}s) ===",
                worker_id, elapsed
            );
            println!(
                "[Worker {}]   Executions: {} ({:.2}/sec)",
                worker_id, executions, exec_per_sec
            );
            println!(
                "[Worker {}]   Cumulative unique offsets: {}",
                worker_id, current_cov
            );
            println!(
                "[Worker {}]   Corpus size: {}",
                worker_id,
                state.corpus().count()
            );

            // Print sample offsets
            let offsets = executor.cumulative_coverage();
            if !offsets.is_empty() {
                let sample: Vec<String> = offsets
                    .iter()
                    .take(10)
                    .map(|x| format!("0x{:x}", x))
                    .collect();
                println!("[Worker {}]   Sample offsets: {:?}", worker_id, sample);
            }
            println!();

            last_cov_print = Instant::now();
        }
    }
}
