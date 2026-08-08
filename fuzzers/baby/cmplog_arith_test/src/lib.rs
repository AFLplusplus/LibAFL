//! Multi-core LibAFL fuzzer with CMPLOG/I2S to test whether it can solve:
//!   (x * 3) + (y / 2) == 0x12345678
//!
//! Based on the fuzzbench fuzzer. Uses SimpleRestartingEventManager (one process)
//! but we launch N copies externally for multi-core scaling.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use core::time::Duration;
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    process,
};

use clap::{Arg, Command};
use libafl::{
    Error,
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleRestartingEventManager,
    executors::{ExitKind, ShadowExecutor, inprocess::InProcessExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{
        HavocScheduledMutator, StdMOptMutator, havoc_mutations, token_mutations::I2SRandReplace,
    },
    observers::{CanTrack, HitcountsMapObserver, TimeObserver},
    schedulers::{
        IndexesLenTimeMinimizerScheduler, StdWeightedScheduler, powersched::PowerSchedule,
    },
    stages::{
        ShadowTracingStage, StdMutationalStage, calibrate::CalibrationStage,
        power::StdPowerMutationalStage,
    },
    state::{HasCorpus, StdState},
};
use libafl_bolts::{
    AsSlice, current_time,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_targets::{
    CmpLogObserver, libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer,
};

/// The fuzzer main (as `no_mangle` C function)
#[unsafe(no_mangle)]
pub extern "C" fn libafl_main() {
    let res = match Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about("LibAFL fuzzer with CMPLOG for arithmetic check")
        .arg(
            Arg::new("out")
                .short('o')
                .long("output")
                .help("Output directory for crashes"),
        )
        .arg(
            Arg::new("in")
                .short('i')
                .long("input")
                .help("Seed corpus directory"),
        )
        .try_get_matches()
    {
        Ok(res) => res,
        Err(err) => {
            eprintln!("Syntax error: {err:?}");
            return;
        }
    };

    let out_dir = PathBuf::from(res.get_one::<String>("out").expect("--output is required"));
    fs::create_dir_all(&out_dir).ok();
    let mut crashes_dir = out_dir.clone();
    crashes_dir.push("crashes");

    let in_dir = PathBuf::from(res.get_one::<String>("in").expect("--input is required"));

    fuzz(out_dir, crashes_dir, &in_dir).expect("Fuzzing failed");
}

fn fuzz(corpus_dir: PathBuf, objective_dir: PathBuf, seed_dir: &PathBuf) -> Result<(), Error> {
    let timeout = Duration::from_millis(1200);

    let monitor = SimpleMonitor::new(|s| {
        let _ = writeln!(std::io::stderr(), "{s}");
        println!("{s}");
    });

    let mut shmem_provider = StdShMemProvider::new()?;

    let (state, mut mgr) =
        match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider, true) {
            Ok(res) => res,
            Err(Error::ShuttingDown) => return Ok(()),
            Err(err) => panic!("Failed to setup restarter: {err}"),
        };

    // Observers
    let edges_observer =
        HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") }).track_indices();
    let time_observer = TimeObserver::new("time");
    let cmplog_observer = CmpLogObserver::new("cmplog", true);

    let map_feedback = MaxMapFeedback::new(&edges_observer);
    let calibration = CalibrationStage::new(&map_feedback);

    let mut feedback = feedback_or!(map_feedback,);
    let mut objective = CrashFeedback::new();

    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            StdRand::new(),
            InMemoryCorpus::new(),
            OnDiskCorpus::new(&objective_dir).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });

    // I2S mutations from cmplog data
    let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
        I2SRandReplace::new()
    )));

    // MOPT mutator
    let mutator = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5)?;
    let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
        StdPowerMutationalStage::new(mutator);

    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        StdWeightedScheduler::with_schedule(
            &mut state,
            &edges_observer,
            Some(PowerSchedule::fast()),
        ),
    );

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Harness
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        unsafe {
            libfuzzer_test_one_input(buf);
        }
        ExitKind::Ok
    };

    let executor = InProcessExecutor::with_timeout(
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    // ShadowExecutor for CMPLOG
    let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

    // CMPLOG tracing stage
    let tracing = ShadowTracingStage::new();

    let mut stages = tuple_list!(calibration, tracing, i2s, power);

    // Initialize target
    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed");
    }

    // Load seeds
    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
            .unwrap_or_else(|e| {
                eprintln!("Failed to load seeds: {e:?}");
                process::exit(0);
            });
        println!("Loaded {} inputs from seeds", state.corpus().count());
    }

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    Ok(())
}
