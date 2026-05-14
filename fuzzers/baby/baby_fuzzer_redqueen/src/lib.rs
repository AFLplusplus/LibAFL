//! A simple in-process fuzzer with redqueen

use core::time::Duration;
use std::{
    env,
    fs::{self},
    path::PathBuf,
    process,
};

use clap::{Arg, Command};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, token_mutations::AflppRedQueen, HavocScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver},
    schedulers::QueueScheduler,
    stages::{mutational::MultiMutationalStage, ColorizationStage, IfStage, StdMutationalStage},
    state::{HasCorpus, HasCurrentTestcase, StdState},
    Error,
};
use libafl_bolts::{
    ownedref::OwnedRefMut,
    rands::StdRand,
    tuples::{tuple_list, Handled},
    AsSlice,
};
use libafl_targets::{
    cmps::{observers::AflppCmpLogObserver, stages::AflppCmplogTracingStage},
    libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer, CMPLOG_MAP_EXTENDED,
};

/// The fuzzer main (as `no_mangle` C function)
#[no_mangle]
pub extern "C" fn libafl_main(
    _argc: core::ffi::c_int,
    _argv: *const *const core::ffi::c_char,
) -> core::ffi::c_int {
    let cmd = Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("AFLplusplus team")
        .about("Example fuzzer for AflppRedQueen Instrumentation")
        .arg(
            Arg::new("out")
                .short('o')
                .long("output")
                .help("The directory to place finds in ('corpus')"),
        )
        .arg(
            Arg::new("in")
                .short('i')
                .long("input")
                .help("The directory to read initial inputs from ('seeds')"),
        );

    let res = match cmd.arg(Arg::new("remaining")).try_get_matches() {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, -o corpus_dir -i seed_dir\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err,
            );
            return 1;
        }
    };

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    // Put crashes and finds inside the same `corpus` directory, in "crashes" and "queue" subdirs.
    let mut out_dir = PathBuf::from(
        res.get_one::<String>("out")
            .expect("The --output parameter is missing")
            .to_string(),
    );
    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return 1;
        }
    }
    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    out_dir.push("queue");

    let in_dir = PathBuf::from(
        res.get_one::<String>("in")
            .expect("The --input parameter is missing")
            .to_string(),
    );
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return 1;
    }

    run_fuzzer(out_dir, crashes, &in_dir, Duration::from_secs(5))
        .expect("An error occurred while fuzzing");
    0
}

/// The actual fuzzer
fn run_fuzzer(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    seed_dir: &PathBuf,
    timeout: Duration,
) -> Result<(), Error> {
    // The monitor provides the user some insight into how the fuzz run is going
    let mon = SimpleMonitor::new(|s| println!("{s}"));
    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // Create an observation channel using the coverage map
    let edges_observer =
        HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") }).track_indices();

    // For this tiny fuzzer, we'll just use the coverage map for
    // feedback. Proper fuzzers will also collect time feedback to use
    // for calibration and queue scheduling
    let mut feedback = MaxMapFeedback::new(&edges_observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        // RNG
        StdRand::new(),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryOnDiskCorpus::new(corpus_dir).unwrap(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(objective_dir).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )?;

    println!("Let's fuzz :)");

    // The actual target run starts here.
    // Call LLVMFuzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    // Setup a mutational stage with a basic bytes mutator
    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mutational_stage = StdMutationalStage::new(mutator);

    // queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The wrapped harness function, calling out to the LLVM-style harness
    fn harness(input: &BytesInput) -> ExitKind {
        let target = input.target_bytes();
        let buf = target.as_slice();
        unsafe {
            libfuzzer_test_one_input(buf);
        }
        ExitKind::Ok
    }
    let mut harness_main: fn(&BytesInput) -> ExitKind = harness;
    let mut harness_cmplog: fn(&BytesInput) -> ExitKind = harness;

    /*
    RedQueen's colorization stage needs a reference to edges_observer
    */
    let colorization = ColorizationStage::new(&edges_observer);

    // Create the executor for an in-process function with one observer for edge coverage
    let mut executor = InProcessExecutor::with_timeout(
        &mut harness_main,
        tuple_list!(edges_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    // Now, we'll setup the rest of the RedQueen stages. We need the cmplog map,
    // an executor that populates it, and observer for it, and the
    // colorization/tracing stages .

    let cmpmap_ref = unsafe { OwnedRefMut::from_mut_ptr(&raw mut CMPLOG_MAP_EXTENDED) };
    let cmplog_observer = AflppCmpLogObserver::new("cmplog", cmpmap_ref, true);
    let cmplog_ref = cmplog_observer.handle();
    let cmplog_executor = InProcessExecutor::with_timeout(
        &mut harness_cmplog,
        tuple_list!(cmplog_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    let tracing = AflppCmplogTracingStage::new(cmplog_executor, cmplog_ref);

    // Setup a randomic Input2State stage
    let rq: MultiMutationalStage<_, _, BytesInput, _, _, _> =
        MultiMutationalStage::new(AflppRedQueen::with_cmplog_options(true, true));

    // We'll only run the cmplog stuff (run colorization, enable comparison tracing, then do mutations based on those) when a test case is on its second schedule
    let cb = |_fuzzer: &mut _,
              _executor: &mut _,
              state: &mut StdState<InMemoryOnDiskCorpus<_>, _, _, _>,
              _event_manager: &mut _|
     -> Result<bool, Error> {
        let testcase = state.current_testcase()?;
        let res = testcase.scheduled_count() == 1; // let's try on the 2nd trial

        Ok(res)
    };
    let cmplog = IfStage::new(cb, tuple_list!(colorization, tracing, rq));

    let mut stages = tuple_list!(cmplog, mutational_stage);

    state
        .load_initial_inputs(
            &mut fuzzer,
            &mut executor,
            &mut mgr,
            std::slice::from_ref(seed_dir),
        )
        .unwrap_or_else(|e| {
            println!("Failed to load initial corpus at {seed_dir:?} - {e:?}");
            process::exit(0);
        });
    println!("We imported {} inputs from disk.", state.corpus().count());

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

    Ok(())
}
