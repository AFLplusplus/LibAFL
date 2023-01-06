use core::ffi::c_int;
use std::{env::temp_dir, fs::create_dir, path::PathBuf};

use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice},
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{ExitKind, InProcessExecutor, TimeoutExecutor},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, Feedback, MaxMapFeedback, NewHashFeedback, TimeFeedback},
    generators::{GeneralizedInputBytesGenerator, RandBytesGenerator},
    inputs::{GeneralizedInput, HasTargetBytes, UsesInput},
    monitors::SimplePrintingMonitor,
    mutators::{
        grimoire::*, havoc_mutations, tokens_mutations, I2SRandReplace, StdMOptMutator,
        StdScheduledMutator, Tokens,
    },
    observers::{
        BacktraceObserver, HitcountsIterableMapObserver, MultiMapObserver, ObserversTuple,
        StdMapObserver, TimeObserver,
    },
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
    },
    stages::{
        CalibrationStage, GeneralizationStage, SkippableStage, StdMutationalStage,
        StdPowerMutationalStage, TracingStage,
    },
    state::{HasClientPerfMonitor, HasCorpus, StdState},
    Error, Fuzzer, StdFuzzer,
};
use libafl_targets::{autotokens, CmpLogObserver, CMPLOG_MAP, COUNTERS_MAPS};
use rand::{thread_rng, RngCore};

use crate::options::LibfuzzerOptions;

static mut BACKTRACE: Option<u64> = None;

fn fuzz_single(
    options: LibfuzzerOptions,
    harness: &extern "C" fn(*const u8, usize) -> c_int,
) -> Result<(), Error> {
    let mut mgr = SimpleEventManager::printing();

    // Create an observation channel using the coverage map
    let edges = unsafe { &mut COUNTERS_MAPS };
    let edges_observer = HitcountsIterableMapObserver::new(MultiMapObserver::new("edges", edges));

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // TODO Create the Cmp observer
    // let cmplog = unsafe { &mut CMPLOG_MAP };
    // let cmplog_observer = CmpLogObserver::new("cmplog", cmplog, true);

    // Create a stacktrace observer
    let backtrace_observer = BacktraceObserver::new(
        "BacktraceObserver",
        unsafe { &mut BACKTRACE },
        libafl::observers::HarnessType::InProcess,
    );

    // New maximization map feedback linked to the edges observer
    let map_feedback = MaxMapFeedback::new_tracking(&edges_observer, true, false);

    let calibration = CalibrationStage::new(&map_feedback);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        map_feedback,
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new_with_observer(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_and_fast!(
        CrashFeedback::new(),
        NewHashFeedback::new(&backtrace_observer)
    );

    let corpus_dir = if let Some(main) = options.dirs().first() {
        main.clone()
    } else {
        let mut rng = thread_rng();
        let mut dir = PathBuf::new();
        let mut last = Ok(());
        for _ in 0..8 {
            dir = temp_dir().join(format!("libafl-corpus-{}", rng.next_u64()));
            last = create_dir(&dir);
            if last.is_ok() {
                break;
            }
        }
        last?;
        dir
    };

    let crash_corpus = if let Some(prefix) = options.artifact_prefix() {
        OnDiskCorpus::with_prefix(prefix.dir().clone(), prefix.filename_prefix().clone()).unwrap()
    } else {
        OnDiskCorpus::new(std::env::current_dir().unwrap()).unwrap()
    };

    // If not restarting, create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        CachedOnDiskCorpus::new(corpus_dir.clone(), 4096).unwrap(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        crash_corpus,
        // A reference to the feedbacks, to create their feedback state
        &mut feedback,
        // A reference to the objectives, to create their objective state
        &mut objective,
    )
    .expect("Failed to create state");

    // TODO Read tokens from libfuzzer dicts
    // if state.metadata().get::<Tokens>().is_none() {
    //     let mut toks = Tokens::default();
    //     for tokenfile in &token_files {
    //         toks.add_from_file(tokenfile)?;
    //     }
    //     #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    //     {
    //         toks += autotokens()?;
    //     }
    //
    //     if !toks.is_empty() {
    //         state.add_metadata(toks);
    //     }
    // }

    // TODO Setup a randomic Input2State stage
    // let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));

    // Setup a MOPT mutator
    let mutator = StdMOptMutator::new(
        &mut state,
        havoc_mutations(), // TODO .merge(tokens_mutations()),
        7,
        5,
    )?;

    // TODO support
    // let grimoire_mutator = StdScheduledMutator::with_max_stack_pow(
    //     tuple_list!(
    //         GrimoireExtensionMutator::new(),
    //         GrimoireRecursiveReplacementMutator::new(),
    //         GrimoireStringReplacementMutator::new(),
    //         // give more probability to avoid large inputs
    //         GrimoireRandomDeleteMutator::new(),
    //         GrimoireRandomDeleteMutator::new(),
    //     ),
    //     3,
    // );
    // let grimoire = StdMutationalStage::new(grimoire_mutator);
    // let skippable_grimoire = SkippableStage::new(grimoire, |_s| opt.grimoire.into());

    let power = StdPowerMutationalStage::new(mutator, &edges_observer);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler =
        IndexesLenTimeMinimizerScheduler::new(PowerQueueScheduler::new(PowerSchedule::FAST));

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &GeneralizedInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        unsafe {
            harness(buf.as_ptr(), buf.len());
        }
        ExitKind::Ok
    };

    // let mut tracing_harness = harness;

    // let generalization = GeneralizationStage::new(&edges_observer);
    //
    // let skippable_generalization = SkippableStage::new(generalization, |_s| opt.grimoire.into());

    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let mut executor = TimeoutExecutor::new(
        InProcessExecutor::new(
            &mut harness,
            tuple_list!(edges_observer, time_observer, backtrace_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )?,
        options.timeout(),
    );

    // TODO Setup a tracing stage in which we log comparisons
    // let tracing = TracingStage::new(InProcessExecutor::new(
    //     &mut tracing_harness,
    //     tuple_list!(cmplog_observer),
    //     &mut fuzzer,
    //     &mut state,
    //     &mut mgr,
    // )?);

    // The order of the stages matter!
    let mut stages = tuple_list!(
        // skippable_generalization,
        calibration,
        // tracing,
        // i2s,
        power,
        // skippable_grimoire
    );

    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        if !options.dirs().is_empty() {
            println!("Loading from {:?}", options.dirs());
            // Load from disk
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, options.dirs())
                .unwrap_or_else(|_| {
                    panic!("Failed to load initial corpus at {:?}", options.dirs())
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }
        if state.corpus().count() < 1 {
            // Generator of printable bytearrays of max size 32
            let mut generator = GeneralizedInputBytesGenerator::from(RandBytesGenerator::new(32));

            // Generate 8 initial inputs
            state
                .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
                .expect("Failed to generate the initial corpus");
            println!(
                "We imported {} inputs from the generator.",
                state.corpus().count()
            );
        }
    }

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    Ok(())
}

pub fn fuzz(
    options: LibfuzzerOptions,
    harness: &extern "C" fn(*const u8, usize) -> c_int,
) -> Result<(), Error> {
    fuzz_single(options, harness)
}
