use core::ffi::c_int;
use std::{env::temp_dir, fs::create_dir, path::PathBuf};

use libafl::{
    bolts::{
        core_affinity::Cores,
        current_nanos,
        launcher::Launcher,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
        AsSlice,
    },
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{EventConfig, EventFirer, LlmpRestartingEventManager, SimpleEventManager},
    executors::{ExitKind, InProcessExecutor, TimeoutExecutor},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, Feedback, MaxMapFeedback, NewHashFeedback, TimeFeedback},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes, UsesInput},
    monitors::{tui::TuiMonitor, SimplePrintingMonitor},
    mutators::{
        grimoire::*, havoc_crossover, havoc_mutations, havoc_mutations_no_crossover,
        tokens_mutations, I2SRandReplace, StdMOptMutator, StdScheduledMutator, Tokens,
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
    state::{HasClientPerfMonitor, HasCorpus, StdState, UsesState},
    Error, Fuzzer, StdFuzzer,
};
use libafl_targets::{autotokens, CmpLogObserver, LLVMCustomMutator, CMPLOG_MAP, COUNTERS_MAPS};
use rand::{thread_rng, RngCore};

use crate::options::LibfuzzerOptions;

static mut BACKTRACE: Option<u64> = None;

struct CustomMutationStatus {
    std_mutational: bool,
    std_no_mutate: bool,
    std_no_crossover: bool,
    custom_mutation: bool,
    custom_crossover: bool,
}

impl CustomMutationStatus {
    fn new() -> Self {
        let custom_mutation = libafl_targets::libfuzzer::has_custom_mutator();
        let custom_crossover = libafl_targets::libfuzzer::has_custom_crossover();

        // we use all libafl mutations
        let std_mutational = !(custom_mutation || custom_crossover);
        // we use libafl crossover, but not libafl mutations
        let std_no_mutate = !std_mutational && custom_mutation && !custom_crossover;
        // we use libafl mutations, but not libafl crossover
        let std_no_crossover = !std_mutational && !custom_mutation && custom_crossover;

        Self {
            std_mutational,
            std_no_mutate,
            std_no_crossover,
            custom_mutation,
            custom_crossover,
        }
    }
}

macro_rules! make_fuzz_closure {
    ($options:ident, $harness:ident) => {
        |state: Option<_>, mut mgr, _cpu_id| {
            let mutator_status = CustomMutationStatus::new();

            // Create an observation channel using the coverage map
            let edges = unsafe { &mut COUNTERS_MAPS };
            let edges_observer =
                HitcountsIterableMapObserver::new(MultiMapObserver::new("edges", edges));

            // Create an observation channel to keep track of the execution time
            let time_observer = TimeObserver::new("time");

            // Create the Cmp observer
            let cmplog_observer = CmpLogObserver::new("cmplog", true);

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
                TimeFeedback::with_observer(&time_observer)
            );

            // A feedback to choose if an input is a solution or not
            let mut objective = feedback_and_fast!(
                CrashFeedback::new(),
                NewHashFeedback::new(&backtrace_observer)
            );

            let corpus_dir = if let Some(main) = $options.dirs().first() {
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

            let crash_corpus = if let Some(prefix) = $options.artifact_prefix() {
                OnDiskCorpus::with_prefix(prefix.dir().clone(), prefix.filename_prefix().clone().unwrap())
                    .unwrap()
            } else {
                OnDiskCorpus::new(std::env::current_dir().unwrap()).unwrap()
            };

            // If not restarting, create a State from scratch
            let mut state = state.unwrap_or_else(|| {
                StdState::new(
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
                .expect("Failed to create state")
            });

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

            // Setup a randomic Input2State stage, conditionally within a custom mutator
            let i2s =
                StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));
            let i2s = SkippableStage::new(i2s, |_| (!mutator_status.custom_mutation).into());
            let cm_i2s = StdMutationalStage::new(unsafe {
                LLVMCustomMutator::mutate_unchecked(StdScheduledMutator::new(tuple_list!(
                    I2SRandReplace::new()
                )))
            });
            let cm_i2s = SkippableStage::new(cm_i2s, |_| mutator_status.custom_mutation.into());

            // Setup a MOPT mutator
            // TODO configure with mutation stacking options from libfuzzer, use tokens from dictionary
            let std_mutator = StdMOptMutator::new(
                &mut state,
                havoc_mutations(), // TODO .merge(tokens_mutations()),
                7,
                5,
            )?;

            let std_power = StdPowerMutationalStage::new(std_mutator, &edges_observer);
            let std_power = SkippableStage::new(std_power, |_| mutator_status.std_mutational.into());

            // for custom mutator and crossover, each have access to the LLVMFuzzerMutate -- but it appears
            // that this method doesn't normally offer stacked mutations where one may expect them
            // we offer stacked mutations since this appears to be expected; see:
            // https://github.com/google/fuzzing/blob/bb05211c12328cb16327bb0d58c0c67a9a44576f/docs/structure-aware-fuzzing.md#example-compression
            // additionally, we perform mutation and crossover in two separate stages due to possible
            // errors introduced by incorrectly handling custom mutations; see explanation below

            // a custom mutator is defined
            // note: in libfuzzer, crossover is enabled by default, but this appears to be unintended
            // and erroneous if custom mutators are defined as it inserts bytes from other test cases
            // without performing the custom mutator's preprocessing beforehand
            // we opt not to use crossover in the LLVMFuzzerMutate and instead have a second crossover pass,
            // though it is likely an error for fuzzers to provide custom mutators but not custom crossovers
            let custom_mutator = unsafe {
                LLVMCustomMutator::mutate_unchecked(StdMOptMutator::new(
                    &mut state,
                    havoc_mutations_no_crossover(), // TODO .merge(tokens_mutations()),
                    7,
                    5,
                )?)
            };
            let std_mutator_no_mutate = StdScheduledMutator::with_max_stack_pow(havoc_crossover(), 3);

            let cm_power = StdPowerMutationalStage::new(custom_mutator, &edges_observer);
            let cm_power = SkippableStage::new(cm_power, |_| mutator_status.custom_mutation.into());
            let cm_std_power = StdMutationalStage::new(std_mutator_no_mutate);
            let cm_std_power =
                SkippableStage::new(cm_std_power, |_| mutator_status.std_no_mutate.into());

            // a custom crossover is defined
            // while the scenario that a custom crossover is defined without a custom mutator is unlikely
            // we handle it here explicitly anyways
            let custom_crossover = unsafe {
                LLVMCustomMutator::crossover_unchecked(StdScheduledMutator::with_max_stack_pow(
                    havoc_mutations_no_crossover(), // TODO .merge(tokens_mutations()),
                    3,
                ))
            };
            let std_mutator_no_crossover = StdMOptMutator::new(
                &mut state,
                havoc_mutations_no_crossover(), // TODO .merge(tokens_mutations()),
                7,
                5,
            )?;

            let cc_power = StdMutationalStage::new(custom_crossover);
            let cc_power = SkippableStage::new(cc_power, |_| mutator_status.custom_crossover.into());
            let cc_std_power = StdPowerMutationalStage::new(std_mutator_no_crossover, &edges_observer);
            let cc_std_power =
                SkippableStage::new(cc_std_power, |_| mutator_status.std_no_crossover.into());

            // unfortunately, we cannot support grimoire and also support custom mutators
            // in the future, we can handle this explicitly, but this introduces issues with generics :(

            // A minimization+queue policy to get testcasess from the corpus
            let scheduler =
                IndexesLenTimeMinimizerScheduler::new(PowerQueueScheduler::new(PowerSchedule::FAST));

            // A fuzzer with feedbacks and a corpus scheduler
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

            // The wrapped harness function, calling out to the LLVM-style harness
            let mut harness = |input: &BytesInput| {
                let target = input.target_bytes();
                let buf = target.as_slice();
                $harness(buf.as_ptr(), buf.len());
                ExitKind::Ok
            };

            let mut tracing_harness = harness;

            // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
            let mut executor = TimeoutExecutor::new(
                InProcessExecutor::new(
                    &mut harness,
                    tuple_list!(edges_observer, time_observer, backtrace_observer),
                    &mut fuzzer,
                    &mut state,
                    &mut mgr,
                )?,
                $options.timeout(),
            );

            // TODO Setup a tracing stage in which we log comparisons
            let tracing = TracingStage::new(InProcessExecutor::new(
                &mut tracing_harness,
                tuple_list!(cmplog_observer),
                &mut fuzzer,
                &mut state,
                &mut mgr,
            )?);

            // The order of the stages matter!
            let mut stages = tuple_list!(
                calibration,
                tracing,
                i2s,
                cm_i2s,
                std_power,
                cm_power,
                cm_std_power,
                cc_std_power,
                cc_power,
            );

            // In case the corpus is empty (on first run), reset
            if state.corpus().count() < 1 {
                if !$options.dirs().is_empty() {
                    println!("Loading from {:?}", $options.dirs());
                    // Load from disk
                    state
                        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, $options.dirs())
                        .unwrap_or_else(|_| {
                            panic!("Failed to load initial corpus at {:?}", $options.dirs())
                        });
                    println!("We imported {} inputs from disk.", state.corpus().count());
                }
                if state.corpus().count() < 1 {
                    // Generator of printable bytearrays of max size 32
                    let mut generator = RandBytesGenerator::from(RandBytesGenerator::new(32));

                    // Generate 8 initial inputs
                    state
                        .generate_initial_inputs(
                            &mut fuzzer,
                            &mut executor,
                            &mut generator,
                            &mut mgr,
                            8,
                        )
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
    };
}

pub fn fuzz(
    options: LibfuzzerOptions,
    harness: &extern "C" fn(*const u8, usize) -> c_int,
) -> Result<(), Error> {
    if let Some(forks) = options.forks() {
        let mut run_client = make_fuzz_closure!(options, harness);
        let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
        let cores = Cores::from((0..forks).map(|i| i.into()).collect::<Vec<_>>());
        let broker_port =
            portpicker::pick_unused_port().expect("Couldn't pick a free broker port.");

        let monitor = TuiMonitor::new(options.fuzzer_name().to_string(), true);

        match Launcher::builder()
            .shmem_provider(shmem_provider)
            .configuration(EventConfig::from_name("default"))
            .monitor(monitor)
            .run_client(&mut run_client)
            .cores(&cores)
            .broker_port(broker_port)
            // TODO .remote_broker_addr(opt.remote_broker_addr)
            .stdout_file(Some("/dev/null"))
            .build()
            .launch()
        {
            Ok(()) => (),
            Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
            res @ Err(_) => return res,
        }
        Ok(())
    } else {
        let mut fuzz_single = make_fuzz_closure!(options, harness);
        let mgr = SimpleEventManager::printing();
        fuzz_single(None, mgr, 0)
    }
}
