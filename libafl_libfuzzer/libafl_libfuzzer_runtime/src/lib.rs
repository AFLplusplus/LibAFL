use core::ffi::{c_char, c_int, CStr};

use crate::options::{LibfuzzerMode, LibfuzzerOptions};

pub(crate) mod feedbacks;
mod fuzz;
mod options;

pub static mut BACKTRACE: Option<u64> = None;

pub(crate) struct CustomMutationStatus {
    std_mutational: bool,
    std_no_mutate: bool,
    std_no_crossover: bool,
    custom_mutation: bool,
    custom_crossover: bool,
}

impl CustomMutationStatus {
    pub(crate) fn new() -> Self {
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
    ($options:ident, $harness:ident, $operation:expr) => {{
        use libafl::{
            bolts::{
                current_nanos,
                rands::StdRand,
                tuples::{Merge, tuple_list},
                AsSlice,
            },
            corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
            executors::{ExitKind, InProcessExecutor, TimeoutExecutor},
            feedback_and_fast, feedback_or, feedback_or_fast,
            feedbacks::{CrashFeedback, MaxMapFeedback, NewHashFeedback, TimeFeedback, TimeoutFeedback},
            generators::RandBytesGenerator,
            inputs::{BytesInput, HasTargetBytes},
            mutators::{
                GrimoireExtensionMutator, GrimoireRecursiveReplacementMutator, GrimoireRandomDeleteMutator,
                GrimoireStringReplacementMutator, havoc_crossover, havoc_mutations, havoc_mutations_no_crossover,
                I2SRandReplace, StdMOptMutator, StdScheduledMutator, Tokens, tokens_mutations
            },
            observers::{BacktraceObserver, HitcountsMapObserver, StdMapObserver, TimeObserver},
            schedulers::{
                powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
            },
            stages::{
                CalibrationStage, GeneralizationStage, SkippableStage, StdMutationalStage, StdPowerMutationalStage,
                TracingStage,
            },
            state::{HasCorpus, StdState},
            StdFuzzer,
        };
        use libafl_targets::{CmpLogObserver, LLVMCustomMutator, COUNTERS_MAPS};
        use rand::{thread_rng, RngCore};

        use crate::CustomMutationStatus;
        use crate::BACKTRACE;
        use crate::feedbacks::LibfuzzerKeepFeedback;

        |state: Option<_>, mut mgr, _cpu_id| {
            let mutator_status = CustomMutationStatus::new();
            let grimoire = if let Some(grimoire) = $options.grimoire() {
                if grimoire && !mutator_status.std_mutational {
                    eprintln!("WARNING: cowardly refusing to use grimoire after detecting the presence of a custom mutator");
                }
                grimoire && mutator_status.std_mutational
            } else if mutator_status.std_mutational {
                if $options.dirs().is_empty() {
                    eprintln!("WARNING: cowardly refusing to use grimoire since we cannot determine if the input is primarily text; set -grimoire=1 or provide a corpus directory.");
                    false
                } else {
                    // TODO determine if the corpus is mostly text to conditionally enable grimoire
                    eprintln!("INFO: inferred grimoire mutator; if this is undesired, set -grimoire=0");
                    true
                }
            } else {
                false
            };

            // Create an observation channel using the coverage map
            let edges = unsafe { &mut COUNTERS_MAPS };
            assert_eq!(1, edges.len());
            let edges_observer =
                HitcountsMapObserver::new(unsafe { StdMapObserver::new("edges", &mut edges[0]) });

            let keep_observer = LibfuzzerKeepFeedback::new();
            let keep = keep_observer.keep();

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
            let map_feedback = MaxMapFeedback::new_tracking(&edges_observer, true, grimoire);

            // Set up a generalization stage for grimoire
            let generalization = GeneralizationStage::new(&edges_observer);
            let generalization = SkippableStage::new(generalization, |_| grimoire.into());

            let calibration = CalibrationStage::new(&map_feedback);

            // Feedback to rate the interestingness of an input
            // This one is composed by two Feedbacks in OR
            let mut feedback = feedback_and_fast!(
                keep_observer,
                feedback_or!(
                    map_feedback,
                    // Time feedback, this one does not need a feedback state
                    TimeFeedback::with_observer(&time_observer)
                )
            );

            // A feedback to choose if an input is a solution or not
            let mut objective = feedback_or_fast!(
                feedback_and_fast!(
                    CrashFeedback::new(),
                    NewHashFeedback::new(&backtrace_observer)
                ),
                TimeoutFeedback::new()
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
                OnDiskCorpus::with_meta_format_and_prefix(prefix.dir(), None, prefix.filename_prefix().clone())
                    .unwrap()
            } else {
                OnDiskCorpus::no_meta(std::env::current_dir().unwrap()).unwrap()
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

            // Attempt to use tokens from libfuzzer dicts
            if state.metadata().get::<Tokens>().is_none() {
                let mut toks = if let Some(tokens) = $options.dict() {
                    tokens.clone()
                } else {
                    Tokens::default()
                };
                #[cfg(any(target_os = "linux", target_vendor = "apple"))]
                {
                    toks += libafl_targets::autotokens()?;
                }

                if !toks.is_empty() {
                    state.add_metadata(toks);
                }
            }

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
            // TODO configure with mutation stacking options from libfuzzer
            let std_mutator = StdMOptMutator::new(
                &mut state,
                havoc_mutations().merge(tokens_mutations()),
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
                    havoc_mutations_no_crossover().merge(tokens_mutations()),
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
                    havoc_mutations_no_crossover().merge(tokens_mutations()),
                    3,
                ))
            };
            let std_mutator_no_crossover = StdMOptMutator::new(
                &mut state,
                havoc_mutations_no_crossover().merge(tokens_mutations()),
                7,
                5,
            )?;

            let cc_power = StdMutationalStage::new(custom_crossover);
            let cc_power = SkippableStage::new(cc_power, |_| mutator_status.custom_crossover.into());
            let cc_std_power = StdPowerMutationalStage::new(std_mutator_no_crossover, &edges_observer);
            let cc_std_power =
                SkippableStage::new(cc_std_power, |_| mutator_status.std_no_crossover.into());

            let grimoire_mutator = StdScheduledMutator::with_max_stack_pow(
                tuple_list!(
                    GrimoireExtensionMutator::new(),
                    GrimoireRecursiveReplacementMutator::new(),
                    GrimoireStringReplacementMutator::new(),
                    // give more probability to avoid large inputs
                    GrimoireRandomDeleteMutator::new(),
                    GrimoireRandomDeleteMutator::new(),
                ),
                3,
            );
            let grimoire = SkippableStage::new(StdMutationalStage::transforming(grimoire_mutator), |_| grimoire.into());

            // A minimization+queue policy to get testcasess from the corpus
            let scheduler =
                IndexesLenTimeMinimizerScheduler::new(PowerQueueScheduler::new(PowerSchedule::FAST));

            // A fuzzer with feedbacks and a corpus scheduler
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

            // The wrapped harness function, calling out to the LLVM-style harness
            let mut harness = |input: &BytesInput| {
                let target = input.target_bytes();
                let buf = target.as_slice();

                let result = $harness(buf.as_ptr(), buf.len());
                *keep.borrow_mut() = result == 0;

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

            // In case the corpus is empty (on first run), reset
            if state.corpus().count() < 1 {
                if !$options.dirs().is_empty() {
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

            // Setup a tracing stage in which we log comparisons
            let tracing = TracingStage::new(InProcessExecutor::new(
                &mut tracing_harness,
                tuple_list!(cmplog_observer),
                &mut fuzzer,
                &mut state,
                &mut mgr,
            )?);

            // The order of the stages matter!
            let mut stages = tuple_list!(
                generalization,
                calibration,
                tracing,
                i2s,
                cm_i2s,
                std_power,
                cm_power,
                cm_std_power,
                cc_std_power,
                cc_power,
                grimoire,
            );

            $operation(&mut fuzzer, &mut stages, &mut executor, &mut state, &mut mgr)
        }
    }};
}

pub(crate) use make_fuzz_closure;

#[allow(non_snake_case)]
#[no_mangle]
pub fn LLVMFuzzerRunDriver(
    argc: *const c_int,
    argv: *const *const *const c_char,
    harness_fn: Option<extern "C" fn(*const u8, usize) -> c_int>,
) -> c_int {
    let harness = harness_fn
        .as_ref()
        .expect("Illegal harness provided to libafl.");
    let argc = unsafe { *argc } as isize;
    let argv = unsafe { *argv };

    let options = LibfuzzerOptions::new(
        (0..argc)
            .map(|i| unsafe { *argv.offset(i) })
            .map(|cstr| unsafe { CStr::from_ptr(cstr) })
            .map(|cstr| cstr.to_str().unwrap()),
    )
    .unwrap();
    let res = match options.mode() {
        LibfuzzerMode::Fuzz => fuzz::fuzz(options, harness),
        LibfuzzerMode::Merge => unimplemented!(),
        LibfuzzerMode::Cmin => unimplemented!(),
    };
    res.expect("Encountered error while performing libfuzzer shimming");
    0
}
