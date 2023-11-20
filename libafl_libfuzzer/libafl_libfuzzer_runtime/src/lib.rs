//! The `LibAFL` `LibFuzzer` runtime, exposing the same functions as the original [`LibFuzzer`](https://llvm.org/docs/LibFuzzer.html).

#![allow(incomplete_features)]
// For `type_eq`
#![cfg_attr(unstable_feature, feature(specialization))]
// For `type_id` and owned things
#![cfg_attr(unstable_feature, feature(intrinsics))]
// For `std::simd`
#![cfg_attr(unstable_feature, feature(portable_simd))]
#![warn(clippy::cargo)]
#![allow(ambiguous_glob_reexports)]
#![deny(clippy::cargo_common_metadata)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(
    clippy::unreadable_literal,
    clippy::type_repetition_in_bounds,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::used_underscore_binding,
    clippy::ptr_as_ptr,
    clippy::missing_panics_doc,
    clippy::missing_docs_in_private_items,
    clippy::module_name_repetitions,
    clippy::ptr_cast_constness,
    clippy::unsafe_derive_deserialize
)]
#![cfg_attr(not(test), warn(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    //unused_results
))]
#![cfg_attr(test, deny(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_must_use,
    //unused_results
))]
#![cfg_attr(
    test,
    deny(
        bad_style,
        dead_code,
        improper_ctypes,
        non_shorthand_field_patterns,
        no_mangle_generic_items,
        overflowing_literals,
        path_statements,
        patterns_in_fns_without_body,
        unconditional_recursion,
        unused,
        unused_allocation,
        unused_comparisons,
        unused_parens,
        while_true
    )
)]
// Till they fix this buggy lint in clippy
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::borrow_deref_ref)]

use core::ffi::{c_char, c_int, CStr};
use std::{fs::File, io::stderr, os::fd::RawFd};

use env_logger::Target;
use libafl::{
    inputs::{BytesInput, HasTargetBytes, Input},
    Error,
};
use libafl_bolts::AsSlice;
use libc::_exit;
use mimalloc::MiMalloc;

use crate::options::{LibfuzzerMode, LibfuzzerOptions};
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod corpus;
mod feedbacks;
mod fuzz;
mod merge;
mod misc;
mod observers;
mod options;
mod report;
mod schedulers;
mod tmin;

mod harness_wrap {
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]
    #![allow(improper_ctypes)]
    #![allow(clippy::unreadable_literal)]
    #![allow(missing_docs)]
    include!(concat!(env!("OUT_DIR"), "/harness_wrap.rs"));
}

pub(crate) use harness_wrap::libafl_libfuzzer_test_one_input;
#[cfg(feature = "mimalloc")]
use mimalloc::MiMalloc;
#[global_allocator]
#[cfg(feature = "mimalloc")]
static GLOBAL: MiMalloc = MiMalloc;

static mut BACKTRACE: Option<u64> = None;

#[allow(clippy::struct_excessive_bools)]
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

macro_rules! fuzz_with {
    ($options:ident, $harness:ident, $operation:expr, $and_then:expr, $edge_maker:expr) => {{
        use libafl_bolts::{
                current_nanos,
                rands::StdRand,
                tuples::{Merge, tuple_list},
                AsSlice,
        };
        use libafl::{
            corpus::Corpus,
            executors::{ExitKind, InProcessExecutor, TimeoutExecutor},
            feedback_and_fast, feedback_not, feedback_or, feedback_or_fast,
            feedbacks::{ConstFeedback, CrashFeedback, MaxMapFeedback, NewHashFeedback, TimeFeedback, TimeoutFeedback},
            generators::RandBytesGenerator,
            inputs::{BytesInput, HasTargetBytes},
            mutators::{
                GrimoireExtensionMutator, GrimoireRecursiveReplacementMutator, GrimoireRandomDeleteMutator,
                GrimoireStringReplacementMutator, havoc_crossover, havoc_mutations, havoc_mutations_no_crossover,
                I2SRandReplace, StdScheduledMutator, StringCategoryRandMutator, StringSubcategoryRandMutator,
                StringCategoryTokenReplaceMutator, StringSubcategoryTokenReplaceMutator, Tokens, tokens_mutations
            },
            observers::{stacktrace::BacktraceObserver, TimeObserver},
            schedulers::{
                IndexesLenTimeMinimizerScheduler, powersched::PowerSchedule, PowerQueueScheduler,
            },
            stages::{
                CalibrationStage, GeneralizationStage, IfStage, StdMutationalStage,
                StdPowerMutationalStage, StringIdentificationStage, TracingStage,
            },
            state::{HasCorpus, StdState},
            StdFuzzer,
        };
        use libafl_targets::{CmpLogObserver, LLVMCustomMutator, OomFeedback, OomObserver};
        use rand::{thread_rng, RngCore};
        use std::{env::temp_dir, fs::create_dir, path::PathBuf};

        use crate::{BACKTRACE, CustomMutationStatus};
        use crate::corpus::{ArtifactCorpus, LibfuzzerCorpus};
        use crate::feedbacks::{LibfuzzerCrashCauseFeedback, LibfuzzerKeepFeedback, ShrinkMapFeedback};
        use crate::misc::should_use_grimoire;
        use crate::observers::{MappedEdgeMapObserver, SizeValueObserver};

        let edge_maker = &$edge_maker;

        let closure = |mut state: Option<_>, mut mgr, _cpu_id| {
            let mutator_status = CustomMutationStatus::new();
            let grimoire_metadata = should_use_grimoire(&mut state, &$options, &mutator_status)?;
            let grimoire = grimoire_metadata.should();

            let edges_observer = edge_maker();
            let size_edges_observer = MappedEdgeMapObserver::new(edge_maker(), SizeValueObserver::default());

            let keep_observer = LibfuzzerKeepFeedback::new();
            let keep = keep_observer.keep();

            // Create an observation channel to keep track of the execution time
            let time_observer = TimeObserver::new("time");

            // Create an OOM observer to monitor if an OOM has occurred
            let oom_observer = OomObserver::new($options.rss_limit(), $options.malloc_limit());

            // Create the Cmp observer
            let cmplog_observer = CmpLogObserver::new("cmplog", true);

            // Create a stacktrace observer
            let backtrace_observer = BacktraceObserver::new(
                "BacktraceObserver",
                unsafe { &mut BACKTRACE },
                if $options.forks().is_some() || $options.tui() { libafl::observers::HarnessType::Child } else { libafl::observers::HarnessType::InProcess }
            );

            // New maximization map feedback linked to the edges observer
            let map_feedback = MaxMapFeedback::tracking(&edges_observer, true, true);
            let shrinking_map_feedback = ShrinkMapFeedback::tracking(&size_edges_observer, false, false);

            // Set up a generalization stage for grimoire
            let generalization = GeneralizationStage::new(&edges_observer);
            let generalization = IfStage::new(|_, _, _, _, _| Ok(grimoire.into()), tuple_list!(generalization));

            let calibration = CalibrationStage::new(&map_feedback);

            // Feedback to rate the interestingness of an input
            // This one is composed by two Feedbacks in OR
            let mut feedback = feedback_and_fast!(
                feedback_not!(
                    feedback_or_fast!(
                        OomFeedback,
                        CrashFeedback::new(),
                        TimeoutFeedback::new()
                    )
                ),
                keep_observer,
                feedback_or!(
                    map_feedback,
                    feedback_and_fast!(ConstFeedback::new($options.shrink()), shrinking_map_feedback),
                    // Time feedback, this one does not need a feedback state
                    TimeFeedback::with_observer(&time_observer)
                )
            );

            // A feedback to choose if an input is a solution or not
            let mut objective = feedback_or_fast!(
                LibfuzzerCrashCauseFeedback::new($options.artifact_prefix().clone()),
                OomFeedback,
                feedback_and_fast!(
                    CrashFeedback::new(),
                    feedback_or_fast!(ConstFeedback::new(!$options.dedup()), NewHashFeedback::new(&backtrace_observer))
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

            let crash_corpus = ArtifactCorpus::new();

            // If not restarting, create a State from scratch
            let mut state = state.unwrap_or_else(|| {
                StdState::new(
                    // RNG
                    StdRand::with_seed(current_nanos()),
                    // Corpus that will be evolved, we keep it in memory for performance
                    LibfuzzerCorpus::new(corpus_dir.clone(), 4096),
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
            state.metadata_map_mut().insert_boxed(grimoire_metadata);

            // Set up a string category analysis stage for unicode mutations
            let unicode_used = $options.unicode();
            let string_mutator = StdScheduledMutator::new(
                tuple_list!(
                    StringCategoryRandMutator,
                    StringSubcategoryRandMutator,
                    StringSubcategoryRandMutator,
                    StringSubcategoryRandMutator,
                    StringSubcategoryRandMutator,
                )
            );
            let string_replace_mutator = StdScheduledMutator::new(
                tuple_list!(
                    StringCategoryTokenReplaceMutator,
                    StringSubcategoryTokenReplaceMutator,
                    StringSubcategoryTokenReplaceMutator,
                    StringSubcategoryTokenReplaceMutator,
                    StringSubcategoryTokenReplaceMutator,
                )
            );
            let string_power = StdMutationalStage::transforming(string_mutator);
            let string_replace_power = StdMutationalStage::transforming(string_replace_mutator);

            let string_analysis = StringIdentificationStage::new();
            let string_analysis = IfStage::new(|_, _, _, _, _| Ok((unicode_used && mutator_status.std_mutational).into()), tuple_list!(string_analysis, string_power, string_replace_power));

            // Attempt to use tokens from libfuzzer dicts
            if !state.has_metadata::<Tokens>() {
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
            let i2s = IfStage::new(|_, _, _, _, _| Ok((!mutator_status.custom_mutation).into()), (i2s, ()));
            let cm_i2s = StdMutationalStage::new(unsafe {
                LLVMCustomMutator::mutate_unchecked(StdScheduledMutator::new(tuple_list!(
                    I2SRandReplace::new()
                )))
            });
            let cm_i2s = IfStage::new(|_, _, _, _, _| Ok(mutator_status.custom_mutation.into()), (cm_i2s, ()));

            // TODO configure with mutation stacking options from libfuzzer
            let std_mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));

            let std_power = StdPowerMutationalStage::new(std_mutator);
            let std_power = IfStage::new(|_, _, _, _, _| Ok(mutator_status.std_mutational.into()), (std_power, ()));

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
                LLVMCustomMutator::mutate_unchecked(StdScheduledMutator::new(havoc_mutations_no_crossover().merge(tokens_mutations())))
            };
            let std_mutator_no_mutate = StdScheduledMutator::with_max_stack_pow(havoc_crossover(), 3);

            let cm_power = StdPowerMutationalStage::new(custom_mutator);
            let cm_power = IfStage::new(|_, _, _, _, _| Ok(mutator_status.custom_mutation.into()), (cm_power, ()));
            let cm_std_power = StdMutationalStage::new(std_mutator_no_mutate);
            let cm_std_power =
                IfStage::new(|_, _, _, _, _| Ok(mutator_status.std_no_mutate.into()), (cm_std_power, ()));

            // a custom crossover is defined
            // while the scenario that a custom crossover is defined without a custom mutator is unlikely
            // we handle it here explicitly anyways
            let custom_crossover = unsafe {
                LLVMCustomMutator::crossover_unchecked(StdScheduledMutator::with_max_stack_pow(
                    havoc_mutations_no_crossover().merge(tokens_mutations()),
                    3,
                ))
            };
            let std_mutator_no_crossover = StdScheduledMutator::new(havoc_mutations_no_crossover().merge(tokens_mutations()));

            let cc_power = StdMutationalStage::new(custom_crossover);
            let cc_power = IfStage::new(|_, _, _, _, _| Ok(mutator_status.custom_crossover.into()), (cc_power, ()));
            let cc_std_power = StdPowerMutationalStage::new(std_mutator_no_crossover);
            let cc_std_power =
                IfStage::new(|_, _, _, _, _| Ok(mutator_status.std_no_crossover.into()), (cc_std_power, ()));

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
            let grimoire = IfStage::new(|_, _, _, _, _| Ok(grimoire.into()), (StdMutationalStage::transforming(grimoire_mutator), ()));

            // A minimization+queue policy to get testcasess from the corpus
            let scheduler = IndexesLenTimeMinimizerScheduler::new(PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::FAST));

            // A fuzzer with feedbacks and a corpus scheduler
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

            // The wrapped harness function, calling out to the LLVM-style harness
            let mut harness = |input: &BytesInput| {
                let target = input.target_bytes();
                let buf = target.as_slice();

                let result = unsafe { crate::libafl_libfuzzer_test_one_input(Some(*$harness), buf.as_ptr(), buf.len()) };
                match result {
                    -2 => ExitKind::Crash,
                    _ => {
                        *keep.borrow_mut() = result == 0;
                        ExitKind::Ok
                    }
                }
            };

            let mut tracing_harness = harness;

            // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
            let mut executor = TimeoutExecutor::new(
                InProcessExecutor::new(
                    &mut harness,
                    tuple_list!(edges_observer, size_edges_observer, time_observer, backtrace_observer, oom_observer),
                    &mut fuzzer,
                    &mut state,
                    &mut mgr,
                )?,
                $options.timeout(),
            );

            // In case the corpus is empty (on first run) or crashed while loading, reset
            if state.must_load_initial_inputs() {
                if !$options.dirs().is_empty() {
                    // Load from disk
                    state
                        .load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, $options.dirs())
                        .unwrap_or_else(|e| {
                            panic!("Failed to load initial corpus at {:?}: {}", $options.dirs(), e)
                        });
                    println!("We imported {} inputs from disk.", state.corpus().count());
                }
                if state.corpus().count() < 1 {
                    // Generator of bytearrays of max size 64
                    let mut generator = RandBytesGenerator::from(RandBytesGenerator::new(64));

                    // Generate 1024 initial inputs
                    state
                        .generate_initial_inputs(
                            &mut fuzzer,
                            &mut executor,
                            &mut generator,
                            &mut mgr,
                            1 << 10,
                        )
                        .expect("Failed to generate the initial corpus");
                    println!(
                        "We imported {} inputs from the generator.",
                        state.corpus().count()
                    );
                }
            }


            // Setup a tracing stage in which we log comparisons
            let tracing = IfStage::new(|_, _, _, _, _| Ok(!$options.skip_tracing()), (TracingStage::new(InProcessExecutor::new(
                &mut tracing_harness,
                tuple_list!(cmplog_observer),
                &mut fuzzer,
                &mut state,
                &mut mgr,
            )?), ()));

            // The order of the stages matter!
            let mut stages = tuple_list!(
                calibration,
                generalization,
                tracing,
                string_analysis,
                i2s,
                cm_i2s,
                std_power,
                cm_power,
                cm_std_power,
                cc_std_power,
                cc_power,
                grimoire,
            );

            #[allow(clippy::unnecessary_mut_passed)] // the functions may not require these many `mut`s
            $operation(&$options, &mut fuzzer, &mut stages, &mut executor, &mut state, &mut mgr)
        };

        #[allow(clippy::redundant_closure_call)]
        $and_then(closure)
    }};

    ($options:ident, $harness:ident, $operation:expr, $and_then:expr) => {{
        use libafl::observers::{
            HitcountsIterableMapObserver, HitcountsMapObserver, MultiMapObserver, StdMapObserver,
        };
        use libafl_targets::{COUNTERS_MAPS, extra_counters};

        // Create an observation channel using the coverage map
        if unsafe { COUNTERS_MAPS.len() } == 1 {
            fuzz_with!($options, $harness, $operation, $and_then, || {
                let edges = unsafe { extra_counters() };
                let edges_observer =
                    HitcountsMapObserver::new(StdMapObserver::from_mut_slice("edges", edges.into_iter().next().unwrap()));
                edges_observer
            })
        } else if unsafe { COUNTERS_MAPS.len() } > 1 {
            fuzz_with!($options, $harness, $operation, $and_then, || {
                let edges = unsafe { extra_counters() };
                let edges_observer =
                    HitcountsIterableMapObserver::new(MultiMapObserver::new("edges", edges));
                edges_observer
            })
        } else {
            panic!("No maps available; cannot fuzz!")
        }
    }};
}

pub(crate) use fuzz_with;

/// Starts to fuzz on a single node
pub fn start_fuzzing_single<F, S, EM>(
    mut fuzz_single: F,
    initial_state: Option<S>,
    mgr: EM,
) -> Result<(), Error>
where
    F: FnMut(Option<S>, EM, usize) -> Result<(), Error>,
{
    fuzz_single(initial_state, mgr, 0)
}

extern "C" {
    // redeclaration against libafl_targets because the pointers in our case may be mutable
    fn libafl_targets_libfuzzer_init(argc: *mut c_int, argv: *mut *mut *const c_char) -> i32;
}

/// Communicate the stderr duplicated fd to subprocesses
pub const STDERR_FD_VAR: &str = "_LIBAFL_LIBFUZZER_STDERR_FD";

/// A method to start the fuzzer at a later point in time from a library.
/// To quote the `libfuzzer` docs:
/// > when it’s ready to start fuzzing, it can call `LLVMFuzzerRunDriver`, passing in the program arguments and a callback. This callback is invoked just like `LLVMFuzzerTestOneInput`, and has the same signature.
///
/// # Safety
/// Will dereference all parameters.
/// This will then call the (potentially unsafe) harness.
/// The fuzzer itself should catch any side effects and, hence be reasonably safe, if the `harness_fn` parameter is correct.
#[allow(non_snake_case, clippy::similar_names, clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn LLVMFuzzerRunDriver(
    argc: *mut c_int,
    argv: *mut *mut *const c_char,
    harness_fn: Option<extern "C" fn(*const u8, usize) -> c_int>,
) -> c_int {
    let harness = harness_fn
        .as_ref()
        .expect("Illegal harness provided to libafl.");

    // early duplicate the stderr fd so we can close it later for the target
    #[cfg(unix)]
    {
        use std::{
            os::fd::{AsRawFd, FromRawFd},
            str::FromStr,
        };

        let stderr_fd = std::env::var(STDERR_FD_VAR)
            .map_err(Error::from)
            .and_then(|s| RawFd::from_str(&s).map_err(Error::from))
            .unwrap_or_else(|_| {
                let stderr = libc::dup(stderr().as_raw_fd());
                std::env::set_var(STDERR_FD_VAR, stderr.to_string());
                stderr
            });
        let stderr = File::from_raw_fd(stderr_fd);
        env_logger::builder()
            .parse_default_env()
            .target(Target::Pipe(Box::new(stderr)))
            .init();
    }

    // it appears that no one, not even libfuzzer, uses this return value
    // https://github.com/llvm/llvm-project/blob/llvmorg-15.0.7/compiler-rt/lib/fuzzer/FuzzerDriver.cpp#L648
    libafl_targets_libfuzzer_init(argc, argv);

    let argc = unsafe { *argc } as isize;
    let argv = unsafe { *argv };

    let options = LibfuzzerOptions::new(
        (0..argc)
            .map(|i| unsafe { *argv.offset(i) })
            .map(|cstr| unsafe { CStr::from_ptr(cstr) })
            .map(|cstr| cstr.to_str().unwrap()),
    )
    .unwrap();

    if !options.unknown().is_empty() {
        eprintln!("Unrecognised options: {:?}", options.unknown());
    }

    for folder in options
        .dirs()
        .iter()
        .chain(std::iter::once(options.artifact_prefix().dir()))
    {
        if !folder.try_exists().unwrap_or(false) {
            eprintln!(
                "Required folder {} did not exist; failing fast.",
                folder.to_string_lossy()
            );
            _exit(1);
        }
    }

    if *options.mode() != LibfuzzerMode::Tmin
        && !options.dirs().is_empty()
        && options.dirs().iter().all(|maybe_dir| maybe_dir.is_file())
    {
        // we've been requested to just run some inputs. Do so.
        for input in options.dirs() {
            let input = BytesInput::from_file(input).unwrap_or_else(|_| {
                panic!("Couldn't load input {}", input.to_string_lossy().as_ref())
            });
            libafl_targets::libfuzzer::libfuzzer_test_one_input(input.target_bytes().as_slice());
        }
        return 0;
    }
    let res = match options.mode() {
        LibfuzzerMode::Fuzz => fuzz::fuzz(&options, harness),
        LibfuzzerMode::Merge => merge::merge(&options, harness),
        LibfuzzerMode::Tmin => tmin::minimize_crash(&options, *harness),
        LibfuzzerMode::Report => report::report(&options, harness),
    };
    match res {
        Ok(()) | Err(Error::ShuttingDown) => 0,
        Err(err) => {
            eprintln!("Encountered error while performing libfuzzer shimming: {err}");
            1
        }
    }
}
