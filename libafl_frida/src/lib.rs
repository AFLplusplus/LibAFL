/*!
The frida executor is a binary-only mode for `LibAFL`.
It can report coverage and, on supported architecutres, even reports memory access errors.

Additional documentation is available in [the `LibAFL` book](https://aflplus.plus/libafl-book/advanced_features/frida.html).
*/

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
    clippy::unreadable_literal,
    clippy::ptr_cast_constness,
    clippy::must_use_candidate
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
    missing_docs,
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

/// The frida-asan allocator
#[cfg(unix)]
pub mod alloc;

#[cfg(unix)]
pub mod asan;

#[cfg(windows)]
/// Windows specific hooks to catch __fastfail like exceptions with Frida, see https://github.com/AFLplusplus/LibAFL/issues/395 for more details
pub mod windows_hooks;

pub mod coverage_rt;

/// Hooking thread lifecycle events. Seems like this is apple-only for now.
#[cfg(target_vendor = "apple")]
pub mod pthread_hook;

#[cfg(feature = "cmplog")]
/// The frida cmplog runtime
pub mod cmplog_rt;

/// The `LibAFL` firda helper
pub mod helper;

pub mod drcov_rt;

/// The frida executor
pub mod executor;

/// Utilities
pub mod utils;

// for parsing asan and cmplog cores
use libafl_bolts::core_affinity::{get_core_ids, CoreId, Cores};

/// A representation of the various Frida options
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct FridaOptions {
    enable_asan: bool,
    enable_asan_leak_detection: bool,
    enable_asan_continue_after_error: bool,
    enable_asan_allocation_backtraces: bool,
    asan_max_allocation: usize,
    asan_max_total_allocation: usize,
    asan_max_allocation_panics: bool,
    enable_coverage: bool,
    enable_drcov: bool,
    instrument_suppress_locations: Option<Vec<(String, usize)>>,
    enable_cmplog: bool,
}

impl FridaOptions {
    /// Parse the frida options from the "`LIBAFL_FRIDA_OPTIONS`" environment variable.
    ///
    /// Options are `:` separated, and each options is a `name=value` string.
    ///
    /// # Panics
    /// Panics, if no `=` sign exists in input, or or `value` behind `=` has zero length.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn parse_env_options() -> Self {
        let mut options = Self::default();
        let mut asan_cores = None;
        let mut cmplog_cores = None;

        if let Ok(env_options) = std::env::var("LIBAFL_FRIDA_OPTIONS") {
            for option in env_options.trim().split(':') {
                let (name, mut value) =
                    option.split_at(option.find('=').expect("Expected a '=' in option string"));
                value = value.get(1..).unwrap();
                match name {
                    "asan" => {
                        options.enable_asan = value.parse().unwrap();
                    }
                    "asan-detect-leaks" => {
                        options.enable_asan_leak_detection = value.parse().unwrap();
                    }
                    "asan-continue-after-error" => {
                        options.enable_asan_continue_after_error = value.parse().unwrap();
                    }
                    "asan-allocation-backtraces" => {
                        options.enable_asan_allocation_backtraces = value.parse().unwrap();
                    }
                    "asan-max-allocation" => {
                        options.asan_max_allocation = value.parse().unwrap();
                    }
                    "asan-max-total-allocation" => {
                        options.asan_max_total_allocation = value.parse().unwrap();
                    }
                    "asan-max-allocation-panics" => {
                        options.asan_max_allocation_panics = value.parse().unwrap();
                    }
                    "asan-cores" => {
                        asan_cores = Cores::from_cmdline(value).ok();
                    }
                    "instrument-suppress-locations" => {
                        options.instrument_suppress_locations = Some(
                            value
                                .split(',')
                                .map(|val| {
                                    let (module, offset) = val.split_at(
                                        val.find('@')
                                            .expect("Expected an '@' in location specifier"),
                                    );
                                    (
                                        module.to_string(),
                                        usize::from_str_radix(
                                            offset.get(1..).unwrap().trim_start_matches("0x"),
                                            16,
                                        )
                                        .unwrap(),
                                    )
                                })
                                .collect(),
                        );
                    }
                    "coverage" => {
                        options.enable_coverage = value.parse().unwrap();
                    }
                    "drcov" => {
                        options.enable_drcov = value.parse().unwrap();
                        #[cfg(not(target_arch = "aarch64"))]
                        assert!(
                            !options.enable_drcov,
                            "DrCov is not currently supported on targets other than aarch64"
                        );
                    }
                    "cmplog" => {
                        options.enable_cmplog = value.parse().unwrap();
                        #[cfg(not(target_arch = "aarch64"))]
                        assert!(
                            !options.enable_cmplog,
                            "cmplog is not currently supported on targets other than aarch64"
                        );

                        if options.enable_cmplog {
                            assert!(cfg!(feature = "cmplog"), "cmplog feature is disabled!");
                        }
                    }
                    "cmplog-cores" => {
                        cmplog_cores = Cores::from_cmdline(value).ok();
                    }
                    _ => {
                        panic!("unknown FRIDA option: '{option}'");
                    }
                }
            } // end of for loop

            if options.enable_asan {
                if let Some(asan_cores) = asan_cores {
                    let core_ids = get_core_ids().unwrap();
                    assert_eq!(
                        core_ids.len(),
                        1,
                        "Client should only be bound to a single core"
                    );
                    let core_id: CoreId = core_ids[0];
                    options.enable_asan = asan_cores.ids.contains(&core_id);
                }
            }
            if options.enable_cmplog {
                if let Some(cmplog_cores) = cmplog_cores {
                    let core_ids = get_core_ids().unwrap();
                    assert_eq!(
                        core_ids.len(),
                        1,
                        "Client should only be bound to a single core"
                    );
                    let core_id = core_ids[0];
                    options.enable_cmplog = cmplog_cores.ids.contains(&core_id);
                }
            }
        }
        options
    }

    /// Is ASAN enabled?
    #[must_use]
    #[inline]
    pub fn asan_enabled(&self) -> bool {
        self.enable_asan
    }

    /// Is coverage enabled?
    #[must_use]
    #[inline]
    pub fn coverage_enabled(&self) -> bool {
        self.enable_coverage
    }

    /// Is `DrCov` enabled?
    #[must_use]
    #[inline]
    pub fn drcov_enabled(&self) -> bool {
        self.enable_drcov
    }

    /// Is `CmpLog` enabled?
    #[must_use]
    #[inline]
    pub fn cmplog_enabled(&self) -> bool {
        self.enable_cmplog
    }

    /// Should ASAN detect leaks
    #[must_use]
    #[inline]
    pub fn asan_detect_leaks(&self) -> bool {
        self.enable_asan_leak_detection
    }

    /// The maximum size that the ASAN allocator should allocate
    #[must_use]
    #[inline]
    pub fn asan_max_allocation(&self) -> usize {
        self.asan_max_allocation
    }

    /// The maximum total allocation size that the ASAN allocator should allocate
    #[must_use]
    #[inline]
    pub fn asan_max_total_allocation(&self) -> usize {
        self.asan_max_total_allocation
    }

    /// Should we panic if the max ASAN allocation size is exceeded
    #[must_use]
    #[inline]
    pub fn asan_max_allocation_panics(&self) -> bool {
        self.asan_max_allocation_panics
    }

    /// Should ASAN continue after a memory error is detected
    #[must_use]
    #[inline]
    pub fn asan_continue_after_error(&self) -> bool {
        self.enable_asan_continue_after_error
    }

    /// Should ASAN gather (and report) allocation-/free-site backtraces
    #[must_use]
    #[inline]
    pub fn asan_allocation_backtraces(&self) -> bool {
        self.enable_asan_allocation_backtraces
    }

    /// Whether stalker should be enabled. I.e. whether at least one stalker requiring option is
    /// enabled.
    #[must_use]
    #[inline]
    pub fn stalker_enabled(&self) -> bool {
        self.enable_asan || self.enable_coverage || self.enable_drcov
    }

    /// A list of locations which will not be instrumented for ASAN or coverage purposes
    #[must_use]
    pub fn dont_instrument_locations(&self) -> Option<Vec<(String, usize)>> {
        self.instrument_suppress_locations.clone()
    }
}

impl Default for FridaOptions {
    fn default() -> Self {
        Self {
            enable_asan: false,
            enable_asan_leak_detection: false,
            enable_asan_continue_after_error: false,
            enable_asan_allocation_backtraces: false,
            asan_max_allocation: 1 << 30,
            asan_max_total_allocation: 1 << 32,
            asan_max_allocation_panics: false,
            enable_coverage: true,
            enable_drcov: false,
            instrument_suppress_locations: None,
            enable_cmplog: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{ptr::addr_of, sync::OnceLock};

    use clap::Parser;
    use frida_gum::Gum;
    use libafl::{
        corpus::{Corpus, InMemoryCorpus, Testcase},
        events::NopEventManager,
        executors::{ExitKind, InProcessExecutor},
        feedback_and_fast, feedback_or_fast,
        feedbacks::ConstFeedback,
        inputs::{BytesInput, HasTargetBytes},
        mutators::{mutations::BitFlipMutator, StdScheduledMutator},
        schedulers::StdScheduler,
        stages::StdMutationalStage,
        state::{HasSolutions, StdState},
        Fuzzer, StdFuzzer,
    };
    use libafl_bolts::{
        cli::FuzzerOptions, rands::StdRand, tuples::tuple_list, AsSlice, SimpleStdoutLogger,
    };

    use crate::{
        asan::{
            asan_rt::AsanRuntime,
            errors::{AsanErrorsFeedback, AsanErrorsObserver, ASAN_ERRORS},
        },
        coverage_rt::CoverageRuntime,
        executor::FridaInProcessExecutor,
        helper::FridaInstrumentationHelper,
    };

    static GUM: OnceLock<Gum> = OnceLock::new();

    unsafe fn test_asan(options: &FuzzerOptions) {
        // The names of the functions to run
        let tests = vec![
            ("LLVMFuzzerTestOneInput", 0),
            ("heap_oob_read", 1),
            ("heap_oob_write", 1),
            ("heap_uaf_write", 1),
            ("heap_uaf_read", 1),
            ("malloc_heap_oob_read", 1),
            ("malloc_heap_oob_write", 1),
            ("malloc_heap_uaf_write", 1),
            ("malloc_heap_uaf_read", 1),
        ];

        let lib = libloading::Library::new(options.clone().harness.unwrap()).unwrap();

        let coverage = CoverageRuntime::new();
        let asan = AsanRuntime::new(options);
        let mut frida_helper = FridaInstrumentationHelper::new(
            GUM.get().expect("Gum uninitialized"),
            options,
            tuple_list!(coverage, asan),
        );

        // Run the tests for each function
        for test in tests {
            let (function_name, err_cnt) = test;
            log::info!("Testing with harness function {}", function_name);

            let mut corpus = InMemoryCorpus::<BytesInput>::new();

            //TODO - make sure we use the right one
            let testcase = Testcase::new(vec![0; 4].into());
            corpus.add(testcase).unwrap();

            let rand = StdRand::with_seed(0);

            let mut feedback = ConstFeedback::new(false);

            // Feedbacks to recognize an input as solution
            let mut objective = feedback_or_fast!(
                // true enables the AsanErrorFeedback
                feedback_and_fast!(ConstFeedback::from(true), AsanErrorsFeedback::new())
            );

            let mut state = StdState::new(
                rand,
                corpus,
                InMemoryCorpus::<BytesInput>::new(),
                &mut feedback,
                &mut objective,
            )
            .unwrap();

            let mut event_manager = NopEventManager::new();

            let mut fuzzer = StdFuzzer::new(StdScheduler::new(), feedback, objective);

            let observers = tuple_list!(
                AsanErrorsObserver::new(addr_of!(ASAN_ERRORS)) //,
            );

            {
                let target_func: libloading::Symbol<
                    unsafe extern "C" fn(data: *const u8, size: usize) -> i32,
                > = lib.get(function_name.as_bytes()).unwrap();

                let mut harness = |input: &BytesInput| {
                    let target = input.target_bytes();
                    let buf = target.as_slice();
                    (target_func)(buf.as_ptr(), buf.len());
                    ExitKind::Ok
                };

                let mut executor = FridaInProcessExecutor::new(
                    GUM.get().expect("Gum uninitialized"),
                    InProcessExecutor::new(
                        &mut harness,
                        observers, // tuple_list!(),
                        &mut fuzzer,
                        &mut state,
                        &mut event_manager,
                    )
                    .unwrap(),
                    &mut frida_helper,
                );

                let mutator = StdScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
                let mut stages = tuple_list!(StdMutationalStage::with_max_iterations(mutator, 1));

                // log::info!("Starting fuzzing!");
                fuzzer
                    .fuzz_one(&mut stages, &mut executor, &mut state, &mut event_manager)
                    .unwrap_or_else(|_| panic!("Error in fuzz_one"));

                log::info!("Done fuzzing! Got {} solutions", state.solutions().count());
            }
            assert_eq!(state.solutions().count(), err_cnt);
        }
    }

    #[test]
    #[cfg(unix)]
    fn run_test_asan() {
        // Read RUST_LOG from the environment and set the log level accordingly (not using env_logger)
        // Note that in cargo test, the output of successfull tests is suppressed by default,
        // both those sent to stdout and stderr. To see the output, run `cargo test -- --nocapture`.
        if let Ok(value) = std::env::var("RUST_LOG") {
            match value.as_str() {
                "off" => log::set_max_level(log::LevelFilter::Off),
                "error" => log::set_max_level(log::LevelFilter::Error),
                "warn" => log::set_max_level(log::LevelFilter::Warn),
                "info" => log::set_max_level(log::LevelFilter::Info),
                "debug" => log::set_max_level(log::LevelFilter::Debug),
                "trace" => log::set_max_level(log::LevelFilter::Trace),
                _ => panic!("Unknown RUST_LOG level: {value}"),
            }
        }

        SimpleStdoutLogger::set_logger().unwrap();

        // Check if the harness dynamic library is present, if not - skip the test
        let test_harness = "test_harness.so";
        assert!(
            std::path::Path::new(test_harness).exists(),
            "Skipping test, {test_harness} not found"
        );

        GUM.set(unsafe { Gum::obtain() })
            .unwrap_or_else(|_| panic!("Failed to initialize Gum"));
        let simulated_args = vec![
            "libafl_frida_test",
            "-A",
            "--disable-excludes",
            "--continue-on-error",
            "-H",
            test_harness,
        ];
        let options: FuzzerOptions = FuzzerOptions::try_parse_from(simulated_args).unwrap();
        unsafe { test_asan(&options) }
    }
}
