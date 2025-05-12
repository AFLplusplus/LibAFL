//! An `afl`-style forkserver fuzzer.
//! Use this if your target has complex state that needs to be reset.
use core::{net::SocketAddr, time::Duration};
use std::{fs, path::PathBuf};

use libafl::{
    Error, HasMetadata,
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{EventConfig, EventRestarter, LlmpRestartingEventManager, launcher::Launcher},
    executors::forkserver::{ForkserverExecutor, SHM_CMPLOG_ENV_VAR},
    feedback_and_fast, feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{
        AFLppRedQueen,
        havoc_mutations::havoc_mutations,
        scheduled::{HavocScheduledMutator, tokens_mutations},
        token_mutations::Tokens,
    },
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{
        CalibrationStage, ColorizationStage, IfStage, StdMutationalStage,
        mutational::MultiMutationalStage,
    },
    state::{HasCorpus, HasCurrentTestcase, StdState},
};
use libafl_bolts::{
    AsSliceMut, TargetArgs,
    core_affinity::Cores,
    nonzero,
    ownedref::OwnedRefMut,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::{Handled, Merge, tuple_list},
};
use libafl_targets::{AFLppCmpLogMap, AFLppCmpLogObserver, AFLppCmplogTracingStage};
use typed_builder::TypedBuilder;

use crate::{CORPUS_CACHE_SIZE, DEFAULT_TIMEOUT_SECS};

/// Creates a Forkserver-based fuzzer.
#[derive(Debug, TypedBuilder)]
pub struct ForkserverBytesCoverageSugar<'a> {
    /// Laucher configuration (default is random)
    #[builder(default = None, setter(strip_option))]
    configuration: Option<String>,
    /// Timeout of the executor
    #[builder(default = None)]
    timeout: Option<u64>,
    /// Input directories
    input_dirs: &'a [PathBuf],
    /// Output directory
    output_dir: PathBuf,
    /// Dictionary
    #[builder(default = None)]
    tokens_file: Option<PathBuf>,
    // Flag if use CmpLog
    #[builder(default = false)]
    use_cmplog: bool,
    #[builder(default = 1337_u16)]
    broker_port: u16,
    /// The list of cores to run on
    cores: &'a Cores,
    /// The `ip:port` address of another broker to connect our new broker to for multi-machine
    /// clusters.
    #[builder(default = None, setter(strip_option))]
    remote_broker_addr: Option<SocketAddr>,
    /// Path to program to execute
    program: String,
    /// Arguments of the program to execute
    arguments: &'a [String],
    #[builder(default = false)]
    /// Print target program output
    debug_output: bool,
    /// Fuzz `iterations` number of times, instead of indefinitely; implies use of `fuzz_loop_for`
    #[builder(default = None)]
    iterations: Option<u64>,
}

impl ForkserverBytesCoverageSugar<'_> {
    /// Runs the fuzzer.
    #[expect(clippy::too_many_lines)]
    pub fn run(&mut self) {
        // a large initial map size that should be enough
        // to house all potential coverage maps for our targets
        // (we will eventually reduce the used size according to the actual map)
        const MAP_SIZE: usize = 65_536;

        let conf = match self.configuration.as_ref() {
            Some(name) => EventConfig::from_name(name),
            None => EventConfig::AlwaysUnique,
        };

        let timeout = Duration::from_secs(self.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS));

        let mut out_dir = self.output_dir.clone();
        if fs::create_dir(&out_dir).is_err() {
            log::info!("Out dir at {:?} already exists.", &out_dir);
            assert!(
                out_dir.is_dir(),
                "Out dir at {:?} is not a valid directory!",
                &out_dir
            );
        }
        let mut crashes = out_dir.clone();
        crashes.push("crashes");
        out_dir.push("queue");

        let shmem_provider = UnixShMemProvider::new().expect("Failed to init shared memory");
        let mut shmem_provider_client = shmem_provider.clone();

        let monitor = MultiMonitor::new(|s| log::info!("{s}"));

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        let mut run_client = |state: Option<_>,
                              mut mgr: LlmpRestartingEventManager<_, _, _, _, _>,
                              _core_id| {
            let time_observer = time_observer.clone();

            // Create an empty set of tokens, first populated by the target program
            let mut tokens = Tokens::new();

            // Coverage map shared between target and fuzzer
            let mut shmem = shmem_provider_client.new_shmem(MAP_SIZE).unwrap();
            unsafe {
                shmem.write_to_env("__AFL_SHM_ID").unwrap();
            }
            let shmem_map = shmem.as_slice_mut();

            // To let know the AFL++ binary that we have a big map
            unsafe {
                std::env::set_var("AFL_MAP_SIZE", format!("{MAP_SIZE}"));
            }

            // Create an observation channel using the coverage map
            let edges_observer = unsafe {
                HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_map))
                    .track_indices()
            };

            // New maximization map feedback linked to the edges observer and the feedback state
            let map_feedback = MaxMapFeedback::with_name("map_feedback", &edges_observer);
            // Extra MapFeedback to deduplicate finds according to the cov map
            let map_objective = MaxMapFeedback::with_name("map_objective", &edges_observer);

            let calibration = CalibrationStage::new(&map_feedback);

            let colorization = ColorizationStage::new(&edges_observer);

            // The cmplog map shared between observer and executor
            let mut cmplog_shmem = shmem_provider_client
                .uninit_on_shmem::<AFLppCmpLogMap>()
                .unwrap();
            // let the forkserver know the shmid
            unsafe {
                cmplog_shmem.write_to_env(SHM_CMPLOG_ENV_VAR).unwrap();
            }
            let cmpmap = unsafe { OwnedRefMut::from_shmem(&mut cmplog_shmem) };

            let cmplog_observer = AFLppCmpLogObserver::new("cmplog", cmpmap, true);
            let cmplog_ref = cmplog_observer.handle();

            let cmplog_executor = ForkserverExecutor::builder()
                .program(self.program.clone())
                .parse_afl_cmdline(self.arguments)
                .is_persistent(true)
                .coverage_map_size(MAP_SIZE)
                // increase timeouts for cmplog
                .timeout(timeout * 10)
                .debug_child(self.debug_output)
                .shmem_provider(&mut shmem_provider_client)
                .build(tuple_list!(cmplog_observer))
                .unwrap();

            let tracing = AFLppCmplogTracingStage::new(cmplog_executor, cmplog_ref);

            // Setup a randomic Input2State stage
            let rq: MultiMutationalStage<_, _, BytesInput, _, _, _> =
                MultiMutationalStage::new(AFLppRedQueen::with_cmplog_options(true, true));

            let cb = |_fuzzer: &mut _,
                      _executor: &mut _,
                      state: &mut StdState<CachedOnDiskCorpus<_>, _, _, _>,
                      _event_manager: &mut _|
             -> Result<bool, Error> {
                if !self.use_cmplog {
                    return Ok(false);
                }
                let testcase = state.current_testcase()?;
                let res = testcase.scheduled_count() == 1; // let's try on the 2nd trial

                Ok(res)
            };

            let cmplog = IfStage::new(cb, tuple_list!(colorization, tracing, rq));

            // Feedback to rate the interestingness of an input
            // This one is composed by two Feedbacks in OR
            let mut feedback = feedback_or!(
                // New maximization map feedback linked to the edges observer and the feedback state
                MaxMapFeedback::new(&edges_observer),
                // Time feedback, this one does not need a feedback state
                TimeFeedback::new(&time_observer)
            );

            // A feedback to choose if an input is a solution or not
            let mut objective = feedback_and_fast!(
                feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new()),
                map_objective
            );

            // If not restarting, create a State from scratch
            let mut state = state.unwrap_or_else(|| {
                StdState::new(
                    // RNG
                    StdRand::new(),
                    // Corpus that will be evolved, we keep a part in memory for performance
                    CachedOnDiskCorpus::new(out_dir.clone(), CORPUS_CACHE_SIZE).unwrap(),
                    // Corpus in which we store solutions (crashes in this example),
                    // on disk so the user can get them after stopping the fuzzer
                    OnDiskCorpus::new(crashes.clone()).unwrap(),
                    &mut feedback,
                    &mut objective,
                )
                .unwrap()
            });

            // A minimization+queue policy to get testcasess from the corpus
            let scheduler =
                IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

            // A fuzzer with feedbacks and a corpus scheduler
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

            let forkserver = ForkserverExecutor::builder()
                .program(self.program.clone())
                .parse_afl_cmdline(self.arguments)
                .is_persistent(true)
                .autotokens(&mut tokens)
                .coverage_map_size(MAP_SIZE)
                .timeout(timeout)
                .debug_child(self.debug_output)
                .shmem_provider(&mut shmem_provider_client)
                .build_dynamic_map(edges_observer, tuple_list!(time_observer));

            let mut executor = forkserver.unwrap();
            if let Some(tokens_file) = &self.tokens_file {
                // if a token file is provided, load it into our set of tokens
                tokens.add_from_file(tokens_file)?;
            }

            if !tokens.is_empty() {
                // add any known tokens to the state
                state.add_metadata(tokens);
            }

            // In case the corpus is empty (on first run), reset
            if state.must_load_initial_inputs() {
                if self.input_dirs.is_empty() {
                    // Generator of printable bytearrays of max size 32
                    let mut generator = RandBytesGenerator::new(nonzero!(32));

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
                    log::info!(
                        "We imported {} inputs from the generator.",
                        state.corpus().count()
                    );
                } else {
                    log::info!("Loading from {:?}", &self.input_dirs);
                    // Load from disk
                    state
                        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, self.input_dirs)
                        .unwrap_or_else(|_| {
                            panic!("Failed to load initial corpus at {:?}", &self.input_dirs);
                        });
                    log::info!("We imported {} inputs from disk.", state.corpus().count());
                }
            }

            if self.tokens_file.is_some() {
                // Setup a basic mutator
                let mutator =
                    HavocScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
                let mutational = StdMutationalStage::new(mutator);

                // The order of the stages matter!
                let mut stages = tuple_list!(calibration, cmplog, mutational);

                if let Some(iters) = self.iterations {
                    fuzzer.fuzz_loop_for(
                        &mut stages,
                        &mut executor,
                        &mut state,
                        &mut mgr,
                        iters,
                    )?;
                    mgr.on_restart(&mut state)?;
                    std::process::exit(0);
                } else {
                    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
                }
            } else {
                // Setup a basic mutator
                let mutator = HavocScheduledMutator::new(havoc_mutations());
                let mutational = StdMutationalStage::new(mutator);

                // The order of the stages matter!
                let mut stages = tuple_list!(calibration, cmplog, mutational);

                if let Some(iters) = self.iterations {
                    fuzzer.fuzz_loop_for(
                        &mut stages,
                        &mut executor,
                        &mut state,
                        &mut mgr,
                        iters,
                    )?;
                    mgr.on_restart(&mut state)?;
                    std::process::exit(0);
                } else {
                    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
                }
            }

            Ok(())
        };

        let launcher = Launcher::builder()
            .shmem_provider(shmem_provider)
            .configuration(conf)
            .monitor(monitor)
            .run_client(&mut run_client)
            .cores(self.cores)
            .broker_port(self.broker_port)
            .remote_broker_addr(self.remote_broker_addr);

        #[cfg(unix)]
        let launcher = launcher.stdout_file(Some("/dev/null"));
        match launcher.build().launch() {
            Ok(()) => (),
            Err(Error::ShuttingDown) => log::info!("\nFuzzing stopped by user. Good Bye."),
            Err(err) => panic!("Fuzzingg failed {err:?}"),
        }
    }
}

/// The python bindings for this sugar
#[cfg(feature = "python")]
pub mod pybind {
    use std::path::PathBuf;

    use libafl_bolts::core_affinity::Cores;
    use pyo3::prelude::*;

    use crate::forkserver;

    /// Python bindings for the `LibAFL` forkserver sugar
    #[pyclass(unsendable)]
    #[derive(Debug)]
    struct ForkserverBytesCoverageSugar {
        input_dirs: Vec<PathBuf>,
        output_dir: PathBuf,
        broker_port: u16,
        cores: Cores,
        use_cmplog: Option<bool>,
        iterations: Option<u64>,
        tokens_file: Option<PathBuf>,
        timeout: Option<u64>,
    }

    #[pymethods]
    impl ForkserverBytesCoverageSugar {
        /// Create a new [`ForkserverBytesCoverageSugar`]
        #[new]
        #[expect(clippy::too_many_arguments)]
        #[pyo3(signature = (
            input_dirs,
            output_dir,
            broker_port,
            cores,
            use_cmplog=None,
            iterations=None,
            tokens_file=None,
            timeout=None
        ))]
        fn new(
            input_dirs: Vec<PathBuf>,
            output_dir: PathBuf,
            broker_port: u16,
            cores: Vec<usize>,
            use_cmplog: Option<bool>,
            iterations: Option<u64>,
            tokens_file: Option<PathBuf>,
            timeout: Option<u64>,
        ) -> Self {
            Self {
                input_dirs,
                output_dir,
                broker_port,
                cores: cores.into(),
                use_cmplog,
                iterations,
                tokens_file,
                timeout,
            }
        }

        /// Run the fuzzer
        #[expect(clippy::needless_pass_by_value)]
        pub fn run(&self, program: String, arguments: Vec<String>) {
            forkserver::ForkserverBytesCoverageSugar::builder()
                .input_dirs(&self.input_dirs)
                .output_dir(self.output_dir.clone())
                .broker_port(self.broker_port)
                .cores(&self.cores)
                .program(program)
                .arguments(&arguments)
                .use_cmplog(self.use_cmplog)
                .timeout(self.timeout)
                .tokens_file(self.tokens_file.clone())
                .iterations(self.iterations)
                .build()
                .run();
        }
    }

    /// Register the module
    pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_class::<ForkserverBytesCoverageSugar>()?;
        Ok(())
    }
}
