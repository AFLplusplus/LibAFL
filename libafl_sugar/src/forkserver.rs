//! An `afl`-style forkserver fuzzer.
//! Use this if your target has complex state that needs to be reset.
use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};
use typed_builder::TypedBuilder;

use libafl::{
    bolts::{
        current_nanos,
        launcher::Launcher,
        os::Cores,
        rands::StdRand,
        shmem::{ShMem, ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge},
        AsMutSlice,
    },
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{EventConfig, EventRestarter, LlmpRestartingEventManager},
    executors::{forkserver::ForkserverExecutorBuilder, TimeoutForkserverExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    monitors::MultiMonitor,
    mutators::scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
    mutators::token_mutations::Tokens,
    observers::{ConstMapObserver, HitcountsMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, HasMetadata, StdState},
    Error,
};

use crate::{CORPUS_CACHE_SIZE, DEFAULT_TIMEOUT_SECS};

/// The default coverage map size to use for forkserver targets
pub const DEFAULT_MAP_SIZE: usize = 65536;

/// Creates a Forkserver-based fuzzer.
#[derive(Debug, TypedBuilder)]
pub struct ForkserverBytesCoverageSugar<'a, const MAP_SIZE: usize> {
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
    #[builder(default = None)]
    use_cmplog: Option<bool>,
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
    /// Use shared mem testcase delivery
    shmem_testcase: bool,
    #[builder(default = false)]
    /// Print target program output
    debug_output: bool,
    /// Fuzz `iterations` number of times, instead of indefinitely; implies use of `fuzz_loop_for`
    #[builder(default = None)]
    iterations: Option<u64>,
}

#[allow(clippy::similar_names)]
impl<'a, const MAP_SIZE: usize> ForkserverBytesCoverageSugar<'a, MAP_SIZE> {
    /// Runs the fuzzer.
    #[allow(clippy::too_many_lines, clippy::similar_names)]
    pub fn run(&mut self) {
        let conf = match self.configuration.as_ref() {
            Some(name) => EventConfig::from_name(name),
            None => EventConfig::AlwaysUnique,
        };

        if self.use_cmplog.unwrap_or(false) {
            println!("[WARNING] use of cmplog not currently supported, use_cmplog ignored.");
        }

        let timeout = Duration::from_secs(self.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS));

        let mut out_dir = self.output_dir.clone();
        if fs::create_dir(&out_dir).is_err() {
            println!("Out dir at {:?} already exists.", &out_dir);
            assert!(
                out_dir.is_dir(),
                "Out dir at {:?} is not a valid directory!",
                &out_dir
            );
        }
        let mut crashes = out_dir.clone();
        crashes.push("crashes");
        out_dir.push("queue");

        let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
        let mut shmem_provider_client = shmem_provider.clone();

        let monitor = MultiMonitor::new(|s| println!("{}", s));

        let mut run_client = |state: Option<StdState<_, _, _, _, _>>,
                              mut mgr: LlmpRestartingEventManager<_, _, _, _>,
                              _core_id| {
            // Coverage map shared between target and fuzzer
            let mut shmem = shmem_provider_client.new_shmem(MAP_SIZE).unwrap();
            shmem.write_to_env("__AFL_SHM_ID").unwrap();
            let shmem_map = shmem.as_mut_slice();

            // Create an observation channel using the coverage map
            let edges_observer = unsafe {
                HitcountsMapObserver::new(ConstMapObserver::<_, MAP_SIZE>::new_from_ptr(
                    "shared_mem",
                    shmem_map.as_mut_ptr(),
                ))
            };

            // Create an observation channel to keep track of the execution time
            let time_observer = TimeObserver::new("time");

            // The state of the edges feedback.
            let feedback_state = MapFeedbackState::with_observer(&edges_observer);

            // Feedback to rate the interestingness of an input
            // This one is composed by two Feedbacks in OR
            let feedback = feedback_or!(
                // New maximization map feedback linked to the edges observer and the feedback state
                MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, false),
                // Time feedback, this one does not need a feedback state
                TimeFeedback::new_with_observer(&time_observer)
            );

            // A feedback to choose if an input is a solution or not
            let objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

            // If not restarting, create a State from scratch
            let mut state = state.unwrap_or_else(|| {
                StdState::new(
                    // RNG
                    StdRand::with_seed(current_nanos()),
                    // Corpus that will be evolved, we keep a part in memory for performance
                    CachedOnDiskCorpus::new(out_dir.clone(), CORPUS_CACHE_SIZE).unwrap(),
                    // Corpus in which we store solutions (crashes in this example),
                    // on disk so the user can get them after stopping the fuzzer
                    OnDiskCorpus::new(crashes.clone()).unwrap(),
                    // States of the feedbacks.
                    // They are the data related to the feedbacks that you want to persist in the State.
                    tuple_list!(feedback_state),
                )
            });

            // Create a dictionary if not existing
            if let Some(tokens_file) = &self.tokens_file {
                if state.metadata().get::<Tokens>().is_none() {
                    state.add_metadata(Tokens::from_file(tokens_file)?);
                }
            }

            // A minimization+queue policy to get testcasess from the corpus
            let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

            // A fuzzer with feedbacks and a corpus scheduler
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

            let forkserver = if self.shmem_testcase {
                ForkserverExecutorBuilder::new()
                    .program(self.program.clone())
                    .args(self.arguments)
                    .debug_child(self.debug_output)
                    .shmem_provider(&mut shmem_provider_client)
                    .build(tuple_list!(edges_observer, time_observer))
            } else {
                ForkserverExecutorBuilder::new()
                    .program(self.program.clone())
                    .args(self.arguments)
                    .debug_child(self.debug_output)
                    .build(tuple_list!(edges_observer, time_observer))
            };

            // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
            let mut executor = TimeoutForkserverExecutor::new(
                forkserver.expect("Failed to create the executor."),
                timeout,
            )
            .expect("Failed to create the executor.");

            // In case the corpus is empty (on first run), reset
            if state.corpus().count() < 1 {
                if self.input_dirs.is_empty() {
                    // Generator of printable bytearrays of max size 32
                    let mut generator = RandBytesGenerator::new(32);

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
                } else {
                    println!("Loading from {:?}", &self.input_dirs);
                    // Load from disk
                    state
                        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, self.input_dirs)
                        .unwrap_or_else(|_| {
                            panic!("Failed to load initial corpus at {:?}", &self.input_dirs);
                        });
                    println!("We imported {} inputs from disk.", state.corpus().count());
                }
            }

            if self.tokens_file.is_some() {
                // Setup a basic mutator
                let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
                let mutational = StdMutationalStage::new(mutator);

                // The order of the stages matter!
                let mut stages = tuple_list!(mutational);

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
                let mutator = StdScheduledMutator::new(havoc_mutations());
                let mutational = StdMutationalStage::new(mutator);

                // The order of the stages matter!
                let mut stages = tuple_list!(mutational);

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
            Err(Error::ShuttingDown) => println!("\nFuzzing stopped by user. Good Bye."),
            Err(err) => panic!("Fuzzingg failed {:?}", err),
        }
    }
}

/// The python bindings for this sugar
#[cfg(feature = "python")]
pub mod pybind {
    use crate::forkserver;
    use libafl::bolts::os::Cores;
    use pyo3::prelude::*;
    use std::path::PathBuf;

    /// Python bindings for the `LibAFL` forkserver sugar
    #[pyclass(unsendable)]
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
        #[allow(clippy::too_many_arguments)]
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
        #[allow(clippy::needless_pass_by_value)]
        pub fn run(&self, program: String, arguments: Vec<String>) {
            forkserver::ForkserverBytesCoverageSugar::<{ forkserver::DEFAULT_MAP_SIZE }>::builder()
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
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<ForkserverBytesCoverageSugar>()?;
        Ok(())
    }
}
