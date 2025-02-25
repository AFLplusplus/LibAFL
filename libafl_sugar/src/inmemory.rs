//! In-Memory fuzzing made easy.
//! Use this sugar for scaling `libfuzzer`-style fuzzers.

use core::fmt::{self, Debug, Formatter};
use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

use libafl::{
    Error, HasMetadata,
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{EventConfig, EventRestarter, LlmpRestartingEventManager, launcher::Launcher},
    executors::{ExitKind, ShadowExecutor, inprocess::InProcessExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{
        havoc_mutations::havoc_mutations,
        scheduled::{StdScheduledMutator, tokens_mutations},
        token_mutations::{I2SRandReplace, Tokens},
    },
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{ShadowTracingStage, StdMutationalStage},
    state::{HasCorpus, StdState},
};
use libafl_bolts::{
    AsSlice,
    core_affinity::Cores,
    nonzero,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{Handled, Merge, tuple_list},
};
use libafl_targets::{CmpLogObserver, edges_map_mut_ptr};
use typed_builder::TypedBuilder;

use crate::{CORPUS_CACHE_SIZE, DEFAULT_TIMEOUT_SECS};

/// In-Memory fuzzing made easy.
/// Use this sugar for scaling `libfuzzer`-style fuzzers.
#[derive(TypedBuilder)]
pub struct InMemoryBytesCoverageSugar<'a, H>
where
    H: FnMut(&[u8]),
{
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
    /// Flag if use `CmpLog`
    #[builder(default = None)]
    use_cmplog: Option<bool>,
    /// The port used for communication between this fuzzer node and other fuzzer nodes
    #[builder(default = 1337_u16)]
    broker_port: u16,
    /// The list of cores to run on
    cores: &'a Cores,
    /// The `ip:port` address of another broker to connect our new broker to for multi-machine
    /// clusters.
    #[builder(default = None, setter(strip_option))]
    remote_broker_addr: Option<SocketAddr>,
    /// Bytes harness
    #[builder(setter(strip_option))]
    harness: Option<H>,
    /// The map size used for the fuzzer
    #[builder(default = 65536usize)]
    map_size: usize,
    /// Fuzz `iterations` number of times, instead of indefinitely; implies use of `fuzz_loop_for`
    #[builder(default = None)]
    iterations: Option<u64>,
}

impl<H> Debug for InMemoryBytesCoverageSugar<'_, H>
where
    H: FnMut(&[u8]),
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryBytesCoverageSugar")
            .field("configuration", &self.configuration)
            .field("timeout", &self.timeout)
            .field("input_dirs", &self.input_dirs)
            .field("output_dir", &self.output_dir)
            .field("tokens_file", &self.tokens_file)
            .field("use_cmplog", &self.use_cmplog)
            .field("broker_port", &self.broker_port)
            .field("cores", &self.cores)
            .field("remote_broker_addr", &self.remote_broker_addr)
            .field(
                "harness",
                if self.harness.is_some() {
                    &"<harness_fn>"
                } else {
                    &"None"
                },
            )
            .finish()
    }
}

impl<H> InMemoryBytesCoverageSugar<'_, H>
where
    H: FnMut(&[u8]),
{
    /// Run the fuzzer
    #[expect(clippy::too_many_lines)]
    pub fn run(&mut self) {
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

        let mut harness_bytes = self.harness.take().unwrap();

        let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

        let monitor = MultiMonitor::new(|s| println!("{s}"));

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");
        let time_ref = time_observer.handle();

        let mut run_client = |state: Option<_>,
                              mut mgr: LlmpRestartingEventManager<_, _, _, _, _>,
                              _core_id| {
            let time_observer = time_observer.clone();

            // Create an observation channel using the coverage map
            let edges_observer = HitcountsMapObserver::new(unsafe {
                StdMapObserver::from_mut_slice(
                    "edges",
                    OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), self.map_size),
                )
            })
            .track_indices();

            let cmplog_observer = CmpLogObserver::new("cmplog", true);

            // Feedback to rate the interestingness of an input
            // This one is composed by two Feedbacks in OR
            let mut feedback = feedback_or!(
                // New maximization map feedback linked to the edges observer and the feedback state
                MaxMapFeedback::new(&edges_observer),
                // Time feedback, this one does not need a feedback state
                TimeFeedback::new(&time_observer)
            );

            // A feedback to choose if an input is a solution or not
            let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

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

            // Create a dictionary if not existing
            if let Some(tokens_file) = &self.tokens_file {
                if state.metadata_map().get::<Tokens>().is_none() {
                    state.add_metadata(Tokens::from_file(tokens_file)?);
                }
            }

            // A minimization+queue policy to get testcasess from the corpus
            let scheduler =
                IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

            // A fuzzer with feedbacks and a corpus scheduler
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

            // The wrapped harness function, calling out to the LLVM-style harness
            let mut harness = |input: &BytesInput| {
                let target = input.target_bytes();
                let buf = target.as_slice();
                (harness_bytes)(buf);
                ExitKind::Ok
            };

            // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
            let mut executor = ShadowExecutor::new(
                InProcessExecutor::with_timeout(
                    &mut harness,
                    tuple_list!(edges_observer, time_observer),
                    &mut fuzzer,
                    &mut state,
                    &mut mgr,
                    timeout,
                )?,
                tuple_list!(cmplog_observer),
            );

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

            // Setup a tracing stage in which we log comparisons
            let tracing = ShadowTracingStage::new(&mut executor);

            // Setup a randomic Input2State stage
            let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(
                I2SRandReplace::new()
            )));

            if self.tokens_file.is_some() {
                // Setup a basic mutator
                let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
                let mutational = StdMutationalStage::new(mutator);

                // The order of the stages matter!
                if self.use_cmplog.unwrap_or(false) {
                    let mut stages = tuple_list!(tracing, i2s, mutational);
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
            } else {
                // Setup a basic mutator
                let mutator = StdScheduledMutator::new(havoc_mutations());
                let mutational = StdMutationalStage::new(mutator);

                // The order of the stages matter!
                if self.use_cmplog.unwrap_or(false) {
                    let mut stages = tuple_list!(tracing, i2s, mutational);
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
            .remote_broker_addr(self.remote_broker_addr)
            .time_ref(Some(time_ref));
        #[cfg(unix)]
        let launcher = launcher.stdout_file(Some("/dev/null"));
        match launcher.build().launch() {
            Ok(()) => (),
            Err(Error::ShuttingDown) => log::info!("\nFuzzing stopped by user. Good Bye."),
            Err(err) => panic!("Fuzzingg failed {err:?}"),
        }
    }
}

/// Python bindings for this sugar
#[cfg(feature = "python")]
pub mod pybind {
    use std::path::PathBuf;

    use libafl_bolts::core_affinity::Cores;
    use pyo3::{prelude::*, types::PyBytes};

    use crate::inmemory;

    /// In-Memory fuzzing made easy.
    /// Use this sugar for scaling `libfuzzer`-style fuzzers.
    #[pyclass(unsendable)]
    #[derive(Debug)]
    struct InMemoryBytesCoverageSugar {
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
    impl InMemoryBytesCoverageSugar {
        /// Create a new [`InMemoryBytesCoverageSugar`]
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
        pub fn run(&self, harness: PyObject) {
            inmemory::InMemoryBytesCoverageSugar::builder()
                .input_dirs(&self.input_dirs)
                .output_dir(self.output_dir.clone())
                .broker_port(self.broker_port)
                .cores(&self.cores)
                .harness(|buf| {
                    Python::with_gil(|py| -> PyResult<()> {
                        let args = (PyBytes::new(py, buf),); // TODO avoid copy
                        harness.call1(py, args)?;
                        Ok(())
                    })
                    .unwrap();
                })
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
        m.add_class::<InMemoryBytesCoverageSugar>()?;
        Ok(())
    }
}
