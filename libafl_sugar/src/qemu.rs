//! In-memory fuzzer with `QEMU`-based binary-only instrumentation
//!
use core::fmt::{self, Debug, Formatter};
use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

use libafl::{
    bolts::{
        core_affinity::Cores,
        current_nanos,
        launcher::Launcher,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge},
        AsSlice,
    },
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{EventConfig, EventRestarter, LlmpRestartingEventManager},
    executors::{ExitKind, ShadowExecutor, TimeoutExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{
        scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
        token_mutations::Tokens,
        I2SRandReplace,
    },
    observers::{HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{ShadowTracingStage, StdMutationalStage},
    state::{HasCorpus, HasMetadata, StdState},
};
pub use libafl_qemu::emu::Emulator;
use libafl_qemu::{
    cmplog, edges, QemuCmpLogHelper, QemuEdgeCoverageHelper, QemuExecutor, QemuHooks,
};
use libafl_targets::CmpLogObserver;
use typed_builder::TypedBuilder;

use crate::{CORPUS_CACHE_SIZE, DEFAULT_TIMEOUT_SECS};

/// Sugar to create a `libfuzzer`-style fuzzer that uses
/// `QEMU`-based binary-only instrumentation
#[derive(TypedBuilder)]
pub struct QemuBytesCoverageSugar<'a, H>
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
    /// Flag if use CmpLog
    #[builder(default = None)]
    use_cmplog: Option<bool>,
    /// The port the fuzzing nodes communicate over
    /// This will spawn a server on this port, and connect to other brokers using this port.
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
    /// Fuzz `iterations` number of times, instead of indefinitely; implies use of `fuzz_loop_for`
    #[builder(default = None)]
    iterations: Option<u64>,
}

impl<'a, H> Debug for QemuBytesCoverageSugar<'a, H>
where
    H: FnMut(&[u8]),
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuBytesCoverageSugar")
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
            .field("iterations", &self.iterations)
            .finish()
    }
}

impl<'a, H> QemuBytesCoverageSugar<'a, H>
where
    H: FnMut(&[u8]),
{
    /// Run the fuzzer
    #[allow(clippy::too_many_lines, clippy::similar_names)]
    pub fn run(&mut self, emulator: &Emulator) {
        let conf = match self.configuration.as_ref() {
            Some(name) => EventConfig::from_name(name),
            None => EventConfig::AlwaysUnique,
        };

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

        let mut harness_bytes = self.harness.take().unwrap();

        let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

        let monitor = MultiMonitor::new(|s| println!("{s}"));

        let mut run_client = |state: Option<_>,
                              mut mgr: LlmpRestartingEventManager<_, _>,
                              _core_id| {
            // Create an observation channel using the coverage map
            let edges = unsafe { &mut edges::EDGES_MAP };
            let edges_counter = unsafe { &mut edges::MAX_EDGES_NUM };
            let edges_observer =
                HitcountsMapObserver::new(VariableMapObserver::new("edges", edges, edges_counter));

            // Create an observation channel to keep track of the execution time
            let time_observer = TimeObserver::new("time");

            // Keep tracks of CMPs
            let cmplog = unsafe { &mut cmplog::CMPLOG_MAP };
            let cmplog_observer = CmpLogObserver::new("cmplog", cmplog, true);

            // Feedback to rate the interestingness of an input
            // This one is composed by two Feedbacks in OR
            let mut feedback = feedback_or!(
                // New maximization map feedback linked to the edges observer and the feedback state
                MaxMapFeedback::new_tracking(&edges_observer, true, false),
                // Time feedback, this one does not need a feedback state
                TimeFeedback::new_with_observer(&time_observer)
            );

            // A feedback to choose if an input is a solution or not
            let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

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
                    &mut feedback,
                    &mut objective,
                )
                .unwrap()
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

            // The wrapped harness function, calling out to the LLVM-style harness
            let mut harness = |input: &BytesInput| {
                let target = input.target_bytes();
                let buf = target.as_slice();
                (harness_bytes)(buf);
                ExitKind::Ok
            };

            if self.use_cmplog.unwrap_or(false) {
                let mut hooks = QemuHooks::new(
                    emulator,
                    tuple_list!(
                        QemuEdgeCoverageHelper::default(),
                        QemuCmpLogHelper::default(),
                    ),
                );

                let executor = QemuExecutor::new(
                    &mut hooks,
                    &mut harness,
                    tuple_list!(edges_observer, time_observer),
                    &mut fuzzer,
                    &mut state,
                    &mut mgr,
                )?;
                let executor = TimeoutExecutor::new(executor, timeout);
                let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

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
                            .load_initial_inputs(
                                &mut fuzzer,
                                &mut executor,
                                &mut mgr,
                                self.input_dirs,
                            )
                            .unwrap_or_else(|_| {
                                panic!("Failed to load initial corpus at {:?}", &self.input_dirs);
                            });
                        println!("We imported {} inputs from disk.", state.corpus().count());
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
                    let mutator =
                        StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
                    let mutational = StdMutationalStage::new(mutator);

                    // The order of the stages matter!
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
                    // Setup a basic mutator
                    let mutator = StdScheduledMutator::new(havoc_mutations());
                    let mutational = StdMutationalStage::new(mutator);

                    // The order of the stages matter!
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
                }
            } else {
                let mut hooks =
                    QemuHooks::new(emulator, tuple_list!(QemuEdgeCoverageHelper::default()));

                let executor = QemuExecutor::new(
                    &mut hooks,
                    &mut harness,
                    tuple_list!(edges_observer, time_observer),
                    &mut fuzzer,
                    &mut state,
                    &mut mgr,
                )?;
                let mut executor = TimeoutExecutor::new(executor, timeout);

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
                            .load_initial_inputs(
                                &mut fuzzer,
                                &mut executor,
                                &mut mgr,
                                self.input_dirs,
                            )
                            .unwrap_or_else(|_| {
                                panic!("Failed to load initial corpus at {:?}", &self.input_dirs);
                            });
                        println!("We imported {} inputs from disk.", state.corpus().count());
                    }
                }

                if self.tokens_file.is_some() {
                    // Setup a basic mutator
                    let mutator =
                        StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
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
        launcher.build().launch().expect("Launcher failed");
    }
}

/// python bindings for this sugar
#[cfg(feature = "python")]
pub mod pybind {
    use std::path::PathBuf;

    use libafl::bolts::core_affinity::Cores;
    use libafl_qemu::emu::pybind::Emulator;
    use pyo3::{prelude::*, types::PyBytes};

    use crate::qemu;

    #[pyclass(unsendable)]
    struct QemuBytesCoverageSugar {
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
    impl QemuBytesCoverageSugar {
        /// Create a new [`QemuBytesCoverageSugar`]
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
        pub fn run(&self, emulator: &Emulator, harness: PyObject) {
            qemu::QemuBytesCoverageSugar::builder()
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
                .run(&emulator.emu);
        }
    }

    /// Register this class
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<QemuBytesCoverageSugar>()?;
        Ok(())
    }
}
