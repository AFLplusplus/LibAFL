//! In-Process fuzzer with `QEMU`-based binary-only instrumentation
use core::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
    time::Duration,
};
use std::{fs, path::PathBuf};
use libafl_qemu::modules::SnapshotModule;
use libafl::{
    HasMetadata,
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{EventConfig, EventRestarter, LlmpRestartingEventManager, launcher::Launcher},
    executors::{ExitKind, ShadowExecutor},
    feedback_and_fast, feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{
        I2SRandReplace,
        havoc_mutations::havoc_mutations,
        scheduled::{HavocScheduledMutator, tokens_mutations},
        token_mutations::Tokens,
    },
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
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
    tuples::{Merge, tuple_list},
};
use libafl_qemu::modules::CmpLogModule;
pub use libafl_qemu::qemu::Qemu;
use libafl_qemu::{Emulator, QemuExecutor, modules::edges::StdEdgeCoverageModule};
use libafl_targets::{CmpLogObserver, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND, edges_map_mut_ptr};
use typed_builder::TypedBuilder;

use crate::{CORPUS_CACHE_SIZE, DEFAULT_TIMEOUT_SECS};

/// Macro to handle the repetitive fuzzing logic
/// This macro generates the complete fuzzing implementation for both cmplog and non-cmplog cases
macro_rules! implement_fuzzing {
    (
        // Macro parameters
        modules: $modules:expr,
        use_shadow: $use_shadow:literal,
        self: $self:expr,
        qemu: $qemu:expr,
        harness_bytes: $harness_bytes:expr,
        edges_observer: $edges_observer:expr,
        time_observer: $time_observer:expr,
        cmplog_observer: $cmplog_observer:expr,
        state: $state:expr,
        mgr: $mgr:expr,
        timeout: $timeout:expr,
        map_feedback: $map_feedback:expr,
        scheduler: $scheduler:expr,
        feedback: $feedback:expr,
        objective: $objective:expr
    ) => {{

        // Create executor - this is where the types differ
        if $use_shadow {
        // Create harness closure
            let mut harness =
                |_emulator: &mut Emulator<_, _, _, _, _, _, _>, _state: &mut _, input: &BytesInput| {
                let target = input.target_bytes();
                let buf = target.as_slice();
                $harness_bytes(buf);
                ExitKind::Ok
            };
            // A fuzzer with feedbacks and a corpus scheduler
            // Build emulator
            let emulator = match $qemu {
                QemuSugarParameter::QemuCli(qemu_cli) => Emulator::empty()
                    .qemu_parameters(qemu_cli.to_owned())
                    .modules($modules)
                    .build()
                    .expect("Could not initialize Emulator"),
                QemuSugarParameter::Qemu(qemu) => Emulator::empty()
                    .modules($modules)
                    .build_with_qemu(*qemu)
                    .expect("Could not initialize Emulator"),
            };
            let mut fuzzer = StdFuzzer::new($scheduler, $feedback, $objective);
            let base_executor = QemuExecutor::new(
                emulator,
                &mut harness,
                tuple_list!($edges_observer, $time_observer),
                &mut fuzzer,
                &mut $state,
                &mut $mgr,
                $timeout,
            )?;
            let mut executor = ShadowExecutor::new(base_executor, tuple_list!($cmplog_observer));
            // Load initial inputs
            load_initial_inputs!(executor, $self, fuzzer, $state, $mgr);

            // Setup and run stages for shadow executor
            setup_fuzzing_stages!(
                shadow,
                executor,
                $self,
                fuzzer,
                $state,
                $mgr,
                $map_feedback
            );
        } else {
            // Create harness closure
            let mut harness =
                |_emulator: &mut Emulator<_, _, _, _, _, _, _>, _state: &mut _, input: &BytesInput| {
                let target = input.target_bytes();
                let buf = target.as_slice();
                $harness_bytes(buf);
                ExitKind::Ok
            };
            // A fuzzer with feedbacks and a corpus scheduler
            // Build emulator
            let emulator = match $qemu {
                QemuSugarParameter::QemuCli(qemu_cli) => Emulator::empty()
                    .qemu_parameters(qemu_cli.to_owned())
                    .modules($modules)
                    .build()
                    .expect("Could not initialize Emulator"),
                QemuSugarParameter::Qemu(qemu) => Emulator::empty()
                    .modules($modules)
                    .build_with_qemu(*qemu)
                    .expect("Could not initialize Emulator"),
            };
            let mut fuzzer = StdFuzzer::new($scheduler, $feedback, $objective);
            let mut executor = QemuExecutor::new(
                emulator,
                &mut harness,
                tuple_list!($edges_observer, $time_observer),
                &mut fuzzer,
                &mut $state,
                &mut $mgr,
                $timeout,
            )?;

            // Load initial inputs
            load_initial_inputs!(executor, $self, fuzzer, $state, $mgr);

            // Setup and run stages for regular executor
            setup_fuzzing_stages!(
                regular,
                executor,
                $self,
                fuzzer,
                $state,
                $mgr,
                $map_feedback
            );
        }
    }};
}

/// Macro to handle initial input loading (common for both paths)
macro_rules! load_initial_inputs {
    ($executor:expr, $self:expr, $fuzzer:expr, $state:expr, $mgr:expr) => {
        if $state.must_load_initial_inputs() {
            if $self.input_dirs.is_empty() {
                // Generator of printable bytearrays of max size 32
                let mut generator = RandBytesGenerator::new(nonzero!(32));

                // Generate 8 initial inputs
                $state
                    .generate_initial_inputs(
                        &mut $fuzzer,
                        &mut $executor,
                        &mut generator,
                        &mut $mgr,
                        8,
                    )
                    .expect("Failed to generate the initial corpus");
                log::info!(
                    "We imported {} inputs from the generator.",
                    $state.corpus().count()
                );
            } else {
                log::info!("Loading from {:?}", &$self.input_dirs);
                // Load from disk
                $state
                    .load_initial_inputs(&mut $fuzzer, &mut $executor, &mut $mgr, $self.input_dirs)
                    .unwrap_or_else(|_| {
                        panic!("Failed to load initial corpus at {:?}", &$self.input_dirs);
                    });
                log::info!("We imported {} inputs from disk.", $state.corpus().count());
            }
        }
    };
}

/// Macro to setup fuzzing stages based on configuration
macro_rules! setup_fuzzing_stages {
    (shadow, $executor:expr, $self:expr, $fuzzer:expr, $state:expr, $mgr:expr, $map_feedback:expr) => {
        if $self.tokens_file.is_some() {
            // Setup a basic mutator with tokens
            let mutator = HavocScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
            let mutational = StdMutationalStage::new(mutator);

            let tracing = ShadowTracingStage::new();
            let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
                I2SRandReplace::new()
            )));

            let mut stages = tuple_list!(tracing, i2s, mutational);
            run_fuzzing_loop!(stages, $executor, $self, $fuzzer, $state, $mgr);
        } else {
            // Setup a basic mutator without tokens
            let mutator = HavocScheduledMutator::new(havoc_mutations());
            let mutational = StdMutationalStage::new(mutator);

            let tracing = ShadowTracingStage::new();
            let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
                I2SRandReplace::new()
            )));

            let mut stages = tuple_list!(tracing, i2s, mutational);
            run_fuzzing_loop!(stages, $executor, $self, $fuzzer, $state, $mgr);
        }
    };

    (regular, $executor:expr, $self:expr, $fuzzer:expr, $state:expr, $mgr:expr, $map_feedback:expr) => {
        if $self.tokens_file.is_some() {
            // Setup a basic mutator with tokens
            let mutator = HavocScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
            let mutational = StdMutationalStage::new(mutator);

            // Regular executor stages
            let mut stages = tuple_list!(mutational);
            run_fuzzing_loop!(stages, $executor, $self, $fuzzer, $state, $mgr);
        } else {
            // Setup a basic mutator without tokens
            let mutator = HavocScheduledMutator::new(havoc_mutations());
            let mutational = StdMutationalStage::new(mutator);

            // Regular executor stages
            let mut stages = tuple_list!(mutational);
            run_fuzzing_loop!(stages, $executor, $self, $fuzzer, $state, $mgr);
        }
    };
}

/// Macro to run the final fuzzing loop (common for both paths)
macro_rules! run_fuzzing_loop {
    ($stages:expr, $executor:expr, $self:expr, $fuzzer:expr, $state:expr, $mgr:expr) => {
        if let Some(iters) = $self.iterations {
            $fuzzer.fuzz_loop_for(&mut $stages, &mut $executor, &mut $state, &mut $mgr, iters)?;
            $mgr.on_restart(&mut $state)?;
            std::process::exit(0);
        } else {
            $fuzzer.fuzz_loop(&mut $stages, &mut $executor, &mut $state, &mut $mgr)?;
        }
    };
}

impl<H> QemuBytesCoverageSugar<'_, H>
where
    H: FnMut(&[u8]),
{
    /// Run the fuzzer - now dramatically simplified thanks to macro deduplication
    pub fn run(&mut self, qemu: QemuSugarParameter) {
        let conf = match self.configuration.as_ref() {
            Some(name) => EventConfig::from_name(name),
            None => EventConfig::AlwaysUnique,
        };

        let timeout = Duration::from_secs(self.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS));

        let mut out_dir = self.output_dir.clone();
        if fs::create_dir(&out_dir).is_err() {
            log::info!("Out dir at {} already exists.", &out_dir.display());
            assert!(
                out_dir.is_dir(),
                "Out dir at {} is not a valid directory!",
                &out_dir.display()
            );
        }
        let mut crashes = out_dir.clone();
        crashes.push("crashes");
        out_dir.push("queue");

        let mut harness_bytes = self.harness.take().unwrap();

        let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
        let monitor = MultiMonitor::new(|s| println!("{s}"));
        let time_observer = TimeObserver::new("time");

        let mut run_client = |state: Option<_>,
                              mut mgr: LlmpRestartingEventManager<_, _, _, _, _>,
                              _core_id| {
            let time_observer = time_observer.clone();

            // Create an observation channel using the coverage map
            let mut edges_observer = unsafe {
                HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                    "edges",
                    OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                    &raw mut MAX_EDGES_FOUND,
                ))
                .track_indices()
            };

            // Keep tracks of CMPs
            let cmplog_observer = CmpLogObserver::new("cmplog", true);

            // New maximization map feedback linked to the edges observer and the feedback state
            let map_feedback = MaxMapFeedback::with_name("map_feedback", &edges_observer);
            // Extra MapFeedback to deduplicate finds according to the cov map
            let map_objective = MaxMapFeedback::with_name("map_objective", &edges_observer);

            // Feedback to rate the interestingness of an input
            let mut feedback = feedback_or!(map_feedback, TimeFeedback::new(&time_observer));
            // A feedback to choose if an input is a solution or not
            let mut objective = feedback_and_fast!(
                feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new()),
                map_objective
            );

            // If not restarting, create a State from scratch
            let mut state = state.unwrap_or_else(|| {
                StdState::new(
                    StdRand::new(),
                    CachedOnDiskCorpus::new(out_dir.clone(), CORPUS_CACHE_SIZE).unwrap(),
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

            // A minimization+queue policy to get testcases from the corpus
            let scheduler =
                IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());



            // Here's where the magic happens - all the duplicated code is now in a single macro call
            match (self.use_cmplog.unwrap_or(false), self.use_snapshot.unwrap_or(false)) {
                (true, true) => {
                    let modules = 
                            tuple_list!(
                                StdEdgeCoverageModule::builder()
                                    .map_observer(edges_observer.as_mut())
                                    .build()
                                    .unwrap(),
                                CmpLogModule::default(),
                                SnapshotModule::new(),
                            );
                                    
                    implement_fuzzing!(
                        modules: modules,
                        use_shadow: true,
                        self: self,
                        qemu: qemu,
                        harness_bytes: harness_bytes,
                        edges_observer: edges_observer,
                        time_observer: time_observer,
                        cmplog_observer: cmplog_observer,
                        state: state,
                        mgr: mgr,
                        timeout: timeout,
                        map_feedback: map_feedback,
                        scheduler: scheduler,
                        feedback: feedback,
                        objective: objective
                    );
                },
                (true, false) => {
                    let modules = 
                            tuple_list!(
                                StdEdgeCoverageModule::builder()
                                    .map_observer(edges_observer.as_mut())
                                    .build()
                                    .unwrap(),
                                CmpLogModule::default(),
                            );
                                    
                    implement_fuzzing!(
                        modules: modules,
                        use_shadow: true,
                        self: self,
                        qemu: qemu,
                        harness_bytes: harness_bytes,
                        edges_observer: edges_observer,
                        time_observer: time_observer,
                        cmplog_observer: cmplog_observer,
                        state: state,
                        mgr: mgr,
                        timeout: timeout,
                        map_feedback: map_feedback,
                        scheduler: scheduler,
                        feedback: feedback,
                        objective: objective
                    );
                },
                (false, true) => {
                    let modules = 
                            tuple_list!(
                                StdEdgeCoverageModule::builder()
                                    .map_observer(edges_observer.as_mut())
                                    .build()
                                    .unwrap(),
                                SnapshotModule::new(),
                            );
                                    
                    implement_fuzzing!(
                        modules: modules,
                        use_shadow: true,
                        self: self,
                        qemu: qemu,
                        harness_bytes: harness_bytes,
                        edges_observer: edges_observer,
                        time_observer: time_observer,
                        cmplog_observer: cmplog_observer,
                        state: state,
                        mgr: mgr,
                        timeout: timeout,
                        map_feedback: map_feedback,
                        scheduler: scheduler,
                        feedback: feedback,
                        objective: objective
                    );
                },
                (false, false) => {
                    let modules = 
                            tuple_list!(
                                StdEdgeCoverageModule::builder()
                                    .map_observer(edges_observer.as_mut())
                                    .build()
                                    .unwrap(),
                            );
                                    
                    implement_fuzzing!(
                        modules: modules,
                        use_shadow: true,
                        self: self,
                        qemu: qemu,
                        harness_bytes: harness_bytes,
                        edges_observer: edges_observer,
                        time_observer: time_observer,
                        cmplog_observer: cmplog_observer,
                        state: state,
                        mgr: mgr,
                        timeout: timeout,
                        map_feedback: map_feedback,
                        scheduler: scheduler,
                        feedback: feedback,
                        objective: objective
                    );
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
        if self.enable_stdout.unwrap_or(false) {
            launcher.build().launch().expect("Launcher failed");
        } else {
            let launcher = launcher.stdout_file(Some("/dev/null"));
            launcher.build().launch().expect("Launcher failed");
        }

        #[cfg(not(unix))]
        launcher.build().launch().expect("Launcher failed");
    }
}


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
    /// Flag if use `CmpLog`
    #[builder(default = None)]
    use_cmplog: Option<bool>,
    #[builder(default = None)]
    use_snapshot: Option<bool>,
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
    /// Disable redirection of stdout to /dev/null on unix build targets
    #[builder(default = None)]
    enable_stdout: Option<bool>,
}

impl<H> Debug for QemuBytesCoverageSugar<'_, H>
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
            .field("enable_stdout", &self.enable_stdout)
            .finish()
    }
}

/// Enum to allow passing either qemu cli parameters or a running qemu instance
#[derive(Debug, Copy, Clone)]
pub enum QemuSugarParameter<'a> {
    /// Argument list to pass to initialize Qemu
    QemuCli(&'a [String]),
    /// Already existing Qemu instance
    Qemu(&'a Qemu),
}

/// python bindings for this sugar
#[cfg(feature = "python")]
pub mod pybind {
    use std::path::PathBuf;

    use libafl_bolts::core_affinity::Cores;
    use libafl_qemu::pybind::Qemu;
    use pyo3::{prelude::*, types::PyBytes};

    use super::QemuSugarParameter;
    use crate::qemu;

    #[pyclass(unsendable)]
    #[derive(Debug)]
    struct QemuBytesCoverageSugar {
        input_dirs: Vec<PathBuf>,
        output_dir: PathBuf,
        broker_port: u16,
        cores: Cores,
        use_cmplog: Option<bool>,
        iterations: Option<u64>,
        tokens_file: Option<PathBuf>,
        timeout: Option<u64>,
        enable_stdout: Option<bool>,
    }

    #[pymethods]
    impl QemuBytesCoverageSugar {
        /// Create a new [`QemuBytesCoverageSugar`]
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
            timeout=None,
            enable_stdout=None,
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
            enable_stdout: Option<bool>,
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
                enable_stdout,
            }
        }

        /// Run the fuzzer
        #[expect(clippy::needless_pass_by_value)]
        pub fn run(&self, qemu: &Qemu, harness: PyObject) {
            qemu::QemuBytesCoverageSugar::builder()
                .input_dirs(&self.input_dirs)
                .output_dir(self.output_dir.clone())
                .broker_port(self.broker_port)
                .cores(&self.cores)
                .harness(|buf| {
                    Python::with_gil(|py| -> PyResult<()> {
                        let args = (PyBytes::new(py, buf),);
                        harness.call1(py, args)?;
                        Ok(())
                    })
                    .unwrap();
                })
                .use_cmplog(self.use_cmplog)
                .timeout(self.timeout)
                .tokens_file(self.tokens_file.clone())
                .iterations(self.iterations)
                .enable_stdout(self.enable_stdout)
                .build()
                .run(QemuSugarParameter::Qemu(&qemu.qemu));
        }
    }

    /// Register this class
    pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_class::<QemuBytesCoverageSugar>()?;
        Ok(())
    }
}