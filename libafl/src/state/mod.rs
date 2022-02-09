//! The fuzzer, and state are the core pieces of every good fuzzer

use core::{fmt::Debug, marker::PhantomData, time::Duration};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
#[cfg(feature = "std")]
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    bolts::{
        rands::Rand,
        serdeany::{SerdeAny, SerdeAnyMap},
    },
    corpus::Corpus,
    events::{Event, EventFirer, LogSeverity},
    feedbacks::FeedbackStatesTuple,
    fuzzer::{Evaluator, ExecuteInputResult},
    generators::Generator,
    inputs::Input,
    monitors::ClientPerfMonitor,
    Error,
};

/// The maximum size of a testcase
pub const DEFAULT_MAX_SIZE: usize = 1_048_576;

/// The [`State`] of the fuzzer.
/// Contains all important information about the current run.
/// Will be used to restart the fuzzing process at any timme.
pub trait State: Serialize + DeserializeOwned {}

/// Trait for elements offering a corpus
pub trait HasCorpus<I: Input> {
    /// The associated type implementing [`Corpus`].
    type Corpus: Corpus<I>;
    /// The testcase corpus
    fn corpus(&self) -> &Self::Corpus;
    /// The testcase corpus (mutable)
    fn corpus_mut(&mut self) -> &mut Self::Corpus;
}

/// Interact with the maximum size
pub trait HasMaxSize {
    /// The maximum size hint for items and mutations returned
    fn max_size(&self) -> usize;
    /// Sets the maximum size hint for the items and mutations
    fn set_max_size(&mut self, max_size: usize);
}

/// Trait for elements offering a corpus of solutions
pub trait HasSolutions<I: Input> {
    /// The associated type implementing [`Corpus`] for solutions
    type Solutions: Corpus<I>;
    /// The solutions corpus
    fn solutions(&self) -> &Self::Solutions;
    /// The solutions corpus (mutable)
    fn solutions_mut(&mut self) -> &mut Self::Solutions;
}

/// Trait for elements offering a rand
pub trait HasRand {
    /// The associated type implementing [`Rand`]
    type Rand: Rand;
    /// The rand instance
    fn rand(&self) -> &Self::Rand;
    /// The rand instance (mutable)
    fn rand_mut(&mut self) -> &mut Self::Rand;
}

/// Trait for offering a [`ClientPerfMonitor`]
pub trait HasClientPerfMonitor {
    /// [`ClientPerfMonitor`] itself
    fn introspection_monitor(&self) -> &ClientPerfMonitor;

    /// Mutatable ref to [`ClientPerfMonitor`]
    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor;

    /// This node's stability
    fn stability(&self) -> &Option<f32>;

    /// This node's stability (mutable)
    fn stability_mut(&mut self) -> &mut Option<f32>;
}

/// Trait for elements offering metadata
pub trait HasMetadata {
    /// A map, storing all metadata
    fn metadata(&self) -> &SerdeAnyMap;
    /// A map, storing all metadata (mutable)
    fn metadata_mut(&mut self) -> &mut SerdeAnyMap;

    /// Add a metadata to the metadata map
    #[inline]
    fn add_metadata<M>(&mut self, meta: M)
    where
        M: SerdeAny,
    {
        self.metadata_mut().insert(meta);
    }

    /// Check for a metadata
    #[inline]
    fn has_metadata<M>(&self) -> bool
    where
        M: SerdeAny,
    {
        self.metadata().get::<M>().is_some()
    }
}

/// Trait for elements offering a feedback
pub trait HasFeedbackStates {
    /// The associated feedback type implementing [`FeedbackStatesTuple`].
    type FeedbackStates: FeedbackStatesTuple;
    /// The feedback states
    fn feedback_states(&self) -> &Self::FeedbackStates;

    /// The feedback states (mutable)
    fn feedback_states_mut(&mut self) -> &mut Self::FeedbackStates;
}

/// Trait for the execution counter
pub trait HasExecutions {
    /// The executions counter
    fn executions(&self) -> &usize;

    /// The executions counter (mutable)
    fn executions_mut(&mut self) -> &mut usize;
}

/// Trait for the starting time
pub trait HasStartTime {
    /// The starting time
    fn start_time(&self) -> &Duration;

    /// The starting time (mutable)
    fn start_time_mut(&mut self) -> &mut Duration;
}

/// The state a fuzz run.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "FT: serde::de::DeserializeOwned")]
pub struct StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    /// RNG instance
    rand: R,
    /// How many times the executor ran the harness/target
    executions: usize,
    /// At what time the fuzzing started
    start_time: Duration,
    /// The corpus
    corpus: C,
    /// States of the feedback used to evaluate an input
    feedback_states: FT,
    // Solutions corpus
    solutions: SC,
    /// Metadata stored for this state by one of the components
    metadata: SerdeAnyMap,
    /// MaxSize testcase size for mutators that appreciate it
    max_size: usize,
    /// The stability of the current fuzzing process
    stability: Option<f32>,

    /// Performance statistics for this fuzzer
    #[cfg(feature = "introspection")]
    introspection_monitor: ClientPerfMonitor,

    phantom: PhantomData<I>,
}

impl<C, FT, I, R, SC> State for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
}

impl<C, FT, I, R, SC> HasRand for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    type Rand = R;

    /// The rand instance
    #[inline]
    fn rand(&self) -> &Self::Rand {
        &self.rand
    }

    /// The rand instance (mutable)
    #[inline]
    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand
    }
}

impl<C, FT, I, R, SC> HasCorpus<I> for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    type Corpus = C;

    /// Returns the corpus
    #[inline]
    fn corpus(&self) -> &C {
        &self.corpus
    }

    /// Returns the mutable corpus
    #[inline]
    fn corpus_mut(&mut self) -> &mut C {
        &mut self.corpus
    }
}

impl<C, FT, I, R, SC> HasSolutions<I> for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    type Solutions = SC;

    /// Returns the solutions corpus
    #[inline]
    fn solutions(&self) -> &SC {
        &self.solutions
    }

    /// Returns the solutions corpus (mutable)
    #[inline]
    fn solutions_mut(&mut self) -> &mut SC {
        &mut self.solutions
    }
}

impl<C, FT, I, R, SC> HasMetadata for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    /// Get all the metadata into an [`hashbrown::HashMap`]
    #[inline]
    fn metadata(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    /// Get all the metadata into an [`hashbrown::HashMap`] (mutable)
    #[inline]
    fn metadata_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<C, FT, I, R, SC> HasFeedbackStates for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    type FeedbackStates = FT;

    /// The feedback states
    #[inline]
    fn feedback_states(&self) -> &FT {
        &self.feedback_states
    }

    /// The feedback states (mutable)
    #[inline]
    fn feedback_states_mut(&mut self) -> &mut FT {
        &mut self.feedback_states
    }
}

impl<C, FT, I, R, SC> HasExecutions for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    /// The executions counter
    #[inline]
    fn executions(&self) -> &usize {
        &self.executions
    }

    /// The executions counter (mutable)
    #[inline]
    fn executions_mut(&mut self) -> &mut usize {
        &mut self.executions
    }
}

impl<C, FT, I, R, SC> HasMaxSize for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
    }
}

impl<C, FT, I, R, SC> HasStartTime for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    /// The starting time
    #[inline]
    fn start_time(&self) -> &Duration {
        &self.start_time
    }

    /// The starting time (mutable)
    #[inline]
    fn start_time_mut(&mut self) -> &mut Duration {
        &mut self.start_time
    }
}

#[cfg(feature = "std")]
impl<C, FT, I, R, SC> StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    /// Loads inputs from a directory.
    /// If `forced` is `true`, the value will be loaded,
    /// even if it's not considered to be `interesting`.
    pub fn load_from_directory<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dir: &Path,
        forced: bool,
        loader: &mut dyn FnMut(&mut Z, &mut Self, &Path) -> Result<I, Error>,
    ) -> Result<(), Error>
    where
        Z: Evaluator<E, EM, I, Self>,
    {
        for entry in fs::read_dir(in_dir)? {
            let entry = entry?;
            let path = entry.path();
            let attributes = fs::metadata(&path);

            if attributes.is_err() {
                continue;
            }

            let attr = attributes?;

            if attr.is_file() && attr.len() > 0 {
                println!("Loading file {:?} ...", &path);
                let input = loader(fuzzer, self, &path)?;
                if forced {
                    let _ = fuzzer.add_input(self, executor, manager, input)?;
                } else {
                    let (res, _) = fuzzer.evaluate_input(self, executor, manager, input)?;
                    if res == ExecuteInputResult::None {
                        println!("File {:?} was not interesting, skipped.", &path);
                    }
                }
            } else if attr.is_dir() {
                self.load_from_directory(fuzzer, executor, manager, &path, forced, loader)?;
            }
        }

        Ok(())
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    /// If `forced` is true, will add all testcases, no matter what.
    fn load_initial_inputs_internal<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
        forced: bool,
    ) -> Result<(), Error>
    where
        Z: Evaluator<E, EM, I, Self>,
        EM: EventFirer<I>,
    {
        for in_dir in in_dirs {
            self.load_from_directory(
                fuzzer,
                executor,
                manager,
                in_dir,
                forced,
                &mut |_, _, path| I::from_file(&path),
            )?;
        }
        manager.fire(
            self,
            Event::Log {
                severity_level: LogSeverity::Debug,
                message: format!("Loaded {} initial testcases.", self.corpus().count()), // get corpus count
                phantom: PhantomData,
            },
        )?;
        Ok(())
    }

    /// Loads all intial inputs, even if they are not considered `interesting`.
    /// This is rarely the right method, use `load_initial_inputs`,
    /// and potentially fix your `Feedback`, instead.
    pub fn load_initial_inputs_forced<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
    ) -> Result<(), Error>
    where
        Z: Evaluator<E, EM, I, Self>,
        EM: EventFirer<I>,
    {
        self.load_initial_inputs_internal(fuzzer, executor, manager, in_dirs, true)
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    pub fn load_initial_inputs<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
    ) -> Result<(), Error>
    where
        Z: Evaluator<E, EM, I, Self>,
        EM: EventFirer<I>,
    {
        self.load_initial_inputs_internal(fuzzer, executor, manager, in_dirs, false)
    }
}

impl<C, FT, I, R, SC> StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    fn generate_initial_internal<G, E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        generator: &mut G,
        manager: &mut EM,
        num: usize,
        forced: bool,
    ) -> Result<(), Error>
    where
        G: Generator<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
        EM: EventFirer<I>,
    {
        let mut added = 0;
        for _ in 0..num {
            let input = generator.generate(self)?;
            if forced {
                let _ = fuzzer.add_input(self, executor, manager, input)?;
                added += 1;
            } else {
                let (res, _) = fuzzer.evaluate_input(self, executor, manager, input)?;
                if res != ExecuteInputResult::None {
                    added += 1;
                }
            }
        }
        manager.fire(
            self,
            Event::Log {
                severity_level: LogSeverity::Debug,
                message: format!("Loaded {} over {} initial testcases", added, num),
                phantom: PhantomData,
            },
        )?;
        Ok(())
    }

    /// Generate `num` initial inputs, using the passed-in generator and force the addition to corpus.
    pub fn generate_initial_inputs_forced<G, E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        generator: &mut G,
        manager: &mut EM,
        num: usize,
    ) -> Result<(), Error>
    where
        G: Generator<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
        EM: EventFirer<I>,
    {
        self.generate_initial_internal(fuzzer, executor, generator, manager, num, true)
    }

    /// Generate `num` initial inputs, using the passed-in generator.
    pub fn generate_initial_inputs<G, E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        generator: &mut G,
        manager: &mut EM,
        num: usize,
    ) -> Result<(), Error>
    where
        G: Generator<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
        EM: EventFirer<I>,
    {
        self.generate_initial_internal(fuzzer, executor, generator, manager, num, false)
    }

    /// Creates a new `State`, taking ownership of all of the individual components during fuzzing.
    pub fn new(rand: R, corpus: C, solutions: SC, feedback_states: FT) -> Self {
        Self {
            rand,
            executions: 0,
            stability: None,
            start_time: Duration::from_millis(0),
            metadata: SerdeAnyMap::default(),
            corpus,
            feedback_states,
            solutions,
            max_size: DEFAULT_MAX_SIZE,
            #[cfg(feature = "introspection")]
            introspection_monitor: ClientPerfMonitor::new(),
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "introspection")]
impl<C, FT, I, R, SC> HasClientPerfMonitor for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    fn introspection_monitor(&self) -> &ClientPerfMonitor {
        &self.introspection_monitor
    }

    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor {
        &mut self.introspection_monitor
    }

    /// This node's stability
    #[inline]
    fn stability(&self) -> &Option<f32> {
        &self.stability
    }

    /// This node's stability (mutable)
    #[inline]
    fn stability_mut(&mut self) -> &mut Option<f32> {
        &mut self.stability
    }
}

#[cfg(not(feature = "introspection"))]
impl<C, FT, I, R, SC> HasClientPerfMonitor for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    fn introspection_monitor(&self) -> &ClientPerfMonitor {
        unimplemented!()
    }

    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor {
        unimplemented!()
    }

    /// This node's stability
    #[inline]
    fn stability(&self) -> &Option<f32> {
        &self.stability
    }

    /// This node's stability (mutable)
    #[inline]
    fn stability_mut(&mut self) -> &mut Option<f32> {
        &mut self.stability
    }
}

#[cfg(feature = "python")]
/// `State` Python bindings
pub mod pybind {
    use crate::bolts::rands::pybind::PythonRand;
    use crate::bolts::tuples::tuple_list;
    use crate::corpus::pybind::PythonCorpus;
    use crate::feedbacks::map::MapFeedbackState;
    use crate::inputs::BytesInput;
    use crate::state::StdState;
    use pyo3::prelude::*;

    macro_rules! define_python_state {
        ($type_name:ident, $struct_name:ident, $py_name:tt, $datatype:ty, $py_map_feedback_state_name:ident, $event_manager_name: ident,
        $fuzzer_name: ident, $executor_name: ident, $rand_printable_generator: ident) => {
            use crate::events::pybind::$event_manager_name;
            use crate::executors::pybind::$executor_name;
            use crate::feedbacks::map::pybind::$py_map_feedback_state_name;
            use crate::fuzzer::pybind::$fuzzer_name;
            use crate::generators::pybind::$rand_printable_generator;

            /// `StdState` with fixed generics
            pub type $type_name = StdState<
                PythonCorpus,
                (MapFeedbackState<$datatype>, ()),
                BytesInput,
                PythonRand,
                PythonCorpus,
            >;

            #[pyclass(unsendable, name = $py_name)]
            #[derive(Debug)]
            /// Python class for StdState
            pub struct $struct_name {
                /// Rust wrapped StdState object
                pub std_state: $type_name,
            }

            #[pymethods]
            impl $struct_name {
                #[new]
                fn new(
                    py_rand: PythonRand,
                    corpus: PythonCorpus,
                    solutions: PythonCorpus,
                    py_map_feedback_state: $py_map_feedback_state_name,
                ) -> Self {
                    Self {
                        std_state: StdState::new(
                            py_rand,
                            corpus,
                            solutions,
                            tuple_list!(py_map_feedback_state.map_feedback_state),
                        ),
                    }
                }

                fn generate_initial_inputs(
                    &mut self,
                    py_fuzzer: &mut $fuzzer_name,
                    py_executor: &mut $executor_name,
                    py_generator: &mut $rand_printable_generator,
                    py_mgr: &mut $event_manager_name,
                    num: usize,
                ) {
                    self.std_state
                        .generate_initial_inputs(
                            &mut py_fuzzer.std_fuzzer,
                            py_executor,
                            &mut py_generator.rand_printable_generator,
                            py_mgr,
                            num,
                        )
                        .expect("Failed to generate the initial corpus".into());
                }
            }
        };
    }

    define_python_state!(
        MyStdStateI8,
        PythonStdStateI8,
        "StdStateI8",
        i8,
        PythonMapFeedbackStateI8,
        PythonEventManagerI8,
        PythonStdFuzzerI8,
        PythonExecutorI8,
        PythonRandPrintablesGeneratorI8
    );

    define_python_state!(
        MyStdStateI16,
        PythonStdStateI16,
        "StdStateI16",
        i16,
        PythonMapFeedbackStateI16,
        PythonEventManagerI16,
        PythonStdFuzzerI16,
        PythonExecutorI16,
        PythonRandPrintablesGeneratorI16
    );

    define_python_state!(
        MyStdStateI32,
        PythonStdStateI32,
        "StdStateI32",
        i32,
        PythonMapFeedbackStateI32,
        PythonEventManagerI32,
        PythonStdFuzzerI32,
        PythonExecutorI32,
        PythonRandPrintablesGeneratorI32
    );

    define_python_state!(
        MyStdStateI64,
        PythonStdStateI64,
        "StdStateI64",
        i64,
        PythonMapFeedbackStateI64,
        PythonEventManagerI64,
        PythonStdFuzzerI64,
        PythonExecutorI64,
        PythonRandPrintablesGeneratorI64
    );
    define_python_state!(
        MyStdStateU8,
        PythonStdStateU8,
        "StdStateU8",
        u8,
        PythonMapFeedbackStateU8,
        PythonEventManagerU8,
        PythonStdFuzzerU8,
        PythonExecutorU8,
        PythonRandPrintablesGeneratorU8
    );
    define_python_state!(
        MyStdStateU16,
        PythonStdStateU16,
        "StdStateU16",
        u16,
        PythonMapFeedbackStateU16,
        PythonEventManagerU16,
        PythonStdFuzzerU16,
        PythonExecutorU16,
        PythonRandPrintablesGeneratorU16
    );
    define_python_state!(
        MyStdStateU32,
        PythonStdStateU32,
        "StdStateU32",
        u32,
        PythonMapFeedbackStateU32,
        PythonEventManagerU32,
        PythonStdFuzzerU32,
        PythonExecutorU32,
        PythonRandPrintablesGeneratorU32
    );
    define_python_state!(
        MyStdStateU64,
        PythonStdStateU64,
        "StdStateU64",
        u64,
        PythonMapFeedbackStateU64,
        PythonEventManagerU64,
        PythonStdFuzzerU64,
        PythonExecutorU64,
        PythonRandPrintablesGeneratorU64
    );

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonStdStateI8>()?;
        m.add_class::<PythonStdStateI16>()?;
        m.add_class::<PythonStdStateI32>()?;
        m.add_class::<PythonStdStateI64>()?;

        m.add_class::<PythonStdStateU8>()?;
        m.add_class::<PythonStdStateU16>()?;
        m.add_class::<PythonStdStateU32>()?;
        m.add_class::<PythonStdStateU64>()?;
        Ok(())
    }
}
