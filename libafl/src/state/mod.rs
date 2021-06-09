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
    events::{Event, EventManager, LogSeverity},
    feedbacks::FeedbackStatesTuple,
    fuzzer::Evaluator,
    generators::Generator,
    inputs::Input,
    stats::ClientPerfStats,
    Error,
};

/// The maximum size of a testcase
pub const DEFAULT_MAX_SIZE: usize = 1_048_576;

pub trait State: Serialize + DeserializeOwned {}

/// Trait for elements offering a corpus
pub trait HasCorpus<C, I>
where
    C: Corpus<I>,
    I: Input,
{
    /// The testcase corpus
    fn corpus(&self) -> &C;
    /// The testcase corpus (mut)
    fn corpus_mut(&mut self) -> &mut C;
}

/// Interact with the maximum size
pub trait HasMaxSize {
    /// The maximum size hint for items and mutations returned
    fn max_size(&self) -> usize;
    /// Sets the maximum size hint for the items and mutations
    fn set_max_size(&mut self, max_size: usize);
}

/// Trait for elements offering a corpus of solutions
pub trait HasSolutions<C, I>
where
    C: Corpus<I>,
    I: Input,
{
    /// The solutions corpus
    fn solutions(&self) -> &C;
    /// The solutions corpus (mut)
    fn solutions_mut(&mut self) -> &mut C;
}

/// Trait for elements offering a rand
pub trait HasRand<R>
where
    R: Rand,
{
    /// The rand instance
    fn rand(&self) -> &R;
    /// The rand instance (mut)
    fn rand_mut(&mut self) -> &mut R;
}

/// Trait for offering a [`ClientPerfStats`]
pub trait HasClientPerfStats {
    /// [`ClientPerfStats`] itself
    fn introspection_stats(&self) -> &ClientPerfStats;

    /// Mutatable ref to [`ClientPerfStats`]
    fn introspection_stats_mut(&mut self) -> &mut ClientPerfStats;
}

/// Trait for elements offering metadata
pub trait HasMetadata {
    /// A map, storing all metadata
    fn metadata(&self) -> &SerdeAnyMap;
    /// A map, storing all metadata (mut)
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
pub trait HasFeedbackStates<FT>
where
    FT: FeedbackStatesTuple,
{
    /// The feedback states
    fn feedback_states(&self) -> &FT;

    /// The feedback states (mut)
    fn feedback_states_mut(&mut self) -> &mut FT;
}

/// Trait for the execution counter
pub trait HasExecutions {
    /// The executions counter
    fn executions(&self) -> &usize;

    /// The executions counter (mut)
    fn executions_mut(&mut self) -> &mut usize;
}

/// Trait for the starting time
pub trait HasStartTime {
    /// The starting time
    fn start_time(&self) -> &Duration;

    /// The starting time (mut)
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

    /// Performance statistics for this fuzzer
    #[cfg(feature = "introspection")]
    introspection_stats: ClientPerfStats,

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

impl<C, FT, I, R, SC> HasRand<R> for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    /// The rand instance
    #[inline]
    fn rand(&self) -> &R {
        &self.rand
    }

    /// The rand instance (mut)
    #[inline]
    fn rand_mut(&mut self) -> &mut R {
        &mut self.rand
    }
}

impl<C, FT, I, R, SC> HasCorpus<C, I> for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
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

impl<C, FT, I, R, SC> HasSolutions<SC, I> for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    /// Returns the solutions corpus
    #[inline]
    fn solutions(&self) -> &SC {
        &self.solutions
    }

    /// Returns the solutions corpus (mut)
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

impl<C, FT, I, R, SC> HasFeedbackStates<FT> for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    /// The feedback states
    #[inline]
    fn feedback_states(&self) -> &FT {
        &self.feedback_states
    }

    /// The feedback states (mut)
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

    /// The executions counter (mut)
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

    /// The starting time (mut)
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
    /// loads inputs from a directory
    /// If `forced` is `true`, the value will be loaded,
    /// even if it's not considered to be `interesting`.
    fn load_from_directory<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dir: &Path,
        forced: bool,
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
                let input = I::from_file(&path)?;
                if forced {
                    let _ = fuzzer.add_input(self, executor, manager, input)?;
                } else {
                    let (is_interesting, _) =
                        fuzzer.evaluate_input(self, executor, manager, input)?;
                    if !is_interesting {
                        println!("File {:?} was not interesting, skipped.", &path);
                    }
                }
            } else if attr.is_dir() {
                self.load_from_directory(fuzzer, executor, manager, &path, forced)?;
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
        EM: EventManager<E, I, Self, Z>,
    {
        for in_dir in in_dirs {
            self.load_from_directory(fuzzer, executor, manager, in_dir, forced)?;
        }
        manager.fire(
            self,
            Event::Log {
                severity_level: LogSeverity::Debug,
                message: format!("Loaded {} initial testcases.", self.corpus().count()), // get corpus count
                phantom: PhantomData,
            },
        )?;
        manager.process(fuzzer, self, executor)?;
        Ok(())
    }

    /// Loads all intial inputs, even if they are not consiered `intesting`.
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
        EM: EventManager<E, I, Self, Z>,
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
        EM: EventManager<E, I, Self, Z>,
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
        G: Generator<I, R>,
        Z: Evaluator<E, EM, I, Self>,
        EM: EventManager<E, I, Self, Z>,
    {
        let mut added = 0;
        for _ in 0..num {
            let input = generator.generate(self.rand_mut())?;
            let (is_interesting, _) = fuzzer.evaluate_input(self, executor, manager, input)?;
            if is_interesting {
                added += 1;
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
        manager.process(fuzzer, self, executor)?;
        Ok(())
    }

    /// Creates a new `State`, taking ownership of all of the individual components during fuzzing.
    pub fn new(rand: R, corpus: C, solutions: SC, feedback_states: FT) -> Self {
        Self {
            rand,
            executions: 0,
            start_time: Duration::from_millis(0),
            metadata: SerdeAnyMap::default(),
            corpus,
            feedback_states,
            solutions,
            max_size: DEFAULT_MAX_SIZE,
            #[cfg(feature = "introspection")]
            introspection_stats: ClientPerfStats::new(),
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "introspection")]
impl<C, FT, I, R, SC> HasClientPerfStats for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    fn introspection_stats(&self) -> &ClientPerfStats {
        &self.introspection_stats
    }

    fn introspection_stats_mut(&mut self) -> &mut ClientPerfStats {
        &mut self.introspection_stats
    }
}

#[cfg(not(feature = "introspection"))]
impl<C, FT, I, R, SC> HasClientPerfStats for StdState<C, FT, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbackStatesTuple,
    SC: Corpus<I>,
{
    fn introspection_stats(&self) -> &ClientPerfStats {
        unimplemented!()
    }

    fn introspection_stats_mut(&mut self) -> &mut ClientPerfStats {
        unimplemented!()
    }
}
