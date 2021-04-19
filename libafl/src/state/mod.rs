//! The fuzzer, and state are the core pieces of every good fuzzer

use core::{fmt::Debug, marker::PhantomData, time::Duration};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    bolts::serdeany::{SerdeAny, SerdeAnyMap},
    corpus::{Corpus, CorpusScheduler, Testcase},
    events::{Event, EventManager, LogSeverity},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::FeedbacksTuple,
    generators::Generator,
    inputs::Input,
    observers::ObserversTuple,
    utils::Rand,
    Error,
};

#[cfg(feature = "std")]
use crate::inputs::bytes::BytesInput;

/// The maximum size of a testcase
pub const DEFAULT_MAX_SIZE: usize = 1_048_576;

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

/// Trait for elements offering a feedbacks tuple
pub trait HasFeedbacks<FT, I>
where
    FT: FeedbacksTuple<I>,
    I: Input,
{
    /// The feedbacks tuple
    fn feedbacks(&self) -> &FT;

    /// The feedbacks tuple (mut)
    fn feedbacks_mut(&mut self) -> &mut FT;

    /// Resets all metadata holds by feedbacks
    #[inline]
    fn discard_feedbacks_metadata(&mut self, input: &I) -> Result<(), Error> {
        // TODO: This could probably be automatic in the feedback somehow?
        self.feedbacks_mut().discard_metadata_all(&input)
    }

    /// Creates a new testcase, appending the metadata from each feedback
    #[inline]
    fn testcase_with_feedbacks_metadata(
        &mut self,
        input: I,
        fitness: u32,
    ) -> Result<Testcase<I>, Error> {
        let mut testcase = Testcase::with_fitness(input, fitness);
        self.feedbacks_mut().append_metadata_all(&mut testcase)?;
        Ok(testcase)
    }
}

/// Trait for elements offering an objective feedbacks tuple
pub trait HasObjectives<FT, I>
where
    FT: FeedbacksTuple<I>,
    I: Input,
{
    /// The objective feedbacks tuple
    fn objectives(&self) -> &FT;

    /// The objective feedbacks tuple (mut)
    fn objectives_mut(&mut self) -> &mut FT;
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

/// Add to the state if interesting
pub trait IfInteresting<I>
where
    I: Input,
{
    /// Evaluate if a set of observation channels has an interesting state
    fn is_interesting<OT>(
        &mut self,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<u32, Error>
    where
        OT: ObserversTuple;

    /// Adds this input to the corpus, if it's intersting, and return the index
    fn add_if_interesting<CS>(
        &mut self,
        input: &I,
        fitness: u32,
        scheduler: &CS,
    ) -> Result<Option<usize>, Error>
    where
        CS: CorpusScheduler<I, Self>,
        Self: Sized;
}

/// Evaluate an input modyfing the state of the fuzzer and returning a fitness
pub trait Evaluator<I>: Sized
where
    I: Input,
{
    /// Runs the input and triggers observers and feedback
    fn evaluate_input<CS, E, EM, OT>(
        &mut self,
        input: I,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
    ) -> Result<(u32, Option<usize>), Error>
    where
        E: Executor<I> + HasObservers<OT>,
        OT: ObserversTuple,
        EM: EventManager<I, Self>,
        CS: CorpusScheduler<I, Self>;
}

/// The state a fuzz run.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "FT: serde::de::DeserializeOwned")]
pub struct State<C, FT, I, OFT, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    SC: Corpus<I>,
    OFT: FeedbacksTuple<I>,
{
    /// RNG instance
    rand: R,
    /// How many times the executor ran the harness/target
    executions: usize,
    /// At what time the fuzzing started
    start_time: Duration,
    /// The corpus
    corpus: C,
    /// Feedbacks used to evaluate an input
    feedbacks: FT,
    // Solutions corpus
    solutions: SC,
    /// Objective Feedbacks
    objectives: OFT,
    /// Metadata stored for this state by one of the components
    metadata: SerdeAnyMap,
    /// MaxSize testcase size for mutators that appreciate it
    max_size: usize,

    phantom: PhantomData<I>,
}

impl<C, FT, I, OFT, R, SC> HasRand<R> for State<C, FT, I, OFT, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    SC: Corpus<I>,
    OFT: FeedbacksTuple<I>,
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

impl<C, FT, I, OFT, R, SC> HasCorpus<C, I> for State<C, FT, I, OFT, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    SC: Corpus<I>,
    OFT: FeedbacksTuple<I>,
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

impl<C, FT, I, OFT, R, SC> HasSolutions<SC, I> for State<C, FT, I, OFT, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    SC: Corpus<I>,
    OFT: FeedbacksTuple<I>,
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

impl<C, FT, I, OFT, R, SC> HasMetadata for State<C, FT, I, OFT, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    SC: Corpus<I>,
    OFT: FeedbacksTuple<I>,
{
    /// Get all the metadata into an HashMap
    #[inline]
    fn metadata(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    /// Get all the metadata into an HashMap (mutable)
    #[inline]
    fn metadata_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<C, FT, I, OFT, R, SC> HasFeedbacks<FT, I> for State<C, FT, I, OFT, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    SC: Corpus<I>,
    OFT: FeedbacksTuple<I>,
{
    /// The feedbacks tuple
    #[inline]
    fn feedbacks(&self) -> &FT {
        &self.feedbacks
    }

    /// The feedbacks tuple (mut)
    #[inline]
    fn feedbacks_mut(&mut self) -> &mut FT {
        &mut self.feedbacks
    }
}

impl<C, FT, I, OFT, R, SC> HasObjectives<OFT, I> for State<C, FT, I, OFT, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    SC: Corpus<I>,
    OFT: FeedbacksTuple<I>,
{
    /// The objective feedbacks tuple
    #[inline]
    fn objectives(&self) -> &OFT {
        &self.objectives
    }

    /// The objective feedbacks tuple (mut)
    #[inline]
    fn objectives_mut(&mut self) -> &mut OFT {
        &mut self.objectives
    }
}

impl<C, FT, I, OFT, R, SC> HasExecutions for State<C, FT, I, OFT, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    SC: Corpus<I>,
    OFT: FeedbacksTuple<I>,
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

impl<C, FT, I, OFT, R, SC> HasMaxSize for State<C, FT, I, OFT, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    SC: Corpus<I>,
    OFT: FeedbacksTuple<I>,
{
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size
    }
}

impl<C, FT, I, OFT, R, SC> HasStartTime for State<C, FT, I, OFT, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    SC: Corpus<I>,
    OFT: FeedbacksTuple<I>,
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

impl<C, FT, I, OFT, R, SC> IfInteresting<I> for State<C, FT, I, OFT, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    SC: Corpus<I>,
    OFT: FeedbacksTuple<I>,
{
    /// Evaluate if a set of observation channels has an interesting state
    fn is_interesting<OT>(
        &mut self,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<u32, Error>
    where
        OT: ObserversTuple,
    {
        self.feedbacks_mut()
            .is_interesting_all(input, observers, exit_kind)
    }

    /// Adds this input to the corpus, if it's intersting, and return the index
    #[inline]
    fn add_if_interesting<CS>(
        &mut self,
        input: &I,
        fitness: u32,
        scheduler: &CS,
    ) -> Result<Option<usize>, Error>
    where
        CS: CorpusScheduler<I, Self>,
    {
        if fitness > 0 {
            let testcase = self.testcase_with_feedbacks_metadata(input.clone(), fitness)?;
            let idx = self.corpus.add(testcase)?;
            scheduler.on_add(self, idx)?;
            Ok(Some(idx))
        } else {
            self.discard_feedbacks_metadata(input)?;
            Ok(None)
        }
    }
}

impl<C, FT, I, OFT, R, SC> Evaluator<I> for State<C, FT, I, OFT, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    SC: Corpus<I>,
    OFT: FeedbacksTuple<I>,
{
    /// Process one input, adding to the respective corpuses if needed and firing the right events
    #[inline]
    fn evaluate_input<CS, E, EM, OT>(
        &mut self,
        // TODO probably we can take a ref to input and pass a cloned one to add_if_interesting
        input: I,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
    ) -> Result<(u32, Option<usize>), Error>
    where
        E: Executor<I> + HasObservers<OT>,
        OT: ObserversTuple,
        C: Corpus<I>,
        EM: EventManager<I, Self>,
        CS: CorpusScheduler<I, Self>,
    {
        let (fitness, is_solution) = self.execute_input(&input, executor, manager)?;
        let observers = executor.observers();

        if is_solution {
            // If the input is a solution, add it to the respective corpus
            let mut testcase = Testcase::new(input.clone());
            self.objectives_mut().append_metadata_all(&mut testcase)?;
            self.solutions_mut().add(testcase)?;
        } else {
            self.objectives_mut().discard_metadata_all(&input)?;
        }

        let corpus_idx = self.add_if_interesting(&input, fitness, scheduler)?;
        if corpus_idx.is_some() {
            let observers_buf = manager.serialize_observers(observers)?;
            manager.fire(
                self,
                Event::NewTestcase {
                    input,
                    observers_buf,
                    corpus_size: self.corpus().count() + 1,
                    client_config: "TODO".into(),
                    time: crate::utils::current_time(),
                    executions: *self.executions(),
                },
            )?;
        }

        Ok((fitness, corpus_idx))
    }
}

#[cfg(feature = "std")]
impl<C, FT, OFT, R, SC> State<C, FT, BytesInput, OFT, R, SC>
where
    C: Corpus<BytesInput>,
    R: Rand,
    FT: FeedbacksTuple<BytesInput>,
    SC: Corpus<BytesInput>,
    OFT: FeedbacksTuple<BytesInput>,
{
    pub fn load_from_directory<CS, E, OT, EM>(
        &mut self,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
        in_dir: &Path,
    ) -> Result<(), Error>
    where
        E: Executor<BytesInput> + HasObservers<OT>,
        OT: ObserversTuple,
        EM: EventManager<BytesInput, Self>,
        CS: CorpusScheduler<BytesInput, Self>,
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
                let bytes = fs::read(&path)?;
                let input = BytesInput::new(bytes);
                let (fitness, is_solution) = self.execute_input(&input, executor, manager)?;
                if self
                    .add_if_interesting(&input, fitness, scheduler)?
                    .is_none()
                {
                    println!("File {:?} was not interesting, skipped.", &path);
                }
                if is_solution {
                    println!("File {:?} is a solution, however will be not considered as it is an initial testcase.", &path);
                }
            } else if attr.is_dir() {
                self.load_from_directory(executor, manager, scheduler, &path)?;
            }
        }

        Ok(())
    }

    pub fn load_initial_inputs<CS, E, OT, EM>(
        &mut self,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
        in_dirs: &[PathBuf],
    ) -> Result<(), Error>
    where
        E: Executor<BytesInput> + HasObservers<OT>,
        OT: ObserversTuple,
        EM: EventManager<BytesInput, Self>,
        CS: CorpusScheduler<BytesInput, Self>,
    {
        for in_dir in in_dirs {
            self.load_from_directory(executor, manager, scheduler, in_dir)?;
        }
        manager.fire(
            self,
            Event::Log {
                severity_level: LogSeverity::Debug,
                message: format!("Loaded {} initial testcases.", self.corpus().count()), // get corpus count
                phantom: PhantomData,
            },
        )?;
        manager.process(self, executor, scheduler)?;
        Ok(())
    }
}

impl<C, FT, I, OFT, R, SC> State<C, FT, I, OFT, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    SC: Corpus<I>,
    OFT: FeedbacksTuple<I>,
{
    /// Runs the input and triggers observers and feedback
    pub fn execute_input<E, EM, OT>(
        &mut self,
        input: &I,
        executor: &mut E,
        event_mgr: &mut EM,
    ) -> Result<(u32, bool), Error>
    where
        E: Executor<I> + HasObservers<OT>,
        OT: ObserversTuple,
        C: Corpus<I>,
        EM: EventManager<I, Self>,
    {
        executor.pre_exec_observers()?;

        executor.pre_exec(self, event_mgr, input)?;
        let exit_kind = executor.run_target(input)?;
        executor.post_exec(self, event_mgr, input)?;

        *self.executions_mut() += 1;
        executor.post_exec_observers()?;

        let observers = executor.observers();
        let fitness =
            self.feedbacks_mut()
                .is_interesting_all(&input, observers, &exit_kind)?;

        let is_solution = self
            .objectives_mut()
            .is_interesting_all(&input, observers, &exit_kind)?
            > 0;
        Ok((fitness, is_solution))
    }

    pub fn generate_initial_inputs<CS, G, E, OT, EM>(
        &mut self,
        executor: &mut E,
        generator: &mut G,
        manager: &mut EM,
        scheduler: &CS,
        num: usize,
    ) -> Result<(), Error>
    where
        G: Generator<I, R>,
        C: Corpus<I>,
        E: Executor<I> + HasObservers<OT>,
        OT: ObserversTuple,
        EM: EventManager<I, Self>,
        CS: CorpusScheduler<I, Self>,
    {
        let mut added = 0;
        for _ in 0..num {
            let input = generator.generate(self.rand_mut())?;
            let (fitness, _) = self.evaluate_input(input, executor, manager, scheduler)?;
            if fitness > 0 {
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
        manager.process(self, executor, scheduler)?;
        Ok(())
    }

    pub fn new(rand: R, corpus: C, feedbacks: FT, solutions: SC, objectives: OFT) -> Self {
        Self {
            rand,
            executions: 0,
            start_time: Duration::from_millis(0),
            metadata: SerdeAnyMap::default(),
            corpus,
            feedbacks,
            solutions,
            objectives,
            max_size: DEFAULT_MAX_SIZE,
            phantom: PhantomData,
        }
    }
}
