//! The fuzzer, and state are the core pieces of every good fuzzer

use core::{fmt::Debug, marker::PhantomData};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    bolts::serdeany::{SerdeAny, SerdeAnyMap},
    corpus::{Corpus, Testcase},
    events::{Event, EventManager, LogSeverity},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::FeedbacksTuple,
    generators::Generator,
    inputs::Input,
    observers::ObserversTuple,
    utils::{current_milliseconds, Rand},
    AflError,
};

#[cfg(feature = "std")]
use crate::inputs::bytes::BytesInput;

/// Trait for elements offering a corpus
pub trait HasCorpus<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// The testcase corpus
    fn corpus(&self) -> &C;
    /// The testcase corpus (mut)
    fn corpus_mut(&mut self) -> &mut C;
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
}

/// The state a fuzz run.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "FT: serde::de::DeserializeOwned")]
pub struct State<C, FT, I, OC, OFT, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    OC: Corpus<I, R>,
    OFT: FeedbacksTuple<I>,
{
    /// How many times the executor ran the harness/target
    executions: usize,
    /// The corpus
    corpus: C,
    // TODO use Duration
    /// At what time the fuzzing started
    start_time: u64,
    /// Metadata stored for this state by one of the components
    metadata: SerdeAnyMap,
    /// Feedbacks used to evaluate an input
    feedbacks: FT,
    // Objective corpus
    objective_corpus: OC,
    /// Objective Feedbacks
    objective_feedbacks: OFT,

    phantom: PhantomData<(R, I)>,
}

#[cfg(feature = "std")]
impl<C, FT, OC, OFT, R> State<C, FT, BytesInput, OC, OFT, R>
where
    C: Corpus<BytesInput, R>,
    R: Rand,
    FT: FeedbacksTuple<BytesInput>,
    OC: Corpus<BytesInput, R>,
    OFT: FeedbacksTuple<BytesInput>,
{
    pub fn load_from_directory<E, OT, EM>(
        &mut self,
        executor: &mut E,
        manager: &mut EM,
        in_dir: &Path,
    ) -> Result<(), AflError>
    where
        C: Corpus<BytesInput, R>,
        E: Executor<BytesInput> + HasObservers<OT>,
        OT: ObserversTuple,
        EM: EventManager<BytesInput>,
    {
        for entry in fs::read_dir(in_dir)? {
            let entry = entry?;
            let path = entry.path();
            let attributes = fs::metadata(&path);

            if !attributes.is_ok() {
                continue;
            }

            let attr = attributes?;

            if attr.is_file() && attr.len() > 0 {
                println!("Loading file {:?} ...", &path);
                let bytes = fs::read(&path)?;
                let input = BytesInput::new(bytes);
                let (fitness, obj_fitness) = self.evaluate_input(&input, executor, manager)?;
                if self.add_if_interesting(input, fitness)?.is_none() {
                    println!("File {:?} was not interesting, skipped.", &path);
                }
                if obj_fitness > 0 {
                    println!("File {:?} is an objective, however will be not added as an initial testcase.", &path);
                }
            } else if attr.is_dir() {
                self.load_from_directory(executor, manager, &path)?;
            }
        }

        Ok(())
    }

    pub fn load_initial_inputs<E, OT, EM>(
        &mut self,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
    ) -> Result<(), AflError>
    where
        C: Corpus<BytesInput, R>,
        E: Executor<BytesInput> + HasObservers<OT>,
        OT: ObserversTuple,
        EM: EventManager<BytesInput>,
    {
        for in_dir in in_dirs {
            self.load_from_directory(executor, manager, in_dir)?;
        }
        manager.fire(
            self,
            Event::Log {
                severity_level: LogSeverity::Debug,
                message: format!("Loaded {} initial testcases.", self.corpus().count()), // get corpus count
                phantom: PhantomData,
            },
        )?;
        manager.process(self)?;
        Ok(())
    }
}

impl<C, FT, I, OC, OFT, R> HasCorpus<C, I, R> for State<C, FT, I, OC, OFT, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    OC: Corpus<I, R>,
    OFT: FeedbacksTuple<I>,
{
    /// Returns the corpus
    fn corpus(&self) -> &C {
        &self.corpus
    }

    /// Returns the mutable corpus
    fn corpus_mut(&mut self) -> &mut C {
        &mut self.corpus
    }
}

/// Trait for elements offering metadata
impl<C, FT, I, OC, OFT, R> HasMetadata for State<C, FT, I, OC, OFT, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    OC: Corpus<I, R>,
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

impl<C, FT, I, OC, OFT, R> State<C, FT, I, OC, OFT, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
    OC: Corpus<I, R>,
    OFT: FeedbacksTuple<I>,
{
    /// Get executions
    #[inline]
    pub fn executions(&self) -> usize {
        self.executions
    }

    /// Set executions
    #[inline]
    pub fn set_executions(&mut self, executions: usize) {
        self.executions = executions
    }

    #[inline]
    pub fn start_time(&self) -> u64 {
        self.start_time
    }
    #[inline]
    pub fn set_start_time(&mut self, ms: u64) {
        self.start_time = ms
    }

    /// Returns vector of feebacks
    #[inline]
    pub fn feedbacks(&self) -> &FT {
        &self.feedbacks
    }

    /// Returns vector of feebacks (mutable)
    #[inline]
    pub fn feedbacks_mut(&mut self) -> &mut FT {
        &mut self.feedbacks
    }

    /// Returns vector of objective feebacks
    #[inline]
    pub fn objective_feedbacks(&self) -> &OFT {
        &self.objective_feedbacks
    }

    /// Returns vector of objective feebacks (mutable)
    #[inline]
    pub fn objective_feedbacks_mut(&mut self) -> &mut OFT {
        &mut self.objective_feedbacks
    }

    // TODO move some of these, like evaluate_input, to FuzzingEngine
    #[inline]
    pub fn is_interesting<OT>(
        &mut self,
        input: &I,
        observers: &OT,
        exit_kind: ExitKind,
    ) -> Result<u32, AflError>
    where
        OT: ObserversTuple,
    {
        Ok(self
            .feedbacks_mut()
            .is_interesting_all(input, observers, exit_kind)?)
    }

    /// Runs the input and triggers observers and feedback
    pub fn evaluate_input<E, EM, OT>(
        &mut self,
        input: &I,
        executor: &mut E,
        event_mgr: &mut EM,
    ) -> Result<(u32, u32), AflError>
    where
        E: Executor<I> + HasObservers<OT>,
        OT: ObserversTuple,
        C: Corpus<I, R>,
        EM: EventManager<I>,
    {
        executor.pre_exec_observers()?;

        executor.pre_exec(self, event_mgr, input)?;
        let exit_kind = executor.run_target(input)?;
        executor.post_exec(&self, event_mgr, input)?;

        self.set_executions(self.executions() + 1);
        executor.post_exec_observers()?;

        let observers = executor.observers();
        let objective_fitness =
            self.objective_feedbacks
                .is_interesting_all(&input, observers, exit_kind.clone())?;
        let fitness = self
            .feedbacks_mut()
            .is_interesting_all(&input, observers, exit_kind)?;
        Ok((fitness, objective_fitness))
    }

    /// Resets all current feedbacks
    #[inline]
    pub fn discard_input(&mut self, input: &I) -> Result<(), AflError> {
        // TODO: This could probably be automatic in the feedback somehow?
        self.feedbacks_mut().discard_metadata_all(&input)
    }

    /// Creates a new testcase, appending the metadata from each feedback
    #[inline]
    pub fn input_to_testcase(&mut self, input: I, fitness: u32) -> Result<Testcase<I>, AflError> {
        let mut testcase = Testcase::new(input);
        testcase.set_fitness(fitness);
        self.feedbacks_mut().append_metadata_all(&mut testcase)?;
        Ok(testcase)
    }

    /// Create a testcase from this input, if it's intersting
    #[inline]
    pub fn testcase_if_interesting(
        &mut self,
        input: I,
        fitness: u32,
    ) -> Result<Option<Testcase<I>>, AflError> {
        if fitness > 0 {
            Ok(Some(self.input_to_testcase(input, fitness)?))
        } else {
            self.discard_input(&input)?;
            Ok(None)
        }
    }

    /// Adds this input to the corpus, if it's intersting
    #[inline]
    pub fn add_if_interesting(&mut self, input: I, fitness: u32) -> Result<Option<usize>, AflError>
    where
        C: Corpus<I, R>,
    {
        if fitness > 0 {
            let testcase = self.input_to_testcase(input, fitness)?;
            Ok(Some(self.corpus_mut().add(testcase)))
        } else {
            self.discard_input(&input)?;
            Ok(None)
        }
    }

    /// Adds this input to the objective corpus, if it's an objective
    #[inline]
    pub fn add_if_objective(&mut self, input: I, fitness: u32) -> Result<Option<usize>, AflError>
    where
        C: Corpus<I, R>,
    {
        if fitness > 0 {
            let testcase = self.input_to_testcase(input, fitness)?;
            Ok(Some(self.objective_corpus.add(testcase)))
        } else {
            self.discard_input(&input)?;
            Ok(None)
        }
    }

    /// Process one input, adding to the respective corpuses if needed and firing the right events
    #[inline]
    pub fn process_input<E, EM, OT>(
        &mut self,
        // TODO probably we can take a ref to input and pass a cloned one to add_if_interesting
        input: I,
        executor: &mut E,
        manager: &mut EM,
    ) -> Result<u32, AflError>
    where
        E: Executor<I> + HasObservers<OT>,
        OT: ObserversTuple,
        C: Corpus<I, R>,
        EM: EventManager<I>,
    {
        let (fitness, obj_fitness) = self.evaluate_input(&input, executor, manager)?;
        let observers = executor.observers();

        if obj_fitness > 0 {
            self.add_if_objective(input.clone(), obj_fitness)?;
        }

        if fitness > 0 {
            let observers_buf = manager.serialize_observers(observers)?;
            manager.fire(
                self,
                Event::NewTestcase {
                    input: input.clone(),
                    observers_buf,
                    corpus_size: self.corpus().count() + 1,
                    client_config: "TODO".into(),
                    time: crate::utils::current_time(),
                    executions: self.executions(),
                },
            )?;
            self.add_if_interesting(input, fitness)?;
        } else {
            self.discard_input(&input)?;
        }

        Ok(fitness)
    }

    pub fn generate_initial_inputs<G, E, OT, EM>(
        &mut self,
        rand: &mut R,
        executor: &mut E,
        generator: &mut G,
        manager: &mut EM,
        num: usize,
    ) -> Result<(), AflError>
    where
        G: Generator<I, R>,
        C: Corpus<I, R>,
        E: Executor<I> + HasObservers<OT>,
        OT: ObserversTuple,
        EM: EventManager<I>,
    {
        let mut added = 0;
        for _ in 0..num {
            let input = generator.generate(rand)?;
            let fitness = self.process_input(input, executor, manager)?;
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
        manager.process(self)?;
        Ok(())
    }

    pub fn new(corpus: C, feedbacks: FT, objective_corpus: OC, objective_feedbacks: OFT) -> Self {
        Self {
            corpus,
            executions: 0,
            start_time: current_milliseconds(),
            metadata: SerdeAnyMap::default(),
            feedbacks: feedbacks,
            objective_corpus: objective_corpus,
            objective_feedbacks: objective_feedbacks,
            phantom: PhantomData,
        }
    }
}
