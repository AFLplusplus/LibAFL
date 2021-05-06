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
    executors::{
        Executor, ExitKind, HasExecHooks, HasExecHooksTuple, HasObservers, HasObserversHooks,
    },
    feedbacks::Feedback,
    generators::Generator,
    inputs::Input,
    mark_feature_time,
    observers::ObserversTuple,
    start_timer,
    stats::ClientPerfStats,
    utils::Rand,
    Error,
};

#[cfg(feature = "introspection")]
use crate::stats::PerfFeature;

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
pub trait HasFeedback<F, I>: Sized
where
    F: Feedback<I>,
    I: Input,
{
    /// The feedback
    fn feedback(&self) -> &F;

    /// The feedback (mut)
    fn feedback_mut(&mut self) -> &mut F;
}

/// Trait for elements offering an objective feedback tuple
pub trait HasObjective<OF, I>: Sized
where
    OF: Feedback<I>,
    I: Input,
{
    /// The objective feedback
    fn objective(&self) -> &OF;

    /// The objective feedback (mut)
    fn objective_mut(&mut self) -> &mut OF;
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
pub trait IfInteresting<I>: Sized
where
    I: Input,
{
    /// Evaluate if a set of observation channels has an interesting state
    fn is_interesting<OT>(
        &mut self,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple;

    /// Adds this input to the corpus, if it's intersting, and return the index
    fn add_if_interesting<CS>(
        &mut self,
        input: &I,
        is_interesting: bool,
        scheduler: &CS,
    ) -> Result<Option<usize>, Error>
    where
        CS: CorpusScheduler<I, Self>,
        Self: Sized;
}

/// Evaluate an input modyfing the state of the fuzzer
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
    ) -> Result<(bool, Option<usize>), Error>
    where
        E: Executor<I>
            + HasObservers<OT>
            + HasExecHooks<EM, I, Self>
            + HasObserversHooks<EM, I, OT, Self>,
        OT: ObserversTuple + HasExecHooksTuple<EM, I, Self>,
        EM: EventManager<I, Self>,
        CS: CorpusScheduler<I, Self>;
}

/// The state a fuzz run.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "F: serde::de::DeserializeOwned")]
pub struct State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
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
    feedback: F,
    // Solutions corpus
    solutions: SC,
    /// Objective Feedbacks
    objective: OF,
    /// Metadata stored for this state by one of the components
    metadata: SerdeAnyMap,
    /// MaxSize testcase size for mutators that appreciate it
    max_size: usize,

    /// Performance statistics for this fuzzer
    #[cfg(feature = "introspection")]
    introspection_stats: ClientPerfStats,

    phantom: PhantomData<I>,
}

impl<C, F, I, OF, R, SC> HasRand<R> for State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
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

impl<C, F, I, OF, R, SC> HasCorpus<C, I> for State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
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

impl<C, F, I, OF, R, SC> HasSolutions<SC, I> for State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
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

impl<C, F, I, OF, R, SC> HasMetadata for State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
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

impl<C, F, I, OF, R, SC> HasFeedback<F, I> for State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
{
    /// The feedback
    #[inline]
    fn feedback(&self) -> &F {
        &self.feedback
    }

    /// The feedback (mut)
    #[inline]
    fn feedback_mut(&mut self) -> &mut F {
        &mut self.feedback
    }
}

impl<C, F, I, OF, R, SC> HasObjective<OF, I> for State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
{
    /// The objective feedback
    #[inline]
    fn objective(&self) -> &OF {
        &self.objective
    }

    /// The objective feedback (mut)
    #[inline]
    fn objective_mut(&mut self) -> &mut OF {
        &mut self.objective
    }
}

impl<C, F, I, OF, R, SC> HasExecutions for State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
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

impl<C, F, I, OF, R, SC> HasMaxSize for State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
{
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size
    }
}

impl<C, F, I, OF, R, SC> HasStartTime for State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
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

impl<C, F, I, OF, R, SC> IfInteresting<I> for State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
{
    /// Evaluate if a set of observation channels has an interesting state
    fn is_interesting<OT>(
        &mut self,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
    {
        self.feedback_mut()
            .is_interesting(input, observers, exit_kind)
    }

    /// Adds this input to the corpus, if it's intersting, and return the index
    #[inline]
    fn add_if_interesting<CS>(
        &mut self,
        input: &I,
        is_interesting: bool,
        scheduler: &CS,
    ) -> Result<Option<usize>, Error>
    where
        CS: CorpusScheduler<I, Self>,
    {
        if is_interesting {
            let mut testcase = Testcase::new(input.clone());
            self.feedback_mut().append_metadata(&mut testcase)?;
            let idx = self.corpus.add(testcase)?;
            scheduler.on_add(self, idx)?;
            Ok(Some(idx))
        } else {
            self.feedback_mut().discard_metadata(&input)?;
            Ok(None)
        }
    }
}

impl<C, F, I, OF, R, SC> Evaluator<I> for State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
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
    ) -> Result<(bool, Option<usize>), Error>
    where
        E: Executor<I>
            + HasObservers<OT>
            + HasExecHooks<EM, I, Self>
            + HasObserversHooks<EM, I, OT, Self>,
        OT: ObserversTuple + HasExecHooksTuple<EM, I, Self>,
        C: Corpus<I>,
        EM: EventManager<I, Self>,
        CS: CorpusScheduler<I, Self>,
    {
        let (is_interesting, is_solution) = self.execute_input(&input, executor, manager)?;
        let observers = executor.observers();

        if is_solution {
            // If the input is a solution, add it to the respective corpus
            let mut testcase = Testcase::new(input.clone());
            self.objective_mut().append_metadata(&mut testcase)?;
            self.solutions_mut().add(testcase)?;
        } else {
            self.objective_mut().discard_metadata(&input)?;
        }

        let corpus_idx = self.add_if_interesting(&input, is_interesting, scheduler)?;
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

        Ok((is_interesting, corpus_idx))
    }
}

#[cfg(feature = "std")]
impl<C, F, OF, R, SC> State<C, F, BytesInput, OF, R, SC>
where
    C: Corpus<BytesInput>,
    R: Rand,
    F: Feedback<BytesInput>,
    SC: Corpus<BytesInput>,
    OF: Feedback<BytesInput>,
{
    /// loads inputs from a directory
    fn load_from_directory<CS, E, OT, EM>(
        &mut self,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
        in_dir: &Path,
    ) -> Result<(), Error>
    where
        E: Executor<BytesInput>
            + HasObservers<OT>
            + HasExecHooks<EM, BytesInput, Self>
            + HasObserversHooks<EM, BytesInput, OT, Self>,
        OT: ObserversTuple + HasExecHooksTuple<EM, BytesInput, Self>,
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
                let (is_interesting, is_solution) =
                    self.execute_input(&input, executor, manager)?;
                if self
                    .add_if_interesting(&input, is_interesting, scheduler)?
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

    /// Loads initial inputs from the passed-in `in_dirs`.
    pub fn load_initial_inputs<CS, E, OT, EM>(
        &mut self,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
        in_dirs: &[PathBuf],
    ) -> Result<(), Error>
    where
        E: Executor<BytesInput>
            + HasObservers<OT>
            + HasExecHooks<EM, BytesInput, Self>
            + HasObserversHooks<EM, BytesInput, OT, Self>,
        OT: ObserversTuple + HasExecHooksTuple<EM, BytesInput, Self>,
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

impl<C, F, I, OF, R, SC> State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
{
    /// Runs the input and triggers observers and feedback
    pub fn execute_input<E, EM, OT>(
        &mut self,
        input: &I,
        executor: &mut E,
        event_mgr: &mut EM,
    ) -> Result<(bool, bool), Error>
    where
        E: Executor<I>
            + HasObservers<OT>
            + HasExecHooks<EM, I, Self>
            + HasObserversHooks<EM, I, OT, Self>,
        OT: ObserversTuple + HasExecHooksTuple<EM, I, Self>,
        C: Corpus<I>,
        EM: EventManager<I, Self>,
    {
        start_timer!(self);
        executor.pre_exec_observers(self, event_mgr, input)?;
        mark_feature_time!(self, PerfFeature::PreExecObservers);

        start_timer!(self);
        executor.pre_exec(self, event_mgr, input)?;
        mark_feature_time!(self, PerfFeature::PreExec);

        start_timer!(self);
        let exit_kind = executor.run_target(input)?;
        mark_feature_time!(self, PerfFeature::TargetExecution);

        start_timer!(self);
        executor.post_exec(self, event_mgr, input)?;
        mark_feature_time!(self, PerfFeature::PostExec);

        *self.executions_mut() += 1;

        start_timer!(self);
        executor.post_exec_observers(self, event_mgr, input)?;
        mark_feature_time!(self, PerfFeature::PostExecObservers);

        let observers = executor.observers();
        #[cfg(not(feature = "introspection"))]
        let is_interesting = self
            .feedback_mut()
            .is_interesting(&input, observers, &exit_kind)?;

        #[cfg(feature = "introspection")]
        let is_interesting = {
            // Init temporary feedback stats here. We can't use the typical pattern above
            // since we need a `mut self` for `feedbacks_mut`, so we can't also hand a
            // new `mut self` to `is_interesting_all_with_perf`. We use this stack
            // variable to get the stats and then update the feedbacks directly
            let mut feedback_stats = [0_u64; crate::stats::NUM_FEEDBACKS];
            let feedback_index = 0;
            let is_interesting = self.feedback_mut().is_interesting_with_perf(
                &input,
                observers,
                &exit_kind,
                &mut feedback_stats,
                feedback_index,
            )?;

            // Update the feedback stats
            self.introspection_stats_mut()
                .update_feedbacks(feedback_stats);

            // Return the total fitness
            is_interesting
        };

        start_timer!(self);
        let is_solution = self
            .objective_mut()
            .is_interesting(&input, observers, &exit_kind)?;

        mark_feature_time!(self, PerfFeature::GetObjectivesInterestingAll);

        Ok((is_interesting, is_solution))
    }

    /// Generate `num` initial inputs, using the passed-in generator.
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
        E: Executor<I>
            + HasObservers<OT>
            + HasExecHooks<EM, I, Self>
            + HasObserversHooks<EM, I, OT, Self>,
        OT: ObserversTuple + HasExecHooksTuple<EM, I, Self>,
        EM: EventManager<I, Self>,
        CS: CorpusScheduler<I, Self>,
    {
        let mut added = 0;
        for _ in 0..num {
            let input = generator.generate(self.rand_mut())?;
            let (is_interesting, _) = self.evaluate_input(input, executor, manager, scheduler)?;
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
        manager.process(self, executor, scheduler)?;
        Ok(())
    }

    /// Creates a new `State`, taking ownership of all of the individual components during fuzzing.
    pub fn new(rand: R, corpus: C, feedback: F, solutions: SC, objective: OF) -> Self {
        Self {
            rand,
            executions: 0,
            start_time: Duration::from_millis(0),
            metadata: SerdeAnyMap::default(),
            corpus,
            feedback,
            solutions,
            objective,
            max_size: DEFAULT_MAX_SIZE,
            #[cfg(feature = "introspection")]
            introspection_stats: ClientPerfStats::new(),
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "introspection")]
impl<C, F, I, OF, R, SC> HasClientPerfStats for State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
{
    fn introspection_stats(&self) -> &ClientPerfStats {
        &self.introspection_stats
    }

    fn introspection_stats_mut(&mut self) -> &mut ClientPerfStats {
        &mut self.introspection_stats
    }
}

#[cfg(not(feature = "introspection"))]
impl<C, F, I, OF, R, SC> HasClientPerfStats for State<C, F, I, OF, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    F: Feedback<I>,
    SC: Corpus<I>,
    OF: Feedback<I>,
{
    fn introspection_stats(&self) -> &ClientPerfStats {
        unimplemented!()
    }

    fn introspection_stats_mut(&mut self) -> &mut ClientPerfStats {
        unimplemented!()
    }
}
