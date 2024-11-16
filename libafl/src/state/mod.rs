//! The fuzzer, and state are the core pieces of every good fuzzer

#[cfg(feature = "std")]
use alloc::vec::Vec;
use core::{
    borrow::BorrowMut,
    cell::{Ref, RefMut},
    fmt::Debug,
    marker::PhantomData,
    time::Duration,
};
#[cfg(feature = "std")]
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(feature = "std")]
use libafl_bolts::core_affinity::{CoreId, Cores};
use libafl_bolts::{
    rands::{Rand, StdRand},
    serdeany::{NamedSerdeAnyMap, SerdeAnyMap},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

mod stack;
pub use stack::StageStack;

#[cfg(feature = "introspection")]
use crate::monitors::ClientPerfMonitor;
#[cfg(feature = "scalability_introspection")]
use crate::monitors::ScalabilityMonitor;
use crate::{
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, HasTestcase, InMemoryCorpus, Testcase},
    events::{Event, EventFirer, LogSeverity},
    feedbacks::StateInitializer,
    fuzzer::{Evaluator, ExecuteInputResult},
    generators::Generator,
    inputs::{Input, NopInput, UsesInput},
    stages::{HasCurrentStageId, HasNestedStageStatus, StageId},
    Error, HasMetadata, HasNamedMetadata,
};

/// The maximum size of a testcase
pub const DEFAULT_MAX_SIZE: usize = 1_048_576;

/// The [`State`] of the fuzzer.
/// Contains all important information about the current run.
/// Will be used to restart the fuzzing process at any time.
pub trait State:
    UsesInput
    + Serialize
    + DeserializeOwned
    + MaybeHasClientPerfMonitor
    + MaybeHasScalabilityMonitor
    + HasCurrentCorpusId
    + HasCurrentStageId
    + Stoppable
{
}

/// Structs which implement this trait are aware of the state. This is used for type enforcement.
pub trait UsesState: UsesInput<Input = <Self::State as UsesInput>::Input> {
    /// The state known by this type.
    type State: State;
}

// blanket impl which automatically defines UsesInput for anything that implements UsesState
impl<KS> UsesInput for KS
where
    KS: UsesState,
{
    type Input = <KS::State as UsesInput>::Input;
}

/// Trait for elements offering a corpus
pub trait HasCorpus {
    /// The associated type implementing [`Corpus`].
    type Corpus: Corpus;

    /// The testcase corpus
    fn corpus(&self) -> &Self::Corpus;
    /// The testcase corpus (mutable)
    fn corpus_mut(&mut self) -> &mut Self::Corpus;
}

// Reflexivity
impl<C> HasCorpus for C
where
    C: Corpus,
{
    type Corpus = Self;

    fn corpus(&self) -> &Self::Corpus {
        self
    }

    fn corpus_mut(&mut self) -> &mut Self::Corpus {
        self
    }
}

/// Interact with the maximum size
pub trait HasMaxSize {
    /// The maximum size hint for items and mutations returned
    fn max_size(&self) -> usize;
    /// Sets the maximum size hint for the items and mutations
    fn set_max_size(&mut self, max_size: usize);
}

/// Trait for elements offering a corpus of solutions
pub trait HasSolutions {
    /// The associated type implementing [`Corpus`] for solutions
    type Solutions: Corpus;

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

#[cfg(feature = "introspection")]
/// Trait for offering a [`ClientPerfMonitor`]
pub trait HasClientPerfMonitor {
    /// [`ClientPerfMonitor`] itself
    fn introspection_monitor(&self) -> &ClientPerfMonitor;

    /// Mutatable ref to [`ClientPerfMonitor`]
    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor;
}

/// Intermediate trait for `HasClientPerfMonitor`
#[cfg(feature = "introspection")]
pub trait MaybeHasClientPerfMonitor: HasClientPerfMonitor {}

/// Intermediate trait for `HasClientPerfmonitor`
#[cfg(not(feature = "introspection"))]
pub trait MaybeHasClientPerfMonitor {}

#[cfg(not(feature = "introspection"))]
impl<T> MaybeHasClientPerfMonitor for T {}

#[cfg(feature = "introspection")]
impl<T> MaybeHasClientPerfMonitor for T where T: HasClientPerfMonitor {}

/// Intermediate trait for `HasScalabilityMonitor`
#[cfg(feature = "scalability_introspection")]
pub trait MaybeHasScalabilityMonitor: HasScalabilityMonitor {}
/// Intermediate trait for `HasScalabilityMonitor`
#[cfg(not(feature = "scalability_introspection"))]
pub trait MaybeHasScalabilityMonitor {}

#[cfg(not(feature = "scalability_introspection"))]
impl<T> MaybeHasScalabilityMonitor for T {}

#[cfg(feature = "scalability_introspection")]
impl<T> MaybeHasScalabilityMonitor for T where T: HasScalabilityMonitor {}

/// Trait for offering a [`ScalabilityMonitor`]
#[cfg(feature = "scalability_introspection")]
pub trait HasScalabilityMonitor {
    /// Ref to [`ScalabilityMonitor`]
    fn scalability_monitor(&self) -> &ScalabilityMonitor;

    /// Mutable ref to [`ScalabilityMonitor`]
    fn scalability_monitor_mut(&mut self) -> &mut ScalabilityMonitor;
}

/// Trait for the execution counter
pub trait HasExecutions {
    /// The executions counter
    fn executions(&self) -> &u64;

    /// The executions counter (mutable)
    fn executions_mut(&mut self) -> &mut u64;
}

/// Trait for some stats of AFL
pub trait HasImported {
    ///the imported testcases counter
    fn imported(&self) -> &usize;

    ///the imported testcases counter (mutable)
    fn imported_mut(&mut self) -> &mut usize;
}

/// Trait for the starting time
pub trait HasStartTime {
    /// The starting time
    fn start_time(&self) -> &Duration;

    /// The starting time (mutable)
    fn start_time_mut(&mut self) -> &mut Duration;
}

/// Trait for the last report time, the last time this node reported progress
pub trait HasLastFoundTime {
    /// The last time we found something by ourselves
    fn last_found_time(&self) -> &Duration;

    /// The last time we found something by ourselves (mutable)
    fn last_found_time_mut(&mut self) -> &mut Duration;
}

/// Trait for the last report time, the last time this node reported progress
pub trait HasLastReportTime {
    /// The last time we reported progress,if available/used.
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time(&self) -> &Option<Duration>;

    /// The last time we reported progress,if available/used (mutable).
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time_mut(&mut self) -> &mut Option<Duration>;
}

/// Struct that holds the options for input loading
#[cfg(feature = "std")]
pub struct LoadConfig<'a, I, S, Z> {
    /// Load Input even if it was deemed "uninteresting" by the fuzzer
    forced: bool,
    /// Function to load input from a Path
    loader: &'a mut dyn FnMut(&mut Z, &mut S, &Path) -> Result<I, Error>,
    /// Error if Input leads to a Solution.
    exit_on_solution: bool,
}

#[cfg(feature = "std")]
impl<I, S, Z> Debug for LoadConfig<'_, I, S, Z> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LoadConfig {{}}")
    }
}

/// The state a fuzz run.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "
        C: serde::Serialize + for<'a> serde::Deserialize<'a>,
        SC: serde::Serialize + for<'a> serde::Deserialize<'a>,
        R: serde::Serialize + for<'a> serde::Deserialize<'a>
    ")]
pub struct StdState<I, C, R, SC> {
    /// RNG instance
    rand: R,
    /// How many times the executor ran the harness/target
    executions: u64,
    /// At what time the fuzzing started
    start_time: Duration,
    /// the number of new paths that imported from other fuzzers
    imported: usize,
    /// The corpus
    corpus: C,
    // Solutions corpus
    solutions: SC,
    /// Metadata stored for this state by one of the components
    metadata: SerdeAnyMap,
    /// Metadata stored with names
    named_metadata: NamedSerdeAnyMap,
    /// `MaxSize` testcase size for mutators that appreciate it
    max_size: usize,
    /// Performance statistics for this fuzzer
    #[cfg(feature = "introspection")]
    introspection_monitor: ClientPerfMonitor,
    #[cfg(feature = "scalability_introspection")]
    scalability_monitor: ScalabilityMonitor,
    #[cfg(feature = "std")]
    /// Remaining initial inputs to load, if any
    remaining_initial_files: Option<Vec<PathBuf>>,
    #[cfg(feature = "std")]
    /// symlinks we have already traversed when loading `remaining_initial_files`
    dont_reenter: Option<Vec<PathBuf>>,
    #[cfg(feature = "std")]
    /// If inputs have been processed for multicore loading
    /// relevant only for `load_initial_inputs_multicore`
    multicore_inputs_processed: Option<bool>,
    /// The last time we reported progress (if available/used).
    /// This information is used by fuzzer `maybe_report_progress`.
    last_report_time: Option<Duration>,
    /// The last time something was added to the corpus
    last_found_time: Duration,
    /// The current index of the corpus; used to record for resumable fuzzing.
    corpus_id: Option<CorpusId>,
    /// Request the fuzzer to stop at the start of the next stage
    /// or at the beginning of the next fuzzing iteration
    stop_requested: bool,
    stage_stack: StageStack,
    phantom: PhantomData<I>,
}

impl<I, C, R, SC> UsesInput for StdState<I, C, R, SC>
where
    I: Input,
{
    type Input = I;
}

impl<I, C, R, SC> State for StdState<I, C, R, SC>
where
    C: Corpus<Input = Self::Input> + Serialize + DeserializeOwned,
    R: Rand,
    SC: Corpus<Input = Self::Input> + Serialize + DeserializeOwned,
    Self: UsesInput,
{
}

impl<I, C, R, SC> HasRand for StdState<I, C, R, SC>
where
    R: Rand,
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

impl<I, C, R, SC> HasCorpus for StdState<I, C, R, SC>
where
    C: Corpus,
{
    type Corpus = C;

    /// Returns the corpus
    #[inline]
    fn corpus(&self) -> &Self::Corpus {
        &self.corpus
    }

    /// Returns the mutable corpus
    #[inline]
    fn corpus_mut(&mut self) -> &mut Self::Corpus {
        &mut self.corpus
    }
}

impl<I, C, R, SC> HasTestcase for StdState<I, C, R, SC>
where
    C: Corpus,
{
    /// To get the testcase
    fn testcase(&self, id: CorpusId) -> Result<Ref<'_, Testcase<C::Input>>, Error> {
        Ok(self.corpus().get(id)?.borrow())
    }

    /// To get mutable testcase
    fn testcase_mut(&self, id: CorpusId) -> Result<RefMut<'_, Testcase<C::Input>>, Error> {
        Ok(self.corpus().get(id)?.borrow_mut())
    }
}

impl<I, C, R, SC> HasSolutions for StdState<I, C, R, SC>
where
    I: Input,
    SC: Corpus<Input = <Self as UsesInput>::Input>,
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

impl<I, C, R, SC> HasMetadata for StdState<I, C, R, SC> {
    /// Get all the metadata into an [`hashbrown::HashMap`]
    #[inline]
    fn metadata_map(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    /// Get all the metadata into an [`hashbrown::HashMap`] (mutable)
    #[inline]
    fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<I, C, R, SC> HasNamedMetadata for StdState<I, C, R, SC> {
    /// Get all the metadata into an [`hashbrown::HashMap`]
    #[inline]
    fn named_metadata_map(&self) -> &NamedSerdeAnyMap {
        &self.named_metadata
    }

    /// Get all the metadata into an [`hashbrown::HashMap`] (mutable)
    #[inline]
    fn named_metadata_map_mut(&mut self) -> &mut NamedSerdeAnyMap {
        &mut self.named_metadata
    }
}

impl<I, C, R, SC> HasExecutions for StdState<I, C, R, SC> {
    /// The executions counter
    #[inline]
    fn executions(&self) -> &u64 {
        &self.executions
    }

    /// The executions counter (mutable)
    #[inline]
    fn executions_mut(&mut self) -> &mut u64 {
        &mut self.executions
    }
}

impl<I, C, R, SC> HasImported for StdState<I, C, R, SC> {
    /// Return the number of new paths that imported from other fuzzers
    #[inline]
    fn imported(&self) -> &usize {
        &self.imported
    }

    /// Return the number of new paths that imported from other fuzzers
    #[inline]
    fn imported_mut(&mut self) -> &mut usize {
        &mut self.imported
    }
}

impl<I, C, R, SC> HasLastFoundTime for StdState<I, C, R, SC> {
    /// Return the number of new paths that imported from other fuzzers
    #[inline]
    fn last_found_time(&self) -> &Duration {
        &self.last_found_time
    }

    /// Return the number of new paths that imported from other fuzzers
    #[inline]
    fn last_found_time_mut(&mut self) -> &mut Duration {
        &mut self.last_found_time
    }
}

impl<I, C, R, SC> HasLastReportTime for StdState<I, C, R, SC> {
    /// The last time we reported progress,if available/used.
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time(&self) -> &Option<Duration> {
        &self.last_report_time
    }

    /// The last time we reported progress,if available/used (mutable).
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time_mut(&mut self) -> &mut Option<Duration> {
        &mut self.last_report_time
    }
}

impl<I, C, R, SC> HasMaxSize for StdState<I, C, R, SC> {
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
    }
}

impl<I, C, R, SC> HasStartTime for StdState<I, C, R, SC> {
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

impl<I, C, R, SC> HasCurrentCorpusId for StdState<I, C, R, SC> {
    fn set_corpus_id(&mut self, id: CorpusId) -> Result<(), Error> {
        self.corpus_id = Some(id);
        Ok(())
    }

    fn clear_corpus_id(&mut self) -> Result<(), Error> {
        self.corpus_id = None;
        Ok(())
    }

    fn current_corpus_id(&self) -> Result<Option<CorpusId>, Error> {
        Ok(self.corpus_id)
    }
}

/// Has information about the current [`Testcase`] we are fuzzing
pub trait HasCurrentTestcase: HasCorpus {
    /// Gets the current [`Testcase`] we are fuzzing
    ///
    /// Will return [`Error::key_not_found`] if no `corpus_id` is currently set.
    fn current_testcase(&self)
        -> Result<Ref<'_, Testcase<<Self::Corpus as Corpus>::Input>>, Error>;
    //fn current_testcase(&self) -> Result<&Testcase<I>, Error>;

    /// Gets the current [`Testcase`] we are fuzzing (mut)
    ///
    /// Will return [`Error::key_not_found`] if no `corpus_id` is currently set.
    fn current_testcase_mut(
        &self,
    ) -> Result<RefMut<'_, Testcase<<Self::Corpus as Corpus>::Input>>, Error>;
    //fn current_testcase_mut(&self) -> Result<&mut Testcase<I>, Error>;

    /// Gets a cloned representation of the current [`Testcase`].
    ///
    /// Will return [`Error::key_not_found`] if no `corpus_id` is currently set.
    ///
    /// # Note
    /// This allocates memory and copies the contents!
    /// For performance reasons, if you just need to access the testcase, use [`Self::current_testcase`] instead.
    fn current_input_cloned(&self) -> Result<<Self::Corpus as Corpus>::Input, Error>;
}

impl<T> HasCurrentTestcase for T
where
    T: HasCorpus + HasCurrentCorpusId,
    <Self::Corpus as Corpus>::Input: Clone,
{
    fn current_testcase(
        &self,
    ) -> Result<Ref<'_, Testcase<<Self::Corpus as Corpus>::Input>>, Error> {
        let Some(corpus_id) = self.current_corpus_id()? else {
            return Err(Error::key_not_found(
                "We are not currently processing a testcase",
            ));
        };

        Ok(self.corpus().get(corpus_id)?.borrow())
    }

    fn current_testcase_mut(
        &self,
    ) -> Result<RefMut<'_, Testcase<<Self::Corpus as Corpus>::Input>>, Error> {
        let Some(corpus_id) = self.current_corpus_id()? else {
            return Err(Error::illegal_state(
                "We are not currently processing a testcase",
            ));
        };

        Ok(self.corpus().get(corpus_id)?.borrow_mut())
    }

    fn current_input_cloned(&self) -> Result<<Self::Corpus as Corpus>::Input, Error> {
        let mut testcase = self.current_testcase_mut()?;
        Ok(testcase.borrow_mut().load_input(self.corpus())?.clone())
    }
}

/// A trait for types that want to expose a stop API
pub trait Stoppable {
    /// Check if stop is requested
    fn stop_requested(&self) -> bool;

    /// Request to stop
    fn request_stop(&mut self);

    /// Discard the stop request
    fn discard_stop_request(&mut self);
}

impl<I, C, R, SC> Stoppable for StdState<I, C, R, SC> {
    fn request_stop(&mut self) {
        self.stop_requested = true;
    }

    fn discard_stop_request(&mut self) {
        self.stop_requested = false;
    }

    fn stop_requested(&self) -> bool {
        self.stop_requested
    }
}

impl<I, C, R, SC> HasCurrentStageId for StdState<I, C, R, SC> {
    fn set_current_stage_id(&mut self, idx: StageId) -> Result<(), Error> {
        self.stage_stack.set_current_stage_id(idx)
    }

    fn clear_stage_id(&mut self) -> Result<(), Error> {
        self.stage_stack.clear_stage_id()
    }

    fn current_stage_id(&self) -> Result<Option<StageId>, Error> {
        self.stage_stack.current_stage_id()
    }

    fn on_restart(&mut self) -> Result<(), Error> {
        self.stage_stack.on_restart()
    }
}

impl<I, C, R, SC> HasNestedStageStatus for StdState<I, C, R, SC> {
    fn enter_inner_stage(&mut self) -> Result<(), Error> {
        self.stage_stack.enter_inner_stage()
    }

    fn exit_inner_stage(&mut self) -> Result<(), Error> {
        self.stage_stack.exit_inner_stage()
    }
}

#[cfg(feature = "std")]
impl<C, I, R, SC> StdState<I, C, R, SC>
where
    I: Input,
    C: Corpus<Input = <Self as UsesInput>::Input>,
    R: Rand,
    SC: Corpus<Input = <Self as UsesInput>::Input>,
{
    /// Decide if the state must load the inputs
    pub fn must_load_initial_inputs(&self) -> bool {
        self.corpus().count() == 0
            || (self.remaining_initial_files.is_some()
                && !self.remaining_initial_files.as_ref().unwrap().is_empty())
    }

    /// List initial inputs from a directory.
    fn next_file(&mut self) -> Result<PathBuf, Error> {
        loop {
            if let Some(path) = self.remaining_initial_files.as_mut().and_then(Vec::pop) {
                let filename = path.file_name().unwrap().to_string_lossy();
                if filename.starts_with('.')
                // || filename
                //     .rsplit_once('-')
                //     .is_some_and(|(_, s)| u64::from_str(s).is_ok())
                {
                    continue;
                }

                let attributes = fs::metadata(&path);

                if attributes.is_err() {
                    continue;
                }

                let attr = attributes?;

                if attr.is_file() && attr.len() > 0 {
                    return Ok(path);
                } else if attr.is_dir() {
                    let files = self.remaining_initial_files.as_mut().unwrap();
                    path.read_dir()?
                        .try_for_each(|entry| entry.map(|e| files.push(e.path())))?;
                } else if attr.is_symlink() {
                    let path = fs::canonicalize(path)?;
                    let dont_reenter = self.dont_reenter.get_or_insert_with(Default::default);
                    if dont_reenter.iter().any(|p| path.starts_with(p)) {
                        continue;
                    }
                    if path.is_dir() {
                        dont_reenter.push(path.clone());
                    }
                    let files = self.remaining_initial_files.as_mut().unwrap();
                    files.push(path);
                }
            } else {
                return Err(Error::iterator_end("No remaining files to load."));
            }
        }
    }

    /// Resets the state of initial files.
    fn reset_initial_files_state(&mut self) {
        self.remaining_initial_files = None;
        self.dont_reenter = None;
    }

    /// Sets canonical paths for provided inputs
    fn canonicalize_input_dirs(&mut self, in_dirs: &[PathBuf]) -> Result<(), Error> {
        if let Some(remaining) = self.remaining_initial_files.as_ref() {
            // everything was loaded
            if remaining.is_empty() {
                return Ok(());
            }
        } else {
            let files = in_dirs.iter().try_fold(Vec::new(), |mut res, file| {
                file.canonicalize().map(|canonicalized| {
                    res.push(canonicalized);
                    res
                })
            })?;
            self.dont_reenter = Some(files.clone());
            self.remaining_initial_files = Some(files);
        }
        Ok(())
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    /// If `forced` is true, will add all testcases, no matter what.
    /// This method takes a list of files.
    fn load_initial_inputs_custom_by_filenames<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        file_list: &[PathBuf],
        load_config: LoadConfig<I, Self, Z>,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        if let Some(remaining) = self.remaining_initial_files.as_ref() {
            // everything was loaded
            if remaining.is_empty() {
                return Ok(());
            }
        } else {
            self.remaining_initial_files = Some(file_list.to_vec());
        }

        self.continue_loading_initial_inputs_custom(fuzzer, executor, manager, load_config)
    }

    fn load_file<E, EM, Z>(
        &mut self,
        path: &PathBuf,
        manager: &mut EM,
        fuzzer: &mut Z,
        executor: &mut E,
        config: &mut LoadConfig<I, Self, Z>,
    ) -> Result<ExecuteInputResult, Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        log::info!("Loading file {:?} ...", &path);
        let input = (config.loader)(fuzzer, self, path)?;
        if config.forced {
            let _: CorpusId = fuzzer.add_input(self, executor, manager, input)?;
            Ok(ExecuteInputResult::Corpus)
        } else {
            let (res, _) = fuzzer.evaluate_input(self, executor, manager, input.clone())?;
            if res == ExecuteInputResult::None {
                fuzzer.add_disabled_input(self, input)?;
                log::warn!("input {:?} was not interesting, adding as disabled.", &path);
            }
            Ok(res)
        }
    }
    /// Loads initial inputs from the passed-in `in_dirs`.
    /// This method takes a list of files and a `LoadConfig`
    /// which specifies the special handling of initial inputs
    fn continue_loading_initial_inputs_custom<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        mut config: LoadConfig<I, Self, Z>,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        loop {
            match self.next_file() {
                Ok(path) => {
                    let res = self.load_file(&path, manager, fuzzer, executor, &mut config)?;
                    if config.exit_on_solution && matches!(res, ExecuteInputResult::Solution) {
                        return Err(Error::invalid_corpus(format!(
                            "Input {} resulted in a solution.",
                            path.display()
                        )));
                    }
                }
                Err(Error::IteratorEnd(_, _)) => break,
                Err(e) => return Err(e),
            }
        }

        manager.fire(
            self,
            Event::Log {
                severity_level: LogSeverity::Debug,
                message: format!("Loaded {} initial testcases.", self.corpus().count()), // get corpus count
                phantom: PhantomData::<I>,
            },
        )?;
        Ok(())
    }

    /// Recursively walk supplied corpus directories
    pub fn walk_initial_inputs<F>(
        &mut self,
        in_dirs: &[PathBuf],
        mut closure: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&PathBuf) -> Result<(), Error>,
    {
        self.canonicalize_input_dirs(in_dirs)?;
        loop {
            match self.next_file() {
                Ok(path) => {
                    closure(&path)?;
                }
                Err(Error::IteratorEnd(_, _)) => break,
                Err(e) => return Err(e),
            }
        }
        self.reset_initial_files_state();
        Ok(())
    }
    /// Loads all intial inputs, even if they are not considered `interesting`.
    /// This is rarely the right method, use `load_initial_inputs`,
    /// and potentially fix your `Feedback`, instead.
    /// This method takes a list of files, instead of folders.
    pub fn load_initial_inputs_by_filenames<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        file_list: &[PathBuf],
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        self.load_initial_inputs_custom_by_filenames(
            fuzzer,
            executor,
            manager,
            file_list,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: false,
                exit_on_solution: false,
            },
        )
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
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        self.canonicalize_input_dirs(in_dirs)?;
        self.continue_loading_initial_inputs_custom(
            fuzzer,
            executor,
            manager,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: true,
                exit_on_solution: false,
            },
        )
    }
    /// Loads initial inputs from the passed-in `in_dirs`.
    /// If `forced` is true, will add all testcases, no matter what.
    /// This method takes a list of files, instead of folders.
    pub fn load_initial_inputs_by_filenames_forced<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        file_list: &[PathBuf],
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        self.load_initial_inputs_custom_by_filenames(
            fuzzer,
            executor,
            manager,
            file_list,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: true,
                exit_on_solution: false,
            },
        )
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
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        self.canonicalize_input_dirs(in_dirs)?;
        self.continue_loading_initial_inputs_custom(
            fuzzer,
            executor,
            manager,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: false,
                exit_on_solution: false,
            },
        )
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    /// Will return a `CorpusError` if a solution is found
    pub fn load_initial_inputs_disallow_solution<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        self.canonicalize_input_dirs(in_dirs)?;
        self.continue_loading_initial_inputs_custom(
            fuzzer,
            executor,
            manager,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: false,
                exit_on_solution: true,
            },
        )
    }

    fn calculate_corpus_size(&mut self) -> Result<usize, Error> {
        let mut count: usize = 0;
        loop {
            match self.next_file() {
                Ok(_) => {
                    count = count.saturating_add(1);
                }
                Err(Error::IteratorEnd(_, _)) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(count)
    }
    /// Loads initial inputs by dividing the from the passed-in `in_dirs`
    /// in a multicore fashion. Divides the corpus in chunks spread across cores.
    pub fn load_initial_inputs_multicore<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
        core_id: &CoreId,
        cores: &Cores,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        if self.multicore_inputs_processed.unwrap_or(false) {
            self.continue_loading_initial_inputs_custom(
                fuzzer,
                executor,
                manager,
                LoadConfig {
                    loader: &mut |_, _, path| I::from_file(path),
                    forced: false,
                    exit_on_solution: false,
                },
            )?;
        } else {
            self.canonicalize_input_dirs(in_dirs)?;
            let corpus_size = self.calculate_corpus_size()?;
            log::info!(
                "{} total_corpus_size, {} cores",
                corpus_size,
                cores.ids.len()
            );
            self.reset_initial_files_state();
            self.canonicalize_input_dirs(in_dirs)?;
            if cores.ids.len() > corpus_size {
                log::info!(
                    "low intial corpus count ({}), no parallelism required.",
                    corpus_size
                );
            } else {
                let core_index = cores
                    .ids
                    .iter()
                    .enumerate()
                    .find(|(_, c)| *c == core_id)
                    .unwrap_or_else(|| panic!("core id {} not in cores list", core_id.0))
                    .0;
                let chunk_size = corpus_size.saturating_div(cores.ids.len());
                let mut skip = core_index.saturating_mul(chunk_size);
                let mut inputs_todo = chunk_size;
                let mut collected_inputs = Vec::new();
                log::info!(
                    "core = {}, core_index = {}, chunk_size = {}, skip = {}",
                    core_id.0,
                    core_index,
                    chunk_size,
                    skip
                );
                loop {
                    match self.next_file() {
                        Ok(path) => {
                            if skip != 0 {
                                skip = skip.saturating_sub(1);
                                continue;
                            }
                            if inputs_todo == 0 {
                                break;
                            }
                            collected_inputs.push(path);
                            inputs_todo = inputs_todo.saturating_sub(1);
                        }
                        Err(Error::IteratorEnd(_, _)) => break,
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                self.remaining_initial_files = Some(collected_inputs);
            }
            self.multicore_inputs_processed = Some(true);
            return self
                .load_initial_inputs_multicore(fuzzer, executor, manager, in_dirs, core_id, cores);
        }
        Ok(())
    }
}

impl<C, I, R, SC> StdState<I, C, R, SC>
where
    I: Input,
    C: Corpus<Input = <Self as UsesInput>::Input>,
    R: Rand,
    SC: Corpus<Input = <Self as UsesInput>::Input>,
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
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        G: Generator<<Self as UsesInput>::Input, Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        let mut added = 0;
        for _ in 0..num {
            let input = generator.generate(self)?;
            if forced {
                let _: CorpusId = fuzzer.add_input(self, executor, manager, input)?;
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
                message: format!("Loaded {added} over {num} initial testcases"),
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
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        G: Generator<<Self as UsesInput>::Input, Self>,
        Z: Evaluator<E, EM, State = Self>,
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
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        G: Generator<<Self as UsesInput>::Input, Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        self.generate_initial_internal(fuzzer, executor, generator, manager, num, false)
    }

    /// Creates a new `State`, taking ownership of all of the individual components during fuzzing.
    pub fn new<F, O>(
        rand: R,
        corpus: C,
        solutions: SC,
        feedback: &mut F,
        objective: &mut O,
    ) -> Result<Self, Error>
    where
        F: StateInitializer<Self>,
        O: StateInitializer<Self>,
        C: Serialize + DeserializeOwned,
        SC: Serialize + DeserializeOwned,
    {
        let mut state = Self {
            rand,
            executions: 0,
            imported: 0,
            start_time: libafl_bolts::current_time(),
            metadata: SerdeAnyMap::default(),
            named_metadata: NamedSerdeAnyMap::default(),
            corpus,
            solutions,
            max_size: DEFAULT_MAX_SIZE,
            stop_requested: false,
            #[cfg(feature = "introspection")]
            introspection_monitor: ClientPerfMonitor::new(),
            #[cfg(feature = "scalability_introspection")]
            scalability_monitor: ScalabilityMonitor::new(),
            #[cfg(feature = "std")]
            remaining_initial_files: None,
            #[cfg(feature = "std")]
            dont_reenter: None,
            last_report_time: None,
            last_found_time: libafl_bolts::current_time(),
            corpus_id: None,
            stage_stack: StageStack::default(),
            phantom: PhantomData,
            #[cfg(feature = "std")]
            multicore_inputs_processed: None,
        };
        feedback.init_state(&mut state)?;
        objective.init_state(&mut state)?;
        Ok(state)
    }
}

impl StdState<NopInput, InMemoryCorpus<NopInput>, StdRand, InMemoryCorpus<NopInput>> {
    /// Create an empty [`StdState`] that has very minimal uses.
    /// Potentially good for testing.
    pub fn nop<I>() -> Result<StdState<I, InMemoryCorpus<I>, StdRand, InMemoryCorpus<I>>, Error>
    where
        I: Input,
    {
        StdState::new(
            StdRand::with_seed(0),
            InMemoryCorpus::<I>::new(),
            InMemoryCorpus::new(),
            &mut (),
            &mut (),
        )
    }
}

#[cfg(feature = "introspection")]
impl<I, C, R, SC> HasClientPerfMonitor for StdState<I, C, R, SC> {
    fn introspection_monitor(&self) -> &ClientPerfMonitor {
        &self.introspection_monitor
    }

    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor {
        &mut self.introspection_monitor
    }
}

#[cfg(feature = "scalability_introspection")]
impl<I, C, R, SC> HasScalabilityMonitor for StdState<I, C, R, SC> {
    fn scalability_monitor(&self) -> &ScalabilityMonitor {
        &self.scalability_monitor
    }

    fn scalability_monitor_mut(&mut self) -> &mut ScalabilityMonitor {
        &mut self.scalability_monitor
    }
}

/// A very simple state without any bells or whistles, for testing.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct NopState<I> {
    metadata: SerdeAnyMap,
    execution: u64,
    stop_requested: bool,
    rand: StdRand,
    phantom: PhantomData<I>,
}

impl<I> NopState<I> {
    /// Create a new State that does nothing (for tests)
    #[must_use]
    pub fn new() -> Self {
        NopState {
            metadata: SerdeAnyMap::new(),
            execution: 0,
            rand: StdRand::default(),
            stop_requested: false,
            phantom: PhantomData,
        }
    }
}

impl<I> HasMaxSize for NopState<I> {
    fn max_size(&self) -> usize {
        16_384
    }

    fn set_max_size(&mut self, _max_size: usize) {
        unimplemented!("NopState doesn't allow setting a max size")
    }
}

impl<I> UsesInput for NopState<I>
where
    I: Input,
{
    type Input = I;
}

impl<I> HasExecutions for NopState<I> {
    fn executions(&self) -> &u64 {
        &self.execution
    }

    fn executions_mut(&mut self) -> &mut u64 {
        &mut self.execution
    }
}

impl<I> Stoppable for NopState<I> {
    fn request_stop(&mut self) {
        self.stop_requested = true;
    }

    fn discard_stop_request(&mut self) {
        self.stop_requested = false;
    }

    fn stop_requested(&self) -> bool {
        self.stop_requested
    }
}

impl<I> HasLastReportTime for NopState<I> {
    fn last_report_time(&self) -> &Option<Duration> {
        unimplemented!();
    }

    fn last_report_time_mut(&mut self) -> &mut Option<Duration> {
        unimplemented!();
    }
}

impl<I> HasMetadata for NopState<I> {
    fn metadata_map(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<I> HasRand for NopState<I> {
    type Rand = StdRand;

    fn rand(&self) -> &Self::Rand {
        &self.rand
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand
    }
}

impl<I> State for NopState<I> where I: Input {}

impl<I> HasCurrentCorpusId for NopState<I> {
    fn set_corpus_id(&mut self, _id: CorpusId) -> Result<(), Error> {
        Ok(())
    }

    fn clear_corpus_id(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn current_corpus_id(&self) -> Result<Option<CorpusId>, Error> {
        Ok(None)
    }
}

impl<I> HasCurrentStageId for NopState<I> {
    fn set_current_stage_id(&mut self, _idx: StageId) -> Result<(), Error> {
        Ok(())
    }

    fn clear_stage_id(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn current_stage_id(&self) -> Result<Option<StageId>, Error> {
        Ok(None)
    }
}

#[cfg(feature = "introspection")]
impl<I> HasClientPerfMonitor for NopState<I> {
    fn introspection_monitor(&self) -> &ClientPerfMonitor {
        unimplemented!();
    }

    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor {
        unimplemented!();
    }
}

#[cfg(feature = "scalability_introspection")]
impl<I> HasScalabilityMonitor for NopState<I> {
    fn scalability_monitor(&self) -> &ScalabilityMonitor {
        unimplemented!();
    }

    fn scalability_monitor_mut(&mut self) -> &mut ScalabilityMonitor {
        unimplemented!();
    }
}

#[cfg(test)]
mod test {
    use crate::{inputs::BytesInput, state::StdState};

    #[test]
    fn test_std_state() {
        StdState::nop::<BytesInput>().expect("couldn't instantiate the test state");
    }
}
