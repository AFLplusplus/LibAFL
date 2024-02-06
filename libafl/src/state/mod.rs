//! The fuzzer, and state are the core pieces of every good fuzzer

use alloc::vec::Vec;
use core::{
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

use libafl_bolts::{
    rands::Rand,
    serdeany::{NamedSerdeAnyMap, SerdeAny, SerdeAnyMap},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[cfg(feature = "introspection")]
use crate::monitors::ClientPerfMonitor;
#[cfg(feature = "scalability_introspection")]
use crate::monitors::ScalabilityMonitor;
use crate::{
    corpus::{Corpus, CorpusId, HasCurrentCorpusIdx, HasTestcase, Testcase},
    events::{Event, EventFirer, LogSeverity},
    feedbacks::Feedback,
    fuzzer::{Evaluator, ExecuteInputResult},
    generators::Generator,
    inputs::{Input, UsesInput},
    stages::{HasCurrentStage, HasNestedStageStatus},
    Error,
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
    + HasCurrentCorpusIdx
    + HasCurrentStage
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
pub trait HasCorpus: UsesInput {
    /// The associated type implementing [`Corpus`].
    type Corpus: Corpus<Input = <Self as UsesInput>::Input>;

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
pub trait HasSolutions: UsesInput {
    /// The associated type implementing [`Corpus`] for solutions
    type Solutions: Corpus<Input = <Self as UsesInput>::Input>;

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

/// Trait for elements offering metadata
pub trait HasMetadata {
    /// A map, storing all metadata
    fn metadata_map(&self) -> &SerdeAnyMap;
    /// A map, storing all metadata (mutable)
    fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap;

    /// Add a metadata to the metadata map
    #[inline]
    fn add_metadata<M>(&mut self, meta: M)
    where
        M: SerdeAny,
    {
        self.metadata_map_mut().insert(meta);
    }

    /// Check for a metadata
    #[inline]
    fn has_metadata<M>(&self) -> bool
    where
        M: SerdeAny,
    {
        self.metadata_map().get::<M>().is_some()
    }

    /// To get metadata
    #[inline]
    fn metadata<M>(&self) -> Result<&M, Error>
    where
        M: SerdeAny,
    {
        self.metadata_map().get::<M>().ok_or_else(|| {
            Error::key_not_found(format!("{} not found", core::any::type_name::<M>()))
        })
    }

    /// To get mutable metadata
    #[inline]
    fn metadata_mut<M>(&mut self) -> Result<&mut M, Error>
    where
        M: SerdeAny,
    {
        self.metadata_map_mut().get_mut::<M>().ok_or_else(|| {
            Error::key_not_found(format!("{} not found", core::any::type_name::<M>()))
        })
    }
}

/// Trait for elements offering named metadata
pub trait HasNamedMetadata {
    /// A map, storing all metadata
    fn named_metadata_map(&self) -> &NamedSerdeAnyMap;
    /// A map, storing all metadata (mutable)
    fn named_metadata_map_mut(&mut self) -> &mut NamedSerdeAnyMap;

    /// Add a metadata to the metadata map
    #[inline]
    fn add_named_metadata<M>(&mut self, meta: M, name: &str)
    where
        M: SerdeAny,
    {
        self.named_metadata_map_mut().insert(meta, name);
    }

    /// Check for a metadata
    #[inline]
    fn has_named_metadata<M>(&self, name: &str) -> bool
    where
        M: SerdeAny,
    {
        self.named_metadata_map().contains::<M>(name)
    }

    /// To get named metadata
    #[inline]
    fn named_metadata<M>(&self, name: &str) -> Result<&M, Error>
    where
        M: SerdeAny,
    {
        self.named_metadata_map().get::<M>(name).ok_or_else(|| {
            Error::key_not_found(format!("{} not found", core::any::type_name::<M>()))
        })
    }

    /// To get mutable named metadata
    #[inline]
    fn named_metadata_mut<M>(&mut self, name: &str) -> Result<&mut M, Error>
    where
        M: SerdeAny,
    {
        self.named_metadata_map_mut()
            .get_mut::<M>(name)
            .ok_or_else(|| {
                Error::key_not_found(format!("{} not found", core::any::type_name::<M>()))
            })
    }
}

/// Trait for the execution counter
pub trait HasExecutions {
    /// The executions counter
    fn executions(&self) -> &usize;

    /// The executions counter (mutable)
    fn executions_mut(&mut self) -> &mut usize;
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
pub trait HasLastReportTime {
    /// The last time we reported progress,if available/used.
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time(&self) -> &Option<Duration>;

    /// The last time we reported progress,if available/used (mutable).
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time_mut(&mut self) -> &mut Option<Duration>;
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
    executions: usize,
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
    /// MaxSize testcase size for mutators that appreciate it
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
    /// Remaining initial inputs to load, if any
    dont_reenter: Option<Vec<PathBuf>>,
    /// The last time we reported progress (if available/used).
    /// This information is used by fuzzer `maybe_report_progress`.
    last_report_time: Option<Duration>,
    /// The current index of the corpus; used to record for resumable fuzzing.
    corpus_idx: Option<CorpusId>,
    /// The stage indexes for each nesting of stages
    stage_idx_stack: Vec<usize>,
    /// The current stage depth
    stage_depth: usize,
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
    C: Corpus<Input = Self::Input>,
    R: Rand,
    SC: Corpus<Input = Self::Input>,
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
    I: Input,
    C: Corpus<Input = <Self as UsesInput>::Input>,
    R: Rand,
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
    I: Input,
    C: Corpus<Input = <Self as UsesInput>::Input>,
    R: Rand,
{
    /// To get the testcase
    fn testcase(&self, id: CorpusId) -> Result<Ref<Testcase<<Self as UsesInput>::Input>>, Error> {
        Ok(self.corpus().get(id)?.borrow())
    }

    /// To get mutable testcase
    fn testcase_mut(
        &self,
        id: CorpusId,
    ) -> Result<RefMut<Testcase<<Self as UsesInput>::Input>>, Error> {
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
    fn executions(&self) -> &usize {
        &self.executions
    }

    /// The executions counter (mutable)
    #[inline]
    fn executions_mut(&mut self) -> &mut usize {
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

impl<I, C, R, SC> HasCurrentCorpusIdx for StdState<I, C, R, SC> {
    fn set_corpus_idx(&mut self, idx: CorpusId) -> Result<(), Error> {
        self.corpus_idx = Some(idx);
        Ok(())
    }

    fn clear_corpus_idx(&mut self) -> Result<(), Error> {
        self.corpus_idx = None;
        Ok(())
    }

    fn current_corpus_idx(&self) -> Result<Option<CorpusId>, Error> {
        Ok(self.corpus_idx)
    }
}

impl<I, C, R, SC> HasCurrentStage for StdState<I, C, R, SC> {
    fn set_stage(&mut self, idx: usize) -> Result<(), Error> {
        // ensure we are in the right frame
        if self.stage_depth != self.stage_idx_stack.len() {
            return Err(Error::illegal_state(
                "stage not resumed before setting stage",
            ));
        }
        self.stage_idx_stack.push(idx);
        Ok(())
    }

    fn clear_stage(&mut self) -> Result<(), Error> {
        self.stage_idx_stack.truncate(self.stage_depth);
        Ok(())
    }

    fn current_stage(&self) -> Result<Option<usize>, Error> {
        Ok(self.stage_idx_stack.get(self.stage_depth).copied())
    }

    fn on_restart(&mut self) -> Result<(), Error> {
        self.stage_depth = 0; // reset the stage depth so that we may resume inward
        Ok(())
    }
}

impl<I, C, R, SC> HasNestedStageStatus for StdState<I, C, R, SC> {
    fn enter_inner_stage(&mut self) -> Result<(), Error> {
        self.stage_depth += 1;
        Ok(())
    }

    fn exit_inner_stage(&mut self) -> Result<(), Error> {
        self.stage_depth -= 1;
        Ok(())
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
    /// Decide if the state nust load the inputs
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
                //     .map_or(false, |(_, s)| u64::from_str(s).is_ok())
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

    /// Loads initial inputs from the passed-in `in_dirs`.
    /// If `forced` is true, will add all testcases, no matter what.
    fn load_initial_inputs_custom<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
        forced: bool,
        loader: &mut dyn FnMut(&mut Z, &mut Self, &Path) -> Result<I, Error>,
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
            let files = in_dirs.iter().try_fold(Vec::new(), |mut res, file| {
                file.canonicalize().map(|canonicalized| {
                    res.push(canonicalized);
                    res
                })
            })?;
            self.dont_reenter = Some(files.clone());
            self.remaining_initial_files = Some(files);
        }

        self.continue_loading_initial_inputs_custom(fuzzer, executor, manager, forced, loader)
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
        forced: bool,
        loader: &mut dyn FnMut(&mut Z, &mut Self, &Path) -> Result<I, Error>,
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

        self.continue_loading_initial_inputs_custom(fuzzer, executor, manager, forced, loader)
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    /// If `forced` is true, will add all testcases, no matter what.
    /// This method takes a list of files.
    fn continue_loading_initial_inputs_custom<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        forced: bool,
        loader: &mut dyn FnMut(&mut Z, &mut Self, &Path) -> Result<I, Error>,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        loop {
            match self.next_file() {
                Ok(path) => {
                    log::info!("Loading file {:?} ...", &path);
                    let input = loader(fuzzer, self, &path)?;
                    if forced {
                        let _: CorpusId = fuzzer.add_input(self, executor, manager, input)?;
                    } else {
                        let (res, _) = fuzzer.evaluate_input(self, executor, manager, input)?;
                        if res == ExecuteInputResult::None {
                            log::warn!("File {:?} was not interesting, skipped.", &path);
                        }
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
            false,
            &mut |_, _, path| I::from_file(path),
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
        self.load_initial_inputs_custom(
            fuzzer,
            executor,
            manager,
            in_dirs,
            true,
            &mut |_, _, path| I::from_file(path),
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
            true,
            &mut |_, _, path| I::from_file(path),
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
        self.load_initial_inputs_custom(
            fuzzer,
            executor,
            manager,
            in_dirs,
            false,
            &mut |_, _, path| I::from_file(path),
        )
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
        F: Feedback<Self>,
        O: Feedback<Self>,
    {
        let mut state = Self {
            rand,
            executions: 0,
            imported: 0,
            start_time: Duration::from_millis(0),
            metadata: SerdeAnyMap::default(),
            named_metadata: NamedSerdeAnyMap::default(),
            corpus,
            solutions,
            max_size: DEFAULT_MAX_SIZE,
            #[cfg(feature = "introspection")]
            introspection_monitor: ClientPerfMonitor::new(),
            #[cfg(feature = "scalability_introspection")]
            scalability_monitor: ScalabilityMonitor::new(),
            #[cfg(feature = "std")]
            remaining_initial_files: None,
            #[cfg(feature = "std")]
            dont_reenter: None,
            last_report_time: None,
            corpus_idx: None,
            stage_depth: 0,
            stage_idx_stack: Vec::new(),
            phantom: PhantomData,
        };
        feedback.init_state(&mut state)?;
        objective.init_state(&mut state)?;
        Ok(state)
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

#[cfg(test)]
pub mod test {
    use core::{marker::PhantomData, time::Duration};

    use libafl_bolts::{rands::StdRand, serdeany::SerdeAnyMap, Error};
    use serde::{Deserialize, Serialize};

    use crate::{
        corpus::{CorpusId, HasCurrentCorpusIdx, InMemoryCorpus},
        inputs::{Input, NopInput, UsesInput},
        stages::test::{test_resume, test_resume_stages},
        state::{
            HasCurrentStage, HasExecutions, HasLastReportTime, HasMetadata, HasRand, State,
            StdState,
        },
    };
    #[cfg(feature = "introspection")]
    use crate::{monitors::ClientPerfMonitor, state::HasClientPerfMonitor};
    #[cfg(feature = "scalability_introspection")]
    use crate::{monitors::ScalabilityMonitor, state::HasScalabilityMonitor};

    /// A very simple state without any bells or whistles, for testing.
    #[derive(Debug, Serialize, Deserialize, Default)]
    pub struct NopState<I> {
        metadata: SerdeAnyMap,
        execution: usize,
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
                phantom: PhantomData,
            }
        }
    }

    impl<I> UsesInput for NopState<I>
    where
        I: Input,
    {
        type Input = I;
    }

    impl<I> HasExecutions for NopState<I> {
        fn executions(&self) -> &usize {
            &self.execution
        }

        fn executions_mut(&mut self) -> &mut usize {
            &mut self.execution
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

    impl<I> HasCurrentCorpusIdx for NopState<I> {
        fn set_corpus_idx(&mut self, _idx: CorpusId) -> Result<(), Error> {
            Ok(())
        }

        fn clear_corpus_idx(&mut self) -> Result<(), Error> {
            Ok(())
        }

        fn current_corpus_idx(&self) -> Result<Option<CorpusId>, Error> {
            Ok(None)
        }
    }

    impl<I> HasCurrentStage for NopState<I> {
        fn set_stage(&mut self, _idx: usize) -> Result<(), Error> {
            Ok(())
        }

        fn clear_stage(&mut self) -> Result<(), Error> {
            Ok(())
        }

        fn current_stage(&self) -> Result<Option<usize>, Error> {
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

    #[must_use]
    pub fn test_std_state<I: Input>() -> StdState<I, InMemoryCorpus<I>, StdRand, InMemoryCorpus<I>>
    {
        StdState::new(
            StdRand::with_seed(0),
            InMemoryCorpus::<I>::new(),
            InMemoryCorpus::new(),
            &mut (),
            &mut (),
        )
        .expect("couldn't instantiate the test state")
    }

    #[test]
    fn resume_simple() {
        let mut state = test_std_state::<NopInput>();
        let (completed, stages) = test_resume_stages();

        test_resume(&completed, &mut state, stages);
    }
}

#[cfg(feature = "python")]
#[allow(missing_docs)]
/// `State` Python bindings
pub mod pybind {
    use alloc::{boxed::Box, vec::Vec};
    use std::path::PathBuf;

    use libafl_bolts::{ownedref::OwnedMutPtr, rands::pybind::PythonRand};
    use pyo3::{prelude::*, types::PyDict};

    use crate::{
        corpus::pybind::PythonCorpus,
        events::pybind::PythonEventManager,
        executors::pybind::PythonExecutor,
        feedbacks::pybind::PythonFeedback,
        fuzzer::pybind::PythonStdFuzzerWrapper,
        generators::pybind::PythonGenerator,
        inputs::BytesInput,
        pybind::PythonMetadata,
        state::{
            HasCorpus, HasExecutions, HasMaxSize, HasMetadata, HasRand, HasSolutions, StdState,
        },
    };

    /// `StdState` with fixed generics
    pub type PythonStdState = StdState<BytesInput, PythonCorpus, PythonRand, PythonCorpus>;

    #[pyclass(unsendable, name = "StdState")]
    #[derive(Debug)]
    /// Python class for StdState
    pub struct PythonStdStateWrapper {
        /// Rust wrapped StdState object
        pub inner: OwnedMutPtr<PythonStdState>,
    }

    impl PythonStdStateWrapper {
        pub fn wrap(r: &mut PythonStdState) -> Self {
            Self {
                inner: OwnedMutPtr::Ptr(r),
            }
        }

        #[must_use]
        pub fn unwrap(&self) -> &PythonStdState {
            self.inner.as_ref()
        }

        pub fn unwrap_mut(&mut self) -> &mut PythonStdState {
            self.inner.as_mut()
        }
    }

    #[pymethods]
    impl PythonStdStateWrapper {
        #[new]
        fn new(
            py_rand: PythonRand,
            corpus: PythonCorpus,
            solutions: PythonCorpus,
            feedback: &mut PythonFeedback,
            objective: &mut PythonFeedback,
        ) -> Self {
            Self {
                inner: OwnedMutPtr::Owned(Box::new(
                    StdState::new(py_rand, corpus, solutions, feedback, objective)
                        .expect("Failed to create a new StdState"),
                )),
            }
        }

        fn metadata(&mut self) -> PyObject {
            let meta = self.inner.as_mut().metadata_map_mut();
            if !meta.contains::<PythonMetadata>() {
                Python::with_gil(|py| {
                    let dict: Py<PyDict> = PyDict::new(py).into();
                    meta.insert(PythonMetadata::new(dict.to_object(py)));
                });
            }
            meta.get::<PythonMetadata>().unwrap().map.clone()
        }

        fn rand(&self) -> PythonRand {
            self.inner.as_ref().rand().clone()
        }

        fn corpus(&self) -> PythonCorpus {
            self.inner.as_ref().corpus().clone()
        }

        fn solutions(&self) -> PythonCorpus {
            self.inner.as_ref().solutions().clone()
        }

        fn executions(&self) -> usize {
            *self.inner.as_ref().executions()
        }

        fn max_size(&self) -> usize {
            self.inner.as_ref().max_size()
        }

        fn generate_initial_inputs(
            &mut self,
            py_fuzzer: &mut PythonStdFuzzerWrapper,
            py_executor: &mut PythonExecutor,
            py_generator: &mut PythonGenerator,
            py_mgr: &mut PythonEventManager,
            num: usize,
        ) {
            self.inner
                .as_mut()
                .generate_initial_inputs(
                    py_fuzzer.unwrap_mut(),
                    py_executor,
                    py_generator,
                    py_mgr,
                    num,
                )
                .expect("Failed to generate the initial corpus");
        }

        #[allow(clippy::needless_pass_by_value)]
        fn load_initial_inputs(
            &mut self,
            py_fuzzer: &mut PythonStdFuzzerWrapper,
            py_executor: &mut PythonExecutor,
            py_mgr: &mut PythonEventManager,
            in_dirs: Vec<PathBuf>,
        ) {
            self.inner
                .as_mut()
                .load_initial_inputs(py_fuzzer.unwrap_mut(), py_executor, py_mgr, &in_dirs)
                .expect("Failed to load the initial corpus");
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonStdStateWrapper>()?;
        Ok(())
    }
}
