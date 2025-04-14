//! The [`Testcase`] is a struct embedded in each [`Corpus`].
//! It will contain a respective input, and metadata.

use alloc::string::String;
#[cfg(feature = "track_hit_feedbacks")]
use alloc::{borrow::Cow, vec::Vec};
use core::{
    cell::{Ref, RefMut},
    hash::Hasher,
    time::Duration,
};

use libafl_bolts::{hasher_std, serdeany::SerdeAnyMap};
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;

use crate::{Error, HasMetadata, corpus::CorpusId, inputs::Input};

/// Shorthand to receive a [`Ref`] or [`RefMut`] to a stored [`Testcase`], by [`CorpusId`].
/// For a normal state, this should return a [`Testcase`] in the corpus, not the objectives.
pub trait HasTestcase<I> {
    /// Shorthand to receive a [`Ref`] to a stored [`Testcase`], by [`CorpusId`].
    /// For a normal state, this should return a [`Testcase`] in the corpus, not the objectives.
    fn testcase(&self, id: CorpusId) -> Result<Ref<Testcase<I>>, Error>;

    /// Shorthand to receive a [`RefMut`] to a stored [`Testcase`], by [`CorpusId`].
    /// For a normal state, this should return a [`Testcase`] in the corpus, not the objectives.
    fn testcase_mut(&self, id: CorpusId) -> Result<RefMut<Testcase<I>>, Error>;
}

#[derive(Serialize, Deserialize, Clone, Debug, TypedBuilder)]
pub struct TestcaseMetadata {
    /// Map of metadata associated with this [`Testcase`]
    #[builder(default)]
    metadata: SerdeAnyMap,
    /// Time needed to execute the input
    #[builder(default)]
    exec_time: Option<Duration>,
    /// Number of fuzzing iterations of this particular input updated in `perform_mutational`
    #[builder(default = 0)]
    scheduled_count: usize,
    /// Number of executions done at discovery time
    executions: u64,
    /// Parent [`CorpusId`], if known
    #[builder(default)]
    parent_id: Option<CorpusId>,
    /// If the testcase is "disabled"
    #[builder(default = false)]
    disabled: bool,
    /// has found crash (or timeout) or not
    #[builder(default = 0)]
    objectives_found: usize,
    /// Vector of `Feedback` names that deemed this `Testcase` as corpus worthy
    #[cfg(feature = "track_hit_feedbacks")]
    hit_feedbacks: Vec<Cow<'static, str>>,
    /// Vector of `Feedback` names that deemed this `Testcase` as solution worthy
    #[cfg(feature = "track_hit_feedbacks")]
    hit_objectives: Vec<Cow<'static, str>>,
}

/// An entry in the [`Testcase`] Corpus
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Testcase<I> {
    /// The [`Input`] of this [`Testcase`], or `None`, if it is not currently in memory
    input: I,
    /// The unique id for [`Testcase`].
    /// It should uniquely identify input at the very least.
    id: String,
    /// The metadata linked to the [`Testcase`]
    metadata: TestcaseMetadata,
    // /// The filename for this [`Testcase`]
    // filename: Option<String>,
}

impl<I> HasMetadata for Testcase<I> {
    /// Get all the metadata into an [`hashbrown::HashMap`]
    #[inline]
    fn metadata_map(&self) -> &SerdeAnyMap {
        &self.metadata.metadata
    }

    /// Get all the metadata into an [`hashbrown::HashMap`] (mutable)
    #[inline]
    fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata.metadata
    }
}

impl<I> Testcase<I>
where
    I: Input,
{
    fn gen_id(input: &I, _md: &TestcaseMetadata) -> String {
        let mut hasher = hasher_std();
        input.hash(&mut hasher);
        let hash = hasher.finish();
        format!("{hash:0>8x}")
    }

    /// Create a new Testcase instance given an input
    #[inline]
    pub fn new(input: I, metadata: TestcaseMetadata) -> Self {
        let id = Self::gen_id(&input, &metadata);

        Self {
            input,
            id,
            metadata,
        }
    }
}

/// Impl of a testcase
impl<I> Testcase<I> {
    pub fn id(&self) -> &String {
        &self.id
    }

    pub fn metadata(&self) -> &TestcaseMetadata {
        &self.metadata
    }

    /// Get the input, if available any
    #[inline]
    pub fn input(&self) -> &I {
        &self.input
    }

    /// Get the input, if any (mutable)
    #[inline]
    pub fn input_mut(&mut self) -> &mut I {
        // self.cached_len = None;
        &mut self.input
    }

    /// Set the input
    #[inline]
    pub fn set_input(&mut self, input: I) {
        self.input = input;
    }

    /// Get the executions
    #[inline]
    pub fn executions(&self) -> u64 {
        self.metadata.executions
    }

    /// Get the executions (mutable)
    #[inline]
    pub fn executions_mut(&mut self) -> &mut u64 {
        &mut self.metadata.executions
    }

    /// Set the executions
    #[inline]
    pub fn set_executions(&mut self, executions: u64) {
        self.metadata.executions = executions;
    }

    /// Get the execution time of the testcase
    #[inline]
    pub fn exec_time(&self) -> &Option<Duration> {
        &self.metadata.exec_time
    }

    /// Get the execution time of the testcase (mutable)
    #[inline]
    pub fn exec_time_mut(&mut self) -> &mut Option<Duration> {
        &mut self.metadata.exec_time
    }

    /// Sets the execution time of the current testcase
    #[inline]
    pub fn set_exec_time(&mut self, time: Duration) {
        self.metadata.exec_time = Some(time);
    }

    /// Get the `scheduled_count`
    #[inline]
    pub fn scheduled_count(&self) -> usize {
        self.metadata.scheduled_count
    }

    /// Set the `scheduled_count`
    #[inline]
    pub fn set_scheduled_count(&mut self, scheduled_count: usize) {
        self.metadata.scheduled_count = scheduled_count;
    }

    /// Get `disabled`
    #[inline]
    pub fn disabled(&mut self) -> bool {
        self.metadata.disabled
    }

    /// Set the testcase as disabled
    #[inline]
    pub fn set_disabled(&mut self, disabled: bool) {
        self.metadata.disabled = disabled;
    }

    /// Get the hit feedbacks
    #[inline]
    #[cfg(feature = "track_hit_feedbacks")]
    pub fn hit_feedbacks(&self) -> &Vec<Cow<'static, str>> {
        &self.metadata.hit_feedbacks
    }

    /// Get the hit feedbacks (mutable)
    #[inline]
    #[cfg(feature = "track_hit_feedbacks")]
    pub fn hit_feedbacks_mut(&mut self) -> &mut Vec<Cow<'static, str>> {
        &mut self.metadata.hit_feedbacks
    }

    /// Get the hit objectives
    #[inline]
    #[cfg(feature = "track_hit_feedbacks")]
    pub fn hit_objectives(&self) -> &Vec<Cow<'static, str>> {
        &self.metadata.hit_objectives
    }

    /// Get the hit objectives (mutable)
    #[inline]
    #[cfg(feature = "track_hit_feedbacks")]
    pub fn hit_objectives_mut(&mut self) -> &mut Vec<Cow<'static, str>> {
        &mut self.metadata.hit_objectives
    }

    // /// Creates a testcase, attaching the id of the parent
    // /// that this [`Testcase`] was derived from on creation
    // pub fn with_parent_id(input: I, parent_id: CorpusId) -> Self {
    //     Testcase {
    //         input: Some(input),
    //         filename: None,
    //         #[cfg(feature = "std")]
    //         file_path: None,
    //         metadata: SerdeAnyMap::default(),
    //         #[cfg(feature = "std")]
    //         metadata_path: None,
    //         exec_time: None,
    //         cached_len: None,
    //         executions: 0,
    //         scheduled_count: 0,
    //         parent_id: Some(parent_id),
    //         disabled: false,
    //         objectives_found: 0,
    //         #[cfg(feature = "track_hit_feedbacks")]
    //         hit_feedbacks: Vec::new(),
    //         #[cfg(feature = "track_hit_feedbacks")]
    //         hit_objectives: Vec::new(),
    //     }
    // }

    /// Get the id of the parent, that this testcase was derived from
    #[must_use]
    pub fn parent_id(&self) -> Option<CorpusId> {
        self.metadata.parent_id
    }

    /// Sets the id of the parent, that this testcase was derived from
    pub fn set_parent_id(&mut self, parent_id: CorpusId) {
        self.metadata.parent_id = Some(parent_id);
    }

    /// Sets the id of the parent, that this testcase was derived from
    pub fn set_parent_id_optional(&mut self, parent_id: Option<CorpusId>) {
        self.metadata.parent_id = parent_id;
    }

    /// Gets how many objectives were found by mutating this testcase
    pub fn objectives_found(&self) -> usize {
        self.metadata.objectives_found
    }

    /// Adds one objectives to the `objectives_found` counter. Mostly called from crash handler or executor.
    pub fn found_objective(&mut self) {
        self.metadata.objectives_found = self.metadata.objectives_found.saturating_add(1);
    }
}

/// The Metadata for each testcase used in power schedules.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    expect(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct SchedulerTestcaseMetadata {
    /// Number of bits set in bitmap, updated in `calibrate_case`
    bitmap_size: u64,
    /// Number of queue cycles behind
    handicap: u64,
    /// Path depth, initialized in `on_add`
    depth: u64,
    /// Offset in `n_fuzz`
    n_fuzz_entry: usize,
    /// Cycles used to calibrate this (not really needed if it were not for `on_replace` and `on_remove`)
    cycle_and_time: (Duration, usize),
}

impl SchedulerTestcaseMetadata {
    /// Create new [`struct@SchedulerTestcaseMetadata`]
    #[must_use]
    pub fn new(depth: u64) -> Self {
        Self {
            bitmap_size: 0,
            handicap: 0,
            depth,
            n_fuzz_entry: 0,
            cycle_and_time: (Duration::default(), 0),
        }
    }

    /// Create new [`struct@SchedulerTestcaseMetadata`] given `n_fuzz_entry`
    #[must_use]
    pub fn with_n_fuzz_entry(depth: u64, n_fuzz_entry: usize) -> Self {
        Self {
            bitmap_size: 0,
            handicap: 0,
            depth,
            n_fuzz_entry,
            cycle_and_time: (Duration::default(), 0),
        }
    }

    /// Get the bitmap size
    #[inline]
    #[must_use]
    pub fn bitmap_size(&self) -> u64 {
        self.bitmap_size
    }

    /// Set the bitmap size
    #[inline]
    pub fn set_bitmap_size(&mut self, val: u64) {
        self.bitmap_size = val;
    }

    /// Get the handicap
    #[inline]
    #[must_use]
    pub fn handicap(&self) -> u64 {
        self.handicap
    }

    /// Set the handicap
    #[inline]
    pub fn set_handicap(&mut self, val: u64) {
        self.handicap = val;
    }

    /// Get the depth
    #[inline]
    #[must_use]
    pub fn depth(&self) -> u64 {
        self.depth
    }

    /// Set the depth
    #[inline]
    pub fn set_depth(&mut self, val: u64) {
        self.depth = val;
    }

    /// Get the `n_fuzz_entry`
    #[inline]
    #[must_use]
    pub fn n_fuzz_entry(&self) -> usize {
        self.n_fuzz_entry
    }

    /// Set the `n_fuzz_entry`
    #[inline]
    pub fn set_n_fuzz_entry(&mut self, val: usize) {
        self.n_fuzz_entry = val;
    }

    /// Get the cycles
    #[inline]
    #[must_use]
    pub fn cycle_and_time(&self) -> (Duration, usize) {
        self.cycle_and_time
    }

    #[inline]
    /// Setter for cycles
    pub fn set_cycle_and_time(&mut self, cycle_and_time: (Duration, usize)) {
        self.cycle_and_time = cycle_and_time;
    }
}

libafl_bolts::impl_serdeany!(SchedulerTestcaseMetadata);
