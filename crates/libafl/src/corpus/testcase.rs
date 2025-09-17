//! The [`Testcase`] is a struct embedded in each [`Corpus`].
//! It will contain a respective input, and metadata.

#[cfg(feature = "track_hit_feedbacks")]
use alloc::{borrow::Cow, vec::Vec};
use alloc::{rc::Rc, string::String};
use core::{
    fmt::{Debug, Formatter},
    hash::Hasher,
    ops::{Deref, DerefMut},
    time::Duration,
};
use std::{
    cell::{Ref, RefCell, RefMut},
    marker::PhantomData,
};

use libafl_bolts::{
    HasLen, hasher_std,
    serdeany::{SerdeAny, SerdeAnyMap},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use typed_builder::TypedBuilder;

use crate::{
    Error, HasMetadata, HasMetadataMut,
    corpus::{Corpus, CorpusId},
    inputs::Input,
    state::HasCorpus,
};

/// A testcase metadata cell that can be instantiated only from a [`TestcaseMetadata`].
pub trait HasInstantiableTestcaseMetadata: HasTestcaseMetadata {
    /// Instantiate a testcase metadata cell from a [`TestcaseMetadata`].
    fn instantiate(metadata: TestcaseMetadata) -> Self;
}

/// Trait implemented by possible [`TestcaseMetadata`] cells.
pub trait HasTestcaseMetadata {
    /// A reference to a testcase metadata.
    type TestcaseMetadataRef<'a>: Deref<Target = TestcaseMetadata>
    where
        Self: 'a;

    /// A mutable reference to a testcase metadata.
    type TestcaseMetadataRefMut<'a>: DerefMut<Target = TestcaseMetadata>
    where
        Self: 'a;

    /// Get a reference to the testcase metadata.
    fn testcase_metadata<'a>(&'a self) -> Self::TestcaseMetadataRef<'a>;
    /// Get a mutable reference to the testcase metadata.
    fn testcase_metadata_mut<'a>(&'a self) -> Self::TestcaseMetadataRefMut<'a>;
    /// Consume the cell, and get the inner testcase metadata.
    fn into_testcase_metadata(self) -> TestcaseMetadata;
}

/// A dummy (empty) [`TestcaseMetadata`] reference.
#[derive(Default, Clone, Copy, Debug)]
pub struct NopTestcaseMetadataRef<'a>(PhantomData<&'a ()>);

/// A dummy (empty) [`TestcaseMetadata`] cell.
#[derive(Default, Clone, Copy, Debug)]
pub struct NopTestcaseMetadataCell;

impl<'a> Deref for NopTestcaseMetadataRef<'a> {
    type Target = TestcaseMetadata;

    fn deref(&self) -> &Self::Target {
        panic!("Invalid testcase metadata ref")
    }
}

impl<'a> DerefMut for NopTestcaseMetadataRef<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        panic!("Invalid testcase metadata ref mut")
    }
}

impl HasTestcaseMetadata for NopTestcaseMetadataCell {
    type TestcaseMetadataRef<'a> = NopTestcaseMetadataRef<'a>;
    type TestcaseMetadataRefMut<'a> = NopTestcaseMetadataRef<'a>;

    fn testcase_metadata<'a>(&'a self) -> Self::TestcaseMetadataRef<'a> {
        NopTestcaseMetadataRef::default()
    }

    fn testcase_metadata_mut<'a>(&'a self) -> Self::TestcaseMetadataRefMut<'a> {
        NopTestcaseMetadataRef::default()
    }

    fn into_testcase_metadata(self) -> TestcaseMetadata {
        panic!("Invalid testcase metadata")
    }
}

impl HasTestcaseMetadata for RefCell<TestcaseMetadata> {
    type TestcaseMetadataRef<'a> = Ref<'a, TestcaseMetadata>;
    type TestcaseMetadataRefMut<'a> = RefMut<'a, TestcaseMetadata>;

    // fn new(md: TestcaseMetadata) -> Self {
    //     RefCell::new(md)
    // }

    fn testcase_metadata<'a>(&'a self) -> Self::TestcaseMetadataRef<'a> {
        self.borrow()
    }

    fn testcase_metadata_mut<'a>(&'a self) -> Self::TestcaseMetadataRefMut<'a> {
        self.borrow_mut()
    }

    fn into_testcase_metadata(self) -> TestcaseMetadata {
        self.into_inner()
    }
}

impl HasInstantiableTestcaseMetadata for RefCell<TestcaseMetadata> {
    fn instantiate(metadata: TestcaseMetadata) -> Self {
        RefCell::new(metadata)
    }
}

impl<T> HasTestcaseMetadata for Rc<T>
where
    T: HasTestcaseMetadata + Clone,
{
    type TestcaseMetadataRef<'a>
        = T::TestcaseMetadataRef<'a>
    where
        Self: 'a;

    type TestcaseMetadataRefMut<'a>
        = T::TestcaseMetadataRefMut<'a>
    where
        Self: 'a;

    // fn new(md: TestcaseMetadata) -> Self {
    //     Rc::new(T::new(md))
    // }
    fn testcase_metadata<'a>(&'a self) -> Self::TestcaseMetadataRef<'a> {
        self.deref().testcase_metadata()
    }

    fn testcase_metadata_mut<'a>(&'a self) -> Self::TestcaseMetadataRefMut<'a> {
        self.deref().testcase_metadata_mut()
    }

    fn into_testcase_metadata(self) -> TestcaseMetadata {
        self.deref().clone().into_testcase_metadata()
    }
}

impl<T> HasInstantiableTestcaseMetadata for Rc<T>
where
    T: HasInstantiableTestcaseMetadata + Clone,
{
    fn instantiate(metadata: TestcaseMetadata) -> Self {
        Rc::new(T::instantiate(metadata))
    }
}

impl<I, M> HasTestcaseMetadata for Testcase<I, M>
where
    M: HasTestcaseMetadata,
{
    type TestcaseMetadataRef<'a>
        = M::TestcaseMetadataRef<'a>
    where
        Self: 'a;
    type TestcaseMetadataRefMut<'a>
        = M::TestcaseMetadataRefMut<'a>
    where
        Self: 'a;

    fn testcase_metadata<'a>(&'a self) -> Self::TestcaseMetadataRef<'a> {
        self.metadata.testcase_metadata()
    }

    fn testcase_metadata_mut<'a>(&'a self) -> Self::TestcaseMetadataRefMut<'a> {
        self.metadata.testcase_metadata_mut()
    }

    fn into_testcase_metadata(self) -> TestcaseMetadata {
        self.metadata.into_testcase_metadata()
    }
}

/// Shorthand to receive a [`Ref`] or [`RefMut`] to a stored [`Testcase`], by [`CorpusId`].
/// For a normal state, this should return a [`Testcase`] in the corpus, not the objectives.
pub trait HasTestcase<I>: HasCorpus<I> {
    /// Shorthand to receive a [`Ref`] to a stored [`Testcase`], by [`CorpusId`].
    /// For a normal state, this should return a [`Testcase`] in the corpus, not the objectives.
    fn testcase(
        &self,
        id: CorpusId,
    ) -> Result<Testcase<I, <Self::Corpus as Corpus<I>>::TestcaseMetadataCell>, Error>;
}

/// The [`Testcase`] metadata.
#[derive(Serialize, Deserialize, Clone, Debug, Default, TypedBuilder)]
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
pub struct Testcase<I, M> {
    /// The [`Input`] of this [`Testcase`], or `None`, if it is not currently in memory
    input: Rc<I>,

    /// The unique id for [`Testcase`].
    /// It should uniquely identify the input.
    id: String,

    /// The metadata linked to the [`Testcase`]
    pub(crate) metadata: M,
}

impl<I, M> Clone for Testcase<I, M>
where
    M: Clone,
{
    fn clone(&self) -> Self {
        Self {
            input: self.input.clone(),
            id: self.id.clone(),
            metadata: self.metadata.clone(),
        }
    }
}

impl<I, M> Debug for Testcase<I, M>
where
    I: Debug,
    M: HasTestcaseMetadata,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Testcase")
            .field("input", self.input.as_ref())
            .field("id", &self.id)
            .field("metadata", &*self.metadata.testcase_metadata())
            .finish()
    }
}

impl<I, M> Serialize for Testcase<I, M>
where
    M: HasTestcaseMetadata,
{
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        todo!()
    }
}

impl<'de, I, M> Deserialize<'de> for Testcase<I, M>
where
    M: HasTestcaseMetadata,
{
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!()
    }
}

impl HasMetadata for TestcaseMetadata {
    fn metadata_map(&self) -> &SerdeAnyMap {
        &self.metadata
    }
}

impl HasMetadataMut for TestcaseMetadata {
    fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<I, M> Testcase<I, M> {
    /// Get the input
    #[inline]
    pub fn input(&self) -> Rc<I> {
        self.input.clone()
    }

    /// Get the associated unique ID.
    pub fn id(&self) -> &String {
        &self.id
    }
}

impl<I, M> Testcase<I, M>
where
    I: HasLen,
{
    /// Get the input length
    pub fn input_len(&self) -> usize {
        self.input.len()
    }
}

impl<I, M> Testcase<I, M>
where
    I: Input,
    M: HasTestcaseMetadata,
{
    /// Create a new Testcase instance given an input
    pub fn new(input: Rc<I>, metadata: M) -> Self {
        let id = Self::compute_id(&input);

        Self {
            input,
            id,
            metadata,
        }
    }

    /// Get the unique ID associated to an input.
    pub fn compute_id(input: &I) -> String {
        let mut hasher = hasher_std();
        input.hash(&mut hasher);
        let hash = hasher.finish();
        format!("{hash:0>8x}")
    }
}

impl<I, M> Testcase<I, M>
where
    M: HasTestcaseMetadata,
    I: Clone,
{
    /// Clone the input embedded in the [`Testcase`].
    pub fn cloned_input(&self) -> I {
        self.input.as_ref().clone()
    }
}

/// Impl of a testcase
impl<I, M> Testcase<I, M>
where
    M: HasTestcaseMetadata,
{
    /// Get the same testcase, with an owned [`TestcaseMetadata`].
    pub fn cloned(self) -> Testcase<I, RefCell<TestcaseMetadata>> {
        Testcase {
            input: self.input,
            id: self.id,
            metadata: RefCell::new(self.metadata.into_testcase_metadata()),
        }
    }

    /// Decompose a [`Testcase`] into its inner input and metadata.
    pub fn into_inner(self) -> (Rc<I>, TestcaseMetadata) {
        (self.input, self.metadata.into_testcase_metadata())
    }

    /// Test whether the metadata map contains a metadata
    #[inline]
    pub fn has_metadata<MT>(&self) -> bool
    where
        MT: SerdeAny,
    {
        self.metadata.testcase_metadata().has_metadata::<MT>()
    }

    /// Get the executions
    #[inline]
    pub fn executions(&self) -> u64 {
        self.metadata.testcase_metadata().executions()
    }

    /// Get the `scheduled_count`
    #[inline]
    pub fn scheduled_count(&self) -> usize {
        self.metadata.testcase_metadata().scheduled_count()
    }

    /// Get `disabled`
    #[inline]
    pub fn disabled(&mut self) -> bool {
        self.metadata.testcase_metadata_mut().disabled()
    }

    /// Get the id of the parent, that this testcase was derived from
    #[must_use]
    pub fn parent_id(&self) -> Option<CorpusId> {
        self.metadata.testcase_metadata().parent_id()
    }

    /// Gets how many objectives were found by mutating this testcase
    pub fn objectives_found(&self) -> usize {
        self.metadata.testcase_metadata().objectives_found()
    }

    /// Set the executions
    #[inline]
    pub fn set_executions(&mut self, executions: u64) {
        self.metadata
            .testcase_metadata_mut()
            .set_executions(executions);
    }

    /// Sets the execution time of the current testcase
    #[inline]
    pub fn set_exec_time(&mut self, time: Duration) {
        self.metadata.testcase_metadata_mut().set_exec_time(time);
    }

    /// Set the `scheduled_count`
    #[inline]
    pub fn set_scheduled_count(&mut self, scheduled_count: usize) {
        self.metadata
            .testcase_metadata_mut()
            .set_scheduled_count(scheduled_count);
    }

    /// Set the testcase as disabled
    #[inline]
    pub fn set_disabled(&mut self, disabled: bool) {
        self.metadata.testcase_metadata_mut().set_disabled(disabled);
    }

    /// Sets the id of the parent, that this testcase was derived from
    pub fn set_parent_id(&mut self, parent_id: CorpusId) {
        self.metadata
            .testcase_metadata_mut()
            .set_parent_id(parent_id);
    }

    /// Sets the id of the parent, that this testcase was derived from
    pub fn set_parent_id_optional(&mut self, parent_id: Option<CorpusId>) {
        self.metadata
            .testcase_metadata_mut()
            .set_parent_id_optional(parent_id);
    }

    /// Adds one objective to the `objectives_found` counter. Mostly called from crash handler or executor.
    pub fn found_objective(&mut self) {
        self.metadata.testcase_metadata_mut().found_objective();
    }
}

impl TestcaseMetadata {
    /// Get the executions
    #[inline]
    pub fn executions(&self) -> u64 {
        self.executions
    }

    /// Get the execution time of the testcase
    #[inline]
    pub fn exec_time(&self) -> &Option<Duration> {
        &self.exec_time
    }

    /// Get the `scheduled_count`
    #[inline]
    pub fn scheduled_count(&self) -> usize {
        self.scheduled_count
    }

    /// Get `disabled`
    #[inline]
    pub fn disabled(&mut self) -> bool {
        self.disabled
    }

    /// Get the hit feedbacks
    #[inline]
    #[cfg(feature = "track_hit_feedbacks")]
    pub fn hit_feedbacks(&self) -> &Vec<Cow<'static, str>> {
        &self.hit_feedbacks
    }

    /// Get the hit objectives
    #[inline]
    #[cfg(feature = "track_hit_feedbacks")]
    pub fn hit_objectives(&self) -> &Vec<Cow<'static, str>> {
        &self.hit_objectives
    }

    /// Get the id of the parent, that this testcase was derived from
    #[must_use]
    pub fn parent_id(&self) -> Option<CorpusId> {
        self.parent_id
    }

    /// Gets how many objectives were found by mutating this testcase
    pub fn objectives_found(&self) -> usize {
        self.objectives_found
    }

    /// Get the executions (mutable)
    #[inline]
    pub fn executions_mut(&mut self) -> &mut u64 {
        &mut self.executions
    }

    /// Set the executions
    #[inline]
    pub fn set_executions(&mut self, executions: u64) {
        self.executions = executions;
    }

    /// Get a mutable reference to the execution time
    pub fn exec_time_mut(&mut self) -> &mut Option<Duration> {
        &mut self.exec_time
    }

    /// Sets the execution time of the current testcase
    #[inline]
    pub fn set_exec_time(&mut self, time: Duration) {
        self.exec_time = Some(time);
    }

    /// Set the `scheduled_count`
    #[inline]
    pub fn set_scheduled_count(&mut self, scheduled_count: usize) {
        self.scheduled_count = scheduled_count;
    }

    /// Set the testcase as disabled
    #[inline]
    pub fn set_disabled(&mut self, disabled: bool) {
        self.disabled = disabled;
    }

    /// Get the hit feedbacks (mutable)
    #[inline]
    #[cfg(feature = "track_hit_feedbacks")]
    pub fn hit_feedbacks_mut(&mut self) -> &mut Vec<Cow<'static, str>> {
        &mut self.hit_feedbacks
    }

    /// Get the hit objectives (mutable)
    #[inline]
    #[cfg(feature = "track_hit_feedbacks")]
    pub fn hit_objectives_mut(&mut self) -> &mut Vec<Cow<'static, str>> {
        &mut self.hit_objectives
    }

    /// Sets the id of the parent, that this testcase was derived from
    pub fn set_parent_id(&mut self, parent_id: CorpusId) {
        self.parent_id = Some(parent_id);
    }

    /// Sets the id of the parent, that this testcase was derived from
    pub fn set_parent_id_optional(&mut self, parent_id: Option<CorpusId>) {
        self.parent_id = parent_id;
    }

    /// Adds one objectives to the `objectives_found` counter. Mostly called from crash handler or executor.
    pub fn found_objective(&mut self) {
        let count = self.objectives_found.saturating_add(1);
        self.objectives_found = count;
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
