//! The testcase is a struct embedded in each corpus.
//! It will contain a respective input, and metadata.

use alloc::string::String;
use core::{
    cell::{Ref, RefMut},
    time::Duration,
};
#[cfg(feature = "std")]
use std::path::PathBuf;

use libafl_bolts::{serdeany::SerdeAnyMap, HasLen};
use serde::{Deserialize, Serialize};

use super::Corpus;
use crate::{
    corpus::CorpusId,
    inputs::{Input, UsesInput},
    state::HasMetadata,
    Error,
};

/// Shorthand to receive a [`Ref`] or [`RefMut`] to a stored [`Testcase`], by [`CorpusId`].
/// For a normal state, this should return a [`Testcase`] in the corpus, not the objectives.
pub trait HasTestcase: UsesInput {
    /// Shorthand to receive a [`Ref`] to a stored [`Testcase`], by [`CorpusId`].
    /// For a normal state, this should return a [`Testcase`] in the corpus, not the objectives.
    fn testcase(&self, id: CorpusId) -> Result<Ref<Testcase<<Self as UsesInput>::Input>>, Error>;

    /// Shorthand to receive a [`RefMut`] to a stored [`Testcase`], by [`CorpusId`].
    /// For a normal state, this should return a [`Testcase`] in the corpus, not the objectives.
    fn testcase_mut(
        &self,
        id: CorpusId,
    ) -> Result<RefMut<Testcase<<Self as UsesInput>::Input>>, Error>;
}

/// An entry in the Testcase Corpus
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct Testcase<I>
where
    I: Input,
{
    /// The [`Input`] of this [`Testcase`], or `None`, if it is not currently in memory
    input: Option<I>,
    /// The filename for this [`Testcase`]
    filename: Option<String>,
    /// Complete path to the [`Input`] on disk, if this [`Testcase`] is backed by a file in the filesystem
    #[cfg(feature = "std")]
    file_path: Option<PathBuf>,
    /// Map of metadata associated with this [`Testcase`]
    metadata: SerdeAnyMap,
    /// Complete path to the metadata [`SerdeAnyMap`] on disk, if this [`Testcase`] is backed by a file in the filesystem
    #[cfg(feature = "std")]
    metadata_path: Option<PathBuf>,
    /// Time needed to execute the input
    exec_time: Option<Duration>,
    /// Cached len of the input, if any
    cached_len: Option<usize>,
    /// Number of executions done at discovery time
    executions: u64,
    /// Number of fuzzing iterations of this particular input updated in `perform_mutational`
    scheduled_count: usize,
    /// Parent [`CorpusId`], if known
    parent_id: Option<CorpusId>,
}

impl<I> HasMetadata for Testcase<I>
where
    I: Input,
{
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

/// Impl of a testcase
impl<I> Testcase<I>
where
    I: Input,
{
    /// Returns this [`Testcase`] with a loaded `Input`]
    pub fn load_input<C: Corpus<Input = I>>(&mut self, corpus: &C) -> Result<&I, Error> {
        corpus.load_input_into(self)?;
        Ok(self.input.as_ref().unwrap())
    }

    /// Get the input, if available any
    #[inline]
    pub fn input(&self) -> &Option<I> {
        &self.input
    }

    /// Get the input, if any (mutable)
    #[inline]
    pub fn input_mut(&mut self) -> &mut Option<I> {
        // self.cached_len = None;
        &mut self.input
    }

    /// Set the input
    #[inline]
    pub fn set_input(&mut self, mut input: I) {
        input.wrapped_as_testcase();
        self.input = Some(input);
    }

    /// Get the filename, if any
    #[inline]
    pub fn filename(&self) -> &Option<String> {
        &self.filename
    }

    /// Get the filename, if any (mutable)
    #[inline]
    pub fn filename_mut(&mut self) -> &mut Option<String> {
        &mut self.filename
    }

    /// Get the filename path, if any
    #[inline]
    #[cfg(feature = "std")]
    pub fn file_path(&self) -> &Option<PathBuf> {
        &self.file_path
    }

    /// Get the filename path, if any (mutable)
    #[inline]
    #[cfg(feature = "std")]
    pub fn file_path_mut(&mut self) -> &mut Option<PathBuf> {
        &mut self.file_path
    }

    /// Get the metadata path, if any
    #[inline]
    #[cfg(feature = "std")]
    pub fn metadata_path(&self) -> &Option<PathBuf> {
        &self.metadata_path
    }

    /// Get the metadata path, if any (mutable)
    #[inline]
    #[cfg(feature = "std")]
    pub fn metadata_path_mut(&mut self) -> &mut Option<PathBuf> {
        &mut self.metadata_path
    }

    /// Get the execution time of the testcase
    #[inline]
    pub fn exec_time(&self) -> &Option<Duration> {
        &self.exec_time
    }

    /// Get the execution time of the testcase (mutable)
    #[inline]
    pub fn exec_time_mut(&mut self) -> &mut Option<Duration> {
        &mut self.exec_time
    }

    /// Sets the execution time of the current testcase
    #[inline]
    pub fn set_exec_time(&mut self, time: Duration) {
        self.exec_time = Some(time);
    }

    /// Get the executions
    #[inline]
    pub fn executions(&self) -> &u64 {
        &self.executions
    }

    /// Get the executions (mutable)
    #[inline]
    pub fn executions_mut(&mut self) -> &mut u64 {
        &mut self.executions
    }

    /// Get the `scheduled_count`
    #[inline]
    pub fn scheduled_count(&self) -> usize {
        self.scheduled_count
    }

    /// Set the `scheduled_count`
    #[inline]
    pub fn set_scheduled_count(&mut self, scheduled_count: usize) {
        self.scheduled_count = scheduled_count;
    }

    /// Create a new Testcase instance given an input
    #[inline]
    pub fn new(mut input: I) -> Self {
        input.wrapped_as_testcase();
        Self {
            input: Some(input),
            filename: None,
            #[cfg(feature = "std")]
            file_path: None,
            metadata: SerdeAnyMap::default(),
            #[cfg(feature = "std")]
            metadata_path: None,
            exec_time: None,
            cached_len: None,
            executions: 0,
            scheduled_count: 0,
            parent_id: None,
        }
    }

    /// Creates a testcase, attaching the id of the parent
    /// that this [`Testcase`] was derived from on creation
    pub fn with_parent_id(mut input: I, parent_id: CorpusId) -> Self {
        input.wrapped_as_testcase();
        Testcase {
            input: Some(input),
            filename: None,
            #[cfg(feature = "std")]
            file_path: None,
            metadata: SerdeAnyMap::default(),
            #[cfg(feature = "std")]
            metadata_path: None,
            exec_time: None,
            cached_len: None,
            executions: 0,
            scheduled_count: 0,
            parent_id: Some(parent_id),
        }
    }

    /// Create a new Testcase instance given an [`Input`] and a `filename`
    #[inline]
    pub fn with_filename(mut input: I, filename: String) -> Self {
        input.wrapped_as_testcase();
        Self {
            input: Some(input),
            filename: Some(filename),
            #[cfg(feature = "std")]
            file_path: None,
            metadata: SerdeAnyMap::default(),
            #[cfg(feature = "std")]
            metadata_path: None,
            exec_time: None,
            cached_len: None,
            executions: 0,
            scheduled_count: 0,
            parent_id: None,
        }
    }

    /// Create a new Testcase instance given an [`Input`] and the number of executions
    #[inline]
    pub fn with_executions(mut input: I, executions: u64) -> Self {
        input.wrapped_as_testcase();
        Self {
            input: Some(input),
            filename: None,
            #[cfg(feature = "std")]
            file_path: None,
            metadata: SerdeAnyMap::default(),
            #[cfg(feature = "std")]
            metadata_path: None,
            exec_time: None,
            cached_len: None,
            executions,
            scheduled_count: 0,
            parent_id: None,
        }
    }

    /// Get the id of the parent, that this testcase was derived from
    #[must_use]
    pub fn parent_id(&self) -> Option<CorpusId> {
        self.parent_id
    }

    /// Sets the id of the parent, that this testcase was derived from
    pub fn set_parent_id(&mut self, parent_id: CorpusId) {
        self.parent_id = Some(parent_id);
    }

    /// Sets the id of the parent, that this testcase was derived from
    pub fn set_parent_id_optional(&mut self, parent_id: Option<CorpusId>) {
        self.parent_id = parent_id;
    }
}

impl<I> Default for Testcase<I>
where
    I: Input,
{
    /// Create a new default Testcase
    #[inline]
    fn default() -> Self {
        Testcase {
            input: None,
            filename: None,
            metadata: SerdeAnyMap::new(),
            exec_time: None,
            cached_len: None,
            scheduled_count: 0,
            executions: 0,
            parent_id: None,
            #[cfg(feature = "std")]
            file_path: None,
            #[cfg(feature = "std")]
            metadata_path: None,
        }
    }
}

/// Impl of a testcase when the input has len
impl<I> Testcase<I>
where
    I: Input + HasLen,
{
    /// Get the cached `len`. Will `Error::EmptyOptional` if `len` is not yet cached.
    #[inline]
    pub fn cached_len(&mut self) -> Option<usize> {
        self.cached_len
    }

    /// Get the `len` or calculate it, if not yet calculated.
    #[allow(clippy::len_without_is_empty)]
    pub fn load_len<C: Corpus<Input = I>>(&mut self, corpus: &C) -> Result<usize, Error> {
        match &self.input {
            Some(i) => {
                let l = i.len();
                self.cached_len = Some(l);
                Ok(l)
            }
            None => {
                if let Some(l) = self.cached_len {
                    Ok(l)
                } else {
                    corpus.load_input_into(self)?;
                    self.load_len(corpus)
                }
            }
        }
    }
}

/// Create a testcase from an input
impl<I> From<I> for Testcase<I>
where
    I: Input,
{
    fn from(input: I) -> Self {
        Testcase::new(input)
    }
}

/// The Metadata for each testcase used in power schedules.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
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

#[cfg(feature = "std")]
impl<I> Drop for Testcase<I>
where
    I: Input,
{
    fn drop(&mut self) {
        if let Some(filename) = &self.filename {
            let mut path = PathBuf::from(filename);
            let lockname = format!(".{}.lafl_lock", path.file_name().unwrap().to_str().unwrap());
            path.set_file_name(lockname);
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(feature = "python")]
#[allow(missing_docs)]
/// `Testcase` Python bindings
pub mod pybind {
    use alloc::{boxed::Box, vec::Vec};

    use libafl_bolts::ownedref::OwnedMutPtr;
    use pyo3::{prelude::*, types::PyDict};

    use super::{HasMetadata, Testcase};
    use crate::{inputs::BytesInput, pybind::PythonMetadata};

    /// `PythonTestcase` with fixed generics
    pub type PythonTestcase = Testcase<BytesInput>;

    #[pyclass(unsendable, name = "Testcase")]
    #[derive(Debug)]
    /// Python class for Testcase
    pub struct PythonTestcaseWrapper {
        /// Rust wrapped Testcase object
        pub inner: OwnedMutPtr<PythonTestcase>,
    }

    impl PythonTestcaseWrapper {
        pub fn wrap(r: &mut PythonTestcase) -> Self {
            Self {
                inner: OwnedMutPtr::Ptr(r),
            }
        }

        #[must_use]
        pub fn unwrap(&self) -> &PythonTestcase {
            self.inner.as_ref()
        }

        pub fn unwrap_mut(&mut self) -> &mut PythonTestcase {
            self.inner.as_mut()
        }
    }

    #[pymethods]
    impl PythonTestcaseWrapper {
        #[new]
        fn new(input: Vec<u8>) -> Self {
            Self {
                inner: OwnedMutPtr::Owned(Box::new(PythonTestcase::new(BytesInput::new(input)))),
            }
        }

        #[getter]
        fn exec_time_ms(&self) -> Option<u128> {
            self.inner.as_ref().exec_time().map(|t| t.as_millis())
        }

        #[getter]
        fn executions(&self) -> u64 {
            *self.inner.as_ref().executions()
        }

        #[getter]
        fn parent_id(&self) -> Option<usize> {
            self.inner.as_ref().parent_id().map(|x| x.0)
        }

        #[getter]
        fn scheduled_count(&self) -> usize {
            self.inner.as_ref().scheduled_count()
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
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonTestcaseWrapper>()?;
        Ok(())
    }
}
