//! The testcase is a struct embedded in each corpus.
//! It will contain a respective input, and metadata.

use alloc::string::String;
use core::{default::Default, option::Option, time::Duration};
#[cfg(feature = "std")]
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    bolts::{serdeany::SerdeAnyMap, HasLen},
    corpus::CorpusId,
    inputs::Input,
    state::HasMetadata,
    Error,
};

/// An entry in the Testcase Corpus
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct Testcase<I>
where
    I: Input,
{
    /// The input of this testcase
    input: Option<I>,
    /// Filename, if this testcase is backed by a file in the filesystem
    filename: Option<String>,
    /// Map of metadata associated with this testcase
    metadata: SerdeAnyMap,
    /// Time needed to execute the input
    exec_time: Option<Duration>,
    /// Cached len of the input, if any
    cached_len: Option<usize>,
    /// Number of executions done at discovery time
    executions: usize,
    /// Number of fuzzing iterations of this particular input updated in perform_mutational
    fuzz_level: usize,
    /// If it has been fuzzed
    fuzzed: bool,
    /// Parent [`CorpusId`], if known
    parent_id: Option<CorpusId>,
}

impl<I> HasMetadata for Testcase<I>
where
    I: Input,
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

/// Impl of a testcase
impl<I> Testcase<I>
where
    I: Input,
{
    /// Returns this testcase with a loaded input
    pub fn load_input(&mut self) -> Result<&I, Error> {
        if self.input.is_none() {
            self.input = Some(I::from_file(self.filename.as_ref().unwrap())?);
        }
        Ok(self.input.as_ref().unwrap())
    }

    /// Store the input to disk if possible
    pub fn store_input(&mut self) -> Result<bool, Error> {
        match self.filename() {
            Some(fname) => {
                let saved = match self.input() {
                    None => false,
                    Some(i) => {
                        i.to_file(fname)?;
                        true
                    }
                };
                if saved {
                    // remove the input from memory
                    *self.input_mut() = None;
                }
                Ok(saved)
            }
            None => Ok(false),
        }
    }

    /// Get the input, if any
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

    /// Set the filename
    #[inline]
    pub fn set_filename(&mut self, filename: String) {
        self.filename = Some(filename);
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
    pub fn executions(&self) -> &usize {
        &self.executions
    }

    /// Get the executions (mutable)
    #[inline]
    pub fn executions_mut(&mut self) -> &mut usize {
        &mut self.executions
    }

    /// Get the `fuzz_level`
    #[inline]
    pub fn fuzz_level(&self) -> usize {
        self.fuzz_level
    }

    /// Set the `fuzz_level`
    #[inline]
    pub fn set_fuzz_level(&mut self, fuzz_level: usize) {
        self.fuzz_level = fuzz_level;
    }

    /// Get if it was fuzzed
    #[inline]
    pub fn fuzzed(&self) -> bool {
        self.fuzzed
    }

    /// Set if it was fuzzed
    #[inline]
    pub fn set_fuzzed(&mut self, fuzzed: bool) {
        self.fuzzed = fuzzed;
    }

    /// Create a new Testcase instance given an input
    #[inline]
    pub fn new(mut input: I) -> Self {
        input.wrapped_as_testcase();
        Self {
            input: Some(input),
            filename: None,
            metadata: Default::default(),
            exec_time: None,
            cached_len: None,
            executions: 0,
            fuzz_level: 0,
            fuzzed: false,
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
            metadata: Default::default(),
            exec_time: None,
            cached_len: None,
            executions: 0,
            fuzz_level: 0,
            fuzzed: false,
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
            metadata: Default::default(),
            exec_time: None,
            cached_len: None,
            executions: 0,
            fuzz_level: 0,
            fuzzed: false,
            parent_id: None,
        }
    }

    /// Create a new Testcase instance given an [`Input`] and the number of executions
    #[inline]
    pub fn with_executions(mut input: I, executions: usize) -> Self {
        input.wrapped_as_testcase();
        Self {
            input: Some(input),
            filename: None,
            metadata: Default::default(),
            exec_time: None,
            cached_len: None,
            executions,
            fuzz_level: 0,
            fuzzed: false,
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
            fuzz_level: 0,
            executions: 0,
            fuzzed: false,
            parent_id: None,
        }
    }
}

/// Impl of a testcase when the input has len
impl<I> Testcase<I>
where
    I: Input + HasLen,
{
    /// Get the cached len
    #[inline]
    pub fn cached_len(&mut self) -> Result<usize, Error> {
        Ok(match &self.input {
            Some(i) => {
                let l = i.len();
                self.cached_len = Some(l);
                l
            }
            None => {
                if let Some(l) = self.cached_len {
                    l
                } else {
                    let l = self.load_input()?.len();
                    self.cached_len = Some(l);
                    l
                }
            }
        })
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
pub struct SchedulerTestcaseMetaData {
    /// Number of bits set in bitmap, updated in calibrate_case
    bitmap_size: u64,
    /// Number of queue cycles behind
    handicap: u64,
    /// Path depth, initialized in on_add
    depth: u64,
    /// Offset in n_fuzz
    n_fuzz_entry: usize,
    /// Cycles used to calibrate this (not really needed if it were not for on_replace and on_remove)
    cycle_and_time: (Duration, usize),
}

impl SchedulerTestcaseMetaData {
    /// Create new [`struct@SchedulerTestcaseMetaData`]
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

    /// Create new [`struct@SchedulerTestcaseMetaData`] given `n_fuzz_entry`
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

crate::impl_serdeany!(SchedulerTestcaseMetaData);

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

    use pyo3::{prelude::*, types::PyDict};

    use super::{HasMetadata, Testcase};
    use crate::{
        bolts::ownedref::OwnedMutPtr,
        inputs::{BytesInput, HasBytesVec},
        pybind::PythonMetadata,
    };

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

        fn load_input(&mut self) -> &[u8] {
            self.inner
                .as_mut()
                .load_input()
                .expect("Failed to load input")
                .bytes()
        }

        #[getter]
        fn exec_time_ms(&self) -> Option<u128> {
            self.inner.as_ref().exec_time().map(|t| t.as_millis())
        }

        #[getter]
        fn executions(&self) -> usize {
            *self.inner.as_ref().executions()
        }

        #[getter]
        fn parent_id(&self) -> Option<usize> {
            self.inner.as_ref().parent_id().map(|x| x.0)
        }

        #[getter]
        fn fuzz_level(&self) -> usize {
            self.inner.as_ref().fuzz_level()
        }

        #[getter]
        fn fuzzed(&self) -> bool {
            self.inner.as_ref().fuzzed()
        }

        fn metadata(&mut self) -> PyObject {
            let meta = self.inner.as_mut().metadata_mut();
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
