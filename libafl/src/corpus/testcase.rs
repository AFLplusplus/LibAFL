//! The testcase is a struct embedded in each corpus.
//! It will contain a respective input, and metadata.

use alloc::string::String;
use core::{convert::Into, default::Default, option::Option, time::Duration};
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{serdeany::SerdeAnyMap, HasLen},
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
    pub fn set_fuzz_leve(&mut self, fuzz_level: usize) {
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

    /// Create a new Testcase instace given an input
    #[inline]
    pub fn new<T>(input: T) -> Self
    where
        T: Into<I>,
    {
        let mut slf = Testcase {
            input: Some(input.into()),
            ..Testcase::default()
        };
        slf.input.as_mut().unwrap().wrapped_as_testcase();
        slf
    }

    /// Create a new Testcase instance given an [`Input`] and a `filename`
    #[inline]
    pub fn with_filename(mut input: I, filename: String) -> Self {
        input.wrapped_as_testcase();
        Testcase {
            input: Some(input),
            filename: Some(filename),
            ..Testcase::default()
        }
    }

    /// Create a new Testcase instance given an [`Input`] and the number of executions
    #[inline]
    pub fn with_executions(mut input: I, executions: usize) -> Self {
        input.wrapped_as_testcase();
        Testcase {
            input: Some(input),
            executions,
            ..Testcase::default()
        }
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
pub struct PowerScheduleTestcaseMetaData {
    /// Number of bits set in bitmap, updated in calibrate_case
    bitmap_size: u64,
    /// Number of queue cycles behind
    handicap: u64,
    /// Path depth, initialized in on_add
    depth: u64,
    /// Offset in n_fuzz
    n_fuzz_entry: usize,
}

impl PowerScheduleTestcaseMetaData {
    /// Create new [`struct@PowerScheduleTestcaseMetaData`]
    #[must_use]
    pub fn new(depth: u64) -> Self {
        Self {
            bitmap_size: 0,
            handicap: 0,
            depth,
            n_fuzz_entry: 0,
        }
    }

    /// Get the bitmap size
    #[must_use]
    pub fn bitmap_size(&self) -> u64 {
        self.bitmap_size
    }

    /// Set the bitmap size
    pub fn set_bitmap_size(&mut self, val: u64) {
        self.bitmap_size = val;
    }

    /// Get the handicap
    #[must_use]
    pub fn handicap(&self) -> u64 {
        self.handicap
    }

    /// Set the handicap
    pub fn set_handicap(&mut self, val: u64) {
        self.handicap = val;
    }

    /// Get the depth
    #[must_use]
    pub fn depth(&self) -> u64 {
        self.depth
    }

    /// Set the depth
    pub fn set_depth(&mut self, val: u64) {
        self.depth = val;
    }

    /// Get the `n_fuzz_entry`
    #[must_use]
    pub fn n_fuzz_entry(&self) -> usize {
        self.n_fuzz_entry
    }

    /// Set the `n_fuzz_entry`
    pub fn set_n_fuzz_entry(&mut self, val: usize) {
        self.n_fuzz_entry = val;
    }
}

crate::impl_serdeany!(PowerScheduleTestcaseMetaData);
