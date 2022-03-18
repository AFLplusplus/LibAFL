//! The testcase is a struct embedded in each corpus.
//! It will contain a respective input, and metadata.

use alloc::string::String;
use core::{convert::Into, default::Default, option::Option, time::Duration};
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{serdeany::SerdeAnyMap, HasLen},
    inputs::Input,
    state::HasMetadata,
    schedulers::{minimizer::IsFavoredMetadata, powersched::{PowerSchedule, PowerScheduleMetadata}},
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


/// Constants for powerschedules
const POWER_BETA: f64 = 1.0;
const MAX_FACTOR: f64 = POWER_BETA * 32.0;
const HAVOC_MAX_MULT: f64 = 64.0;

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


    /// Compute the `power` we assign to each corpus entry
    #[inline]
    #[allow(
        clippy::cast_precision_loss,
        clippy::too_many_lines,
        clippy::cast_sign_loss
    )]
    pub fn calculate_score(
        &mut self,
        psmeta: &PowerScheduleMetadata,
        fuzz_mu: f64,
    ) -> Result<usize, Error> {
        let mut perf_score = 100.0;
        let q_exec_us = self
            .exec_time()
            .ok_or_else(|| Error::KeyNotFound("exec_time not set".to_string()))?
            .as_nanos() as f64;

        let avg_exec_us = psmeta.exec_time().as_nanos() as f64 / psmeta.cycles() as f64;
        let avg_bitmap_size = psmeta.bitmap_size() / psmeta.bitmap_entries();

        let favored = self.has_metadata::<IsFavoredMetadata>();
        let tcmeta = self
            .metadata_mut()
            .get_mut::<PowerScheduleTestcaseMetaData>()
            .ok_or_else(|| Error::KeyNotFound("PowerScheduleTestData not found".to_string()))?;

        if q_exec_us * 0.1 > avg_exec_us {
            perf_score = 10.0;
        } else if q_exec_us * 0.2 > avg_exec_us {
            perf_score = 25.0;
        } else if q_exec_us * 0.5 > avg_exec_us {
            perf_score = 50.0;
        } else if q_exec_us * 0.75 > avg_exec_us {
            perf_score = 75.0;
        } else if q_exec_us * 4.0 < avg_exec_us {
            perf_score = 300.0;
        } else if q_exec_us * 3.0 < avg_exec_us {
            perf_score = 200.0;
        } else if q_exec_us * 2.0 < avg_exec_us {
            perf_score = 150.0;
        }

        let q_bitmap_size = tcmeta.bitmap_size() as f64;
        if q_bitmap_size * 0.3 > avg_bitmap_size as f64 {
            perf_score *= 3.0;
        } else if q_bitmap_size * 0.5 > avg_bitmap_size as f64 {
            perf_score *= 2.0;
        } else if q_bitmap_size * 0.75 > avg_bitmap_size as f64 {
            perf_score *= 1.5;
        } else if q_bitmap_size * 3.0 < avg_bitmap_size as f64 {
            perf_score *= 0.25;
        } else if q_bitmap_size * 2.0 < avg_bitmap_size as f64 {
            perf_score *= 0.5;
        } else if q_bitmap_size * 1.5 < avg_bitmap_size as f64 {
            perf_score *= 0.75;
        }

        if tcmeta.handicap() >= 4 {
            perf_score *= 4.0;
            tcmeta.set_handicap(tcmeta.handicap() - 4);
        } else if tcmeta.handicap() > 0 {
            perf_score *= 2.0;
            tcmeta.set_handicap(tcmeta.handicap() - 1);
        }

        if tcmeta.depth() >= 4 && tcmeta.depth() < 8 {
            perf_score *= 2.0;
        } else if tcmeta.depth() >= 8 && tcmeta.depth() < 14 {
            perf_score *= 3.0;
        } else if tcmeta.depth() >= 14 && tcmeta.depth() < 25 {
            perf_score *= 4.0;
        } else if tcmeta.depth() >= 25 {
            perf_score *= 5.0;
        }

        let mut factor: f64 = 1.0;

        // COE and Fast schedule are fairly different from what are described in the original thesis,
        // This implementation follows the changes made in this pull request https://github.com/AFLplusplus/AFLplusplus/pull/568
        match psmeta.strat() {
            PowerSchedule::EXPLORE => {
                // Nothing happens in EXPLORE
            }
            PowerSchedule::EXPLOIT => {
                factor = MAX_FACTOR;
            }
            PowerSchedule::COE => {
                if libm::log2(f64::from(psmeta.n_fuzz()[tcmeta.n_fuzz_entry()])) > fuzz_mu
                    && !favored
                {
                    // Never skip favorites.
                    factor = 0.0;
                }
            }
            PowerSchedule::FAST => {
                if tcmeta.fuzz_level() != 0 {
                    let lg = libm::log2(f64::from(psmeta.n_fuzz()[tcmeta.n_fuzz_entry()]));

                    match lg {
                        f if f < 2.0 => {
                            factor = 4.0;
                        }
                        f if (2.0..4.0).contains(&f) => {
                            factor = 3.0;
                        }
                        f if (4.0..5.0).contains(&f) => {
                            factor = 2.0;
                        }
                        f if (6.0..7.0).contains(&f) => {
                            if !favored {
                                factor = 0.8;
                            }
                        }
                        f if (7.0..8.0).contains(&f) => {
                            if !favored {
                                factor = 0.6;
                            }
                        }
                        f if f >= 8.0 => {
                            if !favored {
                                factor = 0.4;
                            }
                        }
                        _ => {
                            factor = 1.0;
                        }
                    }

                    if favored {
                        factor *= 1.15;
                    }
                }
            }
            PowerSchedule::LIN => {
                factor = (tcmeta.fuzz_level() as f64)
                    / f64::from(psmeta.n_fuzz()[tcmeta.n_fuzz_entry()] + 1);
            }
            PowerSchedule::QUAD => {
                factor = ((tcmeta.fuzz_level() * tcmeta.fuzz_level()) as f64)
                    / f64::from(psmeta.n_fuzz()[tcmeta.n_fuzz_entry()] + 1);
            }
        }

        if psmeta.strat() != PowerSchedule::EXPLORE {
            if factor > MAX_FACTOR {
                factor = MAX_FACTOR;
            }

            perf_score *= factor / POWER_BETA;
        }

        // Lower bound if the strat is not COE.
        if psmeta.strat() == PowerSchedule::COE && perf_score < 1.0 {
            perf_score = 1.0;
        }

        // Upper bound
        if perf_score > HAVOC_MAX_MULT * 100.0 {
            perf_score = HAVOC_MAX_MULT * 100.0;
        }

        Ok(perf_score as usize)
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
    /// Number of fuzzing iterations, updated in perform_mutational
    fuzz_level: u64,
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
            fuzz_level: 0,
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

    /// Get the fuzz level
    #[must_use]
    pub fn fuzz_level(&self) -> u64 {
        self.fuzz_level
    }

    /// Set the fuzz level
    pub fn set_fuzz_level(&mut self, val: u64) {
        self.fuzz_level = val;
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
