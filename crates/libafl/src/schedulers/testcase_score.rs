//! The `TestcaseScore` is an evaluator providing scores of corpus items.
use alloc::{string::String, vec::Vec};

use libafl_bolts::{HasLen, HasRefCnt};
use num_traits::Zero;
use serde::{Deserialize, Serialize};

use crate::{
    Error, HasMetadata,
    corpus::{Corpus, SchedulerTestcaseMetadata, Testcase},
    feedbacks::MapIndexesMetadata,
    schedulers::{
        minimizer::{IsFavoredMetadata, TopRatedsMetadata},
        powersched::{BaseSchedule, SchedulerMetadata},
    },
    state::HasCorpus,
};

/// Compute the favor factor of a [`Testcase`]. Higher is better.
pub trait TestcaseScore<I, S> {
    /// Computes the favor factor of a [`Testcase`]. Higher is better.
    fn compute(state: &S, entry: &mut Testcase<I>) -> Result<f64, Error>;
}

/// Compute the favor factor of a [`Testcase`]. Lower  is better.
pub trait TestcasePenalty<I, S> {
    /// Computes the favor factor of a [`Testcase`]. Higher is better.
    fn compute(state: &S, entry: &mut Testcase<I>) -> Result<f64, Error>;
}

/// Multiply the testcase size with the execution time.
/// This favors small and quick testcases.
#[derive(Debug, Clone)]
pub struct LenTimeMulTestcasePenalty {}

impl<I, S> TestcasePenalty<I, S> for LenTimeMulTestcasePenalty
where
    S: HasCorpus<I>,
    I: HasLen,
{
    #[expect(clippy::cast_precision_loss)]
    fn compute(state: &S, entry: &mut Testcase<I>) -> Result<f64, Error> {
        // TODO maybe enforce entry.exec_time().is_some()
        Ok(entry.exec_time().map_or(1, |d| d.as_millis()) as f64
            * entry.load_len(state.corpus())? as f64)
    }
}

/// Constants for powerschedules
const POWER_BETA: f64 = 1.0;
const MAX_FACTOR: f64 = POWER_BETA * 32.0;
const HAVOC_MAX_MULT: f64 = 64.0;

/// The power assigned to each corpus entry
/// This result is used for power scheduling
#[derive(Debug, Clone)]
pub struct CorpusPowerTestcaseScore {}

impl<I, S> TestcaseScore<I, S> for CorpusPowerTestcaseScore
where
    S: HasCorpus<I> + HasMetadata,
{
    /// Compute the `power` we assign to each corpus entry
    #[expect(clippy::cast_precision_loss, clippy::too_many_lines)]
    fn compute(state: &S, entry: &mut Testcase<I>) -> Result<f64, Error> {
        let psmeta = state.metadata::<SchedulerMetadata>()?;

        let fuzz_mu = if let Some(strat) = psmeta.strat() {
            if *strat.base() == BaseSchedule::COE {
                let corpus = state.corpus();
                let mut n_paths = 0;
                let mut v = 0.0;
                let cur_index = state.corpus().current().unwrap();
                for id in corpus.ids() {
                    let n_fuzz_entry = if cur_index == id {
                        entry
                            .metadata::<SchedulerTestcaseMetadata>()?
                            .n_fuzz_entry()
                    } else {
                        corpus
                            .get(id)?
                            .borrow()
                            .metadata::<SchedulerTestcaseMetadata>()?
                            .n_fuzz_entry()
                    };
                    v += libm::log2(f64::from(psmeta.n_fuzz()[n_fuzz_entry]));
                    n_paths += 1;
                }

                if n_paths == 0 {
                    return Err(Error::unknown(String::from("Queue state corrput")));
                }

                v /= f64::from(n_paths);
                v
            } else {
                0.0
            }
        } else {
            0.0
        };

        let mut perf_score = 100.0;
        let q_exec_us = entry
            .exec_time()
            .ok_or_else(|| Error::key_not_found("exec_time not set when computing corpus power. This happens if CalibrationStage fails to set it or is not added to stages."))?
            .as_nanos() as f64;

        let avg_exec_us = psmeta.exec_time().as_nanos() as f64 / psmeta.cycles() as f64;
        let avg_bitmap_size = if psmeta.bitmap_entries() == 0 {
            1
        } else {
            psmeta.bitmap_size() / psmeta.bitmap_entries()
        };

        let favored = entry.has_metadata::<IsFavoredMetadata>();
        let tcmeta = entry.metadata::<SchedulerTestcaseMetadata>()?;

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
            // tcmeta.set_handicap(tcmeta.handicap() - 4);
        } else if tcmeta.handicap() > 0 {
            perf_score *= 2.0;
            // tcmeta.set_handicap(tcmeta.handicap() - 1);
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
        if let Some(strat) = psmeta.strat() {
            match strat.base() {
                BaseSchedule::EXPLORE => {
                    // Nothing happens in EXPLORE
                }
                BaseSchedule::EXPLOIT => {
                    factor = MAX_FACTOR;
                }
                BaseSchedule::COE => {
                    if libm::log2(f64::from(psmeta.n_fuzz()[tcmeta.n_fuzz_entry()])) > fuzz_mu
                        && !favored
                    {
                        // Never skip favorites.
                        factor = 0.0;
                    }
                }
                BaseSchedule::FAST => {
                    if entry.scheduled_count() != 0 {
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
                BaseSchedule::LIN => {
                    factor = (entry.scheduled_count() as f64)
                        / f64::from(psmeta.n_fuzz()[tcmeta.n_fuzz_entry()] + 1);
                }
                BaseSchedule::QUAD => {
                    factor = ((entry.scheduled_count() * entry.scheduled_count()) as f64)
                        / f64::from(psmeta.n_fuzz()[tcmeta.n_fuzz_entry()] + 1);
                }
            }
        }

        if let Some(strat) = psmeta.strat()
            && *strat.base() != BaseSchedule::EXPLORE
        {
            if factor > MAX_FACTOR {
                factor = MAX_FACTOR;
            }

            perf_score *= factor / POWER_BETA;
        }

        // Lower bound if the strat is not COE.
        if let Some(strat) = psmeta.strat()
            && *strat.base() == BaseSchedule::COE
            && perf_score < 1.0
        {
            perf_score = 1.0;
        }

        // Upper bound
        if perf_score > HAVOC_MAX_MULT * 100.0 {
            perf_score = HAVOC_MAX_MULT * 100.0;
        }

        if entry.objectives_found() > 0 && psmeta.strat().is_some_and(|s| s.avoid_crash()) {
            perf_score *= 0.00;
        }

        Ok(perf_score)
    }
}

/// The weight for each corpus entry
/// This result is used for corpus scheduling
#[derive(Debug, Clone)]
pub struct CorpusWeightTestcaseScore {}

impl<I, S> TestcaseScore<I, S> for CorpusWeightTestcaseScore
where
    S: HasCorpus<I> + HasMetadata,
{
    /// Compute the `weight` used in weighted corpus entry selection algo
    #[expect(clippy::cast_precision_loss)]
    fn compute(state: &S, entry: &mut Testcase<I>) -> Result<f64, Error> {
        let mut weight = 1.0;
        let psmeta = state.metadata::<SchedulerMetadata>()?;

        let tcmeta = entry.metadata::<SchedulerTestcaseMetadata>()?;
        // This means that this testcase has never gone through the calibration stage before1,
        // In this case we'll just return the default weight
        // This methoud is called in corpus's on_add() method. Fuzz_level is zero at that time.
        if entry.scheduled_count() == 0 || psmeta.cycles() == 0 {
            return Ok(weight);
        }

        let q_exec_us = entry
            .exec_time()
            .ok_or_else(|| Error::key_not_found("exec_time not set when computing corpus weight. This happens if CalibrationStage fails to set it or is not added to stages."))?
            .as_nanos() as f64;
        let favored = entry.has_metadata::<IsFavoredMetadata>();

        let avg_exec_us = psmeta.exec_time().as_nanos() as f64 / psmeta.cycles() as f64;
        let avg_bitmap_size = psmeta.bitmap_size_log() / psmeta.bitmap_entries() as f64;

        let q_bitmap_size = tcmeta.bitmap_size() as f64;

        if let Some(ps) = psmeta.strat() {
            match ps.base() {
                BaseSchedule::FAST | BaseSchedule::COE | BaseSchedule::LIN | BaseSchedule::QUAD => {
                    let hits = psmeta.n_fuzz()[tcmeta.n_fuzz_entry()];
                    if hits > 0 {
                        weight /= libm::log10(f64::from(hits)) + 1.0;
                    }
                }
                _ => (),
            }
        }

        weight *= avg_exec_us / q_exec_us;
        weight *= if avg_bitmap_size.is_zero() {
            // This can happen when the bitmap size of the target is as small as 1.
            1.0
        } else {
            libm::log2(q_bitmap_size).max(1.0) / avg_bitmap_size
        };

        let tc_ref = match entry.metadata_map().get::<MapIndexesMetadata>() {
            Some(meta) => meta.refcnt() as f64,
            None => 0.0,
        };

        let avg_top_size = match state.metadata::<TopRatedsMetadata>() {
            Ok(m) => m.map().len() as f64,
            Err(e) => {
                return Err(Error::key_not_found(format!(
                    "{e:?} You have to use Minimizer scheduler with this.",
                )));
            }
        };

        weight *= 1.0 + (tc_ref / avg_top_size);

        if favored {
            weight *= 5.0;
        }

        // was it fuzzed before?
        if entry.scheduled_count() == 0 {
            weight *= 2.0;
        }

        if entry.objectives_found() > 0 && psmeta.strat().is_some_and(|s| s.avoid_crash()) {
            weight *= 0.00;
        }

        assert!(weight.is_normal());

        Ok(weight)
    }
}

/// The `git blame` timestamp mapping for `SanitizerCoverage` pc-guard map indexes.
///
/// If an index has no mapping, it is considered "old" (timestamp `0`).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    expect(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct GitRecencyMapMetadata {
    /// The reference time used to compute decay (epoch seconds), taken from the `HEAD` commit time.
    pub head_time: u64,
    /// `entries[index] = epoch_seconds` for that `pcguard_index`.
    pub entries: Vec<u64>,
}

libafl_bolts::impl_serdeany!(GitRecencyMapMetadata);

impl GitRecencyMapMetadata {
    /// A fixed 14-day half-life.
    pub const HALF_LIFE_SECS: u64 = 14 * 24 * 60 * 60;

    /// Parse a mapping file generated by `libafl_cc`.
    ///
    /// Format (little-endian):
    /// - `u64 head_time`
    /// - `u64 len`
    /// - `len * u64` entries
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        const HEADER_LEN: usize = 16;
        if bytes.len() < HEADER_LEN {
            return Err(Error::illegal_argument(
                "GitRecencyMapMetadata: mapping file too small",
            ));
        }

        let head_time = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(bytes[8..16].try_into().unwrap());

        let Ok(len_usize) = usize::try_from(len) else {
            return Err(Error::illegal_argument(
                "GitRecencyMapMetadata: mapping length does not fit usize",
            ));
        };

        let expected_len = HEADER_LEN
            .checked_add(len_usize.checked_mul(8).ok_or_else(|| {
                Error::illegal_argument("GitRecencyMapMetadata: mapping length overflow")
            })?)
            .ok_or_else(|| {
                Error::illegal_argument("GitRecencyMapMetadata: mapping length overflow")
            })?;

        if bytes.len() != expected_len {
            return Err(Error::illegal_argument(format!(
                "GitRecencyMapMetadata: mapping file has unexpected size (got {}, expected {})",
                bytes.len(),
                expected_len
            )));
        }

        let mut entries = Vec::with_capacity(len_usize);
        for i in 0..len_usize {
            let start = HEADER_LEN + i * 8;
            let end = start + 8;
            entries.push(u64::from_le_bytes(bytes[start..end].try_into().unwrap()));
        }

        Ok(Self { head_time, entries })
    }

    /// Load a mapping file generated by `libafl_cc` from disk.
    #[cfg(feature = "std")]
    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        let bytes = std::fs::read(path).map_err(Error::from)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the `git blame` timestamp for this `pcguard_index`, or `0` if missing/out of range.
    #[must_use]
    pub fn timestamp_for_index(&self, idx: usize) -> u64 {
        self.entries.get(idx).copied().unwrap_or(0)
    }
}

/// Optional configuration for git-aware scheduling.
///
/// If not present in the state, `GitRecencyTestcaseScore` uses a default `alpha`.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    expect(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct GitRecencyConfigMetadata {
    /// Bias strength. Larger means "recently changed code" is picked more often.
    pub alpha: f64,
}

libafl_bolts::impl_serdeany!(GitRecencyConfigMetadata);

impl GitRecencyConfigMetadata {
    /// Default `alpha` used if no config metadata is present.
    pub const DEFAULT_ALPHA: f64 = 2.0;

    /// Create a new config with the given `alpha`.
    #[must_use]
    pub fn new(alpha: f64) -> Self {
        Self { alpha }
    }
}

impl Default for GitRecencyConfigMetadata {
    fn default() -> Self {
        Self {
            alpha: Self::DEFAULT_ALPHA,
        }
    }
}

/// Cached per-testcase maximum `git blame` timestamp over its covered indices.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    expect(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct GitRecencyTestcaseMetadata {
    /// The max timestamp among all indices this testcase covers.
    pub tc_time: u64,
}

libafl_bolts::impl_serdeany!(GitRecencyTestcaseMetadata);

/// A `TestcaseScore` that boosts corpus weights for testcases covering recently changed code.
#[derive(Debug, Clone)]
pub struct GitRecencyTestcaseScore {}

impl GitRecencyTestcaseScore {
    const HALF_LIFE_SECS_F64: f64 = 14.0 * 24.0 * 60.0 * 60.0;

    fn compute_decay(head_time: u64, tc_time: u64) -> f64 {
        if head_time == 0 || tc_time == 0 {
            return 0.0;
        }

        #[expect(clippy::cast_precision_loss)]
        let age = head_time.saturating_sub(tc_time) as f64;
        libm::exp2(-(age / Self::HALF_LIFE_SECS_F64))
    }
}

impl<I, S> TestcaseScore<I, S> for GitRecencyTestcaseScore
where
    S: HasCorpus<I> + HasMetadata,
{
    fn compute(state: &S, entry: &mut Testcase<I>) -> Result<f64, Error> {
        let base = CorpusWeightTestcaseScore::compute(state, entry)?;

        let Ok(map_meta) = state.metadata::<GitRecencyMapMetadata>() else {
            // No mapping loaded -> no boost.
            return Ok(base);
        };

        let alpha = state
            .metadata::<GitRecencyConfigMetadata>()
            .map(|m| m.alpha)
            .unwrap_or(GitRecencyConfigMetadata::DEFAULT_ALPHA);

        let tc_time = if let Some(meta) = entry.metadata_map().get::<GitRecencyTestcaseMetadata>() {
            meta.tc_time
        } else {
            let mut tc_time = 0u64;
            if let Some(indexes) = entry.metadata_map().get::<MapIndexesMetadata>() {
                for idx in &indexes.list {
                    tc_time = tc_time.max(map_meta.timestamp_for_index(*idx));
                }
            }
            entry.add_metadata(GitRecencyTestcaseMetadata { tc_time });
            tc_time
        };

        let decay = Self::compute_decay(map_meta.head_time, tc_time);
        let boost = 1.0 + alpha * decay;
        Ok(base * boost)
    }
}

#[cfg(test)]
mod git_recency_tests {
    use crate::{
        HasMetadata,
        corpus::{Corpus, InMemoryCorpus, SchedulerTestcaseMetadata, Testcase},
        feedbacks::MapIndexesMetadata,
        inputs::NopInput,
        schedulers::{GitRecencyMapMetadata, GitRecencyTestcaseScore, TestcaseScore},
        state::{HasCorpus, StdState},
    };

    #[test]
    fn test_git_recency_score_boosts_recent() {
        #[cfg(not(feature = "serdeany_autoreg"))]
        unsafe {
            libafl_bolts::serdeany::RegistryBuilder::register::<
                crate::schedulers::powersched::SchedulerMetadata,
            >();
            libafl_bolts::serdeany::RegistryBuilder::register::<GitRecencyMapMetadata>();
            libafl_bolts::serdeany::RegistryBuilder::register::<super::GitRecencyConfigMetadata>();
            libafl_bolts::serdeany::RegistryBuilder::register::<super::GitRecencyTestcaseMetadata>(
            );
            libafl_bolts::serdeany::RegistryBuilder::register::<SchedulerTestcaseMetadata>();
            libafl_bolts::serdeany::RegistryBuilder::register::<MapIndexesMetadata>();
        }

        let mut corpus = InMemoryCorpus::new();
        let mut testcase = Testcase::new(NopInput {});
        testcase.add_metadata(SchedulerTestcaseMetadata::new(0));
        testcase.add_metadata(MapIndexesMetadata::new(vec![0, 2]));
        let id = corpus.add(testcase).unwrap();

        let mut state = StdState::new(
            libafl_bolts::rands::StdRand::with_seed(0),
            corpus,
            InMemoryCorpus::new(),
            &mut (),
            &mut (),
        )
        .unwrap();

        // Required by CorpusWeightTestcaseScore, even though it will early-return.
        let _ = state.metadata_or_insert_with(|| {
            crate::schedulers::powersched::SchedulerMetadata::new(None)
        });

        // Mapping: index 2 is "recent", index 0 is "old".
        state.add_metadata(GitRecencyMapMetadata {
            head_time: 1000,
            entries: vec![1, 0, 990],
        });

        let mut testcase_ref = state.corpus().get(id).unwrap().borrow_mut();
        let score = GitRecencyTestcaseScore::compute(&state, &mut testcase_ref).unwrap();

        // Base weight is 1.0 (scheduled_count==0 or cycles==0).
        assert!(score > 1.0);
    }
}
