//! The `TestcaseScore` is an evaluator providing scores of corpus items.
use alloc::string::{String, ToString};
use core::marker::PhantomData;

use crate::{
    bolts::{HasLen, HasRefCnt},
    corpus::{Corpus, SchedulerTestcaseMetaData, Testcase},
    feedbacks::MapIndexesMetadata,
    schedulers::{
        minimizer::{IsFavoredMetadata, TopRatedsMetadata},
        powersched::{PowerSchedule, SchedulerMetadata},
    },
    state::{HasCorpus, HasMetadata},
    Error,
};

/// Compute the favor factor of a [`Testcase`]. Lower is better.
pub trait TestcaseScore<S>
where
    S: HasMetadata + HasCorpus,
{
    /// Computes the favor factor of a [`Testcase`]. Lower is better.
    fn compute(entry: &mut Testcase<S::Input>, state: &S) -> Result<f64, Error>;
}

/// Multiply the testcase size with the execution time.
/// This favors small and quick testcases.
#[derive(Debug, Clone)]
pub struct LenTimeMulTestcaseScore<S> {
    phantom: PhantomData<S>,
}

impl<S> TestcaseScore<S> for LenTimeMulTestcaseScore<S>
where
    S: HasCorpus + HasMetadata,
    S::Input: HasLen,
{
    #[allow(clippy::cast_precision_loss, clippy::cast_lossless)]
    fn compute(entry: &mut Testcase<S::Input>, _state: &S) -> Result<f64, Error> {
        // TODO maybe enforce entry.exec_time().is_some()
        Ok(entry.exec_time().map_or(1, |d| d.as_millis()) as f64 * entry.cached_len()? as f64)
    }
}

/// Constants for powerschedules
const POWER_BETA: f64 = 1.0;
const MAX_FACTOR: f64 = POWER_BETA * 32.0;
const HAVOC_MAX_MULT: f64 = 64.0;

/// The power assigned to each corpus entry
/// This result is used for power scheduling
#[derive(Debug, Clone)]
pub struct CorpusPowerTestcaseScore<S> {
    phantom: PhantomData<S>,
}

impl<S> TestcaseScore<S> for CorpusPowerTestcaseScore<S>
where
    S: HasCorpus + HasMetadata,
{
    /// Compute the `power` we assign to each corpus entry
    #[allow(
        clippy::cast_precision_loss,
        clippy::too_many_lines,
        clippy::cast_sign_loss,
        clippy::cast_lossless
    )]
    fn compute(entry: &mut Testcase<S::Input>, state: &S) -> Result<f64, Error> {
        let psmeta = state
            .metadata()
            .get::<SchedulerMetadata>()
            .ok_or_else(|| Error::key_not_found("SchedulerMetadata not found".to_string()))?;

        let fuzz_mu = if let Some(strat) = psmeta.strat() {
            if strat == PowerSchedule::COE {
                let corpus = state.corpus();
                let mut n_paths = 0;
                let mut v = 0.0;
                let cur_index = state.corpus().current().unwrap();
                for idx in corpus.ids() {
                    let n_fuzz_entry = if cur_index == idx {
                        entry
                            .metadata()
                            .get::<SchedulerTestcaseMetaData>()
                            .ok_or_else(|| {
                                Error::key_not_found(
                                    "SchedulerTestcaseMetaData not found".to_string(),
                                )
                            })?
                            .n_fuzz_entry()
                    } else {
                        corpus
                            .get(idx)?
                            .borrow()
                            .metadata()
                            .get::<SchedulerTestcaseMetaData>()
                            .ok_or_else(|| {
                                Error::key_not_found(
                                    "SchedulerTestcaseMetaData not found".to_string(),
                                )
                            })?
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
            .ok_or_else(|| Error::key_not_found("exec_time not set".to_string()))?
            .as_nanos() as f64;

        let avg_exec_us = psmeta.exec_time().as_nanos() as f64 / psmeta.cycles() as f64;
        let avg_bitmap_size = if psmeta.bitmap_entries() == 0 {
            1
        } else {
            psmeta.bitmap_size() / psmeta.bitmap_entries()
        };

        let favored = entry.has_metadata::<IsFavoredMetadata>();
        let tcmeta = entry
            .metadata()
            .get::<SchedulerTestcaseMetaData>()
            .ok_or_else(|| {
                Error::key_not_found("SchedulerTestcaseMetaData not found".to_string())
            })?;

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
            match strat {
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
                    if entry.fuzz_level() != 0 {
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
                    factor = (entry.fuzz_level() as f64)
                        / f64::from(psmeta.n_fuzz()[tcmeta.n_fuzz_entry()] + 1);
                }
                PowerSchedule::QUAD => {
                    factor = ((entry.fuzz_level() * entry.fuzz_level()) as f64)
                        / f64::from(psmeta.n_fuzz()[tcmeta.n_fuzz_entry()] + 1);
                }
            }
        }

        if let Some(strat) = psmeta.strat() {
            if strat != PowerSchedule::EXPLORE {
                if factor > MAX_FACTOR {
                    factor = MAX_FACTOR;
                }

                perf_score *= factor / POWER_BETA;
            }
        }

        // Lower bound if the strat is not COE.
        if let Some(strat) = psmeta.strat() {
            if strat == PowerSchedule::COE && perf_score < 1.0 {
                perf_score = 1.0;
            }
        }

        // Upper bound
        if perf_score > HAVOC_MAX_MULT * 100.0 {
            perf_score = HAVOC_MAX_MULT * 100.0;
        }

        Ok(perf_score)
    }
}

/// The weight for each corpus entry
/// This result is used for corpus scheduling
#[derive(Debug, Clone)]
pub struct CorpusWeightTestcaseScore<S> {
    phantom: PhantomData<S>,
}

impl<S> TestcaseScore<S> for CorpusWeightTestcaseScore<S>
where
    S: HasCorpus + HasMetadata,
{
    /// Compute the `weight` used in weighted corpus entry selection algo
    #[allow(clippy::cast_precision_loss, clippy::cast_lossless)]
    fn compute(entry: &mut Testcase<S::Input>, state: &S) -> Result<f64, Error> {
        let mut weight = 1.0;
        let psmeta = state
            .metadata()
            .get::<SchedulerMetadata>()
            .ok_or_else(|| Error::key_not_found("SchedulerMetadata not found".to_string()))?;

        let tcmeta = entry
            .metadata()
            .get::<SchedulerTestcaseMetaData>()
            .ok_or_else(|| {
                Error::key_not_found("SchedulerTestcaseMetaData not found".to_string())
            })?;

        // This means that this testcase has never gone through the calibration stage before1,
        // In this case we'll just return the default weight
        // This methoud is called in corpus's on_add() method. Fuzz_level is zero at that time.
        if entry.fuzz_level() == 0 || psmeta.cycles() == 0 {
            return Ok(weight);
        }

        let q_exec_us = entry
            .exec_time()
            .ok_or_else(|| Error::key_not_found("exec_time not set".to_string()))?
            .as_nanos() as f64;
        let favored = entry.has_metadata::<IsFavoredMetadata>();

        let avg_exec_us = psmeta.exec_time().as_nanos() as f64 / psmeta.cycles() as f64;
        let avg_bitmap_size = psmeta.bitmap_size_log() / psmeta.bitmap_entries() as f64;

        let q_bitmap_size = tcmeta.bitmap_size() as f64;

        if let Some(strat) = psmeta.strat() {
            match strat {
                PowerSchedule::FAST
                | PowerSchedule::COE
                | PowerSchedule::LIN
                | PowerSchedule::QUAD => {
                    let hits = psmeta.n_fuzz()[tcmeta.n_fuzz_entry()];
                    if hits > 0 {
                        weight /= libm::log10(f64::from(hits)) + 1.0;
                    }
                }
                // EXPLORE and EXPLOIT fall into this
                _ => {}
            }
        }

        weight *= avg_exec_us / q_exec_us;
        weight *= libm::log2(q_bitmap_size).max(1.0) / avg_bitmap_size;

        let tc_ref = match entry.metadata().get::<MapIndexesMetadata>() {
            Some(meta) => meta.refcnt() as f64,
            None => 0.0,
        };

        let avg_top_size = state
            .metadata()
            .get::<TopRatedsMetadata>()
            .ok_or_else(|| Error::key_not_found("TopRatedsMetadata not found".to_string()))?
            .map()
            .len() as f64;
        weight *= 1.0 + (tc_ref / avg_top_size);

        if favored {
            weight *= 5.0;
        }

        // was it fuzzed before?
        if entry.fuzz_level() == 0 {
            weight *= 2.0;
        }

        assert!(weight.is_normal());

        Ok(weight)
    }
}
