//! Stage to compute/report AFL stats

#[cfg(feature = "std")]
use alloc::{borrow::Cow, string::ToString};
use core::{marker::PhantomData, time::Duration};

use libafl_bolts::current_time;
#[cfg(feature = "std")]
use serde_json::json;

use crate::{
    corpus::{Corpus, HasCorpus, HasCurrentCorpusId},
    events::EventFirer,
    schedulers::minimizer::IsFavoredMetadata,
    stages::Stage,
    state::HasImported,
    Error, HasMetadata,
};
#[cfg(feature = "std")]
use crate::{
    events::Event,
    monitors::{AggregatorOps, UserStats, UserStatsValue},
};

/// The [`AflStatsStage`] is a simple stage that computes and reports some stats.
#[derive(Debug, Clone, Default)]
pub struct AflStatsStage {
    // the number of testcases that have been fuzzed
    has_fuzzed_size: usize,
    // the number of "favored" testcases
    is_favored_size: usize,
    // the number of testcases found by itself
    own_finds_size: usize,
    // the number of testcases imported by other fuzzers
    imported_size: usize,
    // the last time that we report all stats
    last_report_time: Duration,
    // the interval that we report all stats
    stats_report_interval: Duration,
}

impl<E, EM, S, Z> Stage<E, EM, S, Z> for AflStatsStage
where
    EM: EventFirer<<S::Corpus as Corpus>::Input, S>,
    S: HasImported + HasCorpus + HasMetadata + HasCurrentCorpusId,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut S,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        let Some(corpus_id) = state.current_corpus_id()? else {
            return Err(Error::illegal_state(
                "state is not currently processing a corpus index",
            ));
        };

        // Report your stats every `STATS_REPORT_INTERVAL`
        // compute pending, pending_favored, imported, own_finds
        {
            let testcase = state.corpus().get(corpus_id)?.borrow();
            if testcase.scheduled_count() == 0 {
                self.has_fuzzed_size += 1;
                if testcase.has_metadata::<IsFavoredMetadata>() {
                    self.is_favored_size += 1;
                }
            } else {
                return Ok(());
            }
        }

        let corpus_size = state.corpus().count();
        let pending_size = corpus_size - self.has_fuzzed_size;
        let pend_favored_size = corpus_size - self.is_favored_size;
        self.imported_size = *state.imported();
        self.own_finds_size = corpus_size - self.imported_size;

        let cur = current_time();

        if cur.checked_sub(self.last_report_time).unwrap_or_default() > self.stats_report_interval {
            #[cfg(feature = "std")]
            {
                let json = json!({
                        "pending":pending_size,
                        "pend_fav":pend_favored_size,
                        "own_finds":self.own_finds_size,
                        "imported":self.imported_size,
                });
                _manager.fire(
                    state,
                    Event::UpdateUserStats {
                        name: Cow::from("AflStats"),
                        value: UserStats::new(
                            UserStatsValue::String(Cow::from(json.to_string())),
                            AggregatorOps::None,
                        ),
                        phantom: PhantomData,
                    },
                )?;
            }
            #[cfg(not(feature = "std"))]
            log::info!(
                "pending: {}, pend_favored: {}, own_finds: {}, imported: {}",
                pending_size,
                pend_favored_size,
                self.own_finds_size,
                self.imported_size
            );
            self.last_report_time = cur;
        }

        Ok(())
    }

    #[inline]
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        // Not running the target so we wont't crash/timeout and, hence, don't need to restore anything
        Ok(true)
    }

    #[inline]
    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        // Not running the target so we wont't crash/timeout and, hence, don't need to restore anything
        Ok(())
    }
}

impl AflStatsStage {
    /// create a new instance of the [`AflStatsStage`]
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            stats_report_interval: interval,
            ..Default::default()
        }
    }
}
