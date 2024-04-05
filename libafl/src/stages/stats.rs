//! Stage to compute/report AFL stats

#[cfg(feature = "std")]
use alloc::string::ToString;
use core::{marker::PhantomData, time::Duration};

use libafl_bolts::current_time;
#[cfg(feature = "std")]
use serde_json::json;

use crate::{
    corpus::{Corpus, HasCurrentCorpusIdx},
    events::EventFirer,
    schedulers::minimizer::IsFavoredMetadata,
    stages::Stage,
    state::{HasCorpus, HasImported, HasMetadata, UsesState},
    Error,
};
#[cfg(feature = "std")]
use crate::{
    events::Event,
    monitors::{AggregatorOps, UserStats, UserStatsValue},
};

/// The [`AflStatsStage`] is a simple stage that computes and reports some stats.
#[derive(Debug, Clone)]
pub struct AflStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: EventFirer<State = E::State>,
    Z: UsesState<State = E::State>,
{
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

    phantom: PhantomData<(E, EM, Z)>,
}

impl<E, EM, Z> UsesState for AflStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: EventFirer<State = E::State>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<E, EM, Z> Stage<E, EM, Z> for AflStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: EventFirer<State = E::State>,
    Z: UsesState<State = E::State>,
    E::State: HasImported + HasCorpus + HasMetadata,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut E::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        let Some(corpus_idx) = state.current_corpus_idx()? else {
            return Err(Error::illegal_state(
                "state is not currently processing a corpus index",
            ));
        };

        // Report your stats every `STATS_REPORT_INTERVAL`
        // compute pending, pending_favored, imported, own_finds
        {
            let testcase = state.corpus().get(corpus_idx)?.borrow();
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
                        name: "AflStats".to_string(),
                        value: UserStats::new(
                            UserStatsValue::String(json.to_string()),
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
    fn restart_progress_should_run(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        // Not running the target so we wont't crash/timeout and, hence, don't need to restore anything
        Ok(true)
    }

    #[inline]
    fn clear_restart_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        // Not running the target so we wont't crash/timeout and, hence, don't need to restore anything
        Ok(())
    }
}

impl<E, EM, Z> AflStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: EventFirer<State = E::State>,
    Z: UsesState<State = E::State>,
    E::State: HasImported + HasCorpus + HasMetadata,
{
    /// create a new instance of the [`AflStatsStage`]
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            stats_report_interval: interval,
            ..Default::default()
        }
    }
}

impl<E, EM, Z> Default for AflStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: EventFirer<State = E::State>,
    Z: UsesState<State = E::State>,
    E::State: HasImported + HasCorpus + HasMetadata,
{
    /// the default instance of the [`AflStatsStage`]
    #[must_use]
    fn default() -> Self {
        Self {
            has_fuzzed_size: 0,
            is_favored_size: 0,
            own_finds_size: 0,
            imported_size: 0,
            last_report_time: current_time(),
            stats_report_interval: Duration::from_secs(15),
            phantom: PhantomData,
        }
    }
}
