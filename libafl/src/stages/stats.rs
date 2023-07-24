//! Stage to compute/report AFL stats

use alloc::string::ToString;
use core::{marker::PhantomData, time::Duration};

use serde_json::json;

use crate::{
    bolts::current_time,
    corpus::{Corpus, CorpusId},
    events::{Event, EventFirer},
    monitors::UserStats,
    schedulers::minimizer::IsFavoredMetadata,
    stages::Stage,
    state::{HasCorpus, HasImported, HasMetadata, UsesState},
    Error,
};

/// The [`AFLStatsStage`] is a simple stage that computes and reports some stats.
#[derive(Debug, Clone)]
pub struct AFLStatsStage<E, EM, Z>
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

impl<E, EM, Z> UsesState for AFLStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: EventFirer<State = E::State>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<E, EM, Z> Stage<E, EM, Z> for AFLStatsStage<E, EM, Z>
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
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        // Report your stats every `STATS_REPORT_INTERVAL`
        // compute pending, pending_favored, imported, own_finds

        {
            let testcase = state.corpus().get(corpus_idx)?.borrow();
            if testcase.scheduled_count() == 0 {
                self.has_fuzzed_size += 1;
                if testcase.has_metadata::<IsFavoredMetadata>() {
                    self.is_favored_size += 1;
                }
            }
        }

        let corpus_size = state.corpus().count();
        let pending_size = corpus_size - self.has_fuzzed_size;
        let pend_favored_size = pending_size - self.is_favored_size;
        self.imported_size = *state.imported();
        self.own_finds_size = corpus_size - self.own_finds_size;

        let cur = current_time();

        if cur.checked_sub(self.last_report_time).unwrap_or_default() > self.stats_report_interval {
            let json = json!({
                    "pending":pending_size,
                    "pend_favored":pend_favored_size,
                    "own_finds":self.own_finds_size,
                    "imported":self.imported_size,
            });
            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: "AflStats".to_string(),
                    value: UserStats::String(json.to_string()),
                    phantom: PhantomData,
                },
            )?;
        }
        self.last_report_time = cur;

        Ok(())
    }
}

impl<E, EM, Z> AFLStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: EventFirer<State = E::State>,
    Z: UsesState<State = E::State>,
    E::State: HasImported + HasCorpus + HasMetadata,
{
    /// create a new instance of the [`AFLStatsStage`]
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            stats_report_interval: interval,
            ..Default::default()
        }
    }
}

impl<E, EM, Z> Default for AFLStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: EventFirer<State = E::State>,
    Z: UsesState<State = E::State>,
    E::State: HasImported + HasCorpus + HasMetadata,
{
    /// the default instance of the [`AFLStatsStage`]
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
