//! Stage to compute/report AFL stats

use alloc::string::ToString;
use core::{marker::PhantomData, time::Duration};

use crate::{
    bolts::current_time,
    corpus::{Corpus, CorpusId},
    events::{Event, EventFirer},
    monitors::UserStats,
    schedulers::minimizer::IsFavoredMetadata,
    stages::Stage,
    state::{HasAFLStats, HasCorpus, HasMetadata, UsesState},
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
    E::State: HasAFLStats + HasCorpus + HasMetadata,
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

        let mut is_scheduled = false;
        let mut is_favored = false;
        {
            let testcase = state.corpus().get(corpus_idx)?.borrow();
            if testcase.scheduled_count() == 0 {
                is_scheduled = true;
                if testcase.has_metadata::<IsFavoredMetadata>() {
                    is_favored = true;
                }
            }
        }

        if is_scheduled {
            let pending_size = state.pending_mut();
            if *pending_size > 0 {
                *pending_size -= 1;
            }
        }

        if is_favored {
            let pend_favored_size = state.pend_favored_mut();
            if *pend_favored_size > 0 {
                *state.pend_favored_mut() -= 1;
            }
        }

        *state.own_finds_mut() = state.corpus().count() - state.imported();

        let cur = current_time();

        if cur.checked_sub(self.last_report_time).unwrap_or_default() > self.stats_report_interval {
            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: "pending".to_string(),
                    value: UserStats::Number(*state.pending() as u64),
                    phantom: PhantomData,
                },
            )?;

            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: "pend_fav".to_string(),
                    value: UserStats::Number(*state.pend_favored() as u64),
                    phantom: PhantomData,
                },
            )?;

            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: "own_finds".to_string(),
                    value: UserStats::Number(*state.own_finds() as u64),
                    phantom: PhantomData,
                },
            )?;

            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: "imported".to_string(),
                    value: UserStats::Number(*state.imported() as u64),
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
    E::State: HasAFLStats + HasCorpus + HasMetadata,
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
    E::State: HasAFLStats + HasCorpus + HasMetadata,
{
    /// the default instance of the [`AFLStatsStage`]
    #[must_use]
    fn default() -> Self {
        Self {
            last_report_time: current_time(),
            stats_report_interval: Duration::from_secs(15),
            phantom: PhantomData,
        }
    }
}
