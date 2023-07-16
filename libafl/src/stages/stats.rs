//! Stage to compute/report AFL stats

use core::{marker::PhantomData, time::Duration};

use crate::{
    corpus::CorpusId,
    stages::Stage,
    state::UsesState,
    Error,
};

const STATS_REPORT_INTERVAL: Duration = Duration::from_secs(15); // change this as you want.

pub struct AFLStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
{
    pending: usize,
    pending_favored: usize,
    imported: usize,
    own_finds: usize,
    phantom: PhantomData<(E, EM, Z)>,
}


impl<E, EM, Z> UsesState for AFLStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<E, EM, Z> Stage<E, EM, Z> for AFLStatsStage<E, EM, Z> 
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        // Report your stats every `STATS_REPORT_INTERVAL`
        // compute pending, pending_favored, imported, own_finds

        Ok(())
    }
}
