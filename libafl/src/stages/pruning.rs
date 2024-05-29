use alloc::borrow::Cow;
use core::{marker::PhantomData, time::Duration};

use libafl_bolts::Named;
use typed_builder::TypedBuilder;

use crate::{
    stages::{RetryRestartHelper, Stage},
    state::{HasCorpus, UsesState},
    Error, HasNamedMetadata,
};

#[derive(TypedBuilder, Debug)]
#[builder]
/// Prune the corpus every `interval` with the probability of `prob`
pub struct PruningStage<E, EM, Z> {
    #[builder(default = 50)]
    prob: usize,
    #[builder(default = Duration::from_secs(3600))]
    interval: Duration,
    #[builder(default = libafl_bolts::current_time())]
    start_time: Duration,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<E, EM, Z> UsesState for PruningStage<E, EM, Z>
where
    E: UsesState,
{
    type State = E::State;
}

impl<E, EM, Z> Named for PruningStage<E, EM, Z> {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("Pruning")
    }
}
impl<E, EM, Z> Stage<E, EM, Z> for PruningStage<E, EM, Z>
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
    Self::State: HasNamedMetadata + HasCorpus,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let corpus = state.corpus_mut();
        Ok(())
    }

    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        RetryRestartHelper::clear_restart_progress(state, self)
    }

    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        RetryRestartHelper::restart_progress_should_run(state, self, 3)
    }
}
