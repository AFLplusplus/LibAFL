use core::marker::PhantomData;

use libafl_bolts::Error;

use crate::corpus::CorpusId;
use crate::state::{HasCorpus, State, UsesState};

use super::Scheduler;

/// Never return any testcases.
///
/// Useful with [`crate::corpus::nop::NopCorpus`] and
/// [`crate::feedbacks::ConstFeedback::False`].
#[derive(Debug, Clone)]
pub struct NopScheduler<S>(PhantomData<S>);

impl<S> UsesState for NopScheduler<S>
where
    S: State,
{
    type State = S;
}

impl<S> Scheduler for NopScheduler<S>
where
    S: HasCorpus + State,
{
    fn on_add(&mut self, _state: &mut Self::State, _idx: CorpusId) -> Result<(), Error> {
        Ok(())
    }

    fn next(&mut self, _state: &mut Self::State) -> Result<CorpusId, Error> {
        Err(Error::empty("`NopScheduler` is always empty"))
    }
}

impl<S> NopScheduler<S> {
    /// Create a new [`NopScheduler`].
    #[must_use]
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<S> Default for NopScheduler<S> {
    fn default() -> Self {
        Self::new()
    }
}
