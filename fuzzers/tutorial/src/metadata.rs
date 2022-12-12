use libafl::{
    bolts::tuples::Named,
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, MapIndexesMetadata},
    inputs::UsesInput,
    observers::ObserversTuple,
    schedulers::{MinimizerScheduler, TestcaseScore},
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata},
    Error, SerdeAny,
};
use serde::{Deserialize, Serialize};

use crate::input::PacketData;

#[derive(Debug, SerdeAny, Serialize, Deserialize)]
pub struct PacketLenMetadata {
    pub length: u64,
}

pub struct PacketLenTestcaseScore {}

impl<S> TestcaseScore<S> for PacketLenTestcaseScore
where
    S: HasCorpus<Input = PacketData> + HasMetadata,
{
    fn compute(entry: &mut Testcase<PacketData>, _state: &S) -> Result<f64, Error> {
        Ok(entry
            .metadata()
            .get::<PacketLenMetadata>()
            .map_or(1, |m| m.length) as f64)
    }
}

pub type PacketLenMinimizerScheduler<CS> =
    MinimizerScheduler<CS, PacketLenTestcaseScore, MapIndexesMetadata>;

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct PacketLenFeedback {
    len: u64,
}

impl<S> Feedback<S> for PacketLenFeedback
where
    S: UsesInput<Input = PacketData> + HasClientPerfMonitor,
{
    #[inline]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        input: &PacketData,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        self.len = input.length;
        Ok(false)
    }

    #[inline]
    fn append_metadata(
        &mut self,
        _state: &mut S,
        testcase: &mut Testcase<PacketData>,
    ) -> Result<(), Error> {
        testcase
            .metadata_mut()
            .insert(PacketLenMetadata { length: self.len });
        Ok(())
    }
}

impl Named for PacketLenFeedback {
    #[inline]
    fn name(&self) -> &str {
        "PacketLenFeedback"
    }
}

impl PacketLenFeedback {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
