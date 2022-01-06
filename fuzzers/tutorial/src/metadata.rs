use libafl::{
    bolts::tuples::Named,
    corpus::{FavFactor, MinimizerCorpusScheduler, Testcase},
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, MapIndexesMetadata},
    observers::ObserversTuple,
    state::{HasClientPerfMonitor, HasMetadata},
    Error, SerdeAny,
};

use crate::input::PacketData;

use serde::{Deserialize, Serialize};

#[derive(Debug, SerdeAny, Serialize, Deserialize)]
pub struct PacketLenMetadata {
    pub length: u64,
}

pub struct PacketLenFavFactor {}

impl FavFactor<PacketData> for PacketLenFavFactor {
    fn compute(entry: &mut Testcase<PacketData>) -> Result<u64, Error> {
        Ok(entry
            .metadata()
            .get::<PacketLenMetadata>()
            .map_or(1, |m| m.length))
    }
}

pub type PacketLenMinimizerCorpusScheduler<CS, S> =
    MinimizerCorpusScheduler<CS, PacketLenFavFactor, PacketData, MapIndexesMetadata, S>;

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct PacketLenFeedback {
    len: u64,
}

impl<S> Feedback<PacketData, S> for PacketLenFeedback
where
    S: HasClientPerfMonitor,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        input: &PacketData,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<PacketData>,
        OT: ObserversTuple<PacketData, S>,
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

    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &PacketData) -> Result<(), Error> {
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
