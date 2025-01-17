use std::borrow::Cow;

use libafl::{
    corpus::Testcase,
    executors::ExitKind,
    feedbacks::{Feedback, MapIndexesMetadata, StateInitializer},
    schedulers::{MinimizerScheduler, TestcaseScore},
    Error, HasMetadata,
};
use libafl_bolts::{Named, SerdeAny};
use serde::{Deserialize, Serialize};

use crate::input::PacketData;

#[derive(Debug, SerdeAny, Serialize, Deserialize)]
pub struct PacketLenMetadata {
    pub length: u64,
}

pub struct PacketLenTestcaseScore {}

impl<I, S> TestcaseScore<I, S> for PacketLenTestcaseScore
where
    S: HasMetadata,
{
    fn compute(_state: &S, entry: &mut Testcase<I>) -> Result<f64, Error> {
        Ok(entry
            .metadata_map()
            .get::<PacketLenMetadata>()
            .map_or(1, |m| m.length) as f64)
    }
}

pub type PacketLenMinimizerScheduler<CS, I, S> =
    MinimizerScheduler<CS, PacketLenTestcaseScore, I, MapIndexesMetadata, S>;

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct PacketLenFeedback {
    len: u64,
}

impl<S> StateInitializer<S> for PacketLenFeedback {}

impl<EM, OT, S> Feedback<EM, PacketData, OT, S> for PacketLenFeedback {
    #[inline]
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        input: &PacketData,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        self.len = input.length;
        Ok(false)
    }

    #[inline]
    fn append_metadata(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<PacketData>,
    ) -> Result<(), Error> {
        testcase
            .metadata_map_mut()
            .insert(PacketLenMetadata { length: self.len });
        Ok(())
    }
}

impl Named for PacketLenFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("PacketLenFeedback");
        &NAME
    }
}

impl PacketLenFeedback {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
