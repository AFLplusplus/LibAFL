use std::{fmt::Debug, marker::PhantomData};

#[cfg(feature = "llmp_compression")]
use libafl_bolts::{compress::GzipCompressor, llmp::LLMP_FLAG_COMPRESSED};
use libafl_bolts::{
    llmp::{Flags, LlmpBrokerState, LlmpHook, LlmpMsgHookResult, Tag},
    shmem::ShMemProvider,
    ClientId, Error,
};

#[cfg(feature = "llmp_compression")]
use crate::events::COMPRESS_THRESHOLD;
use crate::{
    events::{BrokerEventResult, Event, _LLMP_TAG_TO_MAIN},
    inputs::Input,
};

/// An LLMP-backed event manager for scalable multi-processed fuzzing
pub struct CentralizedLlmpHook<I, SP> {
    #[cfg(feature = "llmp_compression")]
    compressor: GzipCompressor,
    phantom: PhantomData<(I, SP)>,
}

impl<I, SP> LlmpHook<SP> for CentralizedLlmpHook<I, SP>
where
    I: Input,
    SP: ShMemProvider + 'static,
{
    fn on_new_message(
        &mut self,
        _llmp_broker_state: &mut LlmpBrokerState<SP>,
        client_id: ClientId,
        msg_tag: &mut Tag,
        msg_flags: &mut Flags,
        msg: &mut [u8],
    ) -> Result<LlmpMsgHookResult, Error> {
        if *msg_tag == _LLMP_TAG_TO_MAIN {
            #[cfg(feature = "llmp_compression")]
            let compressor = &self.compressor;
            #[cfg(not(feature = "llmp_compression"))]
            let event_bytes = msg;
            #[cfg(feature = "llmp_compression")]
            let compressed;
            #[cfg(feature = "llmp_compression")]
            let event_bytes = if *msg_flags & LLMP_FLAG_COMPRESSED == LLMP_FLAG_COMPRESSED {
                compressed = compressor.decompress(msg)?;
                &compressed
            } else {
                &*msg
            };
            let event: Event<I> = postcard::from_bytes(event_bytes)?;
            match Self::handle_in_broker(client_id, &event)? {
                BrokerEventResult::Forward => Ok(LlmpMsgHookResult::ForwardToClients),
                BrokerEventResult::Handled => Ok(LlmpMsgHookResult::Handled),
            }
        } else {
            Ok(LlmpMsgHookResult::ForwardToClients)
        }
    }
}

impl<I, SP> Debug for CentralizedLlmpHook<I, SP> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_struct = f.debug_struct("CentralizedLlmpEventBroker");

        #[cfg(feature = "llmp_compression")]
        let debug_struct = debug_struct.field("compressor", &self.compressor);

        debug_struct
            .field("phantom", &self.phantom)
            .finish_non_exhaustive()
    }
}

impl<I, SP> CentralizedLlmpHook<I, SP>
where
    I: Input,
    SP: ShMemProvider + 'static,
{
    /// Create an event broker from a raw broker.
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
            phantom: PhantomData,
        })
    }

    /// Handle arriving events in the broker
    #[allow(clippy::unnecessary_wraps)]
    fn handle_in_broker(
        _client_id: ClientId,
        event: &Event<I>,
    ) -> Result<BrokerEventResult, Error> {
        match &event {
            Event::NewTestcase {
                input: _,
                client_config: _,
                exit_kind: _,
                corpus_size: _,
                observers_buf: _,
                time: _,
                executions: _,
                forward_id: _,
            } => Ok(BrokerEventResult::Forward),
            _ => Ok(BrokerEventResult::Handled),
        }
    }
}
