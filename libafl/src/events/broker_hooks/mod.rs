//! Hooks called on broker side
use alloc::vec::Vec;
use core::marker::PhantomData;

#[cfg(feature = "llmp_compression")]
use libafl_bolts::{compress::GzipCompressor, llmp::LLMP_FLAG_COMPRESSED};
use libafl_bolts::{
    llmp::{Flags, LlmpBrokerInner, LlmpHook, LlmpMsgHookResult, Tag},
    shmem::ShMemProvider,
    ClientId,
};

#[cfg(feature = "llmp_compression")]
use crate::events::llmp::COMPRESS_THRESHOLD;
use crate::{
    events::{llmp::LLMP_TAG_EVENT_TO_BOTH, BrokerEventResult, Event},
    inputs::Input,
    monitors::Monitor,
    Error,
};

/// centralized hook
#[cfg(all(unix, feature = "std"))]
pub mod centralized;
#[cfg(all(unix, feature = "std"))]
pub use centralized::*;

/// Multi-machine hook
#[cfg(all(unix, feature = "multi_machine"))]
pub mod centralized_multi_machine;
#[cfg(all(unix, feature = "multi_machine"))]
pub use centralized_multi_machine::*;

/// An LLMP-backed event hook for scalable multi-processed fuzzing
#[derive(Debug)]
pub struct StdLlmpEventHook<I, MT> {
    monitor: MT,
    #[cfg(feature = "llmp_compression")]
    compressor: GzipCompressor,
    phantom: PhantomData<I>,
}

impl<I, MT, SP> LlmpHook<SP> for StdLlmpEventHook<I, MT>
where
    I: Input,
    MT: Monitor,
    SP: ShMemProvider,
{
    fn on_new_message(
        &mut self,
        _broker_inner: &mut LlmpBrokerInner<SP>,
        client_id: ClientId,
        msg_tag: &mut Tag,
        #[cfg(feature = "llmp_compression")] msg_flags: &mut Flags,
        #[cfg(not(feature = "llmp_compression"))] _msg_flags: &mut Flags,
        msg: &mut [u8],
        _new_msgs: &mut Vec<(Tag, Flags, Vec<u8>)>,
    ) -> Result<LlmpMsgHookResult, Error> {
        let monitor = &mut self.monitor;
        #[cfg(feature = "llmp_compression")]
        let compressor = &self.compressor;

        if *msg_tag == LLMP_TAG_EVENT_TO_BOTH {
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
            match Self::handle_in_broker(monitor, client_id, &event)? {
                BrokerEventResult::Forward => Ok(LlmpMsgHookResult::ForwardToClients),
                BrokerEventResult::Handled => Ok(LlmpMsgHookResult::Handled),
            }
        } else {
            Ok(LlmpMsgHookResult::ForwardToClients)
        }
    }

    fn on_timeout(&mut self) -> Result<(), Error> {
        self.monitor.display("Broker Heartbeat", ClientId(0));
        Ok(())
    }
}

impl<I, MT> StdLlmpEventHook<I, MT>
where
    I: Input,
    MT: Monitor,
{
    /// Create an event broker from a raw broker.
    pub fn new(monitor: MT) -> Result<Self, Error> {
        Ok(Self {
            monitor,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
            phantom: PhantomData,
        })
    }

    /// Handle arriving events in the broker
    #[allow(clippy::unnecessary_wraps)]
    fn handle_in_broker(
        monitor: &mut MT,
        client_id: ClientId,
        event: &Event<I>,
    ) -> Result<BrokerEventResult, Error> {
        match &event {
            Event::NewTestcase {
                corpus_size,
                forward_id,
                ..
            } => {
                let id = if let Some(id) = *forward_id {
                    id
                } else {
                    client_id
                };

                monitor.client_stats_insert(id);
                let client = monitor.client_stats_mut_for(id);
                client.update_corpus_size(*corpus_size as u64);
                monitor.display(event.name(), id);
                Ok(BrokerEventResult::Forward)
            }
            Event::UpdateExecStats {
                time,
                executions,
                phantom: _,
            } => {
                // TODO: The monitor buffer should be added on client add.
                monitor.client_stats_insert(client_id);
                let client = monitor.client_stats_mut_for(client_id);
                client.update_executions(*executions, *time);
                monitor.display(event.name(), client_id);
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateUserStats {
                name,
                value,
                phantom: _,
            } => {
                monitor.client_stats_insert(client_id);
                let client = monitor.client_stats_mut_for(client_id);
                client.update_user_stats(name.clone(), value.clone());
                monitor.aggregate(name);
                monitor.display(event.name(), client_id);
                Ok(BrokerEventResult::Handled)
            }
            #[cfg(feature = "introspection")]
            Event::UpdatePerfMonitor {
                time,
                executions,
                introspection_monitor,
                phantom: _,
            } => {
                // TODO: The monitor buffer should be added on client add.

                // Get the client for the staterestorer ID
                monitor.client_stats_insert(client_id);
                let client = monitor.client_stats_mut_for(client_id);

                // Update the normal monitor for this client
                client.update_executions(*executions, *time);

                // Update the performance monitor for this client
                client.update_introspection_monitor((**introspection_monitor).clone());

                // Display the monitor via `.display` only on core #1
                monitor.display(event.name(), client_id);

                // Correctly handled the event
                Ok(BrokerEventResult::Handled)
            }
            Event::Objective { objective_size, .. } => {
                monitor.client_stats_insert(client_id);
                let client = monitor.client_stats_mut_for(client_id);
                client.update_objective_size(*objective_size as u64);
                monitor.display(event.name(), client_id);
                Ok(BrokerEventResult::Handled)
            }
            Event::Log {
                severity_level,
                message,
                phantom: _,
            } => {
                let (_, _) = (severity_level, message);
                // TODO rely on Monitor
                log::log!((*severity_level).into(), "{message}");
                Ok(BrokerEventResult::Handled)
            }
            Event::CustomBuf { .. } => Ok(BrokerEventResult::Forward),
            Event::Stop => Ok(BrokerEventResult::Forward),
            //_ => Ok(BrokerEventResult::Forward),
        }
    }
}
