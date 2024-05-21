//! LLMP broker

use core::{marker::PhantomData, num::NonZeroUsize, time::Duration};
#[cfg(feature = "std")]
use std::net::ToSocketAddrs;

#[cfg(feature = "llmp_compression")]
use libafl_bolts::{compress::GzipCompressor, llmp::LLMP_FLAG_COMPRESSED};
use libafl_bolts::{llmp, shmem::ShMemProvider, ClientId};

#[cfg(feature = "llmp_compression")]
use crate::events::llmp::COMPRESS_THRESHOLD;
use crate::{
    events::{llmp::LLMP_TAG_EVENT_TO_BOTH, BrokerEventResult, Event},
    inputs::Input,
    monitors::Monitor,
    Error,
};

/// An LLMP-backed event manager for scalable multi-processed fuzzing
#[derive(Debug)]
pub struct LlmpEventBroker<I, MT, SP>
where
    I: Input,
    SP: ShMemProvider + 'static,
    MT: Monitor,
    //CE: CustomEvent<I>,
{
    monitor: MT,
    llmp: llmp::LlmpBroker<SP>,
    #[cfg(feature = "llmp_compression")]
    compressor: GzipCompressor,
    phantom: PhantomData<I>,
}

impl<I, MT, SP> LlmpEventBroker<I, MT, SP>
where
    I: Input,
    SP: ShMemProvider + 'static,
    MT: Monitor,
{
    /// Create an event broker from a raw broker.
    pub fn new(llmp: llmp::LlmpBroker<SP>, monitor: MT) -> Result<Self, Error> {
        Ok(Self {
            monitor,
            llmp,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
            phantom: PhantomData,
        })
    }

    /// Create an LLMP broker on a port.
    ///
    /// The port must not be bound yet to have a broker.
    #[cfg(feature = "std")]
    pub fn on_port(shmem_provider: SP, monitor: MT, port: u16) -> Result<Self, Error> {
        Ok(Self {
            monitor,
            llmp: llmp::LlmpBroker::create_attach_to_tcp(shmem_provider, port)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
            phantom: PhantomData,
        })
    }

    /// Exit the broker process cleanly after at least `n` clients attached and all of them disconnected again
    pub fn set_exit_cleanly_after(&mut self, n_clients: NonZeroUsize) {
        self.llmp.set_exit_cleanly_after(n_clients);
    }

    /// Connect to an LLMP broker on the given address
    #[cfg(feature = "std")]
    pub fn connect_b2b<A>(&mut self, addr: A) -> Result<(), Error>
    where
        A: ToSocketAddrs,
    {
        self.llmp.connect_b2b(addr)
    }

    /// Run forever in the broker
    #[cfg(not(feature = "llmp_broker_timeouts"))]
    pub fn broker_loop(&mut self) -> Result<(), Error> {
        let monitor = &mut self.monitor;
        #[cfg(feature = "llmp_compression")]
        let compressor = &self.compressor;
        self.llmp.loop_forever(
            &mut |client_id, tag, _flags, msg| {
                if tag == LLMP_TAG_EVENT_TO_BOTH {
                    #[cfg(not(feature = "llmp_compression"))]
                    let event_bytes = msg;
                    #[cfg(feature = "llmp_compression")]
                    let compressed;
                    #[cfg(feature = "llmp_compression")]
                    let event_bytes = if _flags & LLMP_FLAG_COMPRESSED == LLMP_FLAG_COMPRESSED {
                        compressed = compressor.decompress(msg)?;
                        &compressed
                    } else {
                        msg
                    };
                    let event: Event<I> = postcard::from_bytes(event_bytes)?;
                    match Self::handle_in_broker(monitor, client_id, &event)? {
                        BrokerEventResult::Forward => Ok(llmp::LlmpMsgHookResult::ForwardToClients),
                        BrokerEventResult::Handled => Ok(llmp::LlmpMsgHookResult::Handled),
                    }
                } else {
                    Ok(llmp::LlmpMsgHookResult::ForwardToClients)
                }
            },
            Some(Duration::from_millis(5)),
        );

        #[cfg(all(feature = "std", feature = "llmp_debug"))]
        println!("The last client quit. Exiting.");

        Err(Error::shutting_down())
    }

    /// Run in the broker until all clients exit
    #[cfg(feature = "llmp_broker_timeouts")]
    pub fn broker_loop(&mut self) -> Result<(), Error> {
        let monitor = &mut self.monitor;
        #[cfg(feature = "llmp_compression")]
        let compressor = &self.compressor;
        self.llmp.loop_with_timeouts(
            &mut |msg_or_timeout| {
                if let Some((client_id, tag, _flags, msg)) = msg_or_timeout {
                    if tag == LLMP_TAG_EVENT_TO_BOTH {
                        #[cfg(not(feature = "llmp_compression"))]
                        let event_bytes = msg;
                        #[cfg(feature = "llmp_compression")]
                        let compressed;
                        #[cfg(feature = "llmp_compression")]
                        let event_bytes = if _flags & LLMP_FLAG_COMPRESSED == LLMP_FLAG_COMPRESSED {
                            compressed = compressor.decompress(msg)?;
                            &compressed
                        } else {
                            msg
                        };
                        let event: Event<I> = postcard::from_bytes(event_bytes)?;
                        match Self::handle_in_broker(monitor, client_id, &event)? {
                            BrokerEventResult::Forward => {
                                Ok(llmp::LlmpMsgHookResult::ForwardToClients)
                            }
                            BrokerEventResult::Handled => Ok(llmp::LlmpMsgHookResult::Handled),
                        }
                    } else {
                        Ok(llmp::LlmpMsgHookResult::ForwardToClients)
                    }
                } else {
                    monitor.display("Broker Heartbeat", ClientId(0));
                    Ok(llmp::LlmpMsgHookResult::Handled)
                }
            },
            Duration::from_secs(30),
            Some(Duration::from_millis(5)),
        );

        #[cfg(feature = "llmp_debug")]
        println!("The last client quit. Exiting.");

        Err(Error::shutting_down())
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
                input: _,
                client_config: _,
                exit_kind: _,
                corpus_size,
                observers_buf: _,
                time,
                executions,
                forward_id,
            } => {
                let id = if let Some(id) = *forward_id {
                    id
                } else {
                    client_id
                };

                monitor.client_stats_insert(id);
                let client = monitor.client_stats_mut_for(id);
                client.update_corpus_size(*corpus_size as u64);
                if id == client_id {
                    // do not update executions for forwarded messages, otherwise we loose the total order
                    // as a forwarded msg with a lower executions may arrive after a stats msg with an higher executions
                    // this also means when you wrap this event manger with centralized EM, you will **NOT** get executions update with the new tc message
                    client.update_executions(*executions, *time);
                }
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
            Event::Objective {
                objective_size,
                executions,
                time,
            } => {
                monitor.client_stats_insert(client_id);
                let client = monitor.client_stats_mut_for(client_id);
                client.update_objective_size(*objective_size as u64);
                client.update_executions(*executions, *time);
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
            //_ => Ok(BrokerEventResult::Forward),
        }
    }
}
