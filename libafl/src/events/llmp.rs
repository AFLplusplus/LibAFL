//! LLMP-backed event manager for scalable multi-processed fuzzing

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
#[cfg(feature = "std")]
use core::sync::atomic::{compiler_fence, Ordering};
use core::{marker::PhantomData, num::NonZeroUsize, time::Duration};
#[cfg(feature = "std")]
use std::net::{SocketAddr, ToSocketAddrs};

use serde::Deserialize;
#[cfg(feature = "std")]
use serde::{de::DeserializeOwned, Serialize};
#[cfg(feature = "std")]
use typed_builder::TypedBuilder;

use super::{CustomBufEventResult, CustomBufHandlerFn};
#[cfg(feature = "std")]
use crate::bolts::core_affinity::CoreId;
#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use crate::bolts::os::startable_self;
#[cfg(all(unix, feature = "std", not(miri)))]
use crate::bolts::os::unix_signals::setup_signal_handler;
#[cfg(all(feature = "std", feature = "fork", unix))]
use crate::bolts::os::{fork, ForkResult};
#[cfg(feature = "llmp_compression")]
use crate::bolts::{
    compress::GzipCompressor,
    llmp::{LLMP_FLAG_COMPRESSED, LLMP_FLAG_INITIALIZED},
};
#[cfg(feature = "std")]
use crate::bolts::{llmp::LlmpConnection, shmem::StdShMemProvider, staterestore::StateRestorer};
#[cfg(all(unix, feature = "std"))]
use crate::events::{shutdown_handler, SHUTDOWN_SIGHANDLER_DATA};
use crate::{
    bolts::{
        llmp::{self, LlmpClient, LlmpClientDescription, Tag},
        shmem::ShMemProvider,
        ClientId,
    },
    events::{
        BrokerEventResult, Event, EventConfig, EventFirer, EventManager, EventManagerId,
        EventProcessor, EventRestarter, HasCustomBufHandlers, HasEventManagerId, ProgressReporter,
    },
    executors::{Executor, HasObservers},
    fuzzer::{EvaluatorObservers, ExecutionProcessor},
    inputs::{Input, InputConverter, UsesInput},
    monitors::Monitor,
    state::{HasClientPerfMonitor, HasExecutions, HasMetadata, UsesState},
    Error,
};

/// Forward this to the client
const _LLMP_TAG_EVENT_TO_CLIENT: Tag = Tag(0x2C11E471);
/// Only handle this in the broker
const _LLMP_TAG_EVENT_TO_BROKER: Tag = Tag(0x2B80438);
/// Handle in both
///
const LLMP_TAG_EVENT_TO_BOTH: Tag = Tag(0x2B0741);
const _LLMP_TAG_RESTART: Tag = Tag(0x8357A87);
const _LLMP_TAG_NO_RESTART: Tag = Tag(0x57A7EE71);

/// The minimum buffer size at which to compress LLMP IPC messages.
#[cfg(feature = "llmp_compression")]
const COMPRESS_THRESHOLD: usize = 1024;

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
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
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
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
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
                    monitor.display("Broker".into(), ClientId(0));
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
                let client = monitor.client_stats_mut_for(id);
                client.update_corpus_size(*corpus_size as u64);
                client.update_executions(*executions as u64, *time);
                monitor.display(event.name().to_string(), id);
                Ok(BrokerEventResult::Forward)
            }
            Event::UpdateExecStats {
                time,
                executions,
                phantom: _,
            } => {
                // TODO: The monitor buffer should be added on client add.
                let client = monitor.client_stats_mut_for(client_id);
                client.update_executions(*executions as u64, *time);
                monitor.display(event.name().to_string(), client_id);
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateUserStats {
                name,
                value,
                phantom: _,
            } => {
                let client = monitor.client_stats_mut_for(client_id);
                client.update_user_stats(name.clone(), value.clone());
                monitor.display(event.name().to_string(), client_id);
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
                let client = monitor.client_stats_mut_for(client_id);

                // Update the normal monitor for this client
                client.update_executions(*executions as u64, *time);

                // Update the performance monitor for this client
                client.update_introspection_monitor((**introspection_monitor).clone());

                // Display the monitor via `.display` only on core #1
                monitor.display(event.name().to_string(), client_id);

                // Correctly handled the event
                Ok(BrokerEventResult::Handled)
            }
            Event::Objective { objective_size } => {
                let client = monitor.client_stats_mut_for(client_id);
                client.update_objective_size(*objective_size as u64);
                monitor.display(event.name().to_string(), client_id);
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

/// An [`EventManager`] that forwards all events to other attached fuzzers on shared maps or via tcp,
/// using low-level message passing, [`crate::bolts::llmp`].
pub struct LlmpEventManager<S, SP>
where
    S: UsesInput,
    SP: ShMemProvider + 'static,
{
    /// The LLMP client for inter process communication
    llmp: LlmpClient<SP>,
    /// The custom buf handler
    custom_buf_handlers: Vec<Box<CustomBufHandlerFn<S>>>,
    #[cfg(feature = "llmp_compression")]
    compressor: GzipCompressor,
    /// The configuration defines this specific fuzzer.
    /// A node will not re-use the observer values sent over LLMP
    /// from nodes with other configurations.
    configuration: EventConfig,
    phantom: PhantomData<S>,
}

impl<S, SP> core::fmt::Debug for LlmpEventManager<S, SP>
where
    SP: ShMemProvider + 'static,
    S: UsesInput,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_struct = f.debug_struct("LlmpEventManager");
        let debug = debug_struct.field("llmp", &self.llmp);
        //.field("custom_buf_handlers", &self.custom_buf_handlers)
        #[cfg(feature = "llmp_compression")]
        let debug = debug.field("compressor", &self.compressor);
        debug
            .field("configuration", &self.configuration)
            .field("phantom", &self.phantom)
            .finish_non_exhaustive()
    }
}

impl<S, SP> Drop for LlmpEventManager<S, SP>
where
    SP: ShMemProvider + 'static,
    S: UsesInput,
{
    /// LLMP clients will have to wait until their pages are mapped by somebody.
    fn drop(&mut self) {
        self.await_restart_safe();
    }
}

impl<S, SP> LlmpEventManager<S, SP>
where
    S: UsesInput + HasExecutions + HasClientPerfMonitor,
    SP: ShMemProvider + 'static,
{
    /// Create a manager from a raw LLMP client
    pub fn new(llmp: LlmpClient<SP>, configuration: EventConfig) -> Result<Self, Error> {
        Ok(Self {
            llmp,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            configuration,
            phantom: PhantomData,
            custom_buf_handlers: vec![],
        })
    }

    /// Create an LLMP event manager on a port
    ///
    /// If the port is not yet bound, it will act as a broker; otherwise, it
    /// will act as a client.
    #[cfg(feature = "std")]
    pub fn on_port(
        shmem_provider: SP,
        port: u16,
        configuration: EventConfig,
    ) -> Result<Self, Error> {
        Ok(Self {
            llmp: LlmpClient::create_attach_to_tcp(shmem_provider, port)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            configuration,
            phantom: PhantomData,
            custom_buf_handlers: vec![],
        })
    }

    /// If a client respawns, it may reuse the existing connection, previously
    /// stored by [`LlmpClient::to_env()`].
    #[cfg(feature = "std")]
    pub fn existing_client_from_env(
        shmem_provider: SP,
        env_name: &str,
        configuration: EventConfig,
    ) -> Result<Self, Error> {
        Ok(Self {
            llmp: LlmpClient::on_existing_from_env(shmem_provider, env_name)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            configuration,
            phantom: PhantomData,
            custom_buf_handlers: vec![],
        })
    }

    /// Describe the client event manager's LLMP parts in a restorable fashion
    pub fn describe(&self) -> Result<LlmpClientDescription, Error> {
        self.llmp.describe()
    }

    /// Create an existing client from description
    pub fn existing_client_from_description(
        shmem_provider: SP,
        description: &LlmpClientDescription,
        configuration: EventConfig,
    ) -> Result<Self, Error> {
        Ok(Self {
            llmp: LlmpClient::existing_client_from_description(shmem_provider, description)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            configuration,
            phantom: PhantomData,
            custom_buf_handlers: vec![],
        })
    }

    /// Write the config for a client [`EventManager`] to env vars, a new
    /// client can reattach using [`LlmpEventManager::existing_client_from_env()`].
    #[cfg(feature = "std")]
    pub fn to_env(&self, env_name: &str) {
        self.llmp.to_env(env_name).unwrap();
    }

    // Handle arriving events in the client
    #[allow(clippy::unused_self)]
    fn handle_in_client<E, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        client_id: ClientId,
        event: Event<S::Input>,
    ) -> Result<(), Error>
    where
        E: Executor<Self, Z> + HasObservers<State = S>,
        for<'a> E::Observers: Deserialize<'a>,
        Z: ExecutionProcessor<E::Observers, State = S> + EvaluatorObservers<E::Observers>,
    {
        match event {
            Event::NewTestcase {
                input,
                client_config,
                exit_kind,
                corpus_size: _,
                observers_buf,
                time: _,
                executions: _,
                forward_id,
            } => {
                log::info!("Received new Testcase from {client_id:?} ({client_config:?}, forward {forward_id:?})");

                let _res = if client_config.match_with(&self.configuration)
                    && observers_buf.is_some()
                {
                    let observers: E::Observers =
                        postcard::from_bytes(observers_buf.as_ref().unwrap())?;
                    fuzzer.process_execution(state, self, input, &observers, &exit_kind, false)?
                } else {
                    fuzzer.evaluate_input_with_observers::<E, Self>(
                        state, executor, self, input, false,
                    )?
                };
                if let Some(item) = _res.1 {
                    log::info!("Added received Testcase as item #{item}");
                }
                Ok(())
            }
            Event::CustomBuf { tag, buf } => {
                for handler in &mut self.custom_buf_handlers {
                    if handler(state, &tag, &buf)? == CustomBufEventResult::Handled {
                        break;
                    }
                }
                Ok(())
            }
            _ => Err(Error::unknown(format!(
                "Received illegal message that message should not have arrived: {:?}.",
                event.name()
            ))),
        }
    }
}

impl<S: UsesInput, SP: ShMemProvider> LlmpEventManager<S, SP> {
    /// Send information that this client is exiting.
    /// The other side may free up all allocated memory.
    /// We are no longer allowed to send anything afterwards.
    pub fn send_exiting(&mut self) -> Result<(), Error> {
        self.llmp.sender.send_exiting()
    }
}

impl<S, SP> UsesState for LlmpEventManager<S, SP>
where
    S: UsesInput,
    SP: ShMemProvider,
{
    type State = S;
}

impl<S, SP> EventFirer for LlmpEventManager<S, SP>
where
    S: UsesInput,
    SP: ShMemProvider,
{
    #[cfg(feature = "llmp_compression")]
    fn fire(
        &mut self,
        _state: &mut Self::State,
        event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        let serialized = postcard::to_allocvec(&event)?;
        let flags = LLMP_FLAG_INITIALIZED;

        match self.compressor.compress(&serialized)? {
            Some(comp_buf) => {
                self.llmp.send_buf_with_flags(
                    LLMP_TAG_EVENT_TO_BOTH,
                    flags | LLMP_FLAG_COMPRESSED,
                    &comp_buf,
                )?;
            }
            None => {
                self.llmp.send_buf(LLMP_TAG_EVENT_TO_BOTH, &serialized)?;
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "llmp_compression"))]
    fn fire(
        &mut self,
        _state: &mut Self::State,
        event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        let serialized = postcard::to_allocvec(&event)?;
        self.llmp.send_buf(LLMP_TAG_EVENT_TO_BOTH, &serialized)?;
        Ok(())
    }

    fn configuration(&self) -> EventConfig {
        self.configuration
    }
}

impl<S, SP> EventRestarter for LlmpEventManager<S, SP>
where
    S: UsesInput,
    SP: ShMemProvider,
{
    /// The LLMP client needs to wait until a broker has mapped all pages before shutting down.
    /// Otherwise, the OS may already have removed the shared maps.
    fn await_restart_safe(&mut self) {
        // wait until we can drop the message safely.
        self.llmp.await_safe_to_unmap_blocking();
    }
}

impl<E, S, SP, Z> EventProcessor<E, Z> for LlmpEventManager<S, SP>
where
    S: UsesInput + HasClientPerfMonitor + HasExecutions,
    SP: ShMemProvider,
    E: HasObservers<State = S> + Executor<Self, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    Z: EvaluatorObservers<E::Observers, State = S> + ExecutionProcessor<E::Observers, State = S>,
{
    fn process(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        executor: &mut E,
    ) -> Result<usize, Error> {
        // TODO: Get around local event copy by moving handle_in_client
        let self_id = self.llmp.sender.id;
        let mut count = 0;
        while let Some((client_id, tag, _flags, msg)) = self.llmp.recv_buf_with_flags()? {
            assert!(
                tag != _LLMP_TAG_EVENT_TO_BROKER,
                "EVENT_TO_BROKER parcel should not have arrived in the client!"
            );

            if client_id == self_id {
                continue;
            }
            #[cfg(not(feature = "llmp_compression"))]
            let event_bytes = msg;
            #[cfg(feature = "llmp_compression")]
            let compressed;
            #[cfg(feature = "llmp_compression")]
            let event_bytes = if _flags & LLMP_FLAG_COMPRESSED == LLMP_FLAG_COMPRESSED {
                compressed = self.compressor.decompress(msg)?;
                &compressed
            } else {
                msg
            };
            let event: Event<S::Input> = postcard::from_bytes(event_bytes)?;
            self.handle_in_client(fuzzer, executor, state, client_id, event)?;
            count += 1;
        }
        Ok(count)
    }
}

impl<E, S, SP, Z> EventManager<E, Z> for LlmpEventManager<S, SP>
where
    E: HasObservers<State = S> + Executor<Self, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    S: UsesInput + HasExecutions + HasClientPerfMonitor + HasMetadata,
    SP: ShMemProvider,
    Z: EvaluatorObservers<E::Observers, State = S> + ExecutionProcessor<E::Observers, State = S>,
{
}

impl<S, SP> HasCustomBufHandlers for LlmpEventManager<S, SP>
where
    S: UsesInput,
    SP: ShMemProvider,
{
    fn add_custom_buf_handler(
        &mut self,
        handler: Box<dyn FnMut(&mut S, &String, &[u8]) -> Result<CustomBufEventResult, Error>>,
    ) {
        self.custom_buf_handlers.push(handler);
    }
}

impl<S, SP> ProgressReporter for LlmpEventManager<S, SP>
where
    S: UsesInput + HasExecutions + HasClientPerfMonitor + HasMetadata,
    SP: ShMemProvider,
{
}

impl<S, SP> HasEventManagerId for LlmpEventManager<S, SP>
where
    S: UsesInput,
    SP: ShMemProvider,
{
    /// Gets the id assigned to this staterestorer.
    fn mgr_id(&self) -> EventManagerId {
        EventManagerId(self.llmp.sender.id.0 as usize)
    }
}

/// A manager that can restart on the fly, storing states in-between (in `on_restart`)
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct LlmpRestartingEventManager<S, SP>
where
    S: UsesInput,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    /// The embedded LLMP event manager
    llmp_mgr: LlmpEventManager<S, SP>,
    /// The staterestorer to serialize the state for the next runner
    staterestorer: StateRestorer<SP>,
    /// Decide if the state restorer must save the serialized state
    save_state: bool,
}

#[cfg(feature = "std")]
impl<S, SP> UsesState for LlmpRestartingEventManager<S, SP>
where
    S: UsesInput,
    SP: ShMemProvider + 'static,
{
    type State = S;
}

#[cfg(feature = "std")]
impl<S, SP> ProgressReporter for LlmpRestartingEventManager<S, SP>
where
    S: UsesInput + HasExecutions + HasClientPerfMonitor + HasMetadata + Serialize,
    SP: ShMemProvider,
{
}

#[cfg(feature = "std")]
impl<S, SP> EventFirer for LlmpRestartingEventManager<S, SP>
where
    SP: ShMemProvider,
    S: UsesInput,
    //CE: CustomEvent<I>,
{
    fn fire(
        &mut self,
        state: &mut Self::State,
        event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        // Check if we are going to crash in the event, in which case we store our current state for the next runner
        self.llmp_mgr.fire(state, event)
    }

    fn configuration(&self) -> EventConfig {
        self.llmp_mgr.configuration()
    }
}

#[cfg(feature = "std")]
impl<S, SP> EventRestarter for LlmpRestartingEventManager<S, SP>
where
    S: UsesInput + HasExecutions + HasClientPerfMonitor + Serialize,
    SP: ShMemProvider,
    //CE: CustomEvent<I>,
{
    /// The llmp client needs to wait until a broker mapped all pages, before shutting down.
    /// Otherwise, the OS may already have removed the shared maps,
    #[inline]
    fn await_restart_safe(&mut self) {
        self.llmp_mgr.await_restart_safe();
    }

    /// Reset the single page (we reuse it over and over from pos 0), then send the current state to the next runner.
    fn on_restart(&mut self, state: &mut S) -> Result<(), Error> {
        // First, reset the page to 0 so the next iteration can read read from the beginning of this page
        self.staterestorer.reset();
        self.staterestorer.save(&(
            if self.save_state { Some(state) } else { None },
            &self.llmp_mgr.describe()?,
        ))
    }

    fn send_exiting(&mut self) -> Result<(), Error> {
        self.staterestorer.send_exiting();
        // Also inform the broker that we are about to exit.
        // This way, the broker can clean up the pages, and eventually exit.
        self.llmp_mgr.send_exiting()
    }
}

#[cfg(feature = "std")]
impl<E, S, SP, Z> EventProcessor<E, Z> for LlmpRestartingEventManager<S, SP>
where
    E: HasObservers<State = S> + Executor<LlmpEventManager<S, SP>, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    S: UsesInput + HasExecutions + HasClientPerfMonitor,
    SP: ShMemProvider + 'static,
    Z: EvaluatorObservers<E::Observers, State = S> + ExecutionProcessor<E::Observers>, //CE: CustomEvent<I>,
{
    fn process(&mut self, fuzzer: &mut Z, state: &mut S, executor: &mut E) -> Result<usize, Error> {
        self.llmp_mgr.process(fuzzer, state, executor)
    }
}

#[cfg(feature = "std")]
impl<E, S, SP, Z> EventManager<E, Z> for LlmpRestartingEventManager<S, SP>
where
    E: HasObservers<State = S> + Executor<LlmpEventManager<S, SP>, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    S: UsesInput + HasExecutions + HasClientPerfMonitor + HasMetadata + Serialize,
    SP: ShMemProvider + 'static,
    Z: EvaluatorObservers<E::Observers, State = S> + ExecutionProcessor<E::Observers>, //CE: CustomEvent<I>,
{
}

#[cfg(feature = "std")]
impl<S, SP> HasEventManagerId for LlmpRestartingEventManager<S, SP>
where
    S: UsesInput + Serialize,
    SP: ShMemProvider + 'static,
{
    fn mgr_id(&self) -> EventManagerId {
        self.llmp_mgr.mgr_id()
    }
}

/// The llmp connection from the actual fuzzer to the process supervising it
const _ENV_FUZZER_SENDER: &str = "_AFL_ENV_FUZZER_SENDER";
const _ENV_FUZZER_RECEIVER: &str = "_AFL_ENV_FUZZER_RECEIVER";
/// The llmp (2 way) connection from a fuzzer to the broker (broadcasting all other fuzzer messages)
const _ENV_FUZZER_BROKER_CLIENT_INITIAL: &str = "_AFL_ENV_FUZZER_BROKER_CLIENT";

#[cfg(feature = "std")]
impl<S, SP> LlmpRestartingEventManager<S, SP>
where
    S: UsesInput,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    /// Create a new runner, the executed child doing the actual fuzzing.
    pub fn new(llmp_mgr: LlmpEventManager<S, SP>, staterestorer: StateRestorer<SP>) -> Self {
        Self {
            llmp_mgr,
            staterestorer,
            save_state: true,
        }
    }

    /// Create a new runner specifying if it must save the serialized state on restart.
    pub fn with_save_state(
        llmp_mgr: LlmpEventManager<S, SP>,
        staterestorer: StateRestorer<SP>,
        save_state: bool,
    ) -> Self {
        Self {
            llmp_mgr,
            staterestorer,
            save_state,
        }
    }

    /// Get the staterestorer
    pub fn staterestorer(&self) -> &StateRestorer<SP> {
        &self.staterestorer
    }

    /// Get the staterestorer (mutable)
    pub fn staterestorer_mut(&mut self) -> &mut StateRestorer<SP> {
        &mut self.staterestorer
    }
}

/// The kind of manager we're creating right now
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy)]
pub enum ManagerKind {
    /// Any kind will do
    Any,
    /// A client, getting messages from a local broker.
    Client {
        /// The CPU core ID of this client
        cpu_core: Option<CoreId>,
    },
    /// A [`llmp::LlmpBroker`], forwarding the packets of local clients.
    Broker,
}

/// Sets up a restarting fuzzer, using the [`StdShMemProvider`], and standard features.
/// The restarting mgr is a combination of restarter and runner, that can be used on systems with and without `fork` support.
/// The restarter will spawn a new process each time the child crashes or timeouts.
#[cfg(feature = "std")]
#[allow(clippy::type_complexity)]
pub fn setup_restarting_mgr_std<MT, S>(
    monitor: MT,
    broker_port: u16,
    configuration: EventConfig,
) -> Result<(Option<S>, LlmpRestartingEventManager<S, StdShMemProvider>), Error>
where
    MT: Monitor + Clone,
    S: DeserializeOwned + UsesInput + HasClientPerfMonitor + HasExecutions,
{
    RestartingMgr::builder()
        .shmem_provider(StdShMemProvider::new()?)
        .monitor(Some(monitor))
        .broker_port(broker_port)
        .configuration(configuration)
        .build()
        .launch()
}

/// Provides a `builder` which can be used to build a [`RestartingMgr`], which is a combination of a
/// `restarter` and `runner`, that can be used on systems both with and without `fork` support. The
/// `restarter` will start a new process each time the child crashes or times out.
#[cfg(feature = "std")]
#[allow(clippy::default_trait_access)]
#[derive(TypedBuilder, Debug)]
pub struct RestartingMgr<MT, S, SP>
where
    S: UsesInput + DeserializeOwned,
    SP: ShMemProvider + 'static,
    MT: Monitor,
    //CE: CustomEvent<I>,
{
    /// The shared memory provider to use for the broker or client spawned by the restarting
    /// manager.
    shmem_provider: SP,
    /// The configuration
    configuration: EventConfig,
    /// The monitor to use
    #[builder(default = None)]
    monitor: Option<MT>,
    /// The broker port to use
    #[builder(default = 1337_u16)]
    broker_port: u16,
    /// The address to connect to
    #[builder(default = None)]
    remote_broker_addr: Option<SocketAddr>,
    /// The type of manager to build
    #[builder(default = ManagerKind::Any)]
    kind: ManagerKind,
    /// The amount of external clients that should have connected (not counting our own tcp client)
    /// before this broker quits _after the last client exited_.
    /// If `None`, the broker will never quit when the last client exits, but run forever.
    ///
    /// So, if this value is `Some(2)`, the broker will not exit after client 1 connected and disconnected,
    /// but it will quit after client 2 connected and disconnected.
    #[builder(default = None)]
    exit_cleanly_after: Option<NonZeroUsize>,
    /// Tell the manager to serialize or not the state on restart
    #[builder(default = true)]
    serialize_state: bool,
    #[builder(setter(skip), default = PhantomData)]
    phantom_data: PhantomData<S>,
}

#[cfg(feature = "std")]
#[allow(clippy::type_complexity, clippy::too_many_lines)]
impl<MT, S, SP> RestartingMgr<MT, S, SP>
where
    SP: ShMemProvider,
    S: UsesInput + HasExecutions + HasClientPerfMonitor + DeserializeOwned,
    MT: Monitor + Clone,
{
    /// Launch the restarting manager
    pub fn launch(&mut self) -> Result<(Option<S>, LlmpRestartingEventManager<S, SP>), Error> {
        // We start ourself as child process to actually fuzz
        let (staterestorer, new_shmem_provider, core_id) = if std::env::var(_ENV_FUZZER_SENDER)
            .is_err()
        {
            let broker_things = |mut broker: LlmpEventBroker<S::Input, MT, SP>,
                                 remote_broker_addr| {
                if let Some(remote_broker_addr) = remote_broker_addr {
                    log::info!("B2b: Connecting to {:?}", &remote_broker_addr);
                    broker.connect_b2b(remote_broker_addr)?;
                };

                if let Some(exit_cleanly_after) = self.exit_cleanly_after {
                    broker.set_exit_cleanly_after(exit_cleanly_after);
                }

                broker.broker_loop()
            };

            // We get here if we are on Unix, or we are a broker on Windows (or without forks).
            let (mgr, core_id) = match self.kind {
                ManagerKind::Any => {
                    let connection =
                        LlmpConnection::on_port(self.shmem_provider.clone(), self.broker_port)?;
                    match connection {
                        LlmpConnection::IsBroker { broker } => {
                            let event_broker = LlmpEventBroker::<S::Input, MT, SP>::new(
                                broker,
                                self.monitor.take().unwrap(),
                            )?;

                            // Yep, broker. Just loop here.
                            log::info!(
                                "Doing broker things. Run this tool again to start fuzzing in a client."
                            );

                            broker_things(event_broker, self.remote_broker_addr)?;

                            return Err(Error::shutting_down());
                        }
                        LlmpConnection::IsClient { client } => {
                            let mgr = LlmpEventManager::<S, SP>::new(client, self.configuration)?;
                            (mgr, None)
                        }
                    }
                }
                ManagerKind::Broker => {
                    let event_broker = LlmpEventBroker::<S::Input, MT, SP>::on_port(
                        self.shmem_provider.clone(),
                        self.monitor.take().unwrap(),
                        self.broker_port,
                    )?;

                    broker_things(event_broker, self.remote_broker_addr)?;
                    unreachable!("The broker may never return normally, only on errors or when shutting down.");
                }
                ManagerKind::Client { cpu_core } => {
                    // We are a client
                    let mgr = LlmpEventManager::<S, SP>::on_port(
                        self.shmem_provider.clone(),
                        self.broker_port,
                        self.configuration,
                    )?;

                    (mgr, cpu_core)
                }
            };

            if let Some(core_id) = core_id {
                let core_id: CoreId = core_id;
                log::info!("Setting core affinity to {core_id:?}");
                core_id.set_affinity()?;
            }

            // We are the fuzzer respawner in a llmp client
            mgr.to_env(_ENV_FUZZER_BROKER_CLIENT_INITIAL);

            // First, create a channel from the current fuzzer to the next to store state between restarts.
            #[cfg(unix)]
            let mut staterestorer: StateRestorer<SP> =
                StateRestorer::new(self.shmem_provider.new_shmem(256 * 1024 * 1024)?);

            #[cfg(not(unix))]
            let staterestorer: StateRestorer<SP> =
                StateRestorer::new(self.shmem_provider.new_shmem(256 * 1024 * 1024)?);
            // Store the information to a map.
            staterestorer.write_to_env(_ENV_FUZZER_SENDER)?;

            #[cfg(unix)]
            unsafe {
                let data = &mut SHUTDOWN_SIGHANDLER_DATA;
                // Write the pointer to staterestorer so we can release its shmem later
                core::ptr::write_volatile(
                    &mut data.staterestorer_ptr,
                    &mut staterestorer as *mut _ as *mut std::ffi::c_void,
                );
                data.allocator_pid = std::process::id() as usize;
                data.shutdown_handler = shutdown_handler::<SP> as *const std::ffi::c_void;
            }

            // We setup signal handlers to clean up shmem segments used by state restorer
            #[cfg(all(unix, not(miri)))]
            if let Err(_e) = unsafe { setup_signal_handler(&mut SHUTDOWN_SIGHANDLER_DATA) } {
                // We can live without a proper ctrl+c signal handler. Print and ignore.
                log::error!("Failed to setup signal handlers: {_e}");
            }

            let mut ctr: u64 = 0;
            // Client->parent loop
            loop {
                log::info!("Spawning next client (id {ctr})");

                // On Unix, we fork (when fork feature is enabled)
                #[cfg(all(unix, feature = "fork"))]
                let child_status = {
                    self.shmem_provider.pre_fork()?;
                    match unsafe { fork() }? {
                        ForkResult::Parent(handle) => {
                            self.shmem_provider.post_fork(false)?;
                            handle.status()
                        }
                        ForkResult::Child => {
                            self.shmem_provider.post_fork(true)?;
                            break (staterestorer, self.shmem_provider.clone(), core_id);
                        }
                    }
                };

                // On Windows (or in any case without fork), we spawn ourself again
                #[cfg(any(windows, not(feature = "fork")))]
                let child_status = startable_self()?.status()?;
                #[cfg(all(unix, not(feature = "fork")))]
                let child_status = child_status.code().unwrap_or_default();

                compiler_fence(Ordering::SeqCst);

                #[allow(clippy::manual_assert)]
                if !staterestorer.has_content() && self.serialize_state {
                    #[cfg(unix)]
                    if child_status == 137 {
                        // Out of Memory, see https://tldp.org/LDP/abs/html/exitcodes.html
                        // and https://github.com/AFLplusplus/LibAFL/issues/32 for discussion.
                        panic!("Fuzzer-respawner: The fuzzed target crashed with an out of memory error! Fix your harness, or switch to another executor (for example, a forkserver).");
                    }

                    // Storing state in the last round did not work
                    panic!("Fuzzer-respawner: Storing state in crashed fuzzer instance did not work, no point to spawn the next client! This can happen if the child calls `exit()`, in that case make sure it uses `abort()`, if it got killed unrecoverable (OOM), or if there is a bug in the fuzzer itself. (Child exited with: {child_status})");
                }

                if staterestorer.wants_to_exit() {
                    return Err(Error::shutting_down());
                }

                ctr = ctr.wrapping_add(1);
            }
        } else {
            // We are the newly started fuzzing instance (i.e. on Windows), first, connect to our own restore map.
            // We get here *only on Windows*, if we were started by a restarting fuzzer.
            // A staterestorer and a receiver for single communication
            (
                StateRestorer::from_env(&mut self.shmem_provider, _ENV_FUZZER_SENDER)?,
                self.shmem_provider.clone(),
                None,
            )
        };

        if let Some(core_id) = core_id {
            let core_id: CoreId = core_id;
            core_id.set_affinity()?;
        }

        // If we're restarting, deserialize the old state.
        let (state, mut mgr) =
            if let Some((state_opt, mgr_description)) = staterestorer.restore()? {
                (
                    state_opt,
                    LlmpRestartingEventManager::with_save_state(
                        LlmpEventManager::existing_client_from_description(
                            new_shmem_provider,
                            &mgr_description,
                            self.configuration,
                        )?,
                        staterestorer,
                        self.serialize_state,
                    ),
                )
            } else {
                log::info!("First run. Let's set it all up");
                // Mgr to send and receive msgs from/to all other fuzzer instances
                let mgr = LlmpEventManager::<S, SP>::existing_client_from_env(
                    new_shmem_provider,
                    _ENV_FUZZER_BROKER_CLIENT_INITIAL,
                    self.configuration,
                )?;

                (
                    None,
                    LlmpRestartingEventManager::with_save_state(
                        mgr,
                        staterestorer,
                        self.serialize_state,
                    ),
                )
            };
        // We reset the staterestorer, the next staterestorer and receiver (after crash) will reuse the page from the initial message.
        mgr.staterestorer.reset();

        /* TODO: Not sure if this is needed
        // We commit an empty NO_RESTART message to this buf, against infinite loops,
        // in case something crashes in the fuzzer.
        staterestorer.send_buf(_LLMP_TAG_NO_RESTART, []);
        */

        Ok((state, mgr))
    }
}

/// A manager-like llmp client that converts between input types
pub struct LlmpEventConverter<IC, ICB, DI, S, SP>
where
    S: UsesInput,
    SP: ShMemProvider + 'static,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
{
    llmp: LlmpClient<SP>,
    /// The custom buf handler
    custom_buf_handlers: Vec<Box<CustomBufHandlerFn<S>>>,
    #[cfg(feature = "llmp_compression")]
    compressor: GzipCompressor,
    converter: Option<IC>,
    converter_back: Option<ICB>,
    phantom: PhantomData<S>,
}

impl<IC, ICB, DI, S, SP> core::fmt::Debug for LlmpEventConverter<IC, ICB, DI, S, SP>
where
    SP: ShMemProvider + 'static,
    S: UsesInput,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_struct = f.debug_struct("LlmpEventConverter");
        let debug = debug_struct.field("llmp", &self.llmp);
        //.field("custom_buf_handlers", &self.custom_buf_handlers)
        #[cfg(feature = "llmp_compression")]
        let debug = debug.field("compressor", &self.compressor);
        debug
            .field("converter", &self.converter)
            .field("converter_back", &self.converter_back)
            .field("phantom", &self.phantom)
            .finish_non_exhaustive()
    }
}

impl<IC, ICB, DI, S, SP> LlmpEventConverter<IC, ICB, DI, S, SP>
where
    S: UsesInput + HasExecutions + HasClientPerfMonitor,
    SP: ShMemProvider + 'static,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
{
    /// Create a client from a raw llmp client
    pub fn new(
        llmp: LlmpClient<SP>,
        converter: Option<IC>,
        converter_back: Option<ICB>,
    ) -> Result<Self, Error> {
        Ok(Self {
            llmp,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            converter,
            converter_back,
            phantom: PhantomData,
            custom_buf_handlers: vec![],
        })
    }

    /// Create a client from port and the input converters
    #[cfg(feature = "std")]
    pub fn on_port(
        shmem_provider: SP,
        port: u16,
        converter: Option<IC>,
        converter_back: Option<ICB>,
    ) -> Result<Self, Error> {
        Ok(Self {
            llmp: LlmpClient::create_attach_to_tcp(shmem_provider, port)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            converter,
            converter_back,
            phantom: PhantomData,
            custom_buf_handlers: vec![],
        })
    }

    /// If a client respawns, it may reuse the existing connection, previously stored by [`LlmpClient::to_env()`].
    #[cfg(feature = "std")]
    pub fn existing_client_from_env(
        shmem_provider: SP,
        env_name: &str,
        converter: Option<IC>,
        converter_back: Option<ICB>,
    ) -> Result<Self, Error> {
        Ok(Self {
            llmp: LlmpClient::on_existing_from_env(shmem_provider, env_name)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            phantom: PhantomData,
            converter,
            converter_back,
            custom_buf_handlers: vec![],
        })
    }

    // TODO other new_* routines

    /// Check if it can convert the input
    pub fn can_convert(&self) -> bool {
        self.converter.is_some()
    }

    /// Check if it can convert the input back
    pub fn can_convert_back(&self) -> bool {
        self.converter_back.is_some()
    }

    /// Describe the client event mgr's llmp parts in a restorable fashion
    pub fn describe(&self) -> Result<LlmpClientDescription, Error> {
        self.llmp.describe()
    }

    /// Write the config for a client [`EventManager`] to env vars, a new client can reattach using [`LlmpEventConverter::existing_client_from_env()`].
    #[cfg(feature = "std")]
    pub fn to_env(&self, env_name: &str) {
        self.llmp.to_env(env_name).unwrap();
    }

    // Handle arriving events in the client
    fn handle_in_client<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        _client_id: ClientId,
        event: Event<DI>,
    ) -> Result<(), Error>
    where
        E: Executor<EM, Z> + HasObservers<State = S>,
        EM: UsesState<State = S> + EventFirer,
        for<'a> E::Observers: Deserialize<'a>,
        Z: ExecutionProcessor<E::Observers, State = S> + EvaluatorObservers<E::Observers>,
    {
        match event {
            Event::NewTestcase {
                input,
                client_config: _,
                exit_kind: _,
                corpus_size: _,
                observers_buf: _, // Useless as we are converting between types
                time: _,
                executions: _,
                forward_id,
            } => {
                log::info!("Received new Testcase to convert from {_client_id:?} (forward {forward_id:?}, forward {forward_id:?})");

                let Some(converter) = self.converter_back.as_mut() else {
                    return Ok(());
                };

                let res = fuzzer.evaluate_input_with_observers::<E, EM>(
                    state,
                    executor,
                    manager,
                    converter.convert(input)?,
                    false,
                )?;
                if let Some(item) = res.1 {
                    log::info!("Added received Testcase as item #{item}");
                }
                Ok(())
            }
            Event::CustomBuf { tag, buf } => {
                for handler in &mut self.custom_buf_handlers {
                    if handler(state, &tag, &buf)? == CustomBufEventResult::Handled {
                        break;
                    }
                }
                Ok(())
            }
            _ => Err(Error::unknown(format!(
                "Received illegal message that message should not have arrived: {:?}.",
                event.name()
            ))),
        }
    }

    /// Handle arriving events in the client
    #[allow(clippy::unused_self)]
    pub fn process<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
    ) -> Result<usize, Error>
    where
        E: Executor<EM, Z> + HasObservers<State = S>,
        EM: UsesState<State = S> + EventFirer,
        for<'a> E::Observers: Deserialize<'a>,
        Z: ExecutionProcessor<E::Observers, State = S> + EvaluatorObservers<E::Observers>,
    {
        // TODO: Get around local event copy by moving handle_in_client
        let self_id = self.llmp.sender.id;
        let mut count = 0;
        while let Some((client_id, tag, _flags, msg)) = self.llmp.recv_buf_with_flags()? {
            assert!(
                tag != _LLMP_TAG_EVENT_TO_BROKER,
                "EVENT_TO_BROKER parcel should not have arrived in the client!"
            );

            if client_id == self_id {
                continue;
            }
            #[cfg(not(feature = "llmp_compression"))]
            let event_bytes = msg;
            #[cfg(feature = "llmp_compression")]
            let compressed;
            #[cfg(feature = "llmp_compression")]
            let event_bytes = if _flags & LLMP_FLAG_COMPRESSED == LLMP_FLAG_COMPRESSED {
                compressed = self.compressor.decompress(msg)?;
                &compressed
            } else {
                msg
            };

            let event: Event<DI> = postcard::from_bytes(event_bytes)?;
            self.handle_in_client(fuzzer, executor, state, manager, client_id, event)?;
            count += 1;
        }
        Ok(count)
    }
}

impl<IC, ICB, DI, S, SP> UsesState for LlmpEventConverter<IC, ICB, DI, S, SP>
where
    S: UsesInput,
    SP: ShMemProvider,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
{
    type State = S;
}

impl<IC, ICB, DI, S, SP> EventFirer for LlmpEventConverter<IC, ICB, DI, S, SP>
where
    S: UsesInput,
    SP: ShMemProvider,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
{
    #[cfg(feature = "llmp_compression")]
    fn fire(
        &mut self,
        _state: &mut Self::State,
        event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        if self.converter.is_none() {
            return Ok(());
        }

        // Filter out non interestign events and convert `NewTestcase`
        let converted_event = match event {
            Event::NewTestcase {
                input,
                client_config,
                exit_kind,
                corpus_size,
                observers_buf,
                time,
                executions,
                forward_id,
            } => Event::NewTestcase {
                input: self.converter.as_mut().unwrap().convert(input)?,
                client_config,
                exit_kind,
                corpus_size,
                observers_buf,
                time,
                executions,
                forward_id,
            },
            Event::CustomBuf { buf, tag } => Event::CustomBuf { buf, tag },
            _ => {
                return Ok(());
            }
        };
        let serialized = postcard::to_allocvec(&converted_event)?;
        let flags = LLMP_FLAG_INITIALIZED;

        match self.compressor.compress(&serialized)? {
            Some(comp_buf) => {
                self.llmp.send_buf_with_flags(
                    LLMP_TAG_EVENT_TO_BOTH,
                    flags | LLMP_FLAG_COMPRESSED,
                    &comp_buf,
                )?;
            }
            None => {
                self.llmp.send_buf(LLMP_TAG_EVENT_TO_BOTH, &serialized)?;
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "llmp_compression"))]
    fn fire(
        &mut self,
        _state: &mut Self::State,
        event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        if self.converter.is_none() {
            return Ok(());
        }

        // Filter out non interestign events and convert `NewTestcase`
        let converted_event = match event {
            Event::NewTestcase {
                input,
                client_config,
                exit_kind,
                corpus_size,
                observers_buf,
                time,
                executions,
                forward_id,
            } => Event::NewTestcase {
                input: self.converter.as_mut().unwrap().convert(input)?,
                client_config,
                exit_kind,
                corpus_size,
                observers_buf,
                time,
                executions,
                forward_id,
            },
            Event::CustomBuf { buf, tag } => Event::CustomBuf { buf, tag },
            _ => {
                return Ok(());
            }
        };
        let serialized = postcard::to_allocvec(&converted_event)?;
        self.llmp.send_buf(LLMP_TAG_EVENT_TO_BOTH, &serialized)?;
        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use core::sync::atomic::{compiler_fence, Ordering};

    use serial_test::serial;

    use crate::{
        bolts::{
            llmp::{LlmpClient, LlmpSharedMap},
            rands::StdRand,
            shmem::{ShMemProvider, StdShMemProvider},
            staterestore::StateRestorer,
            tuples::tuple_list,
            ClientId,
        },
        corpus::{Corpus, InMemoryCorpus, Testcase},
        events::{llmp::_ENV_FUZZER_SENDER, LlmpEventManager},
        executors::{ExitKind, InProcessExecutor},
        feedbacks::ConstFeedback,
        fuzzer::Fuzzer,
        inputs::BytesInput,
        mutators::BitFlipMutator,
        schedulers::RandScheduler,
        stages::StdMutationalStage,
        state::StdState,
        StdFuzzer,
    };

    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_mgr_state_restore() {
        let rand = StdRand::with_seed(0);

        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(vec![0; 4].into());
        corpus.add(testcase).unwrap();

        let solutions = InMemoryCorpus::<BytesInput>::new();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        let mut state =
            StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();

        let mut shmem_provider = StdShMemProvider::new().unwrap();

        let mut llmp_client = LlmpClient::new(
            shmem_provider.clone(),
            LlmpSharedMap::new(ClientId(0), shmem_provider.new_shmem(1024).unwrap()),
            ClientId(0),
        )
        .unwrap();

        // A little hack for CI. Don't do that in a real-world scenario.
        unsafe {
            llmp_client.mark_safe_to_unmap();
        }

        let mut llmp_mgr = LlmpEventManager::new(llmp_client, "fuzzer".into()).unwrap();

        let scheduler = RandScheduler::new();

        let feedback = ConstFeedback::new(true);
        let objective = ConstFeedback::new(false);

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut harness = |_buf: &BytesInput| ExitKind::Ok;
        let mut executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(),
            &mut fuzzer,
            &mut state,
            &mut llmp_mgr,
        )
        .unwrap();

        let mutator = BitFlipMutator::new();
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        // First, create a channel from the current fuzzer to the next to store state between restarts.
        let mut staterestorer = StateRestorer::<StdShMemProvider>::new(
            shmem_provider.new_shmem(256 * 1024 * 1024).unwrap(),
        );

        staterestorer.reset();
        staterestorer
            .save(&(&mut state, &llmp_mgr.describe().unwrap()))
            .unwrap();
        assert!(staterestorer.has_content());

        // Store the information to a map.
        staterestorer.write_to_env(_ENV_FUZZER_SENDER).unwrap();

        compiler_fence(Ordering::SeqCst);

        let sc_cpy = StateRestorer::from_env(&mut shmem_provider, _ENV_FUZZER_SENDER).unwrap();
        assert!(sc_cpy.has_content());

        let (mut state_clone, mgr_description) = staterestorer.restore().unwrap().unwrap();
        let mut llmp_clone = LlmpEventManager::existing_client_from_description(
            shmem_provider,
            &mgr_description,
            "fuzzer".into(),
        )
        .unwrap();

        if false {
            fuzzer
                .fuzz_one(
                    &mut stages,
                    &mut executor,
                    &mut state_clone,
                    &mut llmp_clone,
                )
                .unwrap();
        }
    }
}
