//! LLMP-backed event manager for scalable multi-processed fuzzing

#[cfg(feature = "std")]
use alloc::string::ToString;
use alloc::{boxed::Box, vec::Vec};
#[cfg(all(unix, not(miri), feature = "std"))]
use core::ptr::addr_of_mut;
#[cfg(feature = "std")]
use core::sync::atomic::{compiler_fence, Ordering};
use core::{marker::PhantomData, num::NonZeroUsize, time::Duration};
#[cfg(feature = "std")]
use std::net::TcpStream;
#[cfg(feature = "std")]
use std::net::{SocketAddr, ToSocketAddrs};

#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use libafl_bolts::os::startable_self;
#[cfg(all(unix, feature = "std", not(miri)))]
use libafl_bolts::os::unix_signals::setup_signal_handler;
#[cfg(all(feature = "std", feature = "fork", unix))]
use libafl_bolts::os::{fork, ForkResult};
#[cfg(feature = "llmp_compression")]
use libafl_bolts::{
    compress::GzipCompressor,
    llmp::{LLMP_FLAG_COMPRESSED, LLMP_FLAG_INITIALIZED},
};
#[cfg(feature = "std")]
use libafl_bolts::{
    core_affinity::CoreId,
    llmp::{recv_tcp_msg, send_tcp_msg, TcpRequest, TcpResponse},
    IP_LOCALHOST,
};
#[cfg(feature = "adaptive_serialization")]
use libafl_bolts::{
    current_time,
    tuples::{Handle, Handled},
};
#[cfg(feature = "std")]
use libafl_bolts::{
    llmp::LlmpConnection, os::CTRL_C_EXIT, shmem::StdShMemProvider, staterestore::StateRestorer,
};
use libafl_bolts::{
    llmp::{self, LlmpClient, LlmpClientDescription, Tag},
    shmem::ShMemProvider,
    tuples::tuple_list,
    ClientId,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use typed_builder::TypedBuilder;

use super::{hooks::EventManagerHooksTuple, CustomBufEventResult, CustomBufHandlerFn};
#[cfg(any(feature = "std", feature = "adaptive_serialization"))]
use crate::events::AdaptiveSerializer;
#[cfg(all(unix, feature = "std", not(miri)))]
use crate::events::EVENTMGR_SIGHANDLER_STATE;
#[cfg(feature = "adaptive_serialization")]
use crate::observers::TimeObserver;
use crate::{
    events::{
        BrokerEventResult, Event, EventConfig, EventFirer, EventManager, EventManagerId,
        EventProcessor, EventRestarter, HasCustomBufHandlers, HasEventManagerId, ProgressReporter,
    },
    executors::{Executor, HasObservers},
    fuzzer::{EvaluatorObservers, ExecutionProcessor},
    inputs::{Input, InputConverter, UsesInput},
    monitors::Monitor,
    observers::ObserversTuple,
    state::{HasExecutions, HasLastReportTime, State, UsesState},
    Error, HasMetadata,
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
#[cfg(any(feature = "llmp_compression", feature = "tcp_compression"))]
pub const COMPRESS_THRESHOLD: usize = 1024;

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

/// An [`EventManager`] that forwards all events to other attached fuzzers on shared maps or via tcp,
/// using low-level message passing, [`llmp`].
pub struct LlmpEventManager<EMH, S, SP>
where
    S: State,
    SP: ShMemProvider + 'static,
{
    hooks: EMH,
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
    #[cfg(feature = "adaptive_serialization")]
    serialization_time: Duration,
    #[cfg(feature = "adaptive_serialization")]
    deserialization_time: Duration,
    #[cfg(feature = "adaptive_serialization")]
    serializations_cnt: usize,
    #[cfg(feature = "adaptive_serialization")]
    should_serialize_cnt: usize,
    #[cfg(feature = "adaptive_serialization")]
    time_ref: Handle<TimeObserver>,
    phantom: PhantomData<S>,
}

#[cfg(feature = "adaptive_serialization")]
impl<EMH, S, SP> AdaptiveSerializer for LlmpEventManager<EMH, S, SP>
where
    SP: ShMemProvider + 'static,
    S: State,
{
    fn serialization_time(&self) -> Duration {
        self.serialization_time
    }
    fn deserialization_time(&self) -> Duration {
        self.deserialization_time
    }
    fn serializations_cnt(&self) -> usize {
        self.serializations_cnt
    }
    fn should_serialize_cnt(&self) -> usize {
        self.should_serialize_cnt
    }

    fn serialization_time_mut(&mut self) -> &mut Duration {
        &mut self.serialization_time
    }
    fn deserialization_time_mut(&mut self) -> &mut Duration {
        &mut self.deserialization_time
    }
    fn serializations_cnt_mut(&mut self) -> &mut usize {
        &mut self.serializations_cnt
    }
    fn should_serialize_cnt_mut(&mut self) -> &mut usize {
        &mut self.should_serialize_cnt
    }

    fn time_ref(&self) -> &Handle<TimeObserver> {
        &self.time_ref
    }
}

impl<EMH, S, SP> core::fmt::Debug for LlmpEventManager<EMH, S, SP>
where
    SP: ShMemProvider + 'static,
    S: State,
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

impl<EMH, S, SP> Drop for LlmpEventManager<EMH, S, SP>
where
    SP: ShMemProvider + 'static,
    S: State,
{
    /// LLMP clients will have to wait until their pages are mapped by somebody.
    fn drop(&mut self) {
        self.await_restart_safe();
    }
}

impl<S, SP> LlmpEventManager<(), S, SP>
where
    S: State,
    SP: ShMemProvider + 'static,
{
    /// Create a manager from a raw LLMP client
    #[cfg(not(feature = "adaptive_serialization"))]
    pub fn new(llmp: LlmpClient<SP>, configuration: EventConfig) -> Result<Self, Error> {
        Ok(LlmpEventManager {
            hooks: tuple_list!(),
            llmp,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
            configuration,
            phantom: PhantomData,
            custom_buf_handlers: vec![],
        })
    }

    /// Create an LLMP event manager on a port
    ///
    /// If the port is not yet bound, it will act as a broker; otherwise, it
    /// will act as a client.
    #[cfg(all(feature = "std", not(feature = "adaptive_serialization")))]
    pub fn on_port(
        shmem_provider: SP,
        port: u16,
        configuration: EventConfig,
    ) -> Result<LlmpEventManager<(), S, SP>, Error> {
        let llmp = LlmpClient::create_attach_to_tcp(shmem_provider, port)?;
        Self::new(llmp, configuration)
    }

    /// If a client respawns, it may reuse the existing connection, previously
    /// stored by [`LlmpClient::to_env()`].
    #[cfg(all(feature = "std", not(feature = "adaptive_serialization")))]
    pub fn existing_client_from_env(
        shmem_provider: SP,
        env_name: &str,
        configuration: EventConfig,
    ) -> Result<LlmpEventManager<(), S, SP>, Error> {
        let llmp = LlmpClient::on_existing_from_env(shmem_provider, env_name)?;
        Self::new(llmp, configuration)
    }

    /// Create an existing client from description
    #[cfg(not(feature = "adaptive_serialization"))]
    pub fn existing_client_from_description(
        shmem_provider: SP,
        description: &LlmpClientDescription,
        configuration: EventConfig,
    ) -> Result<LlmpEventManager<(), S, SP>, Error> {
        let llmp = LlmpClient::existing_client_from_description(shmem_provider, description)?;
        Self::new(llmp, configuration)
    }

    /// Create a manager from a raw LLMP client
    #[cfg(feature = "adaptive_serialization")]
    pub fn new(
        llmp: LlmpClient<SP>,
        configuration: EventConfig,
        time_ref: Handle<TimeObserver>,
    ) -> Result<Self, Error> {
        Ok(LlmpEventManager {
            hooks: tuple_list!(),
            llmp,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
            configuration,
            serialization_time: Duration::ZERO,
            deserialization_time: Duration::ZERO,
            serializations_cnt: 0,
            should_serialize_cnt: 0,
            time_ref,
            phantom: PhantomData,
            custom_buf_handlers: vec![],
        })
    }

    /// Create an LLMP event manager on a port
    ///
    /// If the port is not yet bound, it will act as a broker; otherwise, it
    /// will act as a client.
    #[cfg(all(feature = "std", feature = "adaptive_serialization"))]
    pub fn on_port(
        shmem_provider: SP,
        port: u16,
        configuration: EventConfig,
        time_ref: Handle<TimeObserver>,
    ) -> Result<LlmpEventManager<(), S, SP>, Error> {
        let llmp = LlmpClient::create_attach_to_tcp(shmem_provider, port)?;
        Self::new(llmp, configuration, time_ref)
    }

    /// If a client respawns, it may reuse the existing connection, previously
    /// stored by [`LlmpClient::to_env()`].
    #[cfg(all(feature = "std", feature = "adaptive_serialization"))]
    pub fn existing_client_from_env(
        shmem_provider: SP,
        env_name: &str,
        configuration: EventConfig,
        time_ref: Handle<TimeObserver>,
    ) -> Result<LlmpEventManager<(), S, SP>, Error> {
        let llmp = LlmpClient::on_existing_from_env(shmem_provider, env_name)?;
        Self::new(llmp, configuration, time_ref)
    }

    /// Create an existing client from description
    #[cfg(feature = "adaptive_serialization")]
    pub fn existing_client_from_description(
        shmem_provider: SP,
        description: &LlmpClientDescription,
        configuration: EventConfig,
        time_ref: Handle<TimeObserver>,
    ) -> Result<LlmpEventManager<(), S, SP>, Error> {
        let llmp = LlmpClient::existing_client_from_description(shmem_provider, description)?;
        Self::new(llmp, configuration, time_ref)
    }
}

impl<EMH, S, SP> LlmpEventManager<EMH, S, SP>
where
    S: State,
    SP: ShMemProvider + 'static,
{
    /// Create a manager from a raw LLMP client with hooks
    #[cfg(not(feature = "adaptive_serialization"))]
    pub fn with_hooks(
        llmp: LlmpClient<SP>,
        configuration: EventConfig,
        hooks: EMH,
    ) -> Result<Self, Error> {
        Ok(Self {
            hooks,
            llmp,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
            configuration,
            phantom: PhantomData,
            custom_buf_handlers: vec![],
        })
    }

    /// Create an LLMP event manager on a port with hook
    ///
    /// If the port is not yet bound, it will act as a broker; otherwise, it
    /// will act as a client.
    /// This will make a new connection to the broker so will return its new [`ClientId`], too
    #[cfg(all(feature = "std", not(feature = "adaptive_serialization")))]
    pub fn on_port_with_hooks(
        shmem_provider: SP,
        port: u16,
        configuration: EventConfig,
        hooks: EMH,
    ) -> Result<Self, Error> {
        let llmp = LlmpClient::create_attach_to_tcp(shmem_provider, port)?;
        Self::with_hooks(llmp, configuration, hooks)
    }

    /// If a client respawns, it may reuse the existing connection, previously
    /// stored by [`LlmpClient::to_env()`].
    /// create a event manager from env with hooks
    #[cfg(all(feature = "std", not(feature = "adaptive_serialization")))]
    pub fn existing_client_from_env_with_hooks(
        shmem_provider: SP,
        env_name: &str,
        configuration: EventConfig,
        hooks: EMH,
    ) -> Result<Self, Error> {
        let llmp = LlmpClient::on_existing_from_env(shmem_provider, env_name)?;
        Self::with_hooks(llmp, configuration, hooks)
    }

    /// Create an existing client from description
    #[cfg(not(feature = "adaptive_serialization"))]
    pub fn existing_client_from_description_with_hooks(
        shmem_provider: SP,
        description: &LlmpClientDescription,
        configuration: EventConfig,
        hooks: EMH,
    ) -> Result<Self, Error> {
        let llmp = LlmpClient::existing_client_from_description(shmem_provider, description)?;
        Self::with_hooks(llmp, configuration, hooks)
    }

    /// Create a manager from a raw LLMP client with hooks
    #[cfg(feature = "adaptive_serialization")]
    pub fn with_hooks(
        llmp: LlmpClient<SP>,
        configuration: EventConfig,
        hooks: EMH,
        time_ref: Handle<TimeObserver>,
    ) -> Result<Self, Error> {
        Ok(Self {
            hooks,
            llmp,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
            configuration,
            serialization_time: Duration::ZERO,
            deserialization_time: Duration::ZERO,
            serializations_cnt: 0,
            should_serialize_cnt: 0,
            time_ref,
            phantom: PhantomData,
            custom_buf_handlers: vec![],
        })
    }

    /// Create an LLMP event manager on a port with hook
    ///
    /// If the port is not yet bound, it will act as a broker; otherwise, it
    /// will act as a client.
    /// This will make a new connection to the broker so will return its new [`ClientId`], too
    #[cfg(all(feature = "std", feature = "adaptive_serialization"))]
    pub fn on_port_with_hooks(
        shmem_provider: SP,
        port: u16,
        configuration: EventConfig,
        hooks: EMH,
        time_ref: Handle<TimeObserver>,
    ) -> Result<Self, Error> {
        let llmp = LlmpClient::create_attach_to_tcp(shmem_provider, port)?;
        Self::with_hooks(llmp, configuration, hooks, time_ref)
    }

    /// If a client respawns, it may reuse the existing connection, previously
    /// stored by [`LlmpClient::to_env()`].
    /// create a event manager from env with hooks
    #[cfg(all(feature = "std", feature = "adaptive_serialization"))]
    pub fn existing_client_from_env_with_hooks(
        shmem_provider: SP,
        env_name: &str,
        configuration: EventConfig,
        hooks: EMH,
        time_ref: Handle<TimeObserver>,
    ) -> Result<Self, Error> {
        let llmp = LlmpClient::on_existing_from_env(shmem_provider, env_name)?;
        Self::with_hooks(llmp, configuration, hooks, time_ref)
    }

    /// Create an existing client from description
    #[cfg(feature = "adaptive_serialization")]
    pub fn existing_client_from_description_with_hooks(
        shmem_provider: SP,
        description: &LlmpClientDescription,
        configuration: EventConfig,
        hooks: EMH,
        time_ref: Handle<TimeObserver>,
    ) -> Result<Self, Error> {
        let llmp = LlmpClient::existing_client_from_description(shmem_provider, description)?;
        Self::with_hooks(llmp, configuration, hooks, time_ref)
    }

    /// Calling this function will tell the llmp broker that this client is exiting
    /// This should be called from the restarter not from the actual fuzzer client
    /// This function serves the same roll as the `LlmpClient.send_exiting()`
    /// However, from the the event restarter process it is forbidden to call `send_exiting()`
    /// (You can call it and it compiles but you should never do so)
    /// `send_exiting()` is exclusive to the fuzzer client.
    #[cfg(feature = "std")]
    pub fn detach_from_broker(&self, broker_port: u16) -> Result<(), Error> {
        let client_id = self.llmp.sender().id();
        let Ok(mut stream) = TcpStream::connect((IP_LOCALHOST, broker_port)) else {
            log::error!("Connection refused.");
            return Ok(());
        };
        // The broker tells us hello we don't care we just tell it our client died
        let TcpResponse::BrokerConnectHello {
            broker_shmem_description: _,
            hostname: _,
        } = recv_tcp_msg(&mut stream)?.try_into()?
        else {
            return Err(Error::illegal_state(
                "Received unexpected Broker Hello".to_string(),
            ));
        };
        let msg = TcpRequest::ClientQuit { client_id };
        // Send this mesasge off and we are leaving.
        match send_tcp_msg(&mut stream, &msg) {
            Ok(_) => (),
            Err(e) => log::error!("Failed to send tcp message {:#?}", e),
        }
        log::info!("Asking he broker to be disconnected");
        Ok(())
    }

    /// Describe the client event manager's LLMP parts in a restorable fashion
    pub fn describe(&self) -> Result<LlmpClientDescription, Error> {
        self.llmp.describe()
    }

    /// Write the config for a client [`EventManager`] to env vars, a new
    /// client can reattach using [`LlmpEventManager::existing_client_from_env()`].
    #[cfg(feature = "std")]
    pub fn to_env(&self, env_name: &str) {
        self.llmp.to_env(env_name).unwrap();
    }
}

impl<EMH, S, SP> LlmpEventManager<EMH, S, SP>
where
    EMH: EventManagerHooksTuple<S>,
    S: State + HasExecutions + HasMetadata,
    SP: ShMemProvider + 'static,
{
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
        if !self.hooks.pre_exec_all(state, client_id, &event)? {
            return Ok(());
        }
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

                let res = if client_config.match_with(&self.configuration)
                    && observers_buf.is_some()
                {
                    #[cfg(feature = "adaptive_serialization")]
                    let start = current_time();
                    let observers: E::Observers =
                        postcard::from_bytes(observers_buf.as_ref().unwrap())?;
                    #[cfg(feature = "adaptive_serialization")]
                    {
                        self.deserialization_time = current_time() - start;
                    }
                    #[cfg(feature = "scalability_introspection")]
                    {
                        state.scalability_monitor_mut().testcase_with_observers += 1;
                    }
                    fuzzer.execute_and_process(state, self, input, &observers, &exit_kind, false)?
                } else {
                    #[cfg(feature = "scalability_introspection")]
                    {
                        state.scalability_monitor_mut().testcase_without_observers += 1;
                    }
                    fuzzer.evaluate_input_with_observers::<E, Self>(
                        state, executor, self, input, false,
                    )?
                };
                if let Some(item) = res.1 {
                    log::info!("Added received Testcase as item #{item}");
                }
            }
            Event::CustomBuf { tag, buf } => {
                for handler in &mut self.custom_buf_handlers {
                    if handler(state, &tag, &buf)? == CustomBufEventResult::Handled {
                        break;
                    }
                }
            }
            _ => {
                return Err(Error::unknown(format!(
                    "Received illegal message that message should not have arrived: {:?}.",
                    event.name()
                )));
            }
        }
        self.hooks.post_exec_all(state, client_id)?;
        Ok(())
    }
}

impl<EMH, S: State, SP: ShMemProvider> LlmpEventManager<EMH, S, SP> {
    /// Send information that this client is exiting.
    /// The other side may free up all allocated memory.
    /// We are no longer allowed to send anything afterwards.
    pub fn send_exiting(&mut self) -> Result<(), Error> {
        self.llmp.sender_mut().send_exiting()
    }
}

impl<EMH, S, SP> UsesState for LlmpEventManager<EMH, S, SP>
where
    S: State,
    SP: ShMemProvider,
{
    type State = S;
}

impl<EMH, S, SP> EventFirer for LlmpEventManager<EMH, S, SP>
where
    S: State,
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

        match self.compressor.maybe_compress(&serialized) {
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

    #[cfg(not(feature = "adaptive_serialization"))]
    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error>
    where
        OT: ObserversTuple<Self::State> + Serialize,
    {
        Ok(Some(postcard::to_allocvec(observers)?))
    }

    #[cfg(feature = "adaptive_serialization")]
    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error>
    where
        OT: ObserversTuple<Self::State> + Serialize,
    {
        const SERIALIZE_TIME_FACTOR: u32 = 2;
        const SERIALIZE_PERCENTAGE_THRESHOLD: usize = 80;
        self.serialize_observers_adaptive(
            observers,
            SERIALIZE_TIME_FACTOR,
            SERIALIZE_PERCENTAGE_THRESHOLD,
        )
    }

    fn configuration(&self) -> EventConfig {
        self.configuration
    }
}

impl<EMH, S, SP> EventRestarter for LlmpEventManager<EMH, S, SP>
where
    S: State,
    SP: ShMemProvider,
{
    /// The LLMP client needs to wait until a broker has mapped all pages before shutting down.
    /// Otherwise, the OS may already have removed the shared maps.
    fn await_restart_safe(&mut self) {
        // wait until we can drop the message safely.
        self.llmp.await_safe_to_unmap_blocking();
    }
}

impl<E, EMH, S, SP, Z> EventProcessor<E, Z> for LlmpEventManager<EMH, S, SP>
where
    EMH: EventManagerHooksTuple<S>,
    S: State + HasExecutions + HasMetadata,
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
        let self_id = self.llmp.sender().id();
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

impl<E, EMH, S, SP, Z> EventManager<E, Z> for LlmpEventManager<EMH, S, SP>
where
    E: HasObservers<State = S> + Executor<Self, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    EMH: EventManagerHooksTuple<S>,
    S: State + HasExecutions + HasMetadata + HasLastReportTime,
    SP: ShMemProvider,
    Z: EvaluatorObservers<E::Observers, State = S> + ExecutionProcessor<E::Observers, State = S>,
{
}

impl<EMH, S, SP> HasCustomBufHandlers for LlmpEventManager<EMH, S, SP>
where
    S: State,
    SP: ShMemProvider,
{
    fn add_custom_buf_handler(
        &mut self,
        handler: Box<dyn FnMut(&mut S, &str, &[u8]) -> Result<CustomBufEventResult, Error>>,
    ) {
        self.custom_buf_handlers.push(handler);
    }
}

impl<EMH, S, SP> ProgressReporter for LlmpEventManager<EMH, S, SP>
where
    S: State + HasExecutions + HasMetadata + HasLastReportTime,
    SP: ShMemProvider,
{
}

impl<EMH, S, SP> HasEventManagerId for LlmpEventManager<EMH, S, SP>
where
    S: State,
    SP: ShMemProvider,
{
    /// Gets the id assigned to this staterestorer.
    fn mgr_id(&self) -> EventManagerId {
        EventManagerId(self.llmp.sender().id().0 as usize)
    }
}

/// Specify if the State must be persistent over restarts
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LlmpShouldSaveState {
    /// Always save and restore the state on restart (not OOM resistant)
    OnRestart,
    /// Never save the state (not OOM resistant)
    Never,
    /// Best-effort save and restore the state on restart (OOM safe)
    /// This adds additional runtime costs when processing events
    OOMSafeOnRestart,
    /// Never save the state (OOM safe)
    /// This adds additional runtime costs when processing events
    OOMSafeNever,
}

impl LlmpShouldSaveState {
    /// Check if the state must be saved `on_restart()`
    #[must_use]
    pub fn on_restart(&self) -> bool {
        matches!(
            self,
            LlmpShouldSaveState::OnRestart | LlmpShouldSaveState::OOMSafeOnRestart
        )
    }

    /// Check if the policy is OOM safe
    #[must_use]
    pub fn oom_safe(&self) -> bool {
        matches!(
            self,
            LlmpShouldSaveState::OOMSafeOnRestart | LlmpShouldSaveState::OOMSafeNever
        )
    }
}

/// A manager that can restart on the fly, storing states in-between (in `on_restart`)
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct LlmpRestartingEventManager<EMH, S, SP>
where
    S: State,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    /// The embedded LLMP event manager
    llmp_mgr: LlmpEventManager<EMH, S, SP>,
    /// The staterestorer to serialize the state for the next runner
    staterestorer: StateRestorer<SP>,
    /// Decide if the state restorer must save the serialized state
    save_state: LlmpShouldSaveState,
}

#[cfg(all(feature = "std", feature = "adaptive_serialization"))]
impl<EMH, S, SP> AdaptiveSerializer for LlmpRestartingEventManager<EMH, S, SP>
where
    SP: ShMemProvider + 'static,
    S: State,
{
    fn serialization_time(&self) -> Duration {
        self.llmp_mgr.serialization_time()
    }
    fn deserialization_time(&self) -> Duration {
        self.llmp_mgr.deserialization_time()
    }
    fn serializations_cnt(&self) -> usize {
        self.llmp_mgr.serializations_cnt()
    }
    fn should_serialize_cnt(&self) -> usize {
        self.llmp_mgr.should_serialize_cnt()
    }

    fn serialization_time_mut(&mut self) -> &mut Duration {
        self.llmp_mgr.serialization_time_mut()
    }
    fn deserialization_time_mut(&mut self) -> &mut Duration {
        self.llmp_mgr.deserialization_time_mut()
    }
    fn serializations_cnt_mut(&mut self) -> &mut usize {
        self.llmp_mgr.serializations_cnt_mut()
    }
    fn should_serialize_cnt_mut(&mut self) -> &mut usize {
        self.llmp_mgr.should_serialize_cnt_mut()
    }

    fn time_ref(&self) -> &Handle<TimeObserver> {
        &self.llmp_mgr.time_ref
    }
}

#[cfg(all(feature = "std", not(feature = "adaptive_serialization")))]
impl<EMH, S, SP> AdaptiveSerializer for LlmpRestartingEventManager<EMH, S, SP>
where
    SP: ShMemProvider + 'static,
    S: State,
{
}

#[cfg(feature = "std")]
impl<EMH, S, SP> UsesState for LlmpRestartingEventManager<EMH, S, SP>
where
    S: State,
    SP: ShMemProvider + 'static,
{
    type State = S;
}

#[cfg(feature = "std")]
impl<EMH, S, SP> ProgressReporter for LlmpRestartingEventManager<EMH, S, SP>
where
    S: State + HasExecutions + HasMetadata + HasLastReportTime,
    SP: ShMemProvider,
{
}

#[cfg(feature = "std")]
impl<EMH, S, SP> EventFirer for LlmpRestartingEventManager<EMH, S, SP>
where
    SP: ShMemProvider,
    S: State,
    //CE: CustomEvent<I>,
{
    fn fire(
        &mut self,
        state: &mut Self::State,
        event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        // Check if we are going to crash in the event, in which case we store our current state for the next runner
        self.llmp_mgr.fire(state, event)?;
        self.intermediate_save()?;
        Ok(())
    }

    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error>
    where
        OT: ObserversTuple<Self::State> + Serialize,
    {
        self.llmp_mgr.serialize_observers(observers)
    }

    fn configuration(&self) -> EventConfig {
        self.llmp_mgr.configuration()
    }
}

#[cfg(feature = "std")]
impl<EMH, S, SP> EventRestarter for LlmpRestartingEventManager<EMH, S, SP>
where
    S: State + HasExecutions,
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
        state.on_restart()?;

        // First, reset the page to 0 so the next iteration can read read from the beginning of this page
        self.staterestorer.reset();
        self.staterestorer.save(&(
            if self.save_state.on_restart() {
                Some(state)
            } else {
                None
            },
            &self.llmp_mgr.describe()?,
        ))?;

        log::info!("Waiting for broker...");
        self.await_restart_safe();
        Ok(())
    }

    fn send_exiting(&mut self) -> Result<(), Error> {
        self.staterestorer.send_exiting();
        // Also inform the broker that we are about to exit.
        // This way, the broker can clean up the pages, and eventually exit.
        self.llmp_mgr.send_exiting()
    }
}

#[cfg(feature = "std")]
impl<E, EMH, S, SP, Z> EventProcessor<E, Z> for LlmpRestartingEventManager<EMH, S, SP>
where
    E: HasObservers<State = S> + Executor<LlmpEventManager<EMH, S, SP>, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    EMH: EventManagerHooksTuple<S>,
    S: State + HasExecutions + HasMetadata,
    SP: ShMemProvider + 'static,
    Z: EvaluatorObservers<E::Observers, State = S> + ExecutionProcessor<E::Observers>, //CE: CustomEvent<I>,
{
    fn process(&mut self, fuzzer: &mut Z, state: &mut S, executor: &mut E) -> Result<usize, Error> {
        let res = self.llmp_mgr.process(fuzzer, state, executor)?;
        self.intermediate_save()?;
        Ok(res)
    }
}

#[cfg(feature = "std")]
impl<E, EMH, S, SP, Z> EventManager<E, Z> for LlmpRestartingEventManager<EMH, S, SP>
where
    E: HasObservers<State = S> + Executor<LlmpEventManager<EMH, S, SP>, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    EMH: EventManagerHooksTuple<S>,
    S: State + HasExecutions + HasMetadata + HasLastReportTime,
    SP: ShMemProvider + 'static,
    Z: EvaluatorObservers<E::Observers, State = S> + ExecutionProcessor<E::Observers>, //CE: CustomEvent<I>,
{
}

#[cfg(feature = "std")]
impl<EMH, S, SP> HasEventManagerId for LlmpRestartingEventManager<EMH, S, SP>
where
    S: State,
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
impl<EMH, S, SP> LlmpRestartingEventManager<EMH, S, SP>
where
    S: State,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    /// Create a new runner, the executed child doing the actual fuzzing.
    pub fn new(llmp_mgr: LlmpEventManager<EMH, S, SP>, staterestorer: StateRestorer<SP>) -> Self {
        Self {
            llmp_mgr,
            staterestorer,
            save_state: LlmpShouldSaveState::OnRestart,
        }
    }

    /// Create a new runner specifying if it must save the serialized state on restart.
    pub fn with_save_state(
        llmp_mgr: LlmpEventManager<EMH, S, SP>,
        staterestorer: StateRestorer<SP>,
        save_state: LlmpShouldSaveState,
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

    /// Save LLMP state and empty state in staterestorer
    pub fn intermediate_save(&mut self) -> Result<(), Error> {
        // First, reset the page to 0 so the next iteration can read read from the beginning of this page
        if self.save_state.oom_safe() {
            self.staterestorer.reset();
            self.staterestorer
                .save(&(None::<S>, &self.llmp_mgr.describe()?))?;
        }
        Ok(())
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
#[cfg(all(feature = "std", not(feature = "adaptive_serialization")))]
#[allow(clippy::type_complexity)]
pub fn setup_restarting_mgr_std<MT, S>(
    monitor: MT,
    broker_port: u16,
    configuration: EventConfig,
) -> Result<
    (
        Option<S>,
        LlmpRestartingEventManager<(), S, StdShMemProvider>,
    ),
    Error,
>
where
    MT: Monitor + Clone,
    S: State + HasExecutions,
{
    RestartingMgr::builder()
        .shmem_provider(StdShMemProvider::new()?)
        .monitor(Some(monitor))
        .broker_port(broker_port)
        .configuration(configuration)
        .hooks(tuple_list!())
        .build()
        .launch()
}

/// Sets up a restarting fuzzer, using the [`StdShMemProvider`], and standard features.
/// The restarting mgr is a combination of restarter and runner, that can be used on systems with and without `fork` support.
/// The restarter will spawn a new process each time the child crashes or timeouts.
#[cfg(all(feature = "std", feature = "adaptive_serialization"))]
#[allow(clippy::type_complexity)]
pub fn setup_restarting_mgr_std<MT, S>(
    monitor: MT,
    broker_port: u16,
    configuration: EventConfig,
    time_obs: &TimeObserver,
) -> Result<
    (
        Option<S>,
        LlmpRestartingEventManager<(), S, StdShMemProvider>,
    ),
    Error,
>
where
    MT: Monitor + Clone,
    S: State + HasExecutions,
{
    RestartingMgr::builder()
        .shmem_provider(StdShMemProvider::new()?)
        .monitor(Some(monitor))
        .broker_port(broker_port)
        .configuration(configuration)
        .hooks(tuple_list!())
        .time_ref(time_obs.handle())
        .build()
        .launch()
}

/// Provides a `builder` which can be used to build a [`RestartingMgr`], which is a combination of a
/// `restarter` and `runner`, that can be used on systems both with and without `fork` support. The
/// `restarter` will start a new process each time the child crashes or times out.
#[cfg(feature = "std")]
#[allow(clippy::default_trait_access, clippy::ignored_unit_patterns)]
#[derive(TypedBuilder, Debug)]
pub struct RestartingMgr<EMH, MT, S, SP>
where
    EMH: EventManagerHooksTuple<S>,
    S: State,
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
    #[builder(default = LlmpShouldSaveState::OnRestart)]
    serialize_state: LlmpShouldSaveState,
    /// The hooks passed to event manager:
    hooks: EMH,
    #[cfg(feature = "adaptive_serialization")]
    time_ref: Handle<TimeObserver>,
    #[builder(setter(skip), default = PhantomData)]
    phantom_data: PhantomData<(EMH, S)>,
}

#[cfg(feature = "std")]
#[allow(clippy::type_complexity, clippy::too_many_lines)]
impl<EMH, MT, S, SP> RestartingMgr<EMH, MT, S, SP>
where
    EMH: EventManagerHooksTuple<S> + Copy + Clone,
    SP: ShMemProvider,
    S: State + HasExecutions,
    MT: Monitor + Clone,
{
    /// Launch the broker and the clients and fuzz
    pub fn launch(&mut self) -> Result<(Option<S>, LlmpRestartingEventManager<EMH, S, SP>), Error> {
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
                            #[cfg(not(feature = "adaptive_serialization"))]
                            let mgr = LlmpEventManager::<EMH, S, SP>::with_hooks(
                                client,
                                self.configuration,
                                self.hooks,
                            )?;
                            #[cfg(feature = "adaptive_serialization")]
                            let mgr = LlmpEventManager::<EMH, S, SP>::with_hooks(
                                client,
                                self.configuration,
                                self.hooks,
                                self.time_ref.clone(),
                            )?;
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
                    #[cfg(not(feature = "adaptive_serialization"))]
                    let mgr = LlmpEventManager::<EMH, S, SP>::on_port_with_hooks(
                        self.shmem_provider.clone(),
                        self.broker_port,
                        self.configuration,
                        self.hooks,
                    )?;
                    #[cfg(feature = "adaptive_serialization")]
                    let mgr = LlmpEventManager::<EMH, S, SP>::on_port_with_hooks(
                        self.shmem_provider.clone(),
                        self.broker_port,
                        self.configuration,
                        self.hooks,
                        self.time_ref.clone(),
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
            let staterestorer: StateRestorer<SP> =
                StateRestorer::new(self.shmem_provider.new_shmem(256 * 1024 * 1024)?);

            #[cfg(not(unix))]
            let staterestorer: StateRestorer<SP> =
                StateRestorer::new(self.shmem_provider.new_shmem(256 * 1024 * 1024)?);
            // Store the information to a map.
            staterestorer.write_to_env(_ENV_FUZZER_SENDER)?;

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
                            unsafe {
                                libc::signal(libc::SIGINT, libc::SIG_IGN);
                            }
                            self.shmem_provider.post_fork(false)?;
                            handle.status()
                        }
                        ForkResult::Child => {
                            self.shmem_provider.post_fork(true)?;
                            break (staterestorer, self.shmem_provider.clone(), core_id);
                        }
                    }
                };

                // If this guy wants to fork, then ignore sigit
                #[cfg(any(windows, not(feature = "fork")))]
                unsafe {
                    #[cfg(windows)]
                    libafl_bolts::os::windows_exceptions::signal(
                        libafl_bolts::os::windows_exceptions::SIGINT,
                        libafl_bolts::os::windows_exceptions::sig_ign(),
                    );

                    #[cfg(unix)]
                    libc::signal(libc::SIGINT, libc::SIG_IGN);
                }

                // On Windows (or in any case without fork), we spawn ourself again
                #[cfg(any(windows, not(feature = "fork")))]
                let child_status = startable_self()?.status()?;
                #[cfg(any(windows, not(feature = "fork")))]
                let child_status = child_status.code().unwrap_or_default();

                compiler_fence(Ordering::SeqCst);

                if child_status == CTRL_C_EXIT || staterestorer.wants_to_exit() {
                    // if ctrl-c is pressed, we end up in this branch
                    if let Err(err) = mgr.detach_from_broker(self.broker_port) {
                        log::error!("Failed to detach from broker: {err}");
                    }
                    return Err(Error::shutting_down());
                }

                #[allow(clippy::manual_assert)]
                if !staterestorer.has_content() && !self.serialize_state.oom_safe() {
                    if let Err(err) = mgr.detach_from_broker(self.broker_port) {
                        log::error!("Failed to detach from broker: {err}");
                    }
                    #[cfg(unix)]
                    if child_status == 9 {
                        panic!("Target received SIGKILL!. This could indicate the target crashed due to OOM, user sent SIGKILL, or the target was in an unrecoverable situation and could not save state to restart");
                    }
                    // Storing state in the last round did not work
                    panic!("Fuzzer-respawner: Storing state in crashed fuzzer instance did not work, no point to spawn the next client! This can happen if the child calls `exit()`, in that case make sure it uses `abort()`, if it got killed unrecoverable (OOM), or if there is a bug in the fuzzer itself. (Child exited with: {child_status})");
                }

                ctr = ctr.wrapping_add(1);
            }
        } else {
            // At this point we are the fuzzer *NOT* the restarter.
            // We setup signal handlers to clean up shmem segments used by state restorer
            #[cfg(all(unix, not(miri)))]
            if let Err(_e) =
                unsafe { setup_signal_handler(addr_of_mut!(EVENTMGR_SIGHANDLER_STATE)) }
            {
                // We can live without a proper ctrl+c signal handler. Print and ignore.
                log::error!("Failed to setup signal handlers: {_e}");
            }

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
                #[cfg(not(feature = "adaptive_serialization"))]
                let llmp_mgr = LlmpEventManager::existing_client_from_description_with_hooks(
                    new_shmem_provider,
                    &mgr_description,
                    self.configuration,
                    self.hooks,
                )?;
                #[cfg(feature = "adaptive_serialization")]
                let llmp_mgr = LlmpEventManager::existing_client_from_description_with_hooks(
                    new_shmem_provider,
                    &mgr_description,
                    self.configuration,
                    self.hooks,
                    self.time_ref.clone(),
                )?;
                (
                    state_opt,
                    LlmpRestartingEventManager::with_save_state(
                        llmp_mgr,
                        staterestorer,
                        self.serialize_state,
                    ),
                )
            } else {
                log::info!("First run. Let's set it all up");
                // Mgr to send and receive msgs from/to all other fuzzer instances
                #[cfg(not(feature = "adaptive_serialization"))]
                let mgr = LlmpEventManager::<EMH, S, SP>::existing_client_from_env_with_hooks(
                    new_shmem_provider,
                    _ENV_FUZZER_BROKER_CLIENT_INITIAL,
                    self.configuration,
                    self.hooks,
                )?;
                #[cfg(feature = "adaptive_serialization")]
                let mgr = LlmpEventManager::<EMH, S, SP>::existing_client_from_env_with_hooks(
                    new_shmem_provider,
                    _ENV_FUZZER_BROKER_CLIENT_INITIAL,
                    self.configuration,
                    self.hooks,
                    self.time_ref.clone(),
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
        if self.serialize_state.oom_safe() {
            mgr.intermediate_save()?;
        } else {
            mgr.staterestorer.reset();
        }

        /* TODO: Not sure if this is needed
        // We commit an empty NO_RESTART message to this buf, against infinite loops,
        // in case something crashes in the fuzzer.
        staterestorer.send_buf(_LLMP_TAG_NO_RESTART, []);
        */

        Ok((state, mgr))
    }
}

/// A manager-like llmp client that converts between input types
pub struct LlmpEventConverter<DI, IC, ICB, S, SP>
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

impl<DI, IC, ICB, S, SP> core::fmt::Debug for LlmpEventConverter<DI, IC, ICB, S, SP>
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

impl<DI, IC, ICB, S, SP> LlmpEventConverter<DI, IC, ICB, S, SP>
where
    S: UsesInput + HasExecutions + HasMetadata,
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
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
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
        let llmp = LlmpClient::create_attach_to_tcp(shmem_provider, port)?;
        Ok(Self {
            llmp,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
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
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
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
        client_id: ClientId,
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
                log::info!("Received new Testcase to convert from {client_id:?} (forward {forward_id:?}, forward {forward_id:?})");

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
        let self_id = self.llmp.sender().id();
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

impl<DI, IC, ICB, S, SP> UsesState for LlmpEventConverter<DI, IC, ICB, S, SP>
where
    S: State,
    SP: ShMemProvider,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
{
    type State = S;
}

impl<DI, IC, ICB, S, SP> EventFirer for LlmpEventConverter<DI, IC, ICB, S, SP>
where
    S: State,
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

        match self.compressor.maybe_compress(&serialized) {
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

    #[cfg(feature = "adaptive_serialization")]
    use libafl_bolts::tuples::Handled;
    use libafl_bolts::{
        llmp::{LlmpClient, LlmpSharedMap},
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        staterestore::StateRestorer,
        tuples::tuple_list,
        ClientId,
    };
    use serial_test::serial;

    use crate::{
        corpus::{Corpus, InMemoryCorpus, Testcase},
        events::llmp::{LlmpEventManager, _ENV_FUZZER_SENDER},
        executors::{ExitKind, InProcessExecutor},
        feedbacks::ConstFeedback,
        fuzzer::Fuzzer,
        inputs::BytesInput,
        mutators::BitFlipMutator,
        observers::TimeObserver,
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

        let time = TimeObserver::new("time");
        #[cfg(feature = "adaptive_serialization")]
        let time_ref = time.handle();

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

        #[cfg(not(feature = "adaptive_serialization"))]
        let mut llmp_mgr = LlmpEventManager::new(llmp_client, "fuzzer".into()).unwrap();
        #[cfg(feature = "adaptive_serialization")]
        let mut llmp_mgr =
            LlmpEventManager::new(llmp_client, "fuzzer".into(), time_ref.clone()).unwrap();

        let scheduler = RandScheduler::new();

        let feedback = ConstFeedback::new(true);
        let objective = ConstFeedback::new(false);

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut harness = |_buf: &BytesInput| ExitKind::Ok;
        let mut executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(time),
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
        #[cfg(not(feature = "adaptive_serialization"))]
        let mut llmp_clone = LlmpEventManager::existing_client_from_description(
            shmem_provider,
            &mgr_description,
            "fuzzer".into(),
        )
        .unwrap();
        #[cfg(feature = "adaptive_serialization")]
        let mut llmp_clone = LlmpEventManager::existing_client_from_description(
            shmem_provider,
            &mgr_description,
            "fuzzer".into(),
            time_ref,
        )
        .unwrap();

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
