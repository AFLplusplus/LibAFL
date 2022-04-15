//! LLMP-backed event manager for scalable multi-processed fuzzing

#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use crate::bolts::os::startable_self;
#[cfg(all(feature = "std", feature = "fork", unix))]
use crate::bolts::os::{fork, ForkResult};
#[cfg(feature = "llmp_compression")]
use crate::bolts::{
    compress::GzipCompressor,
    llmp::{LLMP_FLAG_COMPRESSED, LLMP_FLAG_INITIALIZED},
};
#[cfg(feature = "std")]
use crate::bolts::{llmp::LlmpConnection, shmem::StdShMemProvider, staterestore::StateRestorer};
use crate::{
    bolts::{
        llmp::{self, Flags, LlmpClient, LlmpClientDescription, Tag},
        shmem::ShMemProvider,
    },
    events::{
        BrokerEventResult, Event, EventConfig, EventFirer, EventManager, EventManagerId,
        EventProcessor, EventRestarter, HasEventManagerId, ProgressReporter,
    },
    executors::{Executor, HasObservers},
    fuzzer::{EvaluatorObservers, ExecutionProcessor},
    inputs::Input,
    monitors::Monitor,
    observers::ObserversTuple,
    Error,
};
use alloc::string::ToString;
#[cfg(feature = "std")]
use core::sync::atomic::{compiler_fence, Ordering};
use core::{marker::PhantomData, time::Duration};
#[cfg(feature = "std")]
use core_affinity::CoreId;
use serde::de::DeserializeOwned;
#[cfg(feature = "std")]
use serde::Serialize;
#[cfg(feature = "std")]
use std::net::{SocketAddr, ToSocketAddrs};
#[cfg(feature = "std")]
use typed_builder::TypedBuilder;

/// Forward this to the client
const _LLMP_TAG_EVENT_TO_CLIENT: Tag = 0x2C11E471;
/// Only handle this in the broker
const _LLMP_TAG_EVENT_TO_BROKER: Tag = 0x2B80438;
/// Handle in both
///
const LLMP_TAG_EVENT_TO_BOTH: Tag = 0x2B0741;
const _LLMP_TAG_RESTART: Tag = 0x8357A87;
const _LLMP_TAG_NO_RESTART: Tag = 0x57A7EE71;

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
    /// Create an even broker from a raw broker.
    pub fn new(llmp: llmp::LlmpBroker<SP>, monitor: MT) -> Result<Self, Error> {
        Ok(Self {
            monitor,
            llmp,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            phantom: PhantomData,
        })
    }

    /// Create llmp on a port
    /// The port must not be bound yet to have a broker.
    #[cfg(feature = "std")]
    pub fn new_on_port(shmem_provider: SP, monitor: MT, port: u16) -> Result<Self, Error> {
        Ok(Self {
            monitor,
            llmp: llmp::LlmpBroker::create_attach_to_tcp(shmem_provider, port)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            phantom: PhantomData,
        })
    }

    /// Connect to an llmp broker on the givien address
    #[cfg(feature = "std")]
    pub fn connect_b2b<A>(&mut self, addr: A) -> Result<(), Error>
    where
        A: ToSocketAddrs,
    {
        self.llmp.connect_b2b(addr)
    }

    /// Run forever in the broker
    pub fn broker_loop(&mut self) -> Result<(), Error> {
        let monitor = &mut self.monitor;
        #[cfg(feature = "llmp_compression")]
        let compressor = &self.compressor;
        self.llmp.loop_forever(
            &mut |client_id: u32, tag: Tag, _flags: Flags, msg: &[u8]| {
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

        Ok(())
    }

    /// Handle arriving events in the broker
    #[allow(clippy::unnecessary_wraps)]
    fn handle_in_broker(
        monitor: &mut MT,
        client_id: u32,
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
            } => {
                let client = monitor.client_stats_mut_for(client_id);
                client.update_corpus_size(*corpus_size as u64);
                client.update_executions(*executions as u64, *time);
                monitor.display(event.name().to_string(), client_id);
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
                #[cfg(feature = "std")]
                println!("[LOG {}]: {}", severity_level, message);
                Ok(BrokerEventResult::Handled)
            } //_ => Ok(BrokerEventResult::Forward),
        }
    }
}

/// An [`EventManager`] that forwards all events to other attached fuzzers on shared maps or via tcp,
/// using low-level message passing, [`crate::bolts::llmp`].
#[derive(Debug)]
pub struct LlmpEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    llmp: LlmpClient<SP>,
    #[cfg(feature = "llmp_compression")]
    compressor: GzipCompressor,
    configuration: EventConfig,
    phantom: PhantomData<(I, OT, S)>,
}

impl<I, OT, S, SP> Drop for LlmpEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider + 'static,
{
    /// LLMP clients will have to wait until their pages are mapped by somebody.
    fn drop(&mut self) {
        self.await_restart_safe();
    }
}

impl<I, OT, S, SP> LlmpEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider + 'static,
{
    /// Create a manager from a raw llmp client
    pub fn new(llmp: LlmpClient<SP>, configuration: EventConfig) -> Result<Self, Error> {
        Ok(Self {
            llmp,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            configuration,
            phantom: PhantomData,
        })
    }

    /// Create llmp on a port
    /// If the port is not yet bound, it will act as broker
    /// Else, it will act as client.
    #[cfg(feature = "std")]
    pub fn new_on_port(
        shmem_provider: SP,
        port: u16,
        configuration: EventConfig,
    ) -> Result<Self, Error> {
        Ok(Self {
            llmp: llmp::LlmpClient::create_attach_to_tcp(shmem_provider, port)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            configuration,
            phantom: PhantomData,
        })
    }

    /// If a client respawns, it may reuse the existing connection, previously stored by [`LlmpClient::to_env()`].
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
        })
    }

    /// Describe the client event mgr's llmp parts in a restorable fashion
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
            llmp: llmp::LlmpClient::existing_client_from_description(shmem_provider, description)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            configuration,
            phantom: PhantomData,
        })
    }

    /// Write the config for a client [`EventManager`] to env vars, a new client can reattach using [`LlmpEventManager::existing_client_from_env()`].
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
        _client_id: u32,
        event: Event<I>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<I, S> + DeserializeOwned,
        E: Executor<Self, I, S, Z> + HasObservers<I, OT, S>,
        Z: ExecutionProcessor<I, OT, S> + EvaluatorObservers<I, OT, S>,
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
            } => {
                #[cfg(feature = "std")]
                println!(
                    "Received new Testcase from {} ({:?})",
                    _client_id, client_config
                );

                let _res = if client_config.match_with(&self.configuration)
                    && observers_buf.is_some()
                {
                    let observers: OT = postcard::from_bytes(observers_buf.as_ref().unwrap())?;
                    fuzzer.process_execution(state, self, input, &observers, &exit_kind, false)?
                } else {
                    fuzzer.evaluate_input_with_observers(state, executor, self, input, false)?
                };
                #[cfg(feature = "std")]
                if let Some(item) = _res.1 {
                    println!("Added received Testcase as item #{}", item);
                }
                Ok(())
            }
            _ => Err(Error::Unknown(format!(
                "Received illegal message that message should not have arrived: {:?}.",
                event.name()
            ))),
        }
    }
}

impl<I, OT, S, SP> EventFirer<I> for LlmpEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider,
    //CE: CustomEvent<I>,
{
    #[cfg(feature = "llmp_compression")]
    fn fire<S2>(&mut self, _state: &mut S2, event: Event<I>) -> Result<(), Error> {
        let serialized = postcard::to_allocvec(&event)?;
        let flags: Flags = LLMP_FLAG_INITIALIZED;

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
    fn fire<S2>(&mut self, _state: &mut S2, event: Event<I>) -> Result<(), Error> {
        let serialized = postcard::to_allocvec(&event)?;
        self.llmp.send_buf(LLMP_TAG_EVENT_TO_BOTH, &serialized)?;
        Ok(())
    }

    fn configuration(&self) -> EventConfig {
        self.configuration
    }
}

impl<I, OT, S, SP> EventRestarter<S> for LlmpEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider,
    //CE: CustomEvent<I>,
{
    /// The llmp client needs to wait until a broker mapped all pages, before shutting down.
    /// Otherwise, the OS may already have removed the shared maps,
    fn await_restart_safe(&mut self) {
        // wait until we can drop the message safely.
        self.llmp.await_safe_to_unmap_blocking();
    }
}

impl<E, I, OT, S, SP, Z> EventProcessor<E, I, S, Z> for LlmpEventManager<I, OT, S, SP>
where
    SP: ShMemProvider,
    E: Executor<Self, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    OT: ObserversTuple<I, S> + DeserializeOwned,
    Z: ExecutionProcessor<I, OT, S> + EvaluatorObservers<I, OT, S>, //CE: CustomEvent<I>,
{
    fn process(&mut self, fuzzer: &mut Z, state: &mut S, executor: &mut E) -> Result<usize, Error> {
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
            let event: Event<I> = postcard::from_bytes(event_bytes)?;
            self.handle_in_client(fuzzer, executor, state, client_id, event)?;
            count += 1;
        }
        Ok(count)
    }
}

impl<E, I, OT, S, SP, Z> EventManager<E, I, S, Z> for LlmpEventManager<I, OT, S, SP>
where
    E: Executor<Self, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    OT: ObserversTuple<I, S> + DeserializeOwned,
    SP: ShMemProvider,
    Z: ExecutionProcessor<I, OT, S> + EvaluatorObservers<I, OT, S>, //CE: CustomEvent<I>,
{
}

impl<I, OT, S, SP> ProgressReporter<I> for LlmpEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S> + DeserializeOwned,
    SP: ShMemProvider,
{
}

impl<I, OT, S, SP> HasEventManagerId for LlmpEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S> + DeserializeOwned,
    SP: ShMemProvider,
{
    /// Gets the id assigned to this staterestorer.
    fn mgr_id(&self) -> EventManagerId {
        EventManagerId {
            id: self.llmp.sender.id as usize,
        }
    }
}

/// A manager that can restart on the fly, storing states in-between (in `on_restart`)
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct LlmpRestartingEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    /// The embedded llmp event manager
    llmp_mgr: LlmpEventManager<I, OT, S, SP>,
    /// The staterestorer to serialize the state for the next runner
    staterestorer: StateRestorer<SP>,
}

#[cfg(feature = "std")]
impl<I, OT, S, SP> ProgressReporter<I> for LlmpRestartingEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S>,
    S: Serialize,
    SP: ShMemProvider,
{
}

#[cfg(feature = "std")]
impl<I, OT, S, SP> EventFirer<I> for LlmpRestartingEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider,
    //CE: CustomEvent<I>,
{
    fn fire<S2>(&mut self, state: &mut S2, event: Event<I>) -> Result<(), Error> {
        // Check if we are going to crash in the event, in which case we store our current state for the next runner
        self.llmp_mgr.fire(state, event)
    }

    fn configuration(&self) -> EventConfig {
        self.llmp_mgr.configuration()
    }
}

#[cfg(feature = "std")]
impl<I, OT, S, SP> EventRestarter<S> for LlmpRestartingEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S>,
    S: Serialize,
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
        self.staterestorer
            .save(&(state, &self.llmp_mgr.describe()?))
    }
}

#[cfg(feature = "std")]
impl<E, I, OT, S, SP, Z> EventProcessor<E, I, S, Z> for LlmpRestartingEventManager<I, OT, S, SP>
where
    E: Executor<LlmpEventManager<I, OT, S, SP>, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    Z: ExecutionProcessor<I, OT, S> + EvaluatorObservers<I, OT, S>,
    OT: ObserversTuple<I, S> + DeserializeOwned,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    fn process(&mut self, fuzzer: &mut Z, state: &mut S, executor: &mut E) -> Result<usize, Error> {
        self.llmp_mgr.process(fuzzer, state, executor)
    }
}

#[cfg(feature = "std")]
impl<E, I, OT, S, SP, Z> EventManager<E, I, S, Z> for LlmpRestartingEventManager<I, OT, S, SP>
where
    E: Executor<LlmpEventManager<I, OT, S, SP>, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    S: Serialize,
    Z: ExecutionProcessor<I, OT, S> + EvaluatorObservers<I, OT, S>,
    OT: ObserversTuple<I, S> + DeserializeOwned,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
}

#[cfg(feature = "std")]
impl<I, OT, S, SP> HasEventManagerId for LlmpRestartingEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S> + DeserializeOwned,
    S: Serialize,
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
impl<I, OT, S, SP> LlmpRestartingEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S> + DeserializeOwned,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    /// Create a new runner, the executed child doing the actual fuzzing.
    pub fn new(llmp_mgr: LlmpEventManager<I, OT, S, SP>, staterestorer: StateRestorer<SP>) -> Self {
        Self {
            llmp_mgr,
            staterestorer,
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
        /// The cpu core id of this client
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
pub fn setup_restarting_mgr_std<I, MT, OT, S>(
    monitor: MT,
    broker_port: u16,
    configuration: EventConfig,
) -> Result<
    (
        Option<S>,
        LlmpRestartingEventManager<I, OT, S, StdShMemProvider>,
    ),
    Error,
>
where
    I: Input,
    S: DeserializeOwned,
    MT: Monitor + Clone,
    OT: ObserversTuple<I, S> + DeserializeOwned,
    S: DeserializeOwned,
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
pub struct RestartingMgr<I, MT, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S> + DeserializeOwned,
    S: DeserializeOwned,
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
    #[builder(setter(skip), default = PhantomData)]
    phantom_data: PhantomData<(I, OT, S)>,
}

#[cfg(feature = "std")]
#[allow(clippy::type_complexity, clippy::too_many_lines)]
impl<I, MT, OT, S, SP> RestartingMgr<I, MT, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple<I, S> + DeserializeOwned,
    S: DeserializeOwned,
    SP: ShMemProvider,
    MT: Monitor + Clone,
{
    /// Launch the restarting manager
    pub fn launch(
        &mut self,
    ) -> Result<(Option<S>, LlmpRestartingEventManager<I, OT, S, SP>), Error> {
        // We start ourself as child process to actually fuzz
        let (staterestorer, new_shmem_provider, core_id) = if std::env::var(_ENV_FUZZER_SENDER)
            .is_err()
        {
            let broker_things = |mut broker: LlmpEventBroker<I, MT, SP>, remote_broker_addr| {
                if let Some(remote_broker_addr) = remote_broker_addr {
                    println!("B2b: Connecting to {:?}", &remote_broker_addr);
                    broker.connect_b2b(remote_broker_addr)?;
                };

                broker.broker_loop()
            };

            // We get here if we are on Unix, or we are a broker on Windows (or without forks).
            let (mgr, core_id) = match self.kind {
                ManagerKind::Any => {
                    let connection =
                        LlmpConnection::on_port(self.shmem_provider.clone(), self.broker_port)?;
                    match connection {
                        LlmpConnection::IsBroker { broker } => {
                            let event_broker = LlmpEventBroker::<I, MT, SP>::new(
                                broker,
                                self.monitor.take().unwrap(),
                            )?;

                            // Yep, broker. Just loop here.
                            println!(
                                "Doing broker things. Run this tool again to start fuzzing in a client."
                            );

                            broker_things(event_broker, self.remote_broker_addr)?;

                            return Err(Error::ShuttingDown);
                        }
                        LlmpConnection::IsClient { client } => {
                            let mgr =
                                LlmpEventManager::<I, OT, S, SP>::new(client, self.configuration)?;
                            (mgr, None)
                        }
                    }
                }
                ManagerKind::Broker => {
                    let event_broker = LlmpEventBroker::<I, MT, SP>::new_on_port(
                        self.shmem_provider.clone(),
                        self.monitor.take().unwrap(),
                        self.broker_port,
                    )?;

                    broker_things(event_broker, self.remote_broker_addr)?;

                    return Err(Error::ShuttingDown);
                }
                ManagerKind::Client { cpu_core } => {
                    // We are a client
                    let mgr = LlmpEventManager::<I, OT, S, SP>::new_on_port(
                        self.shmem_provider.clone(),
                        self.broker_port,
                        self.configuration,
                    )?;

                    (mgr, cpu_core)
                }
            };

            if let Some(core_id) = core_id {
                println!("Setting core affinity to {:?}", core_id);
                core_affinity::set_for_current(core_id);
            }

            // We are the fuzzer respawner in a llmp client
            mgr.to_env(_ENV_FUZZER_BROKER_CLIENT_INITIAL);

            // First, create a channel from the current fuzzer to the next to store state between restarts.
            let staterestorer: StateRestorer<SP> =
                StateRestorer::new(self.shmem_provider.new_shmem(256 * 1024 * 1024)?);
            // Store the information to a map.
            staterestorer.write_to_env(_ENV_FUZZER_SENDER)?;

            let mut ctr: u64 = 0;
            // Client->parent loop
            loop {
                println!("Spawning next client (id {})", ctr);

                // On Unix, we fork
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

                // On windows (or in any case without fork), we spawn ourself again
                #[cfg(any(windows, not(feature = "fork")))]
                let child_status = startable_self()?.status()?;
                #[cfg(all(unix, not(feature = "fork")))]
                let child_status = child_status.code().unwrap_or_default();

                compiler_fence(Ordering::SeqCst);

                #[allow(clippy::manual_assert)]
                if !staterestorer.has_content() {
                    #[cfg(unix)]
                    if child_status == 137 {
                        // Out of Memory, see https://tldp.org/LDP/abs/html/exitcodes.html
                        // and https://github.com/AFLplusplus/LibAFL/issues/32 for discussion.
                        panic!("Fuzzer-respawner: The fuzzed target crashed with an out of memory error! Fix your harness, or switch to another executor (for example, a forkserver).");
                    }

                    // Storing state in the last round did not work
                    panic!("Fuzzer-respawner: Storing state in crashed fuzzer instance did not work, no point to spawn the next client! This can happen if the child calls `exit()`, in that case make sure it uses `abort()`, if it got killed unrecoverable (OOM), or if there is a bug in the fuzzer itself. (Child exited with: {})", child_status);
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
            core_affinity::set_for_current(core_id);
        }

        // If we're restarting, deserialize the old state.
        let (state, mut mgr) = if let Some((state, mgr_description)) = staterestorer.restore()? {
            (
                Some(state),
                LlmpRestartingEventManager::new(
                    LlmpEventManager::existing_client_from_description(
                        new_shmem_provider,
                        &mgr_description,
                        self.configuration,
                    )?,
                    staterestorer,
                ),
            )
        } else {
            println!("First run. Let's set it all up");
            // Mgr to send and receive msgs from/to all other fuzzer instances
            let mgr = LlmpEventManager::<I, OT, S, SP>::existing_client_from_env(
                new_shmem_provider,
                _ENV_FUZZER_BROKER_CLIENT_INITIAL,
                self.configuration,
            )?;

            (None, LlmpRestartingEventManager::new(mgr, staterestorer))
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

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use serial_test::serial;

    use crate::{
        bolts::{
            llmp::{LlmpClient, LlmpSharedMap},
            rands::StdRand,
            shmem::{ShMemProvider, StdShMemProvider},
            staterestore::StateRestorer,
            tuples::tuple_list,
        },
        corpus::{Corpus, InMemoryCorpus, Testcase},
        events::{llmp::_ENV_FUZZER_SENDER, LlmpEventManager},
        executors::{ExitKind, InProcessExecutor},
        inputs::BytesInput,
        mutators::BitFlipMutator,
        schedulers::RandScheduler,
        stages::StdMutationalStage,
        state::StdState,
        Fuzzer, StdFuzzer,
    };
    use core::sync::atomic::{compiler_fence, Ordering};

    #[test]
    #[serial]
    fn test_mgr_state_restore() {
        let rand = StdRand::with_seed(0);

        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(vec![0; 4]);
        corpus.add(testcase).unwrap();

        let solutions = InMemoryCorpus::<BytesInput>::new();

        let mut state = StdState::new(rand, corpus, solutions, tuple_list!());

        let mut shmem_provider = StdShMemProvider::new().unwrap();

        let mut llmp_client = LlmpClient::new(
            shmem_provider.clone(),
            LlmpSharedMap::new(0, shmem_provider.new_shmem(1024).unwrap()),
            0,
        )
        .unwrap();

        // A little hack for CI. Don't do that in a real-world scenario.
        unsafe {
            llmp_client.mark_safe_to_unmap();
        }

        let mut llmp_mgr =
            LlmpEventManager::<BytesInput, (), _, _>::new(llmp_client, "fuzzer".into()).unwrap();

        let scheduler = RandScheduler::new();

        let mut fuzzer = StdFuzzer::new(scheduler, (), ());

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
