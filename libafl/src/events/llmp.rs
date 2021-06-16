//! LLMP-backed event manager for scalable multi-processed fuzzing

use alloc::{string::ToString, vec::Vec};
use core::{marker::PhantomData, time::Duration};
use core_affinity::CoreId;
use serde::{de::DeserializeOwned, Serialize};

#[cfg(feature = "std")]
use core::ptr::{addr_of, read_volatile};

#[cfg(feature = "std")]
use crate::bolts::{
    llmp::{LlmpClient, LlmpConnection, LlmpReceiver},
    shmem::StdShMemProvider,
};

#[cfg(feature = "std")]
use std::net::{SocketAddr, ToSocketAddrs};

use crate::{
    bolts::{
        llmp::{self, Flags, LlmpClientDescription, LlmpSender, Tag},
        shmem::ShMemProvider,
    },
    events::{BrokerEventResult, Event, EventFirer, EventManager, EventProcessor, EventRestarter},
    executors::ExitKind,
    executors::{Executor, HasExecHooksTuple, HasObservers, HasObserversHooks},
    fuzzer::{Evaluator, IfInteresting, IsInteresting},
    inputs::Input,
    observers::ObserversTuple,
    stats::Stats,
    Error,
};

#[cfg(feature = "llmp_compression")]
use crate::bolts::{
    compress::GzipCompressor,
    llmp::{LLMP_FLAG_COMPRESSED, LLMP_FLAG_INITIALIZED},
};

#[cfg(all(feature = "std", windows))]
use crate::bolts::os::startable_self;

#[cfg(all(feature = "std", unix))]
use crate::bolts::os::{fork, ForkResult};

#[cfg(all(target_os = "android", feature = "std"))]
use crate::bolts::os::ashmem_server::AshmemService;

#[cfg(feature = "std")]
use typed_builder::TypedBuilder;

/// Forward this to the client
const _LLMP_TAG_EVENT_TO_CLIENT: llmp::Tag = 0x2C11E471;
/// Only handle this in the broker
const _LLMP_TAG_EVENT_TO_BROKER: llmp::Tag = 0x2B80438;
/// Handle in both
///
const LLMP_TAG_EVENT_TO_BOTH: llmp::Tag = 0x2B0741;
const _LLMP_TAG_RESTART: llmp::Tag = 0x8357A87;
const _LLMP_TAG_NO_RESTART: llmp::Tag = 0x57A7EE71;

/// The minimum buffer size at which to compress LLMP IPC messages.
#[cfg(feature = "llmp_compression")]
const COMPRESS_THRESHOLD: usize = 1024;

#[derive(Debug)]
pub struct LlmpEventBroker<I, SP, ST>
where
    I: Input,
    SP: ShMemProvider + 'static,
    ST: Stats,
    //CE: CustomEvent<I>,
{
    stats: ST,
    llmp: llmp::LlmpBroker<SP>,
    #[cfg(feature = "llmp_compression")]
    compressor: GzipCompressor,
    phantom: PhantomData<I>,
}

impl<I, SP, ST> LlmpEventBroker<I, SP, ST>
where
    I: Input,
    SP: ShMemProvider + 'static,
    ST: Stats,
{
    /// Create an even broker from a raw broker.
    pub fn new(llmp: llmp::LlmpBroker<SP>, stats: ST) -> Result<Self, Error> {
        Ok(Self {
            stats,
            llmp,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            phantom: PhantomData,
        })
    }

    /// Create llmp on a port
    /// The port must not be bound yet to have a broker.
    #[cfg(feature = "std")]
    pub fn new_on_port(shmem_provider: SP, stats: ST, port: u16) -> Result<Self, Error> {
        Ok(Self {
            stats,
            llmp: llmp::LlmpBroker::create_attach_to_tcp(shmem_provider, port)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            phantom: PhantomData,
        })
    }

    #[cfg(feature = "std")]
    pub fn connect_b2b<A>(&mut self, addr: A) -> Result<(), Error>
    where
        A: ToSocketAddrs,
    {
        self.llmp.connect_b2b(addr)
    }

    /// Run forever in the broker
    pub fn broker_loop(&mut self) -> Result<(), Error> {
        let stats = &mut self.stats;
        #[cfg(feature = "llmp_compression")]
        let compressor = &self.compressor;
        self.llmp.loop_forever(
            &mut |sender_id: u32, tag: Tag, _flags: Flags, msg: &[u8]| {
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
                    match Self::handle_in_broker(stats, sender_id, &event)? {
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
        stats: &mut ST,
        sender_id: u32,
        event: &Event<I>,
    ) -> Result<BrokerEventResult, Error> {
        match &event {
            Event::NewTestcase {
                input: _,
                client_config: _,
                corpus_size,
                observers_buf: _,
                time,
                executions,
            } => {
                let client = stats.client_stats_mut_for(sender_id);
                client.update_corpus_size(*corpus_size as u64);
                client.update_executions(*executions as u64, *time);
                stats.display(event.name().to_string(), sender_id);
                Ok(BrokerEventResult::Forward)
            }
            Event::UpdateStats {
                time,
                executions,
                phantom: _,
            } => {
                // TODO: The stats buffer should be added on client add.
                let client = stats.client_stats_mut_for(sender_id);
                client.update_executions(*executions as u64, *time);
                stats.display(event.name().to_string(), sender_id);
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateUserStats {
                name,
                value,
                phantom: _,
            } => {
                let client = stats.client_stats_mut_for(sender_id);
                client.update_user_stats(name.clone(), value.clone());
                stats.display(event.name().to_string(), sender_id);
                Ok(BrokerEventResult::Handled)
            }
            #[cfg(feature = "introspection")]
            Event::UpdatePerfStats {
                time,
                executions,
                introspection_stats,
                phantom: _,
            } => {
                // TODO: The stats buffer should be added on client add.

                // Get the client for the sender ID
                let client = stats.client_stats_mut_for(sender_id);

                // Update the normal stats for this client
                client.update_executions(*executions as u64, *time);

                // Update the performance stats for this client
                client.update_introspection_stats(**introspection_stats);

                // Display the stats via `.display` only on core #1
                stats.display(event.name().to_string(), sender_id);

                // Correctly handled the event
                Ok(BrokerEventResult::Handled)
            }
            Event::Objective { objective_size } => {
                let client = stats.client_stats_mut_for(sender_id);
                client.update_objective_size(*objective_size as u64);
                stats.display(event.name().to_string(), sender_id);
                Ok(BrokerEventResult::Handled)
            }
            Event::Log {
                severity_level,
                message,
                phantom: _,
            } => {
                let (_, _) = (severity_level, message);
                // TODO rely on Stats
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
    OT: ObserversTuple,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    llmp: llmp::LlmpClient<SP>,
    #[cfg(feature = "llmp_compression")]
    compressor: GzipCompressor,
    configuration: String,
    phantom: PhantomData<(I, OT, S)>,
}

impl<I, OT, S, SP> Drop for LlmpEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple,
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
    OT: ObserversTuple,
    SP: ShMemProvider + 'static,
{
    /// Create a manager from a raw llmp client
    pub fn new(llmp: llmp::LlmpClient<SP>, configuration: String) -> Result<Self, Error> {
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
        configuration: String,
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
        configuration: String,
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
        configuration: String,
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
        _sender_id: u32,
        event: Event<I>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple + HasExecHooksTuple<Self, I, S, Z>,
        E: Executor<Self, I, S, Z> + HasObservers<OT> + HasObserversHooks<Self, I, OT, S, Z>,
        Z: IfInteresting<I, S> + IsInteresting<I, OT, S> + Evaluator<E, Self, I, S>,
    {
        match event {
            Event::NewTestcase {
                input,
                client_config,
                corpus_size: _,
                observers_buf,
                time: _,
                executions: _,
            } => {
                // TODO: here u should match client_config, if equal to the current one do not re-execute
                // we need to pass engine to process() too, TODO
                #[cfg(feature = "std")]
                println!("Received new Testcase from {}", _sender_id);

                if client_config != self.configuration {
                    fuzzer.evaluate_input_events(state, executor, self, input, false)?;
                } else {
                    let observers: OT = postcard::from_bytes(&observers_buf)?;
                    // TODO include ExitKind in NewTestcase
                    // TODO check for objective too
                    let is_interesting =
                        fuzzer.is_interesting(state, self, &input, &observers, &ExitKind::Ok)?;
                    if fuzzer
                        .add_if_interesting(state, &input, is_interesting)?
                        .is_some()
                    {
                        #[cfg(feature = "std")]
                        println!("Added received Testcase");
                    }
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

impl<I, OT, S, SP> EventFirer<I, S> for LlmpEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple,
    SP: ShMemProvider,
    //CE: CustomEvent<I>,
{
    #[cfg(feature = "llmp_compression")]
    fn fire(&mut self, _state: &mut S, event: Event<I>) -> Result<(), Error> {
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
    fn fire(&mut self, _state: &mut S, event: Event<I>) -> Result<(), Error> {
        let serialized = postcard::to_allocvec(&event)?;
        self.llmp.send_buf(LLMP_TAG_EVENT_TO_BOTH, &serialized)?;
        Ok(())
    }
}

impl<I, OT, S, SP> EventRestarter<S> for LlmpEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple,
    SP: ShMemProvider,
    //CE: CustomEvent<I>,
{
    /// The llmp client needs to wait until a broker mapped all pages, before shutting down.
    /// Otherwise, the OS may already have removed the shared maps,
    fn await_restart_safe(&mut self) {
        // wait until we can drop the message safely.
        self.llmp.await_save_to_unmap_blocking();
    }
}

impl<E, I, OT, S, SP, Z> EventProcessor<E, S, Z> for LlmpEventManager<I, OT, S, SP>
where
    SP: ShMemProvider,
    E: Executor<Self, I, S, Z> + HasObservers<OT> + HasObserversHooks<Self, I, OT, S, Z>,
    I: Input,
    OT: ObserversTuple + HasExecHooksTuple<Self, I, S, Z>,
    Z: IfInteresting<I, S> + IsInteresting<I, OT, S> + Evaluator<E, Self, I, S>, //CE: CustomEvent<I>,
{
    fn process(&mut self, fuzzer: &mut Z, state: &mut S, executor: &mut E) -> Result<usize, Error> {
        // TODO: Get around local event copy by moving handle_in_client
        let mut events = vec![];
        let self_id = self.llmp.sender.id;
        while let Some((sender_id, tag, _flags, msg)) = self.llmp.recv_buf_with_flags()? {
            if tag == _LLMP_TAG_EVENT_TO_BROKER {
                panic!("EVENT_TO_BROKER parcel should not have arrived in the client!");
            }
            if sender_id == self_id {
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
            events.push((sender_id, event));
        }
        let count = events.len();
        events.drain(..).try_for_each(|(sender_id, event)| {
            self.handle_in_client(fuzzer, executor, state, sender_id, event)
        })?;
        Ok(count)
    }
}

impl<E, I, OT, S, SP, Z> EventManager<E, I, S, Z> for LlmpEventManager<I, OT, S, SP>
where
    SP: ShMemProvider,
    E: Executor<Self, I, S, Z> + HasObservers<OT> + HasObserversHooks<Self, I, OT, S, Z>,
    I: Input,
    OT: ObserversTuple + HasExecHooksTuple<Self, I, S, Z>,
    Z: IfInteresting<I, S> + IsInteresting<I, OT, S> + Evaluator<E, Self, I, S>, //CE: CustomEvent<I>,
{
}

/// Serialize the current state and corpus during an executiont to bytes.
/// On top, add the current llmp event manager instance to be restored
/// This method is needed when the fuzzer run crashes and has to restart.
pub fn serialize_state_mgr<I, OT, S, SP>(
    state: &S,
    mgr: &LlmpEventManager<I, OT, S, SP>,
) -> Result<Vec<u8>, Error>
where
    I: Input,
    OT: ObserversTuple,
    S: Serialize,
    SP: ShMemProvider,
{
    Ok(postcard::to_allocvec(&(&state, &mgr.describe()?))?)
}

/// Deserialize the state and corpus tuple, previously serialized with `serialize_state_corpus(...)`
#[allow(clippy::type_complexity)]
pub fn deserialize_state_mgr<I, OT, S, SP>(
    shmem_provider: SP,
    state_corpus_serialized: &[u8],
    configuration: String,
) -> Result<(S, LlmpEventManager<I, OT, S, SP>), Error>
where
    I: Input,
    OT: ObserversTuple,
    S: DeserializeOwned,
    SP: ShMemProvider,
{
    let tuple: (S, _) = postcard::from_bytes(state_corpus_serialized)?;
    Ok((
        tuple.0,
        LlmpEventManager::existing_client_from_description(
            shmem_provider,
            &tuple.1,
            configuration,
        )?,
    ))
}

/// A manager that can restart on the fly, storing states in-between (in `on_resatrt`)
#[derive(Debug)]
pub struct LlmpRestartingEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    /// The embedded llmp event manager
    llmp_mgr: LlmpEventManager<I, OT, S, SP>,
    /// The sender to serialize the state for the next runner
    sender: LlmpSender<SP>,
}

impl<I, OT, S, SP> EventFirer<I, S> for LlmpRestartingEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple,
    S: Serialize,
    SP: ShMemProvider,
    //CE: CustomEvent<I>,
{
    fn fire(&mut self, state: &mut S, event: Event<I>) -> Result<(), Error> {
        // Check if we are going to crash in the event, in which case we store our current state for the next runner
        self.llmp_mgr.fire(state, event)
    }
}

impl<I, OT, S, SP> EventRestarter<S> for LlmpRestartingEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple,
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
        unsafe {
            self.sender.reset();
        }
        let state_corpus_serialized = serialize_state_mgr(state, &self.llmp_mgr)?;
        self.sender
            .send_buf(_LLMP_TAG_RESTART, &state_corpus_serialized)
    }
}

impl<E, I, OT, S, SP, Z> EventProcessor<E, S, Z> for LlmpRestartingEventManager<I, OT, S, SP>
where
    E: Executor<LlmpEventManager<I, OT, S, SP>, I, S, Z>
        + HasObservers<OT>
        + HasObserversHooks<LlmpEventManager<I, OT, S, SP>, I, OT, S, Z>,
    I: Input,
    Z: IfInteresting<I, S>
        + IsInteresting<I, OT, S>
        + Evaluator<E, LlmpEventManager<I, OT, S, SP>, I, S>,
    OT: ObserversTuple + HasExecHooksTuple<LlmpEventManager<I, OT, S, SP>, I, S, Z>,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    fn process(&mut self, fuzzer: &mut Z, state: &mut S, executor: &mut E) -> Result<usize, Error> {
        self.llmp_mgr.process(fuzzer, state, executor)
    }
}

impl<E, I, OT, S, SP, Z> EventManager<E, I, S, Z> for LlmpRestartingEventManager<I, OT, S, SP>
where
    E: Executor<LlmpEventManager<I, OT, S, SP>, I, S, Z>
        + HasObservers<OT>
        + HasObserversHooks<LlmpEventManager<I, OT, S, SP>, I, OT, S, Z>,
    I: Input,
    S: Serialize,
    Z: IfInteresting<I, S>
        + IsInteresting<I, OT, S>
        + Evaluator<E, LlmpEventManager<I, OT, S, SP>, I, S>,
    OT: ObserversTuple + HasExecHooksTuple<LlmpEventManager<I, OT, S, SP>, I, S, Z>,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
}

/// The llmp connection from the actual fuzzer to the process supervising it
const _ENV_FUZZER_SENDER: &str = "_AFL_ENV_FUZZER_SENDER";
const _ENV_FUZZER_RECEIVER: &str = "_AFL_ENV_FUZZER_RECEIVER";
/// The llmp (2 way) connection from a fuzzer to the broker (broadcasting all other fuzzer messages)
const _ENV_FUZZER_BROKER_CLIENT_INITIAL: &str = "_AFL_ENV_FUZZER_BROKER_CLIENT";

impl<I, OT, S, SP> LlmpRestartingEventManager<I, OT, S, SP>
where
    I: Input,
    OT: ObserversTuple,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    /// Create a new runner, the executed child doing the actual fuzzing.
    pub fn new(llmp_mgr: LlmpEventManager<I, OT, S, SP>, sender: LlmpSender<SP>) -> Self {
        Self { llmp_mgr, sender }
    }

    /// Get the sender
    pub fn sender(&self) -> &LlmpSender<SP> {
        &self.sender
    }

    /// Get the sender (mut)
    pub fn sender_mut(&mut self) -> &mut LlmpSender<SP> {
        &mut self.sender
    }
}

/// The kind of manager we're creating right now
#[derive(Debug, Clone, Copy)]
pub enum ManagerKind {
    /// Any kind will do
    Any,
    /// A client, getting messages from a local broker.
    Client { cpu_core: Option<CoreId> },
    /// A [`LlmpBroker`], forwarding the packets of local clients.
    Broker,
}

/// Sets up a restarting fuzzer, using the [`StdShMemProvider`], and standard features.
/// The restarting mgr is a combination of restarter and runner, that can be used on systems with and without `fork` support.
/// The restarter will spawn a new process each time the child crashes or timeouts.
#[cfg(feature = "std")]
#[allow(clippy::type_complexity)]
pub fn setup_restarting_mgr_std<I, OT, S, ST>(
    stats: ST,
    broker_port: u16,
    configuration: String,
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
    ST: Stats + Clone,
    OT: ObserversTuple,
    S: DeserializeOwned,
{
    #[cfg(target_os = "android")]
    AshmemService::start().expect("Error starting Ashmem Service");

    RestartingMgr::builder()
        .shmem_provider(StdShMemProvider::new()?)
        .stats(Some(stats))
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
pub struct RestartingMgr<I, OT, S, SP, ST>
where
    I: Input,
    OT: ObserversTuple,
    S: DeserializeOwned,
    SP: ShMemProvider + 'static,
    ST: Stats,
    //CE: CustomEvent<I>,
{
    /// The shared memory provider to use for the broker or client spawned by the restarting
    /// manager.
    shmem_provider: SP,
    /// The configuration
    configuration: String,
    /// The stats to use
    #[builder(default = None)]
    stats: Option<ST>,
    /// The broker port to use
    #[builder(default = 1337_u16)]
    broker_port: u16,
    /// The address to connect to
    #[builder(default = None)]
    remote_broker_addr: Option<SocketAddr>,
    /// The type of manager to build
    #[builder(default = ManagerKind::Any)]
    kind: ManagerKind,
    #[builder(setter(skip), default = PhantomData {})]
    _phantom: PhantomData<(I, OT, S)>,
}

#[cfg(feature = "std")]
#[allow(clippy::type_complexity, clippy::too_many_lines)]
impl<I, OT, S, SP, ST> RestartingMgr<I, OT, S, SP, ST>
where
    I: Input,
    OT: ObserversTuple,
    S: DeserializeOwned,
    SP: ShMemProvider,
    ST: Stats + Clone,
{
    /// Launch the restarting manager
    pub fn launch(
        &mut self,
    ) -> Result<(Option<S>, LlmpRestartingEventManager<I, OT, S, SP>), Error> {
        // We start ourself as child process to actually fuzz
        let (sender, mut receiver, new_shmem_provider, core_id) = if std::env::var(
            _ENV_FUZZER_SENDER,
        )
        .is_err()
        {
            let broker_things = |mut broker: LlmpEventBroker<I, SP, ST>, remote_broker_addr| {
                if let Some(remote_broker_addr) = remote_broker_addr {
                    println!("B2b: Connecting to {:?}", &remote_broker_addr);
                    broker.connect_b2b(remote_broker_addr)?;
                };

                broker.broker_loop()
            };

            // We get here if we are on Unix, or we are a broker on Windows.
            let (mgr, core_id) = match self.kind {
                ManagerKind::Any => {
                    let connection =
                        LlmpConnection::on_port(self.shmem_provider.clone(), self.broker_port)?;
                    match connection {
                        LlmpConnection::IsBroker { broker } => {
                            let event_broker = LlmpEventBroker::<I, SP, ST>::new(
                                broker,
                                self.stats.take().unwrap(),
                            )?;

                            // Yep, broker. Just loop here.
                            println!(
                                "Doing broker things. Run this tool again to start fuzzing in a client."
                            );

                            broker_things(event_broker, self.remote_broker_addr)?;

                            return Err(Error::ShuttingDown);
                        }
                        LlmpConnection::IsClient { client } => {
                            let mgr = LlmpEventManager::<I, OT, S, SP>::new(
                                client,
                                self.configuration.clone(),
                            )?;
                            (mgr, None)
                        }
                    }
                }
                ManagerKind::Broker => {
                    let event_broker = LlmpEventBroker::<I, SP, ST>::new_on_port(
                        self.shmem_provider.clone(),
                        self.stats.take().unwrap(),
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
                        self.configuration.clone(),
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

            // First, create a channel from the fuzzer (sender) to us (receiver) to report its state for restarts.
            let sender = { LlmpSender::new(self.shmem_provider.clone(), 0, false)? };

            let map = {
                self.shmem_provider
                    .clone_ref(&sender.out_maps.last().unwrap().shmem)?
            };
            let receiver = LlmpReceiver::on_existing_map(self.shmem_provider.clone(), map, None)?;
            // Store the information to a map.
            sender.to_env(_ENV_FUZZER_SENDER)?;
            receiver.to_env(_ENV_FUZZER_RECEIVER)?;

            let mut ctr: u64 = 0;
            // Client->parent loop
            loop {
                dbg!("Spawning next client (id {})", ctr);

                // On Unix, we fork
                #[cfg(unix)]
                let child_status = {
                    self.shmem_provider.pre_fork()?;
                    match unsafe { fork() }? {
                        ForkResult::Parent(handle) => {
                            self.shmem_provider.post_fork(false)?;
                            handle.status()
                        }
                        ForkResult::Child => {
                            self.shmem_provider.post_fork(true)?;
                            break (sender, receiver, self.shmem_provider.clone(), core_id);
                        }
                    }
                };

                // On windows, we spawn ourself again
                #[cfg(windows)]
                let child_status = startable_self()?.status()?;

                if unsafe { read_volatile(addr_of!((*receiver.current_recv_map.page()).size_used)) }
                    == 0
                {
                    #[cfg(unix)]
                    if child_status == 137 {
                        // Out of Memory, see https://tldp.org/LDP/abs/html/exitcodes.html
                        // and https://github.com/AFLplusplus/LibAFL/issues/32 for discussion.
                        panic!("Fuzzer-respawner: The fuzzed target crashed with an out of memory error! Fix your harness, or switch to another executor (for example, a forkserver).");
                    }

                    // Storing state in the last round did not work
                    panic!("Fuzzer-respawner: Storing state in crashed fuzzer instance did not work, no point to spawn the next client! (Child exited with: {})", child_status);
                }

                ctr = ctr.wrapping_add(1);
            }
        } else {
            // We are the newly started fuzzing instance (i.e. on Windows), first, connect to our own restore map.
            // We get here *only on Windows*, if we were started by a restarting fuzzer.
            // A sender and a receiver for single communication
            (
                LlmpSender::on_existing_from_env(self.shmem_provider.clone(), _ENV_FUZZER_SENDER)?,
                LlmpReceiver::on_existing_from_env(
                    self.shmem_provider.clone(),
                    _ENV_FUZZER_RECEIVER,
                )?,
                self.shmem_provider.clone(),
                None,
            )
        };

        if let Some(core_id) = core_id {
            core_affinity::set_for_current(core_id);
        }

        println!("We're a client, let's fuzz :)");

        // If we're restarting, deserialize the old state.
        let (state, mut mgr) = match receiver.recv_buf()? {
            None => {
                println!("First run. Let's set it all up");
                // Mgr to send and receive msgs from/to all other fuzzer instances
                let mgr = LlmpEventManager::<I, OT, S, SP>::existing_client_from_env(
                    new_shmem_provider,
                    _ENV_FUZZER_BROKER_CLIENT_INITIAL,
                    self.configuration.clone(),
                )?;

                (None, LlmpRestartingEventManager::new(mgr, sender))
            }
            // Restoring from a previous run, deserialize state and corpus.
            Some((_sender, _tag, msg)) => {
                println!("Subsequent run. Let's load all data from shmem (received {} bytes from previous instance)", msg.len());
                let (state, mgr): (S, LlmpEventManager<I, OT, S, SP>) =
                    deserialize_state_mgr(new_shmem_provider, msg, self.configuration.clone())?;

                (Some(state), LlmpRestartingEventManager::new(mgr, sender))
            }
        };
        // We reset the sender, the next sender and receiver (after crash) will reuse the page from the initial message.
        unsafe {
            mgr.sender_mut().reset();
        }
        /* TODO: Not sure if this is needed
        // We commit an empty NO_RESTART message to this buf, against infinite loops,
        // in case something crashes in the fuzzer.
        sender.send_buf(_LLMP_TAG_NO_RESTART, []);
        */

        Ok((state, mgr))
    }
}
