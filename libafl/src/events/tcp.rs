//! TCP-backed event manager for scalable multi-processed fuzzing

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    marker::PhantomData,
    num::NonZeroUsize,
    sync::atomic::{compiler_fence, Ordering},
};
use std::{
    env,
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::Arc,
};

#[cfg(feature = "std")]
use libafl_bolts::core_affinity::CoreId;
#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use libafl_bolts::os::startable_self;
#[cfg(all(unix, feature = "std", not(miri)))]
use libafl_bolts::os::unix_signals::setup_signal_handler;
#[cfg(all(feature = "std", feature = "fork", unix))]
use libafl_bolts::os::{fork, ForkResult};
use libafl_bolts::{shmem::ShMemProvider, ClientId};
#[cfg(feature = "std")]
use libafl_bolts::{shmem::StdShMemProvider, staterestore::StateRestorer};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{broadcast, mpsc},
    task::{spawn, JoinHandle},
};
#[cfg(feature = "std")]
use typed_builder::TypedBuilder;

use super::{CustomBufEventResult, CustomBufHandlerFn};
#[cfg(all(unix, feature = "std"))]
use crate::events::{shutdown_handler, SHUTDOWN_SIGHANDLER_DATA};
use crate::{
    events::{
        BrokerEventResult, Event, EventConfig, EventFirer, EventManager, EventManagerId,
        EventProcessor, EventRestarter, HasCustomBufHandlers, HasEventManagerId, ProgressReporter,
    },
    executors::{Executor, HasObservers},
    fuzzer::{EvaluatorObservers, ExecutionProcessor},
    inputs::{Input, UsesInput},
    monitors::Monitor,
    state::{HasClientPerfMonitor, HasExecutions, HasLastReportTime, HasMetadata, UsesState},
    Error,
};

/// Tries to create (synchronously) a [`TcpListener`] that is `nonblocking` (for later use in tokio).
/// Will error if the port is already in use (or other errors occur)
fn create_nonblocking_listener<A: ToSocketAddrs>(addr: A) -> Result<TcpListener, Error> {
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// An TCP-backed event manager for simple multi-processed fuzzing
#[derive(Debug)]
pub struct TcpEventBroker<I, MT>
where
    I: Input,
    MT: Monitor,
    //CE: CustomEvent<I>,
{
    monitor: MT,
    /// A `nonblocking` [`TcpListener`] that we will `take` and convert to a Tokio listener in [`Self::broker_loop()`].
    listener: Option<TcpListener>,
    /// Amount of all clients ever, after which (when all are disconnected) this broker should quit.
    exit_cleanly_after: Option<NonZeroUsize>,
    phantom: PhantomData<I>,
}

const UNDEFINED_CLIENT_ID: ClientId = ClientId(0xffffffff);

impl<I, MT> TcpEventBroker<I, MT>
where
    I: Input,
    MT: Monitor,
{
    /// Create a TCP broker, listening on the given address.
    pub fn new<A: ToSocketAddrs>(addr: A, monitor: MT) -> Result<Self, Error> {
        Ok(Self::with_listener(
            create_nonblocking_listener(addr)?,
            monitor,
        ))
    }

    /// Create a TCP broker, with a listener that needs to already be bound to an address.
    pub fn with_listener(listener: TcpListener, monitor: MT) -> Self {
        Self {
            listener: Some(listener),
            monitor,
            phantom: PhantomData,
            exit_cleanly_after: None,
        }
    }

    /// Exit the broker process cleanly after at least `n` clients attached and all of them disconnected again
    pub fn set_exit_cleanly_after(&mut self, n_clients: NonZeroUsize) {
        self.exit_cleanly_after = Some(n_clients);
    }

    /// Run in the broker until all clients exit
    #[tokio::main(flavor = "current_thread")]
    #[allow(clippy::too_many_lines)]
    pub async fn broker_loop(&mut self) -> Result<(), Error> {
        let (tx_bc, rx) = broadcast::channel(1024);
        let (tx, mut rx_mpsc) = mpsc::channel(1024);

        let exit_cleanly_after = self.exit_cleanly_after;

        let listener = self
            .listener
            .take()
            .ok_or_else(|| Error::illegal_state("Listener has already been used / was none"))?;
        let listener = tokio::net::TcpListener::from_std(listener)?;

        let tokio_broker = spawn(async move {
            let mut recv_handles: Vec<JoinHandle<_>> = vec![];
            let mut receivers: Vec<Arc<tokio::sync::Mutex<broadcast::Receiver<_>>>> = vec![];

            loop {
                let mut reached_max = false;
                if let Some(max_clients) = exit_cleanly_after {
                    if max_clients.get() <= recv_handles.len() {
                        // we waited for all the clients we wanted to see attached. Now wait for them to close their tcp connections.
                        reached_max = true;
                    }
                }

                // Asynchronously wait for an inbound socket.
                let (socket, _) = listener.accept().await.expect("Accept failed");
                let (mut read, mut write) = tokio::io::split(socket);

                // Protocol: the new client communicate its old ClientId or -1 if new
                let mut this_client_id = [0; 4];
                read.read_exact(&mut this_client_id)
                    .await
                    .expect("Socket closed?");
                let this_client_id = ClientId(u32::from_le_bytes(this_client_id));

                let (this_client_id, is_old) = if this_client_id == UNDEFINED_CLIENT_ID {
                    if reached_max {
                        (UNDEFINED_CLIENT_ID, false) // Dumb id
                    } else {
                        // ClientIds for this broker start at 0.
                        (ClientId(recv_handles.len().try_into().unwrap()), false)
                    }
                } else {
                    (this_client_id, true)
                };

                let this_client_id_bytes = this_client_id.0.to_le_bytes();

                // Protocol: Send the client id for this node;
                write.write_all(&this_client_id_bytes).await.unwrap();

                if !is_old && reached_max {
                    continue;
                }

                let tx_inner = tx.clone();

                let handle = async move {
                    // In a loop, read data from the socket and write the data back.
                    loop {
                        let mut len_buf = [0; 4];

                        if read.read_exact(&mut len_buf).await.is_err() {
                            // The socket is closed, the client is restarting
                            log::info!("Socket closed, client restarting");
                            return;
                        }

                        let mut len = u32::from_le_bytes(len_buf);
                        // we forward the sender id as well, so we add 4 bytes to the message length
                        len += 4;

                        #[cfg(feature = "tcp_debug")]
                        println!("len +4 = {len:?}");

                        let mut buf = vec![0; len as usize];

                        if read
                            .read_exact(&mut buf)
                            .await
                            // .expect("Failed to read data from socket"); // TODO verify if we have to handle this error
                            .is_err()
                        {
                            // The socket is closed, the client is restarting
                            log::info!("Socket closed, client restarting");
                            return;
                        }

                        #[cfg(feature = "tcp_debug")]
                        println!("len: {len:?} - {buf:?}");
                        tx_inner.send(buf).await.expect("Could not send");
                    }
                };

                let client_idx = this_client_id.0 as usize;

                // Keep all handles around.
                if is_old {
                    recv_handles[client_idx].abort();
                    recv_handles[client_idx] = spawn(handle);
                } else {
                    recv_handles.push(spawn(handle));
                    // Get old messages only if new
                    let rx_inner = Arc::new(tokio::sync::Mutex::new(rx.resubscribe()));
                    receivers.push(rx_inner.clone());
                }

                let rx_inner = receivers[client_idx].clone();

                // The forwarding end. No need to keep a handle to this (TODO: unless they don't quit/get stuck?)
                spawn(async move {
                    // In a loop, read data from the socket and write the data back.
                    loop {
                        let buf: Vec<u8> = rx_inner
                            .lock()
                            .await
                            .recv()
                            .await
                            .expect("Could not receive");
                        // TODO handle full capacity, Lagged https://docs.rs/tokio/latest/tokio/sync/broadcast/error/enum.RecvError.html

                        #[cfg(feature = "tcp_debug")]
                        println!("{buf:?}");

                        if buf.len() <= 4 {
                            log::warn!("We got no contents (or only the length) in a broadcast");
                            continue;
                        }

                        if buf[..4] == this_client_id_bytes {
                            #[cfg(feature = "tcp_debug")]
                            eprintln!(
                            "Not forwarding message from this very client ({this_client_id:?})."
                        );
                            continue;
                        }

                        // subtract 4 since the client_id isn't part of the actual message.
                        let len = u32::try_from(buf.len() - 4).unwrap();
                        let len_buf: [u8; 4] = len.to_le_bytes();

                        // Write message length
                        if write.write_all(&len_buf).await.is_err() {
                            // The socket is closed, the client is restarting
                            log::info!("Socket closed, client restarting");
                            return;
                        }
                        // Write the rest
                        if write.write_all(&buf).await.is_err() {
                            // The socket is closed, the client is restarting
                            log::info!("Socket closed, client restarting");
                            return;
                        }
                    }
                });
            }

            /*log::info!("Joining handles..");
            // wait for all clients to exit/error out
            for recv_handle in recv_handles {
                drop(recv_handle.await);
            }*/
        });

        loop {
            let buf = rx_mpsc.recv().await.expect("Could not receive");

            // read client ID.
            let mut client_id_buf = [0_u8; 4];
            client_id_buf.copy_from_slice(&buf[..4]);

            let client_id = ClientId(u32::from_le_bytes(client_id_buf));

            // cut off the ID.
            let event_bytes = &buf[4..];

            let event: Event<I> = postcard::from_bytes(event_bytes).unwrap();
            match Self::handle_in_broker(&mut self.monitor, client_id, &event).unwrap() {
                BrokerEventResult::Forward => {
                    tx_bc.send(buf).expect("Could not send");
                }
                BrokerEventResult::Handled => (),
            }

            if tokio_broker.is_finished() {
                tokio_broker.await.unwrap();
                break;
            }
        }

        #[cfg(feature = "tcp_debug")]
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

/// An [`EventManager`] that forwards all events to other attached via tcp.
pub struct TcpEventManager<S>
where
    S: UsesInput,
{
    /// The TCP stream for inter process communication
    tcp: TcpStream,
    /// Our `CientId`
    client_id: ClientId,
    /// The custom buf handler
    custom_buf_handlers: Vec<Box<CustomBufHandlerFn<S>>>,
    #[cfg(feature = "tcp_compression")]
    compressor: GzipCompressor,
    /// The configuration defines this specific fuzzer.
    /// A node will not re-use the observer values sent over TCP
    /// from nodes with other configurations.
    configuration: EventConfig,
    phantom: PhantomData<S>,
}

impl<S> core::fmt::Debug for TcpEventManager<S>
where
    S: UsesInput,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_struct = f.debug_struct("TcpEventManager");
        let debug = debug_struct.field("tcp", &self.tcp);
        //.field("custom_buf_handlers", &self.custom_buf_handlers)
        #[cfg(feature = "tcp_compression")]
        let debug = debug.field("compressor", &self.compressor);
        debug
            .field("configuration", &self.configuration)
            .field("phantom", &self.phantom)
            .finish_non_exhaustive()
    }
}

impl<S> Drop for TcpEventManager<S>
where
    S: UsesInput,
{
    /// TCP clients will have to wait until their pages are mapped by somebody.
    fn drop(&mut self) {
        self.await_restart_safe();
    }
}

impl<S> TcpEventManager<S>
where
    S: UsesInput + HasExecutions + HasClientPerfMonitor,
{
    /// Create a manager from a raw TCP client specifying the client id
    pub fn existing<A: ToSocketAddrs>(
        addr: &A,
        client_id: ClientId,
        configuration: EventConfig,
    ) -> Result<Self, Error> {
        let mut tcp = TcpStream::connect(addr)?;

        let mut our_client_id_buf = client_id.0.to_le_bytes();
        tcp.write_all(&our_client_id_buf)
            .expect("Cannot write to the broker");

        tcp.read_exact(&mut our_client_id_buf)
            .expect("Cannot read from the broker");
        let client_id = ClientId(u32::from_le_bytes(our_client_id_buf));

        println!("Our client id: {client_id:?}");

        Ok(Self {
            tcp,
            client_id,
            #[cfg(feature = "tcp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            configuration,
            phantom: PhantomData,
            custom_buf_handlers: vec![],
        })
    }

    /// Create a manager from a raw TCP client
    pub fn new<A: ToSocketAddrs>(addr: &A, configuration: EventConfig) -> Result<Self, Error> {
        Self::existing(addr, UNDEFINED_CLIENT_ID, configuration)
    }

    /// Create an TCP event manager on a port specifying the client id
    ///
    /// If the port is not yet bound, it will act as a broker; otherwise, it
    /// will act as a client.
    pub fn existing_on_port(
        port: u16,
        client_id: ClientId,
        configuration: EventConfig,
    ) -> Result<Self, Error> {
        Self::existing(&("127.0.0.1", port), client_id, configuration)
    }

    /// Create an TCP event manager on a port
    ///
    /// If the port is not yet bound, it will act as a broker; otherwise, it
    /// will act as a client.
    pub fn on_port(port: u16, configuration: EventConfig) -> Result<Self, Error> {
        Self::new(&("127.0.0.1", port), configuration)
    }

    /// Create an TCP event manager on a port specifying the client id from env
    ///
    /// If the port is not yet bound, it will act as a broker; otherwise, it
    /// will act as a client.
    pub fn existing_from_env<A: ToSocketAddrs>(
        addr: &A,
        env_name: &str,
        configuration: EventConfig,
    ) -> Result<Self, Error> {
        let this_id = ClientId(str::parse::<u32>(&env::var(env_name)?)?);
        Self::existing(addr, this_id, configuration)
    }

    /// Write the client id for a client [`EventManager`] to env vars
    pub fn to_env(&self, env_name: &str) {
        env::set_var(env_name, format!("{}", self.client_id.0));
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

impl<S> TcpEventManager<S>
where
    S: UsesInput,
{
    /// Send information that this client is exiting.
    /// The other side may free up all allocated memory.
    /// We are no longer allowed to send anything afterwards.
    pub fn send_exiting(&mut self) -> Result<(), Error> {
        //TODO: Should not be needed since TCP does that for us
        //self.tcp.sender.send_exiting()
        Ok(())
    }
}

impl<S> UsesState for TcpEventManager<S>
where
    S: UsesInput,
{
    type State = S;
}

impl<S> EventFirer for TcpEventManager<S>
where
    S: UsesInput,
{
    #[cfg(feature = "tcp_compression")]
    fn fire(
        &mut self,
        _state: &mut Self::State,
        event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        let serialized = postcard::to_allocvec(&event)?;
        let flags = TCP_FLAG_INITIALIZED;

        match self.compressor.compress(&serialized)? {
            Some(comp_buf) => {
                self.tcp.send_buf_with_flags(
                    TCP_TAG_EVENT_TO_BOTH,
                    flags | TCP_FLAG_COMPRESSED,
                    &comp_buf,
                )?;
            }
            None => {
                self.tcp.send_buf(TCP_TAG_EVENT_TO_BOTH, &serialized)?;
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "tcp_compression"))]
    fn fire(
        &mut self,
        _state: &mut Self::State,
        event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        let serialized = postcard::to_allocvec(&event)?;
        let size = u32::try_from(serialized.len()).unwrap();
        self.tcp.write_all(&size.to_le_bytes())?;
        self.tcp.write_all(&self.client_id.0.to_le_bytes())?;
        self.tcp.write_all(&serialized)?;
        Ok(())
    }

    fn configuration(&self) -> EventConfig {
        self.configuration
    }
}

impl<S> EventRestarter for TcpEventManager<S>
where
    S: UsesInput,
{
    /// The TCP client needs to wait until a broker has mapped all pages before shutting down.
    /// Otherwise, the OS may already have removed the shared maps.
    fn await_restart_safe(&mut self) {
        // wait until we can drop the message safely.
        //self.tcp.await_safe_to_unmap_blocking();
    }
}

impl<E, S, Z> EventProcessor<E, Z> for TcpEventManager<S>
where
    S: UsesInput + HasClientPerfMonitor + HasExecutions,
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
        let self_id = self.client_id;
        let mut len_buf = [0_u8; 4];
        let mut count = 0;

        self.tcp.set_nonblocking(true).expect("set to non-blocking");

        // read all pending messages
        loop {
            match self.tcp.read_exact(&mut len_buf) {
                Ok(()) => {
                    self.tcp.set_nonblocking(false).expect("set to blocking");
                    let len = u32::from_le_bytes(len_buf);
                    let mut buf = vec![0_u8; len as usize + 4_usize];
                    self.tcp.read_exact(&mut buf).unwrap();

                    let mut client_id_buf = [0_u8; 4];
                    client_id_buf.copy_from_slice(&buf[..4]);

                    let other_client_id = ClientId(u32::from_le_bytes(client_id_buf));

                    self.tcp.set_nonblocking(true).expect("set to non-blocking");
                    if self_id == other_client_id {
                        panic!("Own ID should never have been sent by the broker");
                    } else {
                        println!("{self_id:?} (from {other_client_id:?}) Received: {buf:?}");

                        let event = postcard::from_bytes(&buf[4..])?;
                        self.handle_in_client(fuzzer, executor, state, other_client_id, event)?;
                        count += 1;
                    }
                }

                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    // no new data on the socket
                    break;
                }
                Err(e) => {
                    panic!("Unexpected error {e:?}");
                }
            }
        }
        self.tcp.set_nonblocking(false).expect("set to blocking");

        Ok(count)
    }
}

impl<E, S, Z> EventManager<E, Z> for TcpEventManager<S>
where
    E: HasObservers<State = S> + Executor<Self, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    S: UsesInput + HasExecutions + HasClientPerfMonitor + HasMetadata + HasLastReportTime,
    Z: EvaluatorObservers<E::Observers, State = S> + ExecutionProcessor<E::Observers, State = S>,
{
}

impl<S> HasCustomBufHandlers for TcpEventManager<S>
where
    S: UsesInput,
{
    fn add_custom_buf_handler(
        &mut self,
        handler: Box<dyn FnMut(&mut S, &String, &[u8]) -> Result<CustomBufEventResult, Error>>,
    ) {
        self.custom_buf_handlers.push(handler);
    }
}

impl<S> ProgressReporter for TcpEventManager<S> where
    S: UsesInput + HasExecutions + HasClientPerfMonitor + HasMetadata + HasLastReportTime
{
}

impl<S> HasEventManagerId for TcpEventManager<S>
where
    S: UsesInput,
{
    /// Gets the id assigned to this staterestorer.
    fn mgr_id(&self) -> EventManagerId {
        EventManagerId(self.client_id.0 as usize)
    }
}

/// A manager that can restart on the fly, storing states in-between (in `on_restart`)
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct TcpRestartingEventManager<S, SP>
where
    S: UsesInput,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    /// The embedded TCP event manager
    tcp_mgr: TcpEventManager<S>,
    /// The staterestorer to serialize the state for the next runner
    staterestorer: StateRestorer<SP>,
    /// Decide if the state restorer must save the serialized state
    save_state: bool,
}

#[cfg(feature = "std")]
impl<S, SP> UsesState for TcpRestartingEventManager<S, SP>
where
    S: UsesInput,
    SP: ShMemProvider + 'static,
{
    type State = S;
}

#[cfg(feature = "std")]
impl<S, SP> ProgressReporter for TcpRestartingEventManager<S, SP>
where
    S: UsesInput
        + HasExecutions
        + HasClientPerfMonitor
        + HasMetadata
        + HasLastReportTime
        + Serialize,
    SP: ShMemProvider,
{
}

#[cfg(feature = "std")]
impl<S, SP> EventFirer for TcpRestartingEventManager<S, SP>
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
        self.tcp_mgr.fire(state, event)
    }

    fn configuration(&self) -> EventConfig {
        self.tcp_mgr.configuration()
    }
}

#[cfg(feature = "std")]
impl<S, SP> EventRestarter for TcpRestartingEventManager<S, SP>
where
    S: UsesInput + HasExecutions + HasClientPerfMonitor + Serialize,
    SP: ShMemProvider,
    //CE: CustomEvent<I>,
{
    /// The tcp client needs to wait until a broker mapped all pages, before shutting down.
    /// Otherwise, the OS may already have removed the shared maps,
    #[inline]
    fn await_restart_safe(&mut self) {
        self.tcp_mgr.await_restart_safe();
    }

    /// Reset the single page (we reuse it over and over from pos 0), then send the current state to the next runner.
    fn on_restart(&mut self, state: &mut S) -> Result<(), Error> {
        // First, reset the page to 0 so the next iteration can read read from the beginning of this page
        self.staterestorer.reset();
        self.staterestorer.save(&if self.save_state {
            Some((state, self.tcp_mgr.client_id))
        } else {
            None
        })?;
        self.await_restart_safe();
        Ok(())
    }

    fn send_exiting(&mut self) -> Result<(), Error> {
        self.staterestorer.send_exiting();
        // Also inform the broker that we are about to exit.
        // This way, the broker can clean up the pages, and eventually exit.
        self.tcp_mgr.send_exiting()
    }
}

#[cfg(feature = "std")]
impl<E, S, SP, Z> EventProcessor<E, Z> for TcpRestartingEventManager<S, SP>
where
    E: HasObservers<State = S> + Executor<TcpEventManager<S>, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    S: UsesInput + HasExecutions + HasClientPerfMonitor,
    SP: ShMemProvider + 'static,
    Z: EvaluatorObservers<E::Observers, State = S> + ExecutionProcessor<E::Observers>, //CE: CustomEvent<I>,
{
    fn process(&mut self, fuzzer: &mut Z, state: &mut S, executor: &mut E) -> Result<usize, Error> {
        self.tcp_mgr.process(fuzzer, state, executor)
    }
}

#[cfg(feature = "std")]
impl<E, S, SP, Z> EventManager<E, Z> for TcpRestartingEventManager<S, SP>
where
    E: HasObservers<State = S> + Executor<TcpEventManager<S>, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    S: UsesInput
        + HasExecutions
        + HasClientPerfMonitor
        + HasMetadata
        + HasLastReportTime
        + Serialize,
    SP: ShMemProvider + 'static,
    Z: EvaluatorObservers<E::Observers, State = S> + ExecutionProcessor<E::Observers>, //CE: CustomEvent<I>,
{
}

#[cfg(feature = "std")]
impl<S, SP> HasEventManagerId for TcpRestartingEventManager<S, SP>
where
    S: UsesInput + Serialize,
    SP: ShMemProvider + 'static,
{
    fn mgr_id(&self) -> EventManagerId {
        self.tcp_mgr.mgr_id()
    }
}

/// The tcp connection from the actual fuzzer to the process supervising it
const _ENV_FUZZER_SENDER: &str = "_AFL_ENV_FUZZER_SENDER";
const _ENV_FUZZER_RECEIVER: &str = "_AFL_ENV_FUZZER_RECEIVER";
/// The tcp (2 way) connection from a fuzzer to the broker (broadcasting all other fuzzer messages)
const _ENV_FUZZER_BROKER_CLIENT_INITIAL: &str = "_AFL_ENV_FUZZER_BROKER_CLIENT";

#[cfg(feature = "std")]
impl<S, SP> TcpRestartingEventManager<S, SP>
where
    S: UsesInput,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    /// Create a new runner, the executed child doing the actual fuzzing.
    pub fn new(tcp_mgr: TcpEventManager<S>, staterestorer: StateRestorer<SP>) -> Self {
        Self {
            tcp_mgr,
            staterestorer,
            save_state: true,
        }
    }

    /// Create a new runner specifying if it must save the serialized state on restart.
    pub fn with_save_state(
        tcp_mgr: TcpEventManager<S>,
        staterestorer: StateRestorer<SP>,
        save_state: bool,
    ) -> Self {
        Self {
            tcp_mgr,
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
    /// A broker, forwarding all packets of local clients via TCP.
    Broker,
}

/// Sets up a restarting fuzzer, using the [`StdShMemProvider`], and standard features.
/// The restarting mgr is a combination of restarter and runner, that can be used on systems with and without `fork` support.
/// The restarter will spawn a new process each time the child crashes or timeouts.
#[cfg(feature = "std")]
#[allow(clippy::type_complexity)]
pub fn setup_restarting_mgr_tcp<MT, S>(
    monitor: MT,
    broker_port: u16,
    configuration: EventConfig,
) -> Result<(Option<S>, TcpRestartingEventManager<S, StdShMemProvider>), Error>
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
#[allow(clippy::default_trait_access, clippy::ignored_unit_patterns)]
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
    pub fn launch(&mut self) -> Result<(Option<S>, TcpRestartingEventManager<S, SP>), Error> {
        // We start ourself as child process to actually fuzz
        let (staterestorer, _new_shmem_provider, core_id) = if std::env::var(_ENV_FUZZER_SENDER)
            .is_err()
        {
            let broker_things = |mut broker: TcpEventBroker<S::Input, MT>, _remote_broker_addr| {
                if let Some(exit_cleanly_after) = self.exit_cleanly_after {
                    broker.set_exit_cleanly_after(exit_cleanly_after);
                }

                broker.broker_loop()
            };

            // We get here if we are on Unix, or we are a broker on Windows (or without forks).
            let (mgr, core_id) = match self.kind {
                ManagerKind::Any => {
                    let connection = create_nonblocking_listener(("127.0.0.1", self.broker_port));
                    match connection {
                        Ok(listener) => {
                            let event_broker = TcpEventBroker::<S::Input, MT>::with_listener(
                                listener,
                                self.monitor.take().unwrap(),
                            );

                            // Yep, broker. Just loop here.
                            log::info!(
                                "Doing broker things. Run this tool again to start fuzzing in a client."
                            );

                            broker_things(event_broker, self.remote_broker_addr)?;

                            return Err(Error::shutting_down());
                        }
                        Err(Error::File(_, _)) => {
                            // port was likely already bound
                            let mgr = TcpEventManager::<S>::new(
                                &("127.0.0.1", self.broker_port),
                                self.configuration,
                            )?;
                            (mgr, None)
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                ManagerKind::Broker => {
                    let event_broker = TcpEventBroker::<S::Input, MT>::new(
                        format!("127.0.0.1:{}", self.broker_port),
                        self.monitor.take().unwrap(),
                    )?;

                    broker_things(event_broker, self.remote_broker_addr)?;
                    unreachable!("The broker may never return normally, only on errors or when shutting down.");
                }
                ManagerKind::Client { cpu_core } => {
                    // We are a client
                    let mgr = TcpEventManager::<S>::on_port(self.broker_port, self.configuration)?;

                    (mgr, cpu_core)
                }
            };

            if let Some(core_id) = core_id {
                let core_id: CoreId = core_id;
                log::info!("Setting core affinity to {core_id:?}");
                core_id.set_affinity()?;
            }

            // We are the fuzzer respawner in a tcp client
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
                println!("Spawning next client (id {ctr}) {core_id:?}");

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
        let (state, mut mgr) = if let Some((state_opt, this_id)) = staterestorer.restore()? {
            (
                state_opt,
                TcpRestartingEventManager::with_save_state(
                    TcpEventManager::existing_on_port(
                        self.broker_port,
                        this_id,
                        self.configuration,
                    )?,
                    staterestorer,
                    self.serialize_state,
                ),
            )
        } else {
            log::info!("First run. Let's set it all up");
            // Mgr to send and receive msgs from/to all other fuzzer instances
            let mgr = TcpEventManager::<S>::existing_from_env(
                &("127.0.0.1", self.broker_port),
                _ENV_FUZZER_BROKER_CLIENT_INITIAL,
                self.configuration,
            )?;

            (
                None,
                TcpRestartingEventManager::with_save_state(
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
        staterestorer.send_buf(_TCP_TAG_NO_RESTART, []);
        */

        Ok((state, mgr))
    }
}
