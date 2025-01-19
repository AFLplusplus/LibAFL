//! An event manager that forwards all events to other attached fuzzers on shared maps or via tcp,
//! using low-level message passing, [`libafl_bolts::llmp`].

#[cfg(feature = "std")]
use alloc::string::ToString;
use alloc::vec::Vec;
use core::{marker::PhantomData, time::Duration};
#[cfg(feature = "std")]
use std::net::TcpStream;

#[cfg(feature = "std")]
use libafl_bolts::tuples::MatchNameRef;
#[cfg(feature = "llmp_compression")]
use libafl_bolts::{
    compress::GzipCompressor,
    llmp::{LLMP_FLAG_COMPRESSED, LLMP_FLAG_INITIALIZED},
};
use libafl_bolts::{
    current_time,
    llmp::{LlmpClient, LlmpClientDescription, LLMP_FLAG_FROM_MM},
    shmem::{NopShMemProvider, ShMemProvider},
    tuples::Handle,
    ClientId,
};
#[cfg(feature = "std")]
use libafl_bolts::{
    llmp::{recv_tcp_msg, send_tcp_msg, TcpRequest, TcpResponse},
    IP_LOCALHOST,
};
use serde::{de::DeserializeOwned, Serialize};

#[cfg(feature = "share_objectives")]
use crate::corpus::{Corpus, Testcase};
#[cfg(feature = "llmp_compression")]
use crate::events::llmp::COMPRESS_THRESHOLD;
#[cfg(feature = "std")]
use crate::events::{serialize_observers_adaptive, CanSerializeObserver};
use crate::{
    events::{
        llmp::{LLMP_TAG_EVENT_TO_BOTH, _LLMP_TAG_EVENT_TO_BROKER},
        std_maybe_report_progress, std_on_restart, std_report_progress, AdaptiveSerializer, Event,
        EventConfig, EventFirer, EventManagerHooksTuple, EventManagerId, EventProcessor,
        EventRestarter, HasEventManagerId, ManagerExit, ProgressReporter,
    },
    executors::HasObservers,
    fuzzer::{EvaluatorObservers, ExecutionProcessor},
    inputs::{Input, NopInput},
    observers::TimeObserver,
    stages::HasCurrentStageId,
    state::{
        HasCurrentTestcase, HasExecutions, HasImported, HasLastReportTime, HasSolutions,
        MaybeHasClientPerfMonitor, NopState, Stoppable,
    },
    Error, HasMetadata,
};

/// Default initial capacity of the event buffer - 4KB
const INITIAL_EVENT_BUFFER_SIZE: usize = 1024 * 4;

/// An `EventManager` that forwards all events to other attached fuzzers on shared maps or via tcp,
/// using low-level message passing, `llmp`.
pub struct LlmpEventManager<EMH, I, S, SP>
where
    SP: ShMemProvider,
{
    /// We only send 1 testcase for every `throttle` second
    pub(crate) throttle: Option<Duration>,
    /// We sent last message at `last_sent`
    last_sent: Duration,
    hooks: EMH,
    /// The LLMP client for inter process communication
    llmp: LlmpClient<SP>,
    #[cfg(feature = "llmp_compression")]
    compressor: GzipCompressor,
    /// The configuration defines this specific fuzzer.
    /// A node will not re-use the observer values sent over LLMP
    /// from nodes with other configurations.
    configuration: EventConfig,
    serialization_time: Duration,
    deserialization_time: Duration,
    serializations_cnt: usize,
    should_serialize_cnt: usize,
    pub(crate) time_ref: Option<Handle<TimeObserver>>,
    phantom: PhantomData<(I, S)>,
    event_buffer: Vec<u8>,
}

impl LlmpEventManager<(), NopState<NopInput>, NopInput, NopShMemProvider> {
    /// Creates a builder for [`LlmpEventManager`]
    #[must_use]
    pub fn builder() -> LlmpEventManagerBuilder<()> {
        LlmpEventManagerBuilder::new()
    }
}

/// Builder for `LlmpEventManager`
#[derive(Debug, Copy, Clone)]
pub struct LlmpEventManagerBuilder<EMH> {
    throttle: Option<Duration>,
    hooks: EMH,
}

impl Default for LlmpEventManagerBuilder<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl LlmpEventManagerBuilder<()> {
    /// Create a new `LlmpEventManagerBuilder`
    #[must_use]
    pub fn new() -> Self {
        Self {
            throttle: None,
            hooks: (),
        }
    }

    /// Add hooks to it
    pub fn hooks<EMH>(self, hooks: EMH) -> LlmpEventManagerBuilder<EMH> {
        LlmpEventManagerBuilder {
            throttle: self.throttle,
            hooks,
        }
    }
}

impl<EMH> LlmpEventManagerBuilder<EMH> {
    /// Change the sampling rate
    #[must_use]
    pub fn throttle(mut self, throttle: Duration) -> Self {
        self.throttle = Some(throttle);
        self
    }

    /// Create a manager from a raw LLMP client
    pub fn build_from_client<I, S, SP>(
        self,
        llmp: LlmpClient<SP>,
        configuration: EventConfig,
        time_ref: Option<Handle<TimeObserver>>,
    ) -> Result<LlmpEventManager<EMH, I, S, SP>, Error>
    where
        SP: ShMemProvider,
    {
        Ok(LlmpEventManager {
            throttle: self.throttle,
            last_sent: Duration::from_secs(0),
            hooks: self.hooks,
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
            event_buffer: Vec::with_capacity(INITIAL_EVENT_BUFFER_SIZE),
        })
    }

    /// Create an LLMP event manager on a port.
    /// It expects a broker to exist on this port.
    #[cfg(feature = "std")]
    pub fn build_on_port<I, S, SP>(
        self,
        shmem_provider: SP,
        port: u16,
        configuration: EventConfig,
        time_ref: Option<Handle<TimeObserver>>,
    ) -> Result<LlmpEventManager<EMH, I, S, SP>, Error>
    where
        SP: ShMemProvider,
    {
        let llmp = LlmpClient::create_attach_to_tcp(shmem_provider, port)?;
        Self::build_from_client(self, llmp, configuration, time_ref)
    }

    /// If a client respawns, it may reuse the existing connection, previously
    /// stored by [`LlmpClient::to_env()`].
    #[cfg(feature = "std")]
    pub fn build_existing_client_from_env<I, S, SP>(
        self,
        shmem_provider: SP,
        env_name: &str,
        configuration: EventConfig,
        time_ref: Option<Handle<TimeObserver>>,
    ) -> Result<LlmpEventManager<EMH, I, S, SP>, Error>
    where
        SP: ShMemProvider,
    {
        let llmp = LlmpClient::on_existing_from_env(shmem_provider, env_name)?;
        Self::build_from_client(self, llmp, configuration, time_ref)
    }

    /// Create an existing client from description
    pub fn build_existing_client_from_description<I, S, SP>(
        self,
        shmem_provider: SP,
        description: &LlmpClientDescription,
        configuration: EventConfig,
        time_ref: Option<Handle<TimeObserver>>,
    ) -> Result<LlmpEventManager<EMH, I, S, SP>, Error>
    where
        SP: ShMemProvider,
    {
        let llmp = LlmpClient::existing_client_from_description(shmem_provider, description)?;
        Self::build_from_client(self, llmp, configuration, time_ref)
    }
}

#[cfg(feature = "std")]
impl<EMH, I, OT, S, SP> CanSerializeObserver<OT> for LlmpEventManager<EMH, I, S, SP>
where
    SP: ShMemProvider,
    OT: Serialize + MatchNameRef,
{
    fn serialize_observers(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error> {
        serialize_observers_adaptive::<Self, OT>(self, observers, 2, 80)
    }
}

impl<EMH, I, S, SP> AdaptiveSerializer for LlmpEventManager<EMH, I, S, SP>
where
    SP: ShMemProvider,
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

    fn time_ref(&self) -> &Option<Handle<TimeObserver>> {
        &self.time_ref
    }
}

impl<EMH, I, S, SP> core::fmt::Debug for LlmpEventManager<EMH, I, S, SP>
where
    SP: ShMemProvider,
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

impl<EMH, I, S, SP> Drop for LlmpEventManager<EMH, I, S, SP>
where
    SP: ShMemProvider,
{
    /// LLMP clients will have to wait until their pages are mapped by somebody.
    fn drop(&mut self) {
        self.await_restart_safe();
    }
}

impl<EMH, I, S, SP> LlmpEventManager<EMH, I, S, SP>
where
    SP: ShMemProvider,
{
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
            Ok(()) => (),
            Err(e) => log::error!("Failed to send tcp message {:#?}", e),
        }
        log::debug!("Asking he broker to be disconnected");
        Ok(())
    }

    /// Describe the client event manager's LLMP parts in a restorable fashion
    pub fn describe(&self) -> Result<LlmpClientDescription, Error> {
        self.llmp.describe()
    }

    /// Write the config for a client `EventManager` to env vars, a new
    /// client can reattach using [`LlmpEventManagerBuilder::build_existing_client_from_env()`].
    #[cfg(feature = "std")]
    pub fn to_env(&self, env_name: &str) {
        self.llmp.to_env(env_name).unwrap();
    }
}

impl<EMH, I, S, SP> LlmpEventManager<EMH, I, S, SP>
where
    SP: ShMemProvider,
{
    // Handle arriving events in the client
    fn handle_in_client<E, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        client_id: ClientId,
        event: Event<I>,
    ) -> Result<(), Error>
    where
        S: HasImported + HasSolutions<I> + HasCurrentTestcase<I> + Stoppable,
        EMH: EventManagerHooksTuple<I, S>,
        I: Input,
        E: HasObservers,
        E::Observers: DeserializeOwned,
        Z: ExecutionProcessor<Self, I, E::Observers, S> + EvaluatorObservers<E, Self, I, S>,
    {
        log::trace!("Got event in client: {} from {client_id:?}", event.name());
        if !self.hooks.pre_exec_all(state, client_id, &event)? {
            return Ok(());
        }
        let evt_name = event.name_detailed();
        match event {
            Event::NewTestcase {
                input,
                client_config,
                exit_kind,
                observers_buf,
                #[cfg(feature = "std")]
                forward_id,
                ..
            } => {
                #[cfg(feature = "std")]
                log::debug!("[{}] Received new Testcase {evt_name} from {client_id:?} ({client_config:?}, forward {forward_id:?})", std::process::id());

                let res = if client_config.match_with(&self.configuration)
                    && observers_buf.is_some()
                {
                    let start = current_time();
                    let observers: E::Observers =
                        postcard::from_bytes(observers_buf.as_ref().unwrap())?;
                    {
                        self.deserialization_time = current_time() - start;
                    }
                    fuzzer.evaluate_execution(state, self, input, &observers, &exit_kind, false)?
                } else {
                    fuzzer.evaluate_input_with_observers(state, executor, self, input, false)?
                };
                if let Some(item) = res.1 {
                    *state.imported_mut() += 1;
                    log::debug!("Added received Testcase {evt_name} as item #{item}");
                } else {
                    log::debug!("Testcase {evt_name} was discarded");
                }
            }

            #[cfg(feature = "share_objectives")]
            Event::Objective { input, .. } => {
                log::debug!("Received new Objective");
                let mut testcase = Testcase::from(input);
                testcase.set_parent_id_optional(*state.corpus().current());

                if let Ok(mut tc) = state.current_testcase_mut() {
                    tc.found_objective();
                }

                state.solutions_mut().add(testcase)?;
                log::info!("Added received Objective to Corpus");
            }
            Event::Stop => {
                state.request_stop();
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

impl<EMH, I, S, SP: ShMemProvider> LlmpEventManager<EMH, I, S, SP> {
    /// Send information that this client is exiting.
    /// The other side may free up all allocated memory.
    /// We are no longer allowed to send anything afterwards.
    pub fn send_exiting(&mut self) -> Result<(), Error> {
        self.llmp.sender_mut().send_exiting()
    }
}

impl<EMH, I, S, SP> EventFirer<I, S> for LlmpEventManager<EMH, I, S, SP>
where
    I: Serialize,
    SP: ShMemProvider,
{
    fn should_send(&self) -> bool {
        if let Some(throttle) = self.throttle {
            current_time() - self.last_sent > throttle
        } else {
            true
        }
    }
    fn fire(&mut self, _state: &mut S, event: Event<I>) -> Result<(), Error> {
        #[cfg(feature = "llmp_compression")]
        let flags = LLMP_FLAG_INITIALIZED;

        self.event_buffer.resize(self.event_buffer.capacity(), 0);

        // Serialize the event, reallocating event_buffer if needed
        let written_len = match postcard::to_slice(&event, &mut self.event_buffer) {
            Ok(written) => written.len(),
            Err(postcard::Error::SerializeBufferFull) => {
                let serialized = postcard::to_allocvec(&event)?;
                self.event_buffer = serialized;
                self.event_buffer.len()
            }
            Err(e) => return Err(Error::from(e)),
        };

        #[cfg(feature = "llmp_compression")]
        {
            match self
                .compressor
                .maybe_compress(&self.event_buffer[..written_len])
            {
                Some(comp_buf) => {
                    self.llmp.send_buf_with_flags(
                        LLMP_TAG_EVENT_TO_BOTH,
                        flags | LLMP_FLAG_COMPRESSED,
                        &comp_buf,
                    )?;
                }
                None => {
                    self.llmp
                        .send_buf(LLMP_TAG_EVENT_TO_BOTH, &self.event_buffer[..written_len])?;
                }
            }
        }

        #[cfg(not(feature = "llmp_compression"))]
        {
            self.llmp
                .send_buf(LLMP_TAG_EVENT_TO_BOTH, &self.event_buffer[..written_len])?;
        }

        self.last_sent = current_time();
        Ok(())
    }

    fn configuration(&self) -> EventConfig {
        self.configuration
    }
}

impl<EMH, I, S, SP> EventRestarter<S> for LlmpEventManager<EMH, I, S, SP>
where
    SP: ShMemProvider,
    S: HasCurrentStageId,
{
    fn on_restart(&mut self, state: &mut S) -> Result<(), Error> {
        std_on_restart(self, state)
    }
}

impl<EMH, I, S, SP> ManagerExit for LlmpEventManager<EMH, I, S, SP>
where
    SP: ShMemProvider,
{
    /// The LLMP client needs to wait until a broker has mapped all pages before shutting down.
    /// Otherwise, the OS may already have removed the shared maps.
    fn await_restart_safe(&mut self) {
        // wait until we can drop the message safely.
        self.llmp.await_safe_to_unmap_blocking();
    }

    fn send_exiting(&mut self) -> Result<(), Error> {
        self.llmp.sender_mut().send_exiting()
    }
}

impl<E, EMH, I, S, SP, Z> EventProcessor<E, S, Z> for LlmpEventManager<EMH, I, S, SP>
where
    E: HasObservers,
    E::Observers: DeserializeOwned,
    S: HasImported + HasSolutions<I> + HasCurrentTestcase<I> + Stoppable,
    EMH: EventManagerHooksTuple<I, S>,
    I: DeserializeOwned + Input,
    SP: ShMemProvider,
    Z: ExecutionProcessor<Self, I, E::Observers, S> + EvaluatorObservers<E, Self, I, S>,
{
    fn process(&mut self, fuzzer: &mut Z, state: &mut S, executor: &mut E) -> Result<usize, Error> {
        // TODO: Get around local event copy by moving handle_in_client
        let self_id = self.llmp.sender().id();
        let mut count = 0;
        while let Some((client_id, tag, flags, msg)) = self.llmp.recv_buf_with_flags()? {
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
            let event_bytes = if flags & LLMP_FLAG_COMPRESSED == LLMP_FLAG_COMPRESSED {
                compressed = self.compressor.decompress(msg)?;
                &compressed
            } else {
                msg
            };
            let event: Event<I> = postcard::from_bytes(event_bytes)?;
            log::debug!("Received event in normal llmp {}", event.name_detailed());

            // If the message comes from another machine, do not
            // consider other events than new testcase.
            if !event.is_new_testcase() && (flags & LLMP_FLAG_FROM_MM == LLMP_FLAG_FROM_MM) {
                continue;
            }

            self.handle_in_client(fuzzer, executor, state, client_id, event)?;
            count += 1;
        }
        Ok(count)
    }

    fn on_shutdown(&mut self) -> Result<(), Error> {
        self.send_exiting()
    }
}

impl<EMH, I, S, SP> ProgressReporter<S> for LlmpEventManager<EMH, I, S, SP>
where
    S: HasExecutions + HasLastReportTime + HasMetadata + MaybeHasClientPerfMonitor,
    SP: ShMemProvider,
    I: Serialize,
{
    fn maybe_report_progress(
        &mut self,
        state: &mut S,
        monitor_timeout: Duration,
    ) -> Result<(), Error> {
        std_maybe_report_progress(self, state, monitor_timeout)
    }

    fn report_progress(&mut self, state: &mut S) -> Result<(), Error> {
        std_report_progress(self, state)
    }
}

impl<EMH, I, S, SP> HasEventManagerId for LlmpEventManager<EMH, I, S, SP>
where
    SP: ShMemProvider,
{
    /// Gets the id assigned to this staterestorer.
    fn mgr_id(&self) -> EventManagerId {
        EventManagerId(self.llmp.sender().id().0 as usize)
    }
}
