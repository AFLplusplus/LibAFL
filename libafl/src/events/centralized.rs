//! Centralized event manager is a special event manager that will be used to achieve a more efficient message passing architecture.

// Some technical details..
// A very standard multi-process fuzzing using centralized event manager will consist of 4 components
// 1. The "fuzzer clients", the fuzzer that will do the "normal" fuzzing
// 2. The "centralized broker, the broker that gathers all the testcases from all the fuzzer clients
// 3. The "main evaluator", the evaluator node that will evaluate all the testcases pass by the centralized event manager to see if the testcases are worth propagating
// 4. The "main broker", the gathers the stats from the fuzzer clients and broadcast the newly found testcases from the main evaluator.

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{marker::PhantomData, num::NonZeroUsize, time::Duration};

#[cfg(feature = "adaptive_serialization")]
use libafl_bolts::current_time;
#[cfg(feature = "llmp_compression")]
use libafl_bolts::{
    compress::GzipCompressor,
    llmp::{LLMP_FLAG_COMPRESSED, LLMP_FLAG_INITIALIZED},
};
use libafl_bolts::{
    llmp::{self, LlmpBroker, LlmpClient, LlmpClientDescription, Tag},
    shmem::ShMemProvider,
    ClientId,
};
use serde::{Deserialize, Serialize};

use super::{CustomBufEventResult, HasCustomBufHandlers, ProgressReporter};
#[cfg(feature = "llmp_compression")]
use crate::events::llmp::COMPRESS_THRESHOLD;
#[cfg(feature = "scalability_introspection")]
use crate::state::HasScalabilityMonitor;
use crate::{
    events::{
        llmp::EventStatsCollector, BrokerEventResult, Event, EventConfig, EventFirer, EventManager,
        EventManagerId, EventProcessor, EventRestarter, HasEventManagerId, LogSeverity,
    },
    executors::{Executor, HasObservers},
    fuzzer::{EvaluatorObservers, ExecutionProcessor},
    inputs::{Input, UsesInput},
    observers::ObserversTuple,
    state::{HasExecutions, HasLastReportTime, HasMetadata, UsesState},
    Error,
};

const _LLMP_TAG_TO_MAIN: Tag = Tag(0x3453453);

/// An LLMP-backed event manager for scalable multi-processed fuzzing
pub struct CentralizedLlmpEventBroker<I, SP>
where
    I: Input,
    SP: ShMemProvider + 'static,
    //CE: CustomEvent<I>,
{
    llmp: LlmpBroker<SP>,
    #[cfg(feature = "llmp_compression")]
    compressor: GzipCompressor,
    phantom: PhantomData<I>,
}

impl<I, SP> core::fmt::Debug for CentralizedLlmpEventBroker<I, SP>
where
    SP: ShMemProvider + 'static,
    I: Input,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_struct = f.debug_struct("CentralizedLlmpEventBroker");
        let debug = debug_struct.field("llmp", &self.llmp);
        //.field("custom_buf_handlers", &self.custom_buf_handlers)
        #[cfg(feature = "llmp_compression")]
        let debug = debug.field("compressor", &self.compressor);
        debug
            .field("phantom", &self.phantom)
            .finish_non_exhaustive()
    }
}

impl<I, SP> CentralizedLlmpEventBroker<I, SP>
where
    I: Input,
    SP: ShMemProvider + 'static,
{
    /// Create an event broker from a raw broker.
    pub fn new(llmp: LlmpBroker<SP>) -> Result<Self, Error> {
        Ok(Self {
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
    pub fn on_port(shmem_provider: SP, port: u16, client_timeout: Duration) -> Result<Self, Error> {
        Ok(Self {
            // TODO switch to false after solving the bug
            llmp: LlmpBroker::with_keep_pages_attach_to_tcp(
                shmem_provider,
                port,
                true,
                client_timeout,
            )?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            phantom: PhantomData,
        })
    }

    /// Exit the broker process cleanly after at least `n` clients attached and all of them disconnected again
    pub fn set_exit_cleanly_after(&mut self, n_clients: NonZeroUsize) {
        self.llmp.set_exit_cleanly_after(n_clients);
    }

    /// Run forever in the broker
    #[cfg(not(feature = "llmp_broker_timeouts"))]
    pub fn broker_loop(&mut self) -> Result<(), Error> {
        #[cfg(feature = "llmp_compression")]
        let compressor = &self.compressor;
        self.llmp.loop_forever(
            &mut |client_id, tag, _flags, msg| {
                if tag == _LLMP_TAG_TO_MAIN {
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
                    match Self::handle_in_broker(client_id, &event)? {
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
        #[cfg(feature = "llmp_compression")]
        let compressor = &self.compressor;
        self.llmp.loop_with_timeouts(
            &mut |msg_or_timeout| {
                if let Some((client_id, tag, _flags, msg)) = msg_or_timeout {
                    if tag == _LLMP_TAG_TO_MAIN {
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
                        match Self::handle_in_broker(client_id, &event)? {
                            BrokerEventResult::Forward => {
                                Ok(llmp::LlmpMsgHookResult::ForwardToClients)
                            }
                            BrokerEventResult::Handled => Ok(llmp::LlmpMsgHookResult::Handled),
                        }
                    } else {
                        Ok(llmp::LlmpMsgHookResult::ForwardToClients)
                    }
                } else {
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

/// A wrapper manager to implement a main-secondary architecture witgh another broker
#[derive(Debug)]
pub struct CentralizedEventManager<EM, SP>
where
    EM: UsesState,
    SP: ShMemProvider + 'static,
{
    inner: EM,
    /// The LLMP client for inter process communication
    client: LlmpClient<SP>,
    #[cfg(feature = "llmp_compression")]
    compressor: GzipCompressor,
    is_main: bool,
}

impl<EM, SP> UsesState for CentralizedEventManager<EM, SP>
where
    EM: UsesState,
    SP: ShMemProvider + 'static,
{
    type State = EM::State;
}

#[cfg(feature = "adaptive_serialization")]
impl<EM, SP> EventStatsCollector for CentralizedEventManager<EM, SP>
where
    EM: EventStatsCollector + UsesState,
    SP: ShMemProvider + 'static,
{
    fn serialization_time(&self) -> Duration {
        self.inner.serialization_time()
    }
    fn deserialization_time(&self) -> Duration {
        self.inner.deserialization_time()
    }
    fn serializations_cnt(&self) -> usize {
        self.inner.serializations_cnt()
    }
    fn should_serialize_cnt(&self) -> usize {
        self.inner.should_serialize_cnt()
    }

    fn serialization_time_mut(&mut self) -> &mut Duration {
        self.inner.serialization_time_mut()
    }
    fn deserialization_time_mut(&mut self) -> &mut Duration {
        self.inner.deserialization_time_mut()
    }
    fn serializations_cnt_mut(&mut self) -> &mut usize {
        self.inner.serializations_cnt_mut()
    }
    fn should_serialize_cnt_mut(&mut self) -> &mut usize {
        self.inner.should_serialize_cnt_mut()
    }
}

#[cfg(not(feature = "adaptive_serialization"))]
impl<EM, SP> EventStatsCollector for CentralizedEventManager<EM, SP>
where
    EM: EventStatsCollector + UsesState,
    SP: ShMemProvider + 'static,
{
}

impl<EM, SP> EventFirer for CentralizedEventManager<EM, SP>
where
    EM: EventStatsCollector + EventFirer + HasEventManagerId,
    SP: ShMemProvider + 'static,
{
    fn fire(
        &mut self,
        state: &mut Self::State,
        mut event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        if !self.is_main {
            // secondary node
            let is_nt_or_heartbeat = match &mut event {
                Event::NewTestcase {
                    input: _,
                    client_config: _,
                    exit_kind: _,
                    corpus_size: _,
                    time: _,
                    executions: _,
                    observers_buf: _,
                    forward_id,
                } => {
                    *forward_id = Some(ClientId(self.inner.mgr_id().0 as u32));
                    true
                }
                Event::UpdateExecStats {
                    time: _,
                    executions: _,
                    phantom: _,
                } => true,
                _ => false,
            };
            if is_nt_or_heartbeat {
                return self.forward_to_main(&event);
            }
        }
        self.inner.fire(state, event)
    }

    fn log(
        &mut self,
        state: &mut Self::State,
        severity_level: LogSeverity,
        message: String,
    ) -> Result<(), Error> {
        self.inner.log(state, severity_level, message)
    }

    #[cfg(not(feature = "adaptive_serialization"))]
    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error>
    where
        OT: ObserversTuple<Self::State> + Serialize,
    {
        self.inner.serialize_observers(observers)
    }

    #[cfg(feature = "adaptive_serialization")]
    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error>
    where
        OT: ObserversTuple<Self::State> + Serialize,
    {
        const SERIALIZE_TIME_FACTOR: u32 = 4;
        const SERIALIZE_PERCENTAGE_TRESHOLD: usize = 80;

        let exec_time = observers
            .match_name::<crate::observers::TimeObserver>("time")
            .map(|o| o.last_runtime().unwrap_or(Duration::ZERO))
            .unwrap();

        let mut must_ser = (self.serialization_time() + self.deserialization_time())
            * SERIALIZE_TIME_FACTOR
            < exec_time;
        if must_ser {
            *self.should_serialize_cnt_mut() += 1;
        }

        if self.serializations_cnt() > 32 {
            must_ser = (self.should_serialize_cnt() * 100 / self.serializations_cnt())
                > SERIALIZE_PERCENTAGE_TRESHOLD;
        }

        if self.inner.serialization_time() == Duration::ZERO
            || must_ser
            || self.serializations_cnt().trailing_zeros() >= 8
        {
            let start = current_time();
            let ser = postcard::to_allocvec(observers)?;
            *self.inner.serialization_time_mut() = current_time() - start;

            *self.serializations_cnt_mut() += 1;
            Ok(Some(ser))
        } else {
            *self.serializations_cnt_mut() += 1;
            Ok(None)
        }
    }

    fn configuration(&self) -> EventConfig {
        self.inner.configuration()
    }
}

impl<EM, SP> EventRestarter for CentralizedEventManager<EM, SP>
where
    EM: EventRestarter,
    SP: ShMemProvider + 'static,
{
    #[inline]
    fn on_restart(&mut self, state: &mut Self::State) -> Result<(), Error> {
        self.client.await_safe_to_unmap_blocking();
        self.inner.on_restart(state)?;
        Ok(())
    }

    fn send_exiting(&mut self) -> Result<(), Error> {
        self.client.sender_mut().send_exiting()?;
        self.inner.send_exiting()
    }

    #[inline]
    fn await_restart_safe(&mut self) {
        self.client.await_safe_to_unmap_blocking();
        self.inner.await_restart_safe();
    }
}

impl<E, EM, SP, Z> EventProcessor<E, Z> for CentralizedEventManager<EM, SP>
where
    EM: EventStatsCollector + EventProcessor<E, Z> + EventFirer + HasEventManagerId,
    E: HasObservers<State = Self::State> + Executor<Self, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    Z: EvaluatorObservers<E::Observers, State = Self::State>
        + ExecutionProcessor<E::Observers, State = Self::State>,
    Self::State: HasExecutions + HasMetadata,
    SP: ShMemProvider + 'static,
{
    fn process(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        executor: &mut E,
    ) -> Result<usize, Error> {
        if self.is_main {
            // main node
            self.receive_from_secondary(fuzzer, state, executor)
        } else {
            // The main node does not process incoming events from the broker ATM
            self.inner.process(fuzzer, state, executor)
        }
    }
}

impl<E, EM, SP, Z> EventManager<E, Z> for CentralizedEventManager<EM, SP>
where
    EM: EventStatsCollector + EventManager<E, Z>,
    EM::State: HasExecutions + HasMetadata + HasLastReportTime,
    E: HasObservers<State = Self::State> + Executor<Self, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    Z: EvaluatorObservers<E::Observers, State = Self::State>
        + ExecutionProcessor<E::Observers, State = Self::State>,
    SP: ShMemProvider + 'static,
{
}

impl<EM, SP> HasCustomBufHandlers for CentralizedEventManager<EM, SP>
where
    EM: HasCustomBufHandlers,
    SP: ShMemProvider + 'static,
{
    /// Adds a custom buffer handler that will run for each incoming `CustomBuf` event.
    fn add_custom_buf_handler(
        &mut self,
        handler: Box<
            dyn FnMut(&mut Self::State, &str, &[u8]) -> Result<CustomBufEventResult, Error>,
        >,
    ) {
        self.inner.add_custom_buf_handler(handler);
    }
}

impl<EM, SP> ProgressReporter for CentralizedEventManager<EM, SP>
where
    EM: EventStatsCollector + ProgressReporter + HasEventManagerId,
    EM::State: HasMetadata + HasExecutions + HasLastReportTime,
    SP: ShMemProvider + 'static,
{
}

impl<EM, SP> HasEventManagerId for CentralizedEventManager<EM, SP>
where
    EM: HasEventManagerId + UsesState,
    SP: ShMemProvider + 'static,
{
    fn mgr_id(&self) -> EventManagerId {
        self.inner.mgr_id()
    }
}

impl<EM, SP> CentralizedEventManager<EM, SP>
where
    EM: UsesState,
    SP: ShMemProvider + 'static,
{
    /// Creates a new [`CentralizedEventManager`].
    pub fn new(inner: EM, client: LlmpClient<SP>, is_main: bool) -> Result<Self, Error> {
        Ok(Self {
            inner,
            client,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            is_main,
        })
    }

    /// Create a centralized event manager on a port
    ///
    /// If the port is not yet bound, it will act as a broker; otherwise, it
    /// will act as a client.
    #[cfg(feature = "std")]
    pub fn on_port(inner: EM, shmem_provider: SP, port: u16, is_main: bool) -> Result<Self, Error> {
        Ok(Self {
            inner,
            client: LlmpClient::create_attach_to_tcp(shmem_provider, port)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            is_main,
        })
    }

    /// If a client respawns, it may reuse the existing connection, previously
    /// stored by [`LlmpClient::to_env()`].
    #[cfg(feature = "std")]
    pub fn existing_client_from_env(
        inner: EM,
        shmem_provider: SP,
        env_name: &str,
        is_main: bool,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner,
            client: LlmpClient::on_existing_from_env(shmem_provider, env_name)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            is_main,
        })
    }

    /// Describe the client event manager's LLMP parts in a restorable fashion
    pub fn describe(&self) -> Result<LlmpClientDescription, Error> {
        self.client.describe()
    }

    /// Create an existing client from description
    pub fn existing_client_from_description(
        inner: EM,
        shmem_provider: SP,
        description: &LlmpClientDescription,
        is_main: bool,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner,
            client: LlmpClient::existing_client_from_description(shmem_provider, description)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(COMPRESS_THRESHOLD),
            is_main,
        })
    }

    /// Write the config for a client [`EventManager`] to env vars, a new
    /// client can reattach using [`CentralizedEventManager::existing_client_from_env()`].
    #[cfg(feature = "std")]
    pub fn to_env(&self, env_name: &str) {
        self.client.to_env(env_name).unwrap();
    }

    /// Know if this instance is main or secondary
    pub fn is_main(&self) -> bool {
        self.is_main
    }
}

impl<EM, SP> CentralizedEventManager<EM, SP>
where
    EM: UsesState + EventFirer + EventStatsCollector + HasEventManagerId,
    SP: ShMemProvider + 'static,
{
    #[cfg(feature = "llmp_compression")]
    fn forward_to_main<I>(&mut self, event: &Event<I>) -> Result<(), Error>
    where
        I: Input,
    {
        let serialized = postcard::to_allocvec(event)?;
        let flags = LLMP_FLAG_INITIALIZED;

        match self.compressor.compress(&serialized)? {
            Some(comp_buf) => {
                self.client.send_buf_with_flags(
                    _LLMP_TAG_TO_MAIN,
                    flags | LLMP_FLAG_COMPRESSED,
                    &comp_buf,
                )?;
            }
            None => {
                self.client.send_buf(_LLMP_TAG_TO_MAIN, &serialized)?;
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "llmp_compression"))]
    fn forward_to_main<I>(&mut self, event: &Event<I>) -> Result<(), Error>
    where
        I: Input,
    {
        let serialized = postcard::to_allocvec(event)?;
        self.client.send_buf(_LLMP_TAG_TO_MAIN, &serialized)?;
        Ok(())
    }

    fn receive_from_secondary<E, Z>(
        &mut self,
        fuzzer: &mut Z,
        state: &mut EM::State,
        executor: &mut E,
    ) -> Result<usize, Error>
    where
        E: Executor<Self, Z> + HasObservers<State = EM::State>,
        EM::State: UsesInput + HasExecutions + HasMetadata,
        for<'a> E::Observers: Deserialize<'a>,
        Z: ExecutionProcessor<E::Observers, State = EM::State> + EvaluatorObservers<E::Observers>,
    {
        // TODO: Get around local event copy by moving handle_in_client
        let self_id = self.client.sender().id();
        let mut count = 0;
        while let Some((client_id, tag, _flags, msg)) = self.client.recv_buf_with_flags()? {
            assert!(
                tag == _LLMP_TAG_TO_MAIN,
                "Only _LLMP_TAG_TO_MAIN parcel should have arrived in the main node!"
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
            let event: Event<<<EM as UsesState>::State as UsesInput>::Input> =
                postcard::from_bytes(event_bytes)?;
            self.handle_in_main(fuzzer, executor, state, client_id, event)?;
            count += 1;
        }
        Ok(count)
    }

    // Handle arriving events in the main node
    fn handle_in_main<E, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut EM::State,
        client_id: ClientId,
        event: Event<<EM::State as UsesInput>::Input>,
    ) -> Result<(), Error>
    where
        E: Executor<Self, Z> + HasObservers<State = EM::State>,
        EM::State: UsesInput + HasExecutions + HasMetadata,
        for<'a> E::Observers: Deserialize<'a>,
        Z: ExecutionProcessor<E::Observers, State = EM::State> + EvaluatorObservers<E::Observers>,
    {
        match event {
            Event::NewTestcase {
                input,
                client_config,
                exit_kind,
                corpus_size,
                observers_buf,
                time,
                executions,
                forward_id,
            } => {
                log::info!("Received new Testcase from {client_id:?} ({client_config:?}, forward {forward_id:?})");

                let res =
                    if client_config.match_with(&self.configuration()) && observers_buf.is_some() {
                        let observers: E::Observers =
                            postcard::from_bytes(observers_buf.as_ref().unwrap())?;
                        #[cfg(feature = "scalability_introspection")]
                        {
                            state.scalability_monitor_mut().testcase_with_observers += 1;
                        }
                        fuzzer.process_execution(
                            state,
                            self,
                            input.clone(),
                            &observers,
                            &exit_kind,
                            false,
                        )?
                    } else {
                        #[cfg(feature = "scalability_introspection")]
                        {
                            state.scalability_monitor_mut().testcase_without_observers += 1;
                        }
                        fuzzer.evaluate_input_with_observers::<E, Self>(
                            state,
                            executor,
                            self,
                            input.clone(),
                            false,
                        )?
                    };

                if let Some(item) = res.1 {
                    if res.1.is_some() {
                        self.inner.fire(
                            state,
                            Event::NewTestcase {
                                input,
                                client_config,
                                exit_kind,
                                corpus_size,
                                observers_buf,
                                time,
                                executions,
                                forward_id,
                            },
                        )?;
                    }
                    log::info!("Added received Testcase as item #{item}");
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

/*
impl<EM, SP> Drop for CentralizedEventManager<EM, SP>
where
    EM: UsesState,    SP: ShMemProvider + 'static,
{
    /// LLMP clients will have to wait until their pages are mapped by somebody.
    fn drop(&mut self) {
        self.await_restart_safe();
    }
}*/
