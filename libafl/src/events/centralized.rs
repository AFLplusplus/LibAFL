//! Centralized event manager is a special event manager that will be used to achieve a more efficient message passing architecture.

// Some technical details..
// A very standard multi-process fuzzing using centralized event manager will consist of 4 components
// 1. The "fuzzer clients", the fuzzer that will do the "normal" fuzzing
// 2. The "centralized broker, the broker that gathers all the testcases from all the fuzzer clients
// 3. The "main evaluator", the evaluator node that will evaluate all the testcases pass by the centralized event manager to see if the testcases are worth propagating
// 4. The "main broker", the gathers the stats from the fuzzer clients and broadcast the newly found testcases from the main evaluator.

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{fmt::Debug, time::Duration};
use std::{marker::PhantomData, process};

#[cfg(feature = "llmp_compression")]
use libafl_bolts::{
    compress::GzipCompressor,
    llmp::{LLMP_FLAG_COMPRESSED, LLMP_FLAG_INITIALIZED},
};
use libafl_bolts::{
    llmp::{LlmpClient, LlmpClientDescription, Tag},
    shmem::{NopShMemProvider, ShMemProvider},
    tuples::Handle,
    ClientId,
};
use serde::{Deserialize, Serialize};

use super::NopEventManager;
#[cfg(feature = "llmp_compression")]
use crate::events::llmp::COMPRESS_THRESHOLD;
#[cfg(feature = "scalability_introspection")]
use crate::state::HasScalabilityMonitor;
use crate::{
    events::{
        AdaptiveSerializer, CustomBufEventResult, Event, EventConfig, EventFirer, EventManager,
        EventManagerHooksTuple, EventManagerId, EventProcessor, EventRestarter,
        HasCustomBufHandlers, HasEventManagerId, LogSeverity, ProgressReporter,
    },
    executors::{Executor, HasObservers},
    fuzzer::{EvaluatorObservers, ExecutionProcessor},
    inputs::{Input, NopInput, UsesInput},
    observers::{ObserversTuple, TimeObserver},
    state::{HasExecutions, HasLastReportTime, NopState, State, Stoppable, UsesState},
    Error, HasMetadata,
};

pub(crate) const _LLMP_TAG_TO_MAIN: Tag = Tag(0x3453453);

/// A wrapper manager to implement a main-secondary architecture with another broker
#[derive(Debug)]
pub struct CentralizedEventManager<EM, EMH, S, SP>
where
    EM: UsesState,
    EMH: EventManagerHooksTuple<EM::State>,
    S: State,
    SP: ShMemProvider,
{
    inner: EM,
    /// The centralized LLMP client for inter process communication
    client: LlmpClient<SP>,
    #[cfg(feature = "llmp_compression")]
    compressor: GzipCompressor,
    time_ref: Option<Handle<TimeObserver>>,
    hooks: EMH,
    is_main: bool,
    phantom: PhantomData<S>,
}

impl
    CentralizedEventManager<
        NopEventManager<NopState<NopInput>>,
        (),
        NopState<NopInput>,
        NopShMemProvider,
    >
{
    /// Creates a builder for [`CentralizedEventManager`]
    #[must_use]
    pub fn builder() -> CentralizedEventManagerBuilder {
        CentralizedEventManagerBuilder::new()
    }
}

/// The builder or `CentralizedEventManager`
#[derive(Debug)]
pub struct CentralizedEventManagerBuilder {
    is_main: bool,
}

impl Default for CentralizedEventManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CentralizedEventManagerBuilder {
    /// The constructor
    #[must_use]
    pub fn new() -> Self {
        Self { is_main: false }
    }

    /// Make this a main evaluator node
    #[must_use]
    pub fn is_main(self, is_main: bool) -> Self {
        Self { is_main }
    }

    /// Creates a new [`CentralizedEventManager`].
    pub fn build_from_client<EM, EMH, S, SP>(
        self,
        inner: EM,
        hooks: EMH,
        client: LlmpClient<SP>,
        time_obs: Option<Handle<TimeObserver>>,
    ) -> Result<CentralizedEventManager<EM, EMH, S, SP>, Error>
    where
        EM: UsesState,
        EMH: EventManagerHooksTuple<EM::State>,
        S: State,
        SP: ShMemProvider,
    {
        Ok(CentralizedEventManager {
            inner,
            hooks,
            client,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
            time_ref: time_obs,
            is_main: self.is_main,
            phantom: PhantomData,
        })
    }

    /// Create a centralized event manager on a port
    ///
    /// If the port is not yet bound, it will act as a broker; otherwise, it
    /// will act as a client.
    #[cfg(feature = "std")]
    pub fn build_on_port<EM, EMH, S, SP>(
        self,
        inner: EM,
        hooks: EMH,
        shmem_provider: SP,
        port: u16,
        time_obs: Option<Handle<TimeObserver>>,
    ) -> Result<CentralizedEventManager<EM, EMH, S, SP>, Error>
    where
        EM: UsesState,
        EMH: EventManagerHooksTuple<EM::State>,
        S: State,
        SP: ShMemProvider,
    {
        let client = LlmpClient::create_attach_to_tcp(shmem_provider, port)?;
        Ok(CentralizedEventManager {
            inner,
            hooks,
            client,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
            time_ref: time_obs,
            is_main: self.is_main,
            phantom: PhantomData,
        })
    }

    /// If a client respawns, it may reuse the existing connection, previously
    /// stored by [`LlmpClient::to_env()`].
    #[cfg(feature = "std")]
    pub fn build_existing_client_from_env<EM, EMH, S, SP>(
        self,
        inner: EM,
        hooks: EMH,
        shmem_provider: SP,
        env_name: &str,
        time_obs: Option<Handle<TimeObserver>>,
    ) -> Result<CentralizedEventManager<EM, EMH, S, SP>, Error>
    where
        EM: UsesState,
        EMH: EventManagerHooksTuple<EM::State>,
        S: State,
        SP: ShMemProvider,
    {
        Ok(CentralizedEventManager {
            inner,
            hooks,
            client: LlmpClient::on_existing_from_env(shmem_provider, env_name)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
            time_ref: time_obs,
            is_main: self.is_main,
            phantom: PhantomData,
        })
    }

    /// Create an existing client from description
    #[cfg(feature = "std")]
    pub fn existing_client_from_description<EM, EMH, S, SP>(
        self,
        inner: EM,
        hooks: EMH,
        shmem_provider: SP,
        description: &LlmpClientDescription,
        time_obs: Option<Handle<TimeObserver>>,
    ) -> Result<CentralizedEventManager<EM, EMH, S, SP>, Error>
    where
        EM: UsesState,
        EMH: EventManagerHooksTuple<EM::State>,
        S: State,
        SP: ShMemProvider,
    {
        Ok(CentralizedEventManager {
            inner,
            hooks,
            client: LlmpClient::existing_client_from_description(shmem_provider, description)?,
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::with_threshold(COMPRESS_THRESHOLD),
            time_ref: time_obs,
            is_main: self.is_main,
            phantom: PhantomData,
        })
    }
}
impl<EM, EMH, S, SP> UsesState for CentralizedEventManager<EM, EMH, S, SP>
where
    EM: UsesState,
    EMH: EventManagerHooksTuple<EM::State>,
    S: State,
    SP: ShMemProvider,
{
    type State = EM::State;
}

impl<EM, EMH, S, SP> AdaptiveSerializer for CentralizedEventManager<EM, EMH, S, SP>
where
    EM: AdaptiveSerializer + UsesState,
    EMH: EventManagerHooksTuple<EM::State>,
    S: State,
    SP: ShMemProvider,
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

    fn time_ref(&self) -> &Option<Handle<TimeObserver>> {
        &self.time_ref
    }
}

impl<EM, EMH, S, SP> EventFirer for CentralizedEventManager<EM, EMH, S, SP>
where
    EM: AdaptiveSerializer + EventFirer + HasEventManagerId,
    EMH: EventManagerHooksTuple<EM::State>,
    S: State,
    SP: ShMemProvider,
{
    fn should_send(&self) -> bool {
        self.inner.should_send()
    }

    #[allow(clippy::match_same_arms)]
    fn fire(
        &mut self,
        state: &mut Self::State,
        mut event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        if !self.is_main {
            // secondary node
            let mut is_tc = false;
            // Forward to main only if new tc or heartbeat
            let should_be_forwarded = match &mut event {
                Event::NewTestcase { forward_id, .. } => {
                    *forward_id = Some(ClientId(self.inner.mgr_id().0 as u32));
                    is_tc = true;
                    true
                }
                Event::UpdateExecStats { .. } => true, // send it but this guy won't be handled. the only purpose is to keep this client alive else the broker thinks it is dead and will dc it
                Event::Stop => true,
                _ => false,
            };

            if should_be_forwarded {
                self.forward_to_main(&event)?;
                if is_tc {
                    // early return here because we only send it to centralized not main broker.
                    return Ok(());
                }
            }
        }

        // now inner llmp manager will process it if it's not a new testcase from a secondary node.
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

    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error>
    where
        OT: ObserversTuple<Self::Input, Self::State> + Serialize,
    {
        const SERIALIZE_TIME_FACTOR: u32 = 4; // twice as much as the normal llmp em's value cuz it does this job twice.
        const SERIALIZE_PERCENTAGE_THRESHOLD: usize = 80;
        self.inner.serialize_observers_adaptive(
            observers,
            SERIALIZE_TIME_FACTOR,
            SERIALIZE_PERCENTAGE_THRESHOLD,
        )
    }

    fn configuration(&self) -> EventConfig {
        self.inner.configuration()
    }
}

impl<EM, EMH, S, SP> EventRestarter for CentralizedEventManager<EM, EMH, S, SP>
where
    EM: EventRestarter,
    EMH: EventManagerHooksTuple<EM::State>,
    S: State,
    SP: ShMemProvider,
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

impl<E, EM, EMH, S, SP, Z> EventProcessor<E, Z> for CentralizedEventManager<EM, EMH, S, SP>
where
    EM: AdaptiveSerializer + EventProcessor<E, Z> + EventFirer + HasEventManagerId,
    EMH: EventManagerHooksTuple<EM::State>,
    E: HasObservers + Executor<Self, Z, State = Self::State>,
    E::Observers:
        ObserversTuple<<Self as UsesInput>::Input, <Self as UsesState>::State> + Serialize,
    for<'a> E::Observers: Deserialize<'a>,
    S: State,
    Self::State: HasExecutions + HasMetadata,
    SP: ShMemProvider,
    Z: EvaluatorObservers<Self, E::Observers, State = Self::State>
        + ExecutionProcessor<Self, E::Observers, State = Self::State>,
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
            // self.inner.process(fuzzer, state, executor)
        } else {
            // The main node does not process incoming events from the broker ATM
            self.inner.process(fuzzer, state, executor)
        }
    }

    fn on_shutdown(&mut self) -> Result<(), Error> {
        self.inner.on_shutdown()?;
        self.client.sender_mut().send_exiting()
    }
}

impl<E, EM, EMH, S, SP, Z> EventManager<E, Z> for CentralizedEventManager<EM, EMH, S, SP>
where
    E: HasObservers + Executor<Self, Z, State = Self::State>,
    E::Observers:
        ObserversTuple<<Self as UsesInput>::Input, <Self as UsesState>::State> + Serialize,
    for<'a> E::Observers: Deserialize<'a>,
    EM: AdaptiveSerializer + EventManager<E, Z>,
    EM::State: HasExecutions + HasMetadata + HasLastReportTime,
    EMH: EventManagerHooksTuple<EM::State>,
    S: State,
    SP: ShMemProvider,
    Z: EvaluatorObservers<Self, E::Observers, State = Self::State>
        + ExecutionProcessor<Self, E::Observers, State = Self::State>,
{
}

impl<EM, EMH, S, SP> HasCustomBufHandlers for CentralizedEventManager<EM, EMH, S, SP>
where
    EM: HasCustomBufHandlers,
    EMH: EventManagerHooksTuple<EM::State>,
    S: State,
    SP: ShMemProvider,
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

impl<EM, EMH, S, SP> ProgressReporter for CentralizedEventManager<EM, EMH, S, SP>
where
    EM: AdaptiveSerializer + ProgressReporter + HasEventManagerId,
    EM::State: HasMetadata + HasExecutions + HasLastReportTime,
    EMH: EventManagerHooksTuple<EM::State>,
    S: State,
    SP: ShMemProvider,
{
}

impl<EM, EMH, S, SP> HasEventManagerId for CentralizedEventManager<EM, EMH, S, SP>
where
    EM: HasEventManagerId + UsesState,
    EMH: EventManagerHooksTuple<EM::State>,
    S: State,
    SP: ShMemProvider,
{
    fn mgr_id(&self) -> EventManagerId {
        self.inner.mgr_id()
    }
}

impl<EM, EMH, S, SP> CentralizedEventManager<EM, EMH, S, SP>
where
    EM: UsesState,
    EMH: EventManagerHooksTuple<EM::State>,
    S: State,
    SP: ShMemProvider,
{
    /// Describe the client event manager's LLMP parts in a restorable fashion
    pub fn describe(&self) -> Result<LlmpClientDescription, Error> {
        self.client.describe()
    }

    /// Write the config for a client [`EventManager`] to env vars, a new
    /// client can reattach using [`CentralizedEventManagerBuilder::build_existing_client_from_env()`].
    #[cfg(feature = "std")]
    pub fn to_env(&self, env_name: &str) {
        self.client.to_env(env_name).unwrap();
    }

    /// Know if this instance is main or secondary
    pub fn is_main(&self) -> bool {
        self.is_main
    }
}

impl<EM, EMH, S, SP> CentralizedEventManager<EM, EMH, S, SP>
where
    EM: UsesState + EventFirer + AdaptiveSerializer + HasEventManagerId,
    EMH: EventManagerHooksTuple<EM::State>,
    S: State + Stoppable,
    SP: ShMemProvider,
{
    #[cfg(feature = "llmp_compression")]
    fn forward_to_main<I>(&mut self, event: &Event<I>) -> Result<(), Error>
    where
        I: Input,
    {
        let serialized = postcard::to_allocvec(event)?;
        let flags = LLMP_FLAG_INITIALIZED;

        match self.compressor.maybe_compress(&serialized) {
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
        state: &mut <Self as UsesState>::State,
        executor: &mut E,
    ) -> Result<usize, Error>
    where
        E: Executor<Self, Z, State = <Self as UsesState>::State> + HasObservers,
        E::Observers:
            ObserversTuple<<Self as UsesInput>::Input, <Self as UsesState>::State> + Serialize,
        <Self as UsesState>::State: UsesInput + HasExecutions + HasMetadata,
        for<'a> E::Observers: Deserialize<'a>,
        Z: ExecutionProcessor<Self, E::Observers, State = <Self as UsesState>::State>
            + EvaluatorObservers<Self, E::Observers>,
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
            let event: Event<<<Self as UsesState>::State as UsesInput>::Input> =
                postcard::from_bytes(event_bytes)?;
            log::debug!("Processor received message {}", event.name_detailed());
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
        state: &mut <Self as UsesState>::State,
        client_id: ClientId,
        event: Event<<<Self as UsesState>::State as UsesInput>::Input>,
    ) -> Result<(), Error>
    where
        E: Executor<Self, Z, State = <Self as UsesState>::State> + HasObservers,
        E::Observers:
            ObserversTuple<<Self as UsesInput>::Input, <Self as UsesState>::State> + Serialize,
        <Self as UsesState>::State: UsesInput + HasExecutions + HasMetadata,
        for<'a> E::Observers: Deserialize<'a> + Serialize,
        Z: ExecutionProcessor<Self, E::Observers, State = <Self as UsesState>::State>
            + EvaluatorObservers<Self, E::Observers>,
    {
        log::debug!("handle_in_main!");

        let event_name = event.name_detailed();

        match event {
            Event::NewTestcase {
                input,
                client_config,
                exit_kind,
                corpus_size,
                observers_buf,
                time,
                forward_id,
                #[cfg(feature = "multi_machine")]
                node_id,
            } => {
                log::debug!(
                    "Received {} from {client_id:?} ({client_config:?}, forward {forward_id:?})",
                    event_name
                );

                let res =
                    if client_config.match_with(&self.configuration()) && observers_buf.is_some() {
                        let observers: E::Observers =
                            postcard::from_bytes(observers_buf.as_ref().unwrap())?;
                        #[cfg(feature = "scalability_introspection")]
                        {
                            state.scalability_monitor_mut().testcase_with_observers += 1;
                        }
                        log::debug!(
                            "[{}] Running fuzzer with event {}",
                            process::id(),
                            event_name
                        );
                        fuzzer.evaluate_execution(
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
                        log::debug!(
                            "[{}] Running fuzzer with event {}",
                            process::id(),
                            event_name
                        );
                        fuzzer.evaluate_input_with_observers::<E>(
                            state,
                            executor,
                            self,
                            input.clone(),
                            false,
                        )?
                    };

                if let Some(item) = res.1 {
                    let event = Event::NewTestcase {
                        input,
                        client_config,
                        exit_kind,
                        corpus_size,
                        observers_buf,
                        time,
                        forward_id,
                        #[cfg(feature = "multi_machine")]
                        node_id,
                    };

                    self.hooks.on_fire_all(state, client_id, &event)?;

                    log::debug!(
                        "[{}] Adding received Testcase {} as item #{item}...",
                        process::id(),
                        event_name
                    );

                    self.inner.fire(state, event)?;
                } else {
                    log::debug!("[{}] {} was discarded...)", process::id(), event_name);
                }
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

        Ok(())
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
