//! A wrapper manager to implement a main-secondary architecture with point-to-point channels

use alloc::{boxed::Box, string::String, vec::Vec};
#[cfg(feature = "adaptive_serialization")]
use core::time::Duration;

use serde::{Deserialize, Serialize};

use super::{CustomBufEventResult, HasCustomBufHandlers, ProgressReporter};
#[cfg(feature = "adaptive_serialization")]
use crate::bolts::current_time;
use crate::{
    bolts::{
        llmp::{LlmpReceiver, LlmpSender, PersistentLlmpP2P, Tag},
        shmem::ShMemProvider,
        ClientId,
    },
    events::{
        llmp::EventStatsCollector, Event, EventConfig, EventFirer, EventManager, EventManagerId,
        EventProcessor, EventRestarter, HasEventManagerId, LogSeverity,
    },
    executors::{Executor, HasObservers},
    fuzzer::{EvaluatorObservers, ExecutionProcessor},
    inputs::UsesInput,
    observers::ObserversTuple,
    state::{HasClientPerfMonitor, HasExecutions, HasLastReportTime, HasMetadata, UsesState},
    Error,
};

const _LLMP_TAG_TO_MAIN: Tag = Tag(0x3453453);

/// A wrapper manager to implement a main-secondary architecture with point-to-point channels
#[derive(Debug)]
pub struct CentralizedEventManager<EM, SP>
where
    EM: UsesState,
    SP: ShMemProvider,
{
    inner: EM,
    p2p: PersistentLlmpP2P<SP>,
    p2p_index: usize,
    sender_to_main: Option<LlmpSender<SP>>,
    receivers_from_secondary: Option<Vec<LlmpReceiver<SP>>>,
}

impl<EM, SP> UsesState for CentralizedEventManager<EM, SP>
where
    EM: UsesState,
    SP: ShMemProvider,
{
    type State = EM::State;
}

#[cfg(feature = "adaptive_serialization")]
impl<EM, SP> EventStatsCollector for CentralizedEventManager<EM, SP>
where
    EM: EventStatsCollector + UsesState,
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
}

#[cfg(not(feature = "adaptive_serialization"))]
impl<EM, SP> EventStatsCollector for CentralizedEventManager<EM, SP>
where
    EM: EventStatsCollector + UsesState,
    SP: ShMemProvider,
{
}

impl<EM, SP> EventFirer for CentralizedEventManager<EM, SP>
where
    EM: EventStatsCollector + EventFirer + HasEventManagerId,
    SP: ShMemProvider,
{
    fn fire(
        &mut self,
        state: &mut Self::State,
        mut event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        if let Some(sender) = self.sender_to_main.as_mut() {
            // secondary node
            let is_nt = match &mut event {
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
                _ => false,
            };
            if is_nt {
                // TODO use copression when llmp_compression is enabled
                let serialized = postcard::to_allocvec(&event)?;
                return sender.send_buf(_LLMP_TAG_TO_MAIN, &serialized);
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
    SP: ShMemProvider,
{
    #[inline]
    fn on_restart(&mut self, state: &mut Self::State) -> Result<(), Error> {
        if let Some(sender) = self.sender_to_main.as_ref() {
            self.p2p.get_description_mut(self.p2p_index).sender = sender.describe()?;
        } else if let Some(receivers) = self.receivers_from_secondary.as_ref() {
            debug_assert!(self.p2p.num_channels() == receivers.len());
            for (i, recv) in receivers.iter().enumerate() {
                self.p2p.get_description_mut(i).receiver = recv.describe()?;
            }
        }

        self.inner.on_restart(state)?;
        self.await_restart_safe();
        Ok(())
    }

    fn send_exiting(&mut self) -> Result<(), Error> {
        self.inner.send_exiting()
    }

    #[inline]
    fn await_restart_safe(&mut self) {
        if let Some(sender) = self.sender_to_main.as_ref() {
            sender.await_safe_to_unmap_blocking();
        }
    }
}

impl<E, EM, SP, Z> EventProcessor<E, Z> for CentralizedEventManager<EM, SP>
where
    EM: EventStatsCollector + EventProcessor<E, Z> + EventFirer + HasEventManagerId,
    SP: ShMemProvider,
    E: HasObservers<State = Self::State> + Executor<Self, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    Z: EvaluatorObservers<E::Observers, State = Self::State>
        + ExecutionProcessor<E::Observers, State = Self::State>,
    Self::State: HasExecutions + HasMetadata,
{
    fn process(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        executor: &mut E,
    ) -> Result<usize, Error> {
        if self.receivers_from_secondary.is_some() {
            // main node
            let mut receivers = self.receivers_from_secondary.take().unwrap();
            // TODO in case of error, this is discarded, that is a bug ATM

            for (idx, receiver) in receivers.iter_mut().enumerate() {
                while let Some((_client_id, tag, _flags, msg)) = receiver.recv_buf_with_flags()? {
                    assert!(
                        tag == _LLMP_TAG_TO_MAIN,
                        "Only the TO_MAIN parcel should have arrived in the main node!"
                    );

                    // TODO handle compression
                    let event: Event<<Self::State as UsesInput>::Input> =
                        postcard::from_bytes(msg)?;
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
                            log::info!(
                                "Received new Testcase to evaluate from secondary node {idx:?}"
                            );

                            let res = if client_config.match_with(&self.configuration())
                                && observers_buf.is_some()
                            {
                                #[cfg(feature = "adaptive_serialization")]
                                let start = current_time();
                                let observers: E::Observers =
                                    postcard::from_bytes(observers_buf.as_ref().unwrap())?;

                                #[cfg(feature = "adaptive_serialization")]
                                {
                                    *self.inner.deserialization_time_mut() = current_time() - start;
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
                                fuzzer.evaluate_input_with_observers::<E, Self>(
                                    state,
                                    executor,
                                    self,
                                    input.clone(),
                                    false,
                                )?
                            };
                            if let Some(item) = res.1 {
                                log::info!("Added received Testcase as item #{item}");

                                self.inner.fire(
                                    state,
                                    Event::NewTestcase {
                                        input,
                                        observers_buf,
                                        exit_kind,
                                        corpus_size,
                                        client_config,
                                        time,
                                        executions,
                                        forward_id,
                                    },
                                )?;
                            }
                        }
                        _ => panic!(
                            "Only the NewTestcase event should have arrived to the main node!"
                        ),
                    };
                }
            }

            self.receivers_from_secondary = Some(receivers);

            Ok(0) // TODO is 0 ok?
        } else {
            // The main node does not process incoming events from the broker ATM
            self.inner.process(fuzzer, state, executor)
        }
    }
}

impl<E, EM, SP, Z> EventManager<E, Z> for CentralizedEventManager<EM, SP>
where
    EM: EventStatsCollector + EventManager<E, Z>,
    EM::State: HasClientPerfMonitor + HasExecutions + HasMetadata + HasLastReportTime,
    SP: ShMemProvider,
    E: HasObservers<State = Self::State> + Executor<Self, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    Z: EvaluatorObservers<E::Observers, State = Self::State>
        + ExecutionProcessor<E::Observers, State = Self::State>,
{
}

impl<EM, SP> HasCustomBufHandlers for CentralizedEventManager<EM, SP>
where
    EM: HasCustomBufHandlers,
    SP: ShMemProvider,
{
    /// Adds a custom buffer handler that will run for each incoming `CustomBuf` event.
    fn add_custom_buf_handler(
        &mut self,
        handler: Box<
            dyn FnMut(&mut Self::State, &String, &[u8]) -> Result<CustomBufEventResult, Error>,
        >,
    ) {
        self.inner.add_custom_buf_handler(handler);
    }
}

impl<EM, SP> ProgressReporter for CentralizedEventManager<EM, SP>
where
    EM: EventStatsCollector + ProgressReporter + HasEventManagerId,
    EM::State: HasClientPerfMonitor + HasMetadata + HasExecutions + HasLastReportTime,
    SP: ShMemProvider,
{
}

impl<EM, SP> HasEventManagerId for CentralizedEventManager<EM, SP>
where
    EM: HasEventManagerId + UsesState,
    SP: ShMemProvider,
{
    fn mgr_id(&self) -> EventManagerId {
        self.inner.mgr_id()
    }
}

impl<EM, SP> CentralizedEventManager<EM, SP>
where
    EM: UsesState,
    SP: ShMemProvider,
{
    /// Creates a new [`CentralizedEventManager`].
    #[allow(clippy::needless_pass_by_value)]
    pub fn new_main(
        inner: EM,
        shmem_provider: SP,
        p2p: PersistentLlmpP2P<SP>,
    ) -> Result<Self, Error> {
        let mut receivers_from_secondary = vec![];
        for i in 0..p2p.num_channels() {
            receivers_from_secondary.push(p2p.get_receiver(shmem_provider.clone(), i)?);
        }
        Ok(Self {
            inner,
            p2p,
            p2p_index: 0,
            sender_to_main: None,
            receivers_from_secondary: Some(receivers_from_secondary),
        })
    }

    /// Creates a new [`CentralizedEventManager`].
    pub fn new_secondary(
        inner: EM,
        shmem_provider: SP,
        p2p: PersistentLlmpP2P<SP>,
        p2p_index: usize,
    ) -> Result<Self, Error> {
        let sender_to_main = p2p.get_sender(shmem_provider, p2p_index)?;
        Ok(Self {
            inner,
            p2p,
            p2p_index,
            sender_to_main: Some(sender_to_main),
            receivers_from_secondary: None,
        })
    }

    /// Know if this instance is main or secondary
    pub fn is_main(&self) -> bool {
        self.receivers_from_secondary.is_some()
    }
}
