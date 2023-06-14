//! A wrapper manager to implement a main-secondary architecture with point-to-point channels

use alloc::{boxed::Box, string::String, vec::Vec};
use core::time::Duration;

use serde::{Deserialize, Serialize};

use super::{CustomBufEventResult, HasCustomBufHandlers, ProgressReporter};
use crate::{
    bolts::{
        current_time,
        llmp::{LlmpReceiver, LlmpSender, Tag},
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
    state::{HasClientPerfMonitor, HasExecutions, HasMetadata, UsesState},
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

    fn serialization_time_mut(&mut self) -> &mut Duration {
        self.inner.serialization_time_mut()
    }
    fn deserialization_time_mut(&mut self) -> &mut Duration {
        self.inner.deserialization_time_mut()
    }
    fn serializations_cnt_mut(&mut self) -> &mut usize {
        self.inner.serializations_cnt_mut()
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
                    observers_buf: _,
                    time: _,
                    executions: _,
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
        let exec_time = observers
            .match_name::<crate::observers::TimeObserver>("time")
            .map(|o| o.last_runtime().unwrap_or(Duration::ZERO))
            .unwrap();

        static mut DIOCAN: usize = 0;

        let force = if self.inner.serializations_cnt() > 256 {
            (unsafe { DIOCAN }) as f64 / self.inner.serializations_cnt() as f64 >= 0.8
        } else {
            (self.inner.serialization_time() + self.inner.deserialization_time()) * 4 < exec_time
        };

        // eprintln!("serialize_observers: {:?}    {:?} {:?}", exec_time, self.serialization_time(), self.deserialization_time());
        if self.inner.serialization_time() == Duration::ZERO
            // || (self.inner.serialization_time() + self.inner.deserialization_time()) * 4 < exec_time // self.execution_time
            || self.inner.serializations_cnt().trailing_zeros() >= 8
            || force
        {
            let start = current_time();
            let ser = postcard::to_allocvec(observers)?;
            *self.inner.serialization_time_mut() = current_time() - start;

            // eprintln!("serialized!   {:?} {:?}", ser.len(), (self.serialization_time() + self.deserialization_time()) * 4 < exec_time);

            unsafe { DIOCAN += 1 };

            *self.inner.serializations_cnt_mut() += 1;
            Ok(Some(ser))
        } else {
            *self.inner.serializations_cnt_mut() += 1;
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
        self.inner.on_restart(state)
    }

    fn send_exiting(&mut self) -> Result<(), Error> {
        self.inner.send_exiting()
    }

    #[inline]
    fn await_restart_safe(&mut self) {
        self.inner.await_restart_safe();
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

                                let res = fuzzer.process_execution(
                                    state,
                                    self,
                                    input.clone(),
                                    &observers,
                                    &exit_kind,
                                    false,
                                )?;

                                // Count this as execution even if we are not actually executing nothing for the stats
                                #[cfg(feature = "count_process_execution")]
                                {
                                    *state.executions_mut() += 1;
                                }
                                res
                            } else {
                                let res = fuzzer.evaluate_input_with_observers::<E, Self>(
                                    state,
                                    executor,
                                    self,
                                    input.clone(),
                                    false,
                                )?;

                                #[cfg(feature = "no_count_newtestcases")]
                                {
                                    *state.executions_mut() -= 1;
                                }
                                res
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
    EM::State: HasClientPerfMonitor + HasExecutions + HasMetadata,
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
    EM::State: HasClientPerfMonitor + HasMetadata + HasExecutions,
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
    pub fn new_main(inner: EM, receivers_from_secondary: Vec<LlmpReceiver<SP>>) -> Self {
        Self {
            inner,
            sender_to_main: None,
            receivers_from_secondary: Some(receivers_from_secondary),
        }
    }

    /// Creates a new [`CentralizedEventManager`].
    pub fn new_secondary(inner: EM, sender_to_main: LlmpSender<SP>) -> Self {
        Self {
            inner,
            sender_to_main: Some(sender_to_main),
            receivers_from_secondary: None,
        }
    }
}
