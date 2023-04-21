//! A wrapper manager to implement a main-secondary architecture with point-to-point channels

use alloc::{boxed::Box, string::String, vec::Vec};

use serde::{Deserialize, Serialize};

use super::{CustomBufEventResult, HasCustomBufHandlers, ProgressReporter};
use crate::{
    bolts::{
        llmp::{LlmpReceiver, LlmpSender, Tag},
        shmem::ShMemProvider,
        ClientId,
    },
    events::{
        Event, EventConfig, EventFirer, EventManager, EventManagerId, EventProcessor,
        EventRestarter, HasEventManagerId, LogSeverity,
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

impl<EM, SP> EventFirer for CentralizedEventManager<EM, SP>
where
    EM: EventFirer + HasEventManagerId,
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

    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Vec<u8>, Error>
    where
        OT: ObserversTuple<Self::State> + Serialize,
    {
        self.inner.serialize_observers(observers)
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
    EM: EventProcessor<E, Z> + EventFirer + HasEventManagerId,
    SP: ShMemProvider,
    E: HasObservers<State = Self::State> + Executor<Self, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    Z: EvaluatorObservers<E::Observers, State = Self::State>
        + ExecutionProcessor<E::Observers, State = Self::State>,
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

                            // TODO check the config and use the serialized observers

                            let res = fuzzer.evaluate_input_with_observers::<E, Self>(
                                state,
                                executor,
                                self,
                                input.clone(),
                                false,
                            )?;
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
    EM: EventManager<E, Z>,
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
    EM: ProgressReporter + HasEventManagerId,
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
