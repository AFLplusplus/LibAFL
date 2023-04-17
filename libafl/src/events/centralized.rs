//! A very simple event manager, that just supports log outputs, but no multiprocessing

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};

use super::{CustomBufEventResult, CustomBufHandlerFn, HasCustomBufHandlers, ProgressReporter};
use crate::{
    bolts::ClientId,
    events::{
        BrokerEventResult, Event, EventFirer, EventManager, EventManagerId, EventProcessor,
        EventRestarter, HasEventManagerId,
    },
    inputs::UsesInput,
    monitors::Monitor,
    state::{HasClientPerfMonitor, HasExecutions, HasMetadata, UsesState},
    Error,
};

/// A simple, single-threaded event manager that just logs
#[derive(Debug)]
pub struct CentralizedEventManager<EM, S>
where
    S: UsesInput,
{
    inner: EM,
    phantom: PhantomData<S>,
}

impl<EM, S> UsesState for CentralizedEventManager<EM, S>
where
    S: UsesInput,
{
    type State = S;
}

impl<EM, S> EventFirer for CentralizedEventManager<EM, S>
where
    EM: EventFirer,
    S: UsesInput,
{
    fn fire(
        &mut self,
        _state: &mut Self::State,
        event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        match Self::handle_in_broker(&mut self.monitor, &event)? {
            BrokerEventResult::Forward => self.events.push(event),
            BrokerEventResult::Handled => (),
        };
        Ok(())
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

impl<EM, S> EventRestarter for CentralizedEventManager<EM, S>
where
    EM: EventRestarter,
    S: UsesInput,
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
        self.inner.await_restart_safe()
    }
}

impl<E, EM, S, Z> EventProcessor<E, Z> for CentralizedEventManager<EM, S>
where
    EM: EventProcessor<E, Z>,
    S: UsesInput,
{
    fn process(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _executor: &mut E,
    ) -> Result<usize, Error> {
        let count = self.events.len();
        while !self.events.is_empty() {
            let event = self.events.pop().unwrap();
            self.handle_in_client(state, event)?;
        }
        Ok(count)
    }
}

impl<E, EM, S, Z> EventManager<E, Z> for CentralizedEventManager<EM, S>
where
    EM: EventManager<E, Z>,
    S: UsesInput + HasClientPerfMonitor + HasExecutions + HasMetadata,
{
}

impl<EM, S> HasCustomBufHandlers for CentralizedEventManager<EM, S>
where
    EM: HasCustomBufHandlers,
    S: UsesInput,
{
    /// Adds a custom buffer handler that will run for each incoming `CustomBuf` event.
    fn add_custom_buf_handler(
        &mut self,
        handler: Box<
            dyn FnMut(&mut Self::State, &String, &[u8]) -> Result<CustomBufEventResult, Error>,
        >,
    ) {
        self.custom_buf_handlers.push(handler);
    }
}

impl<EM, S> ProgressReporter for CentralizedEventManager<EM, S>
where
    EM: ProgressReporter,
    S: UsesInput + HasExecutions + HasClientPerfMonitor + HasMetadata,
{
}

impl<EM, S> HasEventManagerId for CentralizedEventManager<EM, S>
where
    EM: HasEventManagerId,
    S: UsesInput,
{
    fn mgr_id(&self) -> EventManagerId {
        self.inner.mgr_id()
    }
}

impl<EM, S> CentralizedEventManager<EM, S>
where
    S: UsesInput,
{
    /// Creates a new [`CentralizedEventManager`].
    pub fn new(inner: EM) -> Self {
        Self {
            inner,
            phantom: PhantomData,
        }
    }
}
