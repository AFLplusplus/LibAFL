use core::fmt::Display;
use std::{sync::Arc, vec::Vec};

use libafl_bolts::{ClientId, Error};
use log::info;
use tokio::{net::ToSocketAddrs, runtime::Runtime, sync::RwLock};

use crate::{
    events::{multi_machine::TcpMultiMachineState, Event, EventManagerHook},
    inputs::Input,
    state::State,
};

/// The multi-machine hook.
/// Warning: This spawns a Tokio Runtime at the first run of the hook (on the init callback).
/// Thus, the init callback should be run in the same process as the one in which the other calls
#[derive(Debug)]
pub struct TcpMultiMachineEventManagerHook<A, I>
where
    I: Input,
{
    shared_state: Arc<RwLock<TcpMultiMachineState<A, I>>>, // the actual state of the broker hook
    rt: Option<Arc<Runtime>>, // the tokio runtime used to interact with other machines. Keep it outside to avoid locking it.
}

impl<A, I> TcpMultiMachineEventManagerHook<A, I>
where
    I: Input,
{
    pub(crate) fn new(shared_state: Arc<RwLock<TcpMultiMachineState<A, I>>>) -> Self {
        Self {
            shared_state,
            rt: None,
        }
    }
}

impl<A, S> EventManagerHook<S> for TcpMultiMachineEventManagerHook<A, S::Input>
where
    A: Clone + Display + ToSocketAddrs + Send + Sync + 'static,
    S: State,
    S::Input: Send + Sync + 'static,
{
    fn init(&mut self) -> Result<(), Error> {
        self.rt =
            Some(Arc::new(Runtime::new().or_else(|_| {
                Err(Error::unknown("Tokio runtime spawning failed"))
            })?));
        let rt = self.rt.clone().unwrap().clone();
        TcpMultiMachineState::init_once(self.shared_state.clone(), rt)?;
        Ok(())
    }

    fn pre_exec(
        &mut self,
        _state: &mut S,
        _client_id: ClientId,
        events: &mut Vec<Event<S::Input>>,
    ) -> Result<bool, Error> {
        // Here, we get all the events from the other clients. we don't want to actually send them directly to
        // other nodes now. We will though receive other nodes' messages and make them go through the centralized
        // filter.
        let shared_state = self.shared_state.clone();
        let incoming_events: Result<Vec<Event<S::Input>>, Error> =
            self.rt.clone().unwrap().block_on(async move {
                let mut state_wr_lock = shared_state.write().await;

                // for event in events.as_ref() {
                //     // First, we handle the message. Since it involves network, we do it first and await on it.
                //     state_wr_lock.handle_new_message_from_node(event).await?;

                //     // add the msg to the list of old messages to send to a future child.
                //     state_wr_lock.old_events.push();
                // }

                let mut incoming_events: Vec<Event<S::Input>> = Vec::new();
                state_wr_lock
                    .handle_new_messages_from_nodes(&mut incoming_events)
                    .await?;

                info!("Received {} new event.", incoming_events.len());

                Ok(incoming_events)
            });

        // Add incoming events to the ones we should filter
        events.extend_from_slice(&incoming_events?);

        Ok(true)
    }

    fn on_fire(
        &mut self,
        _state: &mut S,
        _client_id: ClientId,
        event: &Event<S::Input>,
    ) -> Result<(), Error> {
        info!("new event was fired.");

        // Here, we can access all the messages that passed the EventManager "filter".
        // Thus, the messages are initially destined to be broadcast to the other clients because they were deemed interesting.
        // It could also be used as an llmp hook, in case we need to use multiple filters.
        let shared_state = self.shared_state.clone();
        let res: Result<(), Error> = self.rt.clone().unwrap().block_on(async move {
            let mut state_wr_lock = shared_state.write().await;

            state_wr_lock.send_interesting_event_to_nodes(event).await?;

            info!("Sent a new event to parent.");

            Ok(())
        });

        res?;

        Ok(())
    }
}
