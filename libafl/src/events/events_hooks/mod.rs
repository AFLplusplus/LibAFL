//! Hooks for event managers, especifically these are used to hook before `handle_in_client`.
//!
//! This will allow user to define pre/post-processing code when the event manager receives any message from
//! other clients
use libafl_bolts::ClientId;

use crate::{events::Event, state::State, Error};

/// The `broker_hooks` that are run before and after the event manager calls `handle_in_client`
pub trait EventManagerHook<S>
where
    S: State,
{
    /// The hook that runs before `handle_in_client`
    /// Return false if you want to cancel the subsequent event handling
    fn pre_exec(
        &mut self,
        state: &mut S,
        client_id: ClientId,
        event: &Event<S::Input>,
    ) -> Result<bool, Error>;

    /// Triggered when the even manager decides to fire the event after processing
    fn on_fire(
        &mut self,
        _state: &mut S,
        _client_id: ClientId,
        _event: &Event<S::Input>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// The hook that runs after `handle_in_client`
    /// Return false if you want to cancel the subsequent event handling
    fn post_exec(&mut self, _state: &mut S, _client_id: ClientId) -> Result<bool, Error> {
        Ok(true)
    }
}

/// The tuples contains `broker_hooks` to be executed for `handle_in_client`
pub trait EventManagerHooksTuple<S>
where
    S: State,
{
    /// The hook that runs before `handle_in_client`
    fn pre_exec_all(
        &mut self,
        state: &mut S,
        client_id: ClientId,
        event: &Event<S::Input>,
    ) -> Result<bool, Error>;

    /// Ran when the Event Manager decides to accept an event and propagates it
    fn on_fire_all(
        &mut self,
        state: &mut S,
        client_id: ClientId,
        event: &Event<S::Input>,
    ) -> Result<(), Error>;

    /// The hook that runs after `handle_in_client`
    fn post_exec_all(&mut self, state: &mut S, client_id: ClientId) -> Result<bool, Error>;
}

impl<S> EventManagerHooksTuple<S> for ()
where
    S: State,
{
    /// The hook that runs before `handle_in_client`
    fn pre_exec_all(
        &mut self,
        _state: &mut S,
        _client_id: ClientId,
        _event: &Event<S::Input>,
    ) -> Result<bool, Error> {
        Ok(true)
    }

    fn on_fire_all(
        &mut self,
        _state: &mut S,
        _client_id: ClientId,
        _event: &Event<S::Input>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// The hook that runs after `handle_in_client`
    fn post_exec_all(&mut self, _state: &mut S, _client_id: ClientId) -> Result<bool, Error> {
        Ok(true)
    }
}

impl<Head, Tail, S> EventManagerHooksTuple<S> for (Head, Tail)
where
    Head: EventManagerHook<S>,
    Tail: EventManagerHooksTuple<S>,
    S: State,
{
    /// The hook that runs before `handle_in_client`
    fn pre_exec_all(
        &mut self,
        state: &mut S,
        client_id: ClientId,
        event: &Event<S::Input>,
    ) -> Result<bool, Error> {
        let first = self.0.pre_exec(state, client_id, event)?;
        let second = self.1.pre_exec_all(state, client_id, event)?;
        Ok(first & second)
    }

    fn on_fire_all(
        &mut self,
        state: &mut S,
        client_id: ClientId,
        event: &Event<S::Input>,
    ) -> Result<(), Error> {
        self.0.on_fire(state, client_id, event)?;
        self.1.on_fire_all(state, client_id, event)
    }

    /// The hook that runs after `handle_in_client`
    fn post_exec_all(&mut self, state: &mut S, client_id: ClientId) -> Result<bool, Error> {
        let first = self.0.post_exec(state, client_id)?;
        let second = self.1.post_exec_all(state, client_id)?;
        Ok(first & second)
    }
}
