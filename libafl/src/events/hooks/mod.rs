//! Hooks for event managers, especifically these are used to hook before and and `handle_in_client`.
//! This will allow user to define pre/post-processing code when the event manager receives any message from
//! other clients
use libafl_bolts::ClientId;

use crate::{events::Event, state::State, Error};

/// The hooks that are run before and after the event manager calls `handle_in_client`
pub trait EventManagerHook<S>
where
    S: State,
{
    /// The hook that runs before `handle_in_client`
    /// Return false if you want to cancel the subsequent event handling
    fn pre_exec<E, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        client_id: ClientId,
        event: &Event<S::Input>,
    ) -> Result<bool, Error>;
    /// The hook that runs after `handle_in_client`
    /// Return false if you want to cancel the subsequent event handling
    fn post_exec<E, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        client_id: ClientId,
    ) -> Result<bool, Error>;
}

/// The tuples contains hooks to be executed for `handle_in_client`
pub trait EventManagerHooksTuple<S>
where
    S: State,
{
    /// The hook that runs before `handle_in_client`
    fn pre_exec_all<E, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        client_id: ClientId,
        event: &Event<S::Input>,
    ) -> Result<bool, Error>;
    /// The hook that runs after `handle_in_client`
    fn post_exec_all<E, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        client_id: ClientId,
    ) -> Result<bool, Error>;
}

impl<S> EventManagerHooksTuple<S> for ()
where
    S: State,
{
    /// The hook that runs before `handle_in_client`
    fn pre_exec_all<E, Z>(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut S,
        _client_id: ClientId,
        _event: &Event<S::Input>,
    ) -> Result<bool, Error> {
        Ok(true)
    }
    /// The hook that runs after `handle_in_client`
    fn post_exec_all<E, Z>(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut S,
        _client_id: ClientId,
    ) -> Result<bool, Error> {
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
    fn pre_exec_all<E, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        client_id: ClientId,
        event: &Event<S::Input>,
    ) -> Result<bool, Error> {
        let first = self.0.pre_exec(fuzzer, executor, state, client_id, event)?;
        let second = self
            .1
            .pre_exec_all(fuzzer, executor, state, client_id, event)?;
        Ok(first & second)
    }
    /// The hook that runs after `handle_in_client`
    fn post_exec_all<E, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        client_id: ClientId,
    ) -> Result<bool, Error> {
        let first = self.0.post_exec(fuzzer, executor, state, client_id)?;
        let second = self.1.post_exec_all(fuzzer, executor, state, client_id)?;
        Ok(first & second)
    }
}
