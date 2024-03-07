//! Hooks for event managers, especifically these are used to hook before and and `handle_in_client`.
//! This will allow user to define pre/post-processing code when the event manager receives any message from
//! other clients
use libafl_bolts::ClientId;

use crate::{events::Event, executors::hooks::ExecutorHooksTuple, state::State, Error};

/// The hooks that are run before and after the event manager calls `handle_in_client`
pub trait EventManagerHook<S>
where
    S: State,
{
    /// The hook that runs before `handle_in_client`
    fn pre_exec<E, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        client_id: ClientId,
        event: &Event<S::Input>,
    ) -> Result<(), Error>;
    /// The hook that runs after `handle_in_client`
    fn post_exec<E, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        client_id: ClientId,
    ) -> Result<(), Error>;
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
    ) -> Result<(), Error>;
    /// The hook that runs after `handle_in_client`
    fn post_exec_all<E, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        client_id: ClientId,
    ) -> Result<(), Error>;
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
    ) -> Result<(), Error> {
        Ok(())
    }
    /// The hook that runs after `handle_in_client`
    fn post_exec_all<E, Z>(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut S,
        _client_id: ClientId,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, S> EventManagerHooksTuple<S> for (Head, Tail)
where
    Head: EventManagerHook<S>,
    Tail: ExecutorHooksTuple,
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
    ) -> Result<(), Error> {
        Ok(())
    }
    /// The hook that runs after `handle_in_client`
    fn post_exec_all<E, Z>(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut S,
        _client_id: ClientId,
    ) -> Result<(), Error> {
        Ok(())
    }
}
