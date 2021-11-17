//! Eventmanager manages all events that go to other instances of the fuzzer.

pub mod simple;
pub use simple::*;
pub mod llmp;
pub use llmp::*;

use ahash::AHasher;
use alloc::{string::String, vec::Vec};
use core::{fmt, hash::Hasher, marker::PhantomData, time::Duration};
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use uuid::Uuid;

use crate::{
    bolts::current_time,
    executors::ExitKind,
    inputs::Input,
    monitors::UserStats,
    observers::ObserversTuple,
    state::{HasClientPerfMonitor, HasExecutions},
    Error,
};

/// A per-fuzzer unique `ID`, usually starting with `0` and increasing
/// by `1` in multiprocessed `EventManager`s, such as [`self::llmp::LlmpEventManager`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EventManagerId {
    /// The id
    pub id: usize,
}

#[cfg(feature = "introspection")]
use crate::monitors::ClientPerfMonitor;
#[cfg(feature = "introspection")]
use alloc::boxed::Box;

/// The log event severity
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum LogSeverity {
    /// Debug severity
    Debug,
    /// Information
    Info,
    /// Warning
    Warn,
    /// Error
    Error,
}

impl fmt::Display for LogSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogSeverity::Debug => write!(f, "Debug"),
            LogSeverity::Info => write!(f, "Info"),
            LogSeverity::Warn => write!(f, "Warn"),
            LogSeverity::Error => write!(f, "Error"),
        }
    }
}

/// Indicate if an event worked or not
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum BrokerEventResult {
    /// The broker haneled this. No need to pass it on.
    Handled,
    /// Pass this message along to the clients.
    Forward,
}

/// Distinguish a fuzzer by its config
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum EventConfig {
    AlwaysUnique,
    FromName {
        name_hash: u64,
    },
    #[cfg(feature = "std")]
    BuildID {
        id: Uuid,
    },
}

impl EventConfig {
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        let mut hasher = AHasher::new_with_keys(0, 0);
        hasher.write(name.as_bytes());
        EventConfig::FromName {
            name_hash: hasher.finish(),
        }
    }

    #[cfg(feature = "std")]
    #[must_use]
    pub fn from_build_id() -> Self {
        EventConfig::BuildID {
            id: build_id::get(),
        }
    }

    #[must_use]
    pub fn match_with(&self, other: &EventConfig) -> bool {
        match self {
            EventConfig::AlwaysUnique => false,
            EventConfig::FromName { name_hash: a } => match other {
                #[cfg(not(feature = "std"))]
                EventConfig::AlwaysUnique => false,
                EventConfig::FromName { name_hash: b } => (a == b),
                #[cfg(feature = "std")]
                EventConfig::AlwaysUnique | EventConfig::BuildID { id: _ } => false,
            },
            #[cfg(feature = "std")]
            EventConfig::BuildID { id: a } => match other {
                EventConfig::AlwaysUnique | EventConfig::FromName { name_hash: _ } => false,
                EventConfig::BuildID { id: b } => (a == b),
            },
        }
    }
}

impl From<&str> for EventConfig {
    #[must_use]
    fn from(name: &str) -> Self {
        Self::from_name(name)
    }
}

impl From<String> for EventConfig {
    #[must_use]
    fn from(name: String) -> Self {
        Self::from_name(&name)
    }
}

/*
/// A custom event, for own messages, with own handler.
pub trait CustomEvent<I>: SerdeAny
where
    I: Input,
{
    /// Returns the name of this event
    fn name(&self) -> &str;
    /// This method will be called in the broker
    fn handle_in_broker(&self) -> Result<BrokerEventResult, Error>;
    /// This method will be called in the clients after handle_in_broker (unless BrokerEventResult::Handled) was returned in handle_in_broker
    fn handle_in_client(&self) -> Result<(), Error>;
}
*/

/// Events sent around in the library
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub enum Event<I>
where
    I: Input,
{
    // TODO use an ID to keep track of the original index in the sender Corpus
    // The sender can then use it to send Testcase metadata with CustomEvent
    /// A fuzzer found a new testcase. Rejoice!
    NewTestcase {
        /// The input for the new testcase
        input: I,
        /// The state of the observers when this testcase was found
        observers_buf: Option<Vec<u8>>,
        /// The exit kind
        exit_kind: ExitKind,
        /// The new corpus size of this client
        corpus_size: usize,
        /// The client config for this observers/testcase combination
        client_config: EventConfig,
        /// The time of generation of the event
        time: Duration,
        /// The executions of this client
        executions: usize,
    },
    /// New stats event to monitor.
    UpdateExecutions {
        /// The time of generation of the [`Event`]
        time: Duration,
        /// The executions of this client
        executions: usize,
        /// [`PhantomData`]
        phantom: PhantomData<I>,
    },
    /// New user stats event to monitor.
    UpdateUserStats {
        /// Custom user monitor name
        name: String,
        /// Custom user monitor value
        value: UserStats,
        /// [`PhantomData`]
        phantom: PhantomData<I>,
    },
    /// New monitor with performance monitor.
    #[cfg(feature = "introspection")]
    UpdatePerfMonitor {
        /// The time of generation of the event
        time: Duration,

        /// The executions of this client
        executions: usize,

        /// Current performance statistics
        introspection_monitor: Box<ClientPerfMonitor>,

        phantom: PhantomData<I>,
    },
    /// A new objective was found
    Objective {
        /// Objective corpus size
        objective_size: usize,
    },
    /// Write a new log
    Log {
        /// the severity level
        severity_level: LogSeverity,
        /// The message
        message: String,
        /// `PhantomData`
        phantom: PhantomData<I>,
    },
    /*/// A custom type
    Custom {
        // TODO: Allow custom events
        // custom_event: Box<dyn CustomEvent<I, OT>>,
    },*/
}

impl<I> Event<I>
where
    I: Input,
{
    fn name(&self) -> &str {
        match self {
            Event::NewTestcase {
                input: _,
                client_config: _,
                corpus_size: _,
                exit_kind: _,
                observers_buf: _,
                time: _,
                executions: _,
            } => "Testcase",
            Event::UpdateExecutions {
                time: _,
                executions: _,
                phantom: _,
            }
            | Event::UpdateUserStats {
                name: _,
                value: _,
                phantom: _,
            } => "Stats",
            #[cfg(feature = "introspection")]
            Event::UpdatePerfMonitor {
                time: _,
                executions: _,
                introspection_monitor: _,
                phantom: _,
            } => "PerfMonitor",
            Event::Objective { objective_size: _ } => "Objective",
            Event::Log {
                severity_level: _,
                message: _,
                phantom: _,
            } => "Log",
            /*Event::Custom {
                sender_id: _, /*custom_event} => custom_event.name()*/
            } => "todo",*/
        }
    }
}

/// [`EventFirer`] fire an event.
pub trait EventFirer<I>
where
    I: Input,
{
    /// Send off an [`Event`] to the broker
    ///
    /// For multi-processed managers, such as [`llmp::LlmpEventManager`],
    /// this serializes the [`Event`] and commits it to the [`llmp`] page.
    /// In this case, if you `fire` faster than the broker can consume
    /// (for example for each [`Input`], on multiple cores)
    /// the [`llmp`] shared map may fill up and the client will eventually OOM or [`panic`].
    /// This should not happen for a normal use-cases.
    fn fire<S>(&mut self, state: &mut S, event: Event<I>) -> Result<(), Error>;

    /// Serialize all observers for this type and manager
    fn serialize_observers<OT, S>(&mut self, observers: &OT) -> Result<Vec<u8>, Error>
    where
        OT: ObserversTuple<I, S> + serde::Serialize,
    {
        Ok(postcard::to_allocvec(observers)?)
    }

    /// Get the configuration
    fn configuration(&self) -> EventConfig {
        EventConfig::AlwaysUnique
    }
}

/// [`EventFirer`] fire an event.
pub trait ProgressReporter<I>: EventFirer<I>
where
    I: Input,
{
    /// Given the last time, if `monitor_timeout` seconds passed, send off an info/monitor/heartbeat message to the broker.
    /// Returns the new `last` time (so the old one, unless `monitor_timeout` time has passed and monitor have been sent)
    /// Will return an [`crate::Error`], if the stats could not be sent.
    fn maybe_report_progress<S>(
        &mut self,
        state: &mut S,
        last_report_time: Duration,
        monitor_timeout: Duration,
    ) -> Result<Duration, Error>
    where
        S: HasExecutions + HasClientPerfMonitor,
    {
        let executions = *state.executions();
        let cur = current_time();
        // default to 0 here to avoid crashes on clock skew
        if cur.checked_sub(last_report_time).unwrap_or_default() > monitor_timeout {
            // Default no introspection implmentation
            #[cfg(not(feature = "introspection"))]
            self.fire(
                state,
                Event::UpdateExecutions {
                    executions,
                    time: cur,
                    phantom: PhantomData,
                },
            )?;

            // If performance monitor are requested, fire the `UpdatePerfMonitor` event
            #[cfg(feature = "introspection")]
            {
                state
                    .introspection_monitor_mut()
                    .set_current_time(crate::bolts::cpu::read_time_counter());

                // Send the current monitor over to the manager. This `.clone` shouldn't be
                // costly as `ClientPerfMonitor` impls `Copy` since it only contains `u64`s
                self.fire(
                    state,
                    Event::UpdatePerfMonitor {
                        executions,
                        time: cur,
                        introspection_monitor: Box::new(state.introspection_monitor().clone()),
                        phantom: PhantomData,
                    },
                )?;
            }

            Ok(cur)
        } else {
            if cur.as_millis() % 1000 == 0 {}
            Ok(last_report_time)
        }
    }
}

pub trait EventRestarter<S> {
    /// For restarting event managers, implement a way to forward state to their next peers.
    #[inline]
    fn on_restart(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }

    /// Block until we are safe to exit.
    #[inline]
    fn await_restart_safe(&mut self) {}
}

/// [`EventProcessor`] process all the incoming messages
pub trait EventProcessor<E, I, S, Z> {
    /// Lookup for incoming events and process them.
    /// Return the number of processes events or an error
    fn process(&mut self, fuzzer: &mut Z, state: &mut S, executor: &mut E) -> Result<usize, Error>;

    /// Deserialize all observers for this type and manager
    fn deserialize_observers<OT>(&mut self, observers_buf: &[u8]) -> Result<OT, Error>
    where
        OT: ObserversTuple<I, S> + serde::de::DeserializeOwned,
    {
        Ok(postcard::from_bytes(observers_buf)?)
    }
}

pub trait HasEventManagerId {
    /// The id of this manager. For Multiprocessed [`EventManager`]s,
    /// each client sholud have a unique ids.
    fn mgr_id(&self) -> EventManagerId;
}

/// [`EventManager`] is the main communications hub.
/// For the "normal" multi-processed mode, you may want to look into [`LlmpRestartingEventManager`]
pub trait EventManager<E, I, S, Z>:
    EventFirer<I>
    + EventProcessor<E, I, S, Z>
    + EventRestarter<S>
    + HasEventManagerId
    + ProgressReporter<I>
where
    I: Input,
{
}

/// An eventmgr for tests, and as placeholder if you really don't need an event manager.
#[derive(Copy, Clone, Debug)]
pub struct NopEventManager {}

impl<I> EventFirer<I> for NopEventManager
where
    I: Input,
{
    fn fire<S>(&mut self, _state: &mut S, _event: Event<I>) -> Result<(), Error> {
        Ok(())
    }
}

impl<S> EventRestarter<S> for NopEventManager {}

impl<E, I, S, Z> EventProcessor<E, I, S, Z> for NopEventManager {
    fn process(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _executor: &mut E,
    ) -> Result<usize, Error> {
        Ok(0)
    }
}

impl<E, I, S, Z> EventManager<E, I, S, Z> for NopEventManager where I: Input {}

impl<I> ProgressReporter<I> for NopEventManager where I: Input {}

impl HasEventManagerId for NopEventManager {
    fn mgr_id(&self) -> EventManagerId {
        EventManagerId { id: 0 }
    }
}

#[cfg(test)]
mod tests {

    use tuple_list::tuple_list_type;

    use crate::{
        bolts::{
            current_time,
            tuples::{tuple_list, Named},
        },
        events::{Event, EventConfig},
        executors::ExitKind,
        inputs::bytes::BytesInput,
        observers::StdMapObserver,
    };

    static mut MAP: [u32; 4] = [0; 4];

    #[test]
    fn test_event_serde() {
        let obv = StdMapObserver::new("test", unsafe { &mut MAP });
        let map = tuple_list!(obv);
        let observers_buf = postcard::to_allocvec(&map).unwrap();

        let i = BytesInput::new(vec![0]);
        let e = Event::NewTestcase {
            input: i,
            observers_buf: Some(observers_buf),
            exit_kind: ExitKind::Ok,
            corpus_size: 123,
            client_config: EventConfig::AlwaysUnique,
            time: current_time(),
            executions: 0,
        };

        let serialized = postcard::to_allocvec(&e).unwrap();

        let d = postcard::from_bytes::<Event<BytesInput>>(&serialized).unwrap();
        match d {
            Event::NewTestcase {
                input: _,
                observers_buf,
                corpus_size: _,
                exit_kind: _,
                client_config: _,
                time: _,
                executions: _,
            } => {
                let o: tuple_list_type!(StdMapObserver::<u32>) =
                    postcard::from_bytes(observers_buf.as_ref().unwrap()).unwrap();
                assert_eq!("test", o.0.name());
            }
            _ => panic!("mistmatch"),
        };
    }
}
