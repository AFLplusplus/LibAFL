//! Eventmanager manages all events that go to other instances of the fuzzer.

pub mod simple;
pub use simple::*;
pub mod llmp;
use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, hash::Hasher, marker::PhantomData, time::Duration};

use ahash::AHasher;
pub use llmp::*;
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use uuid::Uuid;

use crate::{
    bolts::current_time,
    executors::ExitKind,
    inputs::Input,
    monitors::UserStats,
    observers::ObserversTuple,
    stages::calibrate::UnstableEntriesMetadata,
    state::{HasClientPerfMonitor, HasExecutions, HasMetadata},
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
use crate::{inputs::UsesInput, state::UsesState};

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

/// The result of a custom buf handler added using [`HasCustomBufHandlers::add_custom_buf_handler`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomBufEventResult {
    /// Exit early from event handling
    Handled,
    /// Call the next handler, if available
    Next,
}

/// Indicate if an event worked or not
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum BrokerEventResult {
    /// The broker handled this. No need to pass it on.
    Handled,
    /// Pass this message along to the clients.
    Forward,
}

/// Distinguish a fuzzer by its config
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventConfig {
    /// Always assume unique setups for fuzzer configs
    AlwaysUnique,
    /// Create a fuzzer config from a name hash
    FromName {
        /// The name hash
        name_hash: u64,
    },
    /// Create a fuzzer config from a build-time [`Uuid`]
    #[cfg(feature = "std")]
    BuildID {
        /// The build-time [`Uuid`]
        id: Uuid,
    },
}

impl EventConfig {
    /// Create a new [`EventConfig`] from a name hash
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        let mut hasher = AHasher::new_with_keys(0, 0);
        hasher.write(name.as_bytes());
        EventConfig::FromName {
            name_hash: hasher.finish(),
        }
    }

    /// Create a new [`EventConfig`] from a build-time [`Uuid`]
    #[cfg(feature = "std")]
    #[must_use]
    pub fn from_build_id() -> Self {
        EventConfig::BuildID {
            id: crate::bolts::build_id::get(),
        }
    }

    /// Match if the currenti [`EventConfig`] matches another given config
    #[must_use]
    pub fn match_with(&self, other: &EventConfig) -> bool {
        match self {
            EventConfig::AlwaysUnique => false,
            EventConfig::FromName { name_hash: a } => match other {
                #[cfg(not(feature = "std"))]
                EventConfig::AlwaysUnique => false,
                EventConfig::FromName { name_hash: b } => a == b,
                #[cfg(feature = "std")]
                EventConfig::AlwaysUnique | EventConfig::BuildID { id: _ } => false,
            },
            #[cfg(feature = "std")]
            EventConfig::BuildID { id: a } => match other {
                EventConfig::AlwaysUnique | EventConfig::FromName { name_hash: _ } => false,
                EventConfig::BuildID { id: b } => a == b,
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
    UpdateExecStats {
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

        /// phantomm data
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
    /// Sends a custom buffer to other clients
    CustomBuf {
        /// The buffer
        buf: Vec<u8>,
        /// Tag of this buffer
        tag: String,
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
            Event::UpdateExecStats {
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
            Event::Objective { .. } => "Objective",
            Event::Log {
                severity_level: _,
                message: _,
                phantom: _,
            } => "Log",
            Event::CustomBuf { .. } => "CustomBuf",
            /*Event::Custom {
                sender_id: _, /*custom_event} => custom_event.name()*/
            } => "todo",*/
        }
    }
}

/// [`EventFirer`] fire an event.
pub trait EventFirer: UsesState {
    /// Send off an [`Event`] to the broker
    ///
    /// For multi-processed managers, such as [`llmp::LlmpEventManager`],
    /// this serializes the [`Event`] and commits it to the [`llmp`] page.
    /// In this case, if you `fire` faster than the broker can consume
    /// (for example for each [`Input`], on multiple cores)
    /// the [`llmp`] shared map may fill up and the client will eventually OOM or [`panic`].
    /// This should not happen for a normal use-case.
    fn fire(
        &mut self,
        state: &mut Self::State,
        event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error>;

    /// Send off an [`Event::Log`] event to the broker.
    /// This is a shortcut for [`EventFirer::fire`] with [`Event::Log`] as argument.
    fn log(
        &mut self,
        state: &mut Self::State,
        severity_level: LogSeverity,
        message: String,
    ) -> Result<(), Error> {
        self.fire(
            state,
            Event::Log {
                severity_level,
                message,
                phantom: PhantomData,
            },
        )
    }

    /// Serialize all observers for this type and manager
    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Vec<u8>, Error>
    where
        OT: ObserversTuple<Self::State> + Serialize,
    {
        Ok(postcard::to_allocvec(observers)?)
    }

    /// Get the configuration
    fn configuration(&self) -> EventConfig {
        EventConfig::AlwaysUnique
    }
}

/// [`ProgressReporter`] report progress to the broker.
pub trait ProgressReporter: EventFirer
where
    Self::State: HasClientPerfMonitor + HasMetadata + HasExecutions,
{
    /// Given the last time, if `monitor_timeout` seconds passed, send off an info/monitor/heartbeat message to the broker.
    /// Returns the new `last` time (so the old one, unless `monitor_timeout` time has passed and monitor have been sent)
    /// Will return an [`crate::Error`], if the stats could not be sent.
    fn maybe_report_progress(
        &mut self,
        state: &mut Self::State,
        last_report_time: Duration,
        monitor_timeout: Duration,
    ) -> Result<Duration, Error> {
        let executions = *state.executions();
        let cur = current_time();
        // default to 0 here to avoid crashes on clock skew
        if cur.checked_sub(last_report_time).unwrap_or_default() > monitor_timeout {
            // Default no introspection implmentation
            #[cfg(not(feature = "introspection"))]
            self.fire(
                state,
                Event::UpdateExecStats {
                    executions,
                    time: cur,
                    phantom: PhantomData,
                },
            )?;

            // Send the stability event to the broker
            if let Some(meta) = state.metadata().get::<UnstableEntriesMetadata>() {
                let unstable_entries = meta.unstable_entries().len();
                let map_len = meta.map_len();
                self.fire(
                    state,
                    Event::UpdateUserStats {
                        name: "stability".to_string(),
                        value: UserStats::Ratio(unstable_entries as u64, map_len as u64),
                        phantom: PhantomData,
                    },
                )?;
            }

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

/// Restartable trait
pub trait EventRestarter: UsesState {
    /// For restarting event managers, implement a way to forward state to their next peers.
    #[inline]
    fn on_restart(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        Ok(())
    }

    /// Block until we are safe to exit.
    #[inline]
    fn await_restart_safe(&mut self) {}
}

/// [`EventProcessor`] process all the incoming messages
pub trait EventProcessor<E, Z>: UsesState {
    /// Lookup for incoming events and process them.
    /// Return the number of processes events or an error
    fn process(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        executor: &mut E,
    ) -> Result<usize, Error>;
}
/// The id of this [`EventManager`].
/// For multi processed [`EventManager`]s,
/// each connected client should have a unique ids.
pub trait HasEventManagerId {
    /// The id of this manager. For Multiprocessed [`EventManager`]s,
    /// each client should have a unique ids.
    fn mgr_id(&self) -> EventManagerId;
}

/// [`EventManager`] is the main communications hub.
/// For the "normal" multi-processed mode, you may want to look into [`LlmpRestartingEventManager`]
pub trait EventManager<E, Z>:
    EventFirer + EventProcessor<E, Z> + EventRestarter + HasEventManagerId + ProgressReporter
where
    Self::State: HasClientPerfMonitor + HasMetadata + HasExecutions,
{
}

/// The handler function for custom buffers exchanged via [`EventManager`]
type CustomBufHandlerFn<S> =
    dyn FnMut(&mut S, &String, &[u8]) -> Result<CustomBufEventResult, Error>;

/// Supports custom buf handlers to handle `CustomBuf` events.
pub trait HasCustomBufHandlers: UsesState {
    /// Adds a custom buffer handler that will run for each incoming `CustomBuf` event.
    fn add_custom_buf_handler(&mut self, handler: Box<CustomBufHandlerFn<Self::State>>);
}

/// An eventmgr for tests, and as placeholder if you really don't need an event manager.
#[derive(Copy, Clone, Debug, Default)]
pub struct NopEventManager<S> {
    phantom: PhantomData<S>,
}

impl<S> NopEventManager<S> {
    /// Creates a new [`NopEventManager`]
    #[must_use]
    pub fn new() -> Self {
        NopEventManager {
            phantom: PhantomData,
        }
    }
}

impl<S> UsesState for NopEventManager<S>
where
    S: UsesInput,
{
    type State = S;
}

impl<S> EventFirer for NopEventManager<S>
where
    S: UsesInput,
{
    fn fire(
        &mut self,
        _state: &mut Self::State,
        _event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<S> EventRestarter for NopEventManager<S> where S: UsesInput {}

impl<E, S, Z> EventProcessor<E, Z> for NopEventManager<S>
where
    S: UsesInput + HasClientPerfMonitor + HasExecutions,
{
    fn process(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut Self::State,
        _executor: &mut E,
    ) -> Result<usize, Error> {
        Ok(0)
    }
}

impl<E, S, Z> EventManager<E, Z> for NopEventManager<S> where
    S: UsesInput + HasClientPerfMonitor + HasExecutions + HasMetadata
{
}

impl<S> HasCustomBufHandlers for NopEventManager<S>
where
    S: UsesInput,
{
    fn add_custom_buf_handler(
        &mut self,
        _handler: Box<
            dyn FnMut(&mut Self::State, &String, &[u8]) -> Result<CustomBufEventResult, Error>,
        >,
    ) {
    }
}

impl<S> ProgressReporter for NopEventManager<S> where
    S: UsesInput + HasClientPerfMonitor + HasExecutions + HasMetadata
{
}

impl<S> HasEventManagerId for NopEventManager<S> {
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
                let o: tuple_list_type!(StdMapObserver::<u32, false>) =
                    postcard::from_bytes(observers_buf.as_ref().unwrap()).unwrap();
                assert_eq!("test", o.0.name());
            }
            _ => panic!("mistmatch"),
        };
    }
}

/// `EventManager` Python bindings
#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use pyo3::prelude::*;

    use crate::{
        events::{
            simple::pybind::PythonSimpleEventManager, Event, EventFirer, EventManager,
            EventManagerId, EventProcessor, EventRestarter, HasEventManagerId, ProgressReporter,
        },
        executors::pybind::PythonExecutor,
        fuzzer::pybind::PythonStdFuzzer,
        inputs::BytesInput,
        state::{pybind::PythonStdState, UsesState},
        Error,
    };

    #[derive(Debug, Clone)]
    pub enum PythonEventManagerWrapper {
        Simple(Py<PythonSimpleEventManager>),
    }

    /// EventManager Trait binding
    #[pyclass(unsendable, name = "EventManager")]
    #[derive(Debug, Clone)]
    pub struct PythonEventManager {
        pub wrapper: PythonEventManagerWrapper,
    }

    macro_rules! unwrap_me {
        ($wrapper:expr, $name:ident, $body:block) => {
            crate::unwrap_me_body!($wrapper, $name, $body, PythonEventManagerWrapper, {
                Simple
            })
        };
    }

    macro_rules! unwrap_me_mut {
        ($wrapper:expr, $name:ident, $body:block) => {
            crate::unwrap_me_mut_body!($wrapper, $name, $body, PythonEventManagerWrapper, {
                Simple
            })
        };
    }

    #[pymethods]
    impl PythonEventManager {
        #[staticmethod]
        #[must_use]
        pub fn new_simple(mgr: Py<PythonSimpleEventManager>) -> Self {
            Self {
                wrapper: PythonEventManagerWrapper::Simple(mgr),
            }
        }
    }

    impl UsesState for PythonEventManager {
        type State = PythonStdState;
    }

    impl EventFirer for PythonEventManager {
        fn fire(&mut self, state: &mut Self::State, event: Event<BytesInput>) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, e, { e.fire(state, event) })
        }
    }

    impl EventRestarter for PythonEventManager {}

    impl EventProcessor<PythonExecutor, PythonStdFuzzer> for PythonEventManager {
        fn process(
            &mut self,
            fuzzer: &mut PythonStdFuzzer,
            state: &mut PythonStdState,
            executor: &mut PythonExecutor,
        ) -> Result<usize, Error> {
            unwrap_me_mut!(self.wrapper, e, { e.process(fuzzer, state, executor) })
        }
    }

    impl ProgressReporter for PythonEventManager {}

    impl HasEventManagerId for PythonEventManager {
        fn mgr_id(&self) -> EventManagerId {
            unwrap_me!(self.wrapper, e, { e.mgr_id() })
        }
    }

    impl EventManager<PythonExecutor, PythonStdFuzzer> for PythonEventManager {}

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonEventManager>()?;
        Ok(())
    }
}
