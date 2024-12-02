//! An [`EventManager`] manages all events that go to other instances of the fuzzer.
//! The messages are commonly information about new Testcases as well as stats and other [`Event`]s.

pub mod events_hooks;
pub use events_hooks::*;

pub mod simple;
pub use simple::*;
#[cfg(all(unix, feature = "std"))]
pub mod centralized;
#[cfg(all(unix, feature = "std"))]
pub use centralized::*;
#[cfg(feature = "std")]
#[allow(clippy::ignored_unit_patterns)]
pub mod launcher;
#[allow(clippy::ignored_unit_patterns)]
pub mod llmp;
pub use llmp::*;
#[cfg(feature = "tcp_manager")]
#[allow(clippy::ignored_unit_patterns)]
pub mod tcp;

pub mod broker_hooks;
use alloc::{borrow::Cow, boxed::Box, string::String, vec::Vec};
use core::{
    fmt,
    hash::{BuildHasher, Hasher},
    marker::PhantomData,
    time::Duration,
};

use ahash::RandomState;
pub use broker_hooks::*;
#[cfg(feature = "std")]
pub use launcher::*;
#[cfg(all(unix, feature = "std"))]
use libafl_bolts::os::unix_signals::{siginfo_t, ucontext_t, Signal, SignalHandler};
#[cfg(all(unix, feature = "std"))]
use libafl_bolts::os::CTRL_C_EXIT;
use libafl_bolts::{
    current_time,
    tuples::{Handle, MatchNameRef},
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use uuid::Uuid;

#[cfg(feature = "introspection")]
use crate::state::HasClientPerfMonitor;
use crate::{
    executors::ExitKind,
    inputs::Input,
    monitors::UserStats,
    observers::ObserversTuple,
    state::{HasExecutions, HasLastReportTime, State},
    Error, HasMetadata,
};
#[cfg(feature = "scalability_introspection")]
use crate::{
    monitors::{AggregatorOps, UserStatsValue},
    state::HasScalabilityMonitor,
};

/// Multi-machine mode
#[cfg(all(unix, feature = "std", feature = "multi_machine"))]
pub mod multi_machine;

/// Check if ctrl-c is sent with this struct
#[cfg(all(unix, feature = "std"))]
pub static mut EVENTMGR_SIGHANDLER_STATE: ShutdownSignalData = ShutdownSignalData {};

/// A signal handler for catching `ctrl-c`.
///
/// The purpose of this signal handler is solely for calling `exit()` with a specific exit code 100
/// In this way, the restarting manager can tell that we really want to exit
#[cfg(all(unix, feature = "std"))]
#[derive(Debug, Clone)]
pub struct ShutdownSignalData {}

/// Shutdown handler. `SigTerm`, `SigInterrupt`, `SigQuit` call this
/// We can't handle SIGKILL in the signal handler, this means that you shouldn't kill your fuzzer with `kill -9` because then the shmem segments are never freed
///
/// # Safety
/// This will exit the program
#[cfg(all(unix, feature = "std"))]
impl SignalHandler for ShutdownSignalData {
    unsafe fn handle(
        &mut self,
        _signal: Signal,
        _info: &mut siginfo_t,
        _context: Option<&mut ucontext_t>,
    ) {
        unsafe {
            #[cfg(unix)]
            libc::_exit(CTRL_C_EXIT);

            #[cfg(windows)]
            windows::Win32::System::Threading::ExitProcess(100);
        }
    }

    fn signals(&self) -> Vec<Signal> {
        vec![Signal::SigTerm, Signal::SigInterrupt, Signal::SigQuit]
    }
}

/// A per-fuzzer unique `ID`, usually starting with `0` and increasing
/// by `1` in multiprocessed [`EventManager`]s, such as [`LlmpEventManager`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct EventManagerId(
    /// The id
    pub usize,
);

#[cfg(all(unix, feature = "std", feature = "multi_machine"))]
use crate::events::multi_machine::NodeId;
#[cfg(feature = "introspection")]
use crate::monitors::ClientPerfMonitor;
use crate::{
    inputs::UsesInput, observers::TimeObserver, stages::HasCurrentStageId, state::UsesState,
};

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

impl From<LogSeverity> for log::Level {
    fn from(value: LogSeverity) -> Self {
        match value {
            LogSeverity::Debug => log::Level::Debug,
            LogSeverity::Info => log::Level::Info,
            LogSeverity::Warn => log::Level::Trace,
            LogSeverity::Error => log::Level::Error,
        }
    }
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
        let mut hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher(); //AHasher::new_with_keys(0, 0);
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
            id: libafl_bolts::build_id::get(),
        }
    }

    /// Match if the current [`EventConfig`] matches another given config
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

// TODO remove forward_id as not anymore needed for centralized
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
        /// The original sender if, if forwarded
        forward_id: Option<libafl_bolts::ClientId>,
        /// The (multi-machine) node from which the tc is from, if any
        #[cfg(all(unix, feature = "std", feature = "multi_machine"))]
        node_id: Option<NodeId>,
    },
    /// New stats event to monitor.
    UpdateExecStats {
        /// The time of generation of the [`Event`]
        time: Duration,
        /// The executions of this client
        executions: u64,
        /// [`PhantomData`]
        phantom: PhantomData<I>,
    },
    /// New user stats event to monitor.
    UpdateUserStats {
        /// Custom user monitor name
        name: Cow<'static, str>,
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
        executions: u64,
        /// Current performance statistics
        introspection_monitor: Box<ClientPerfMonitor>,

        /// phantomm data
        phantom: PhantomData<I>,
    },
    /// A new objective was found
    Objective {
        /// Objective corpus size
        objective_size: usize,
        /// The time when this event was created
        time: Duration,
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
    /// Exit gracefully
    Stop,
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
    /// Event's corresponding name
    pub fn name(&self) -> &str {
        match self {
            Event::NewTestcase { .. } => "Testcase",
            Event::UpdateExecStats { .. } => "Client Heartbeat",
            Event::UpdateUserStats { .. } => "UserStats",
            #[cfg(feature = "introspection")]
            Event::UpdatePerfMonitor { .. } => "PerfMonitor",
            Event::Objective { .. } => "Objective",
            Event::Log { .. } => "Log",
            Event::CustomBuf { .. } => "CustomBuf",
            /*Event::Custom {
                sender_id: _, /*custom_event} => custom_event.name()*/
            } => "todo",*/
            Event::Stop => "Stop",
        }
    }

    /// Event's corresponding name with additional info
    fn name_detailed(&self) -> Cow<'static, str> {
        match self {
            Event::NewTestcase { input, .. } => {
                Cow::Owned(format!("Testcase {}", input.generate_name(None)))
            }
            Event::UpdateExecStats { .. } => Cow::Borrowed("Client Heartbeat"),
            Event::UpdateUserStats { .. } => Cow::Borrowed("UserStats"),
            #[cfg(feature = "introspection")]
            Event::UpdatePerfMonitor { .. } => Cow::Borrowed("PerfMonitor"),
            Event::Objective { .. } => Cow::Borrowed("Objective"),
            Event::Log { .. } => Cow::Borrowed("Log"),
            Event::CustomBuf { .. } => Cow::Borrowed("CustomBuf"),
            Event::Stop => Cow::Borrowed("Stop"),
            /*Event::Custom {
                sender_id: _, /*custom_event} => custom_event.name()*/
            } => "todo",*/
        }
    }

    /// Returns true if self is a new testcase, false otherwise.
    pub fn is_new_testcase(&self) -> bool {
        matches!(self, Event::NewTestcase { .. })
    }
}

/// [`EventFirer`] fires an event.
pub trait EventFirer: UsesState {
    /// Send off an [`Event`] to the broker
    ///
    /// For multi-processed managers, such as [`LlmpEventManager`],
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
    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error>
    where
        OT: ObserversTuple<<Self as UsesInput>::Input, Self::State> + Serialize,
    {
        Ok(Some(postcard::to_allocvec(observers)?))
    }

    /// Get the configuration
    fn configuration(&self) -> EventConfig {
        EventConfig::AlwaysUnique
    }

    /// Return if we really send this event or not
    fn should_send(&self) -> bool;
}

/// [`ProgressReporter`] report progress to the broker.
pub trait ProgressReporter: EventFirer
where
    Self::State: HasMetadata + HasExecutions + HasLastReportTime,
{
    /// Given the last time, if `monitor_timeout` seconds passed, send off an info/monitor/heartbeat message to the broker.
    /// Returns the new `last` time (so the old one, unless `monitor_timeout` time has passed and monitor have been sent)
    /// Will return an [`Error`], if the stats could not be sent.
    fn maybe_report_progress(
        &mut self,
        state: &mut Self::State,
        monitor_timeout: Duration,
    ) -> Result<(), Error> {
        let Some(last_report_time) = state.last_report_time() else {
            // this is the first time we execute, no need to report progress just yet.
            *state.last_report_time_mut() = Some(current_time());
            return Ok(());
        };
        let cur = current_time();
        // default to 0 here to avoid crashes on clock skew
        if cur.checked_sub(*last_report_time).unwrap_or_default() > monitor_timeout {
            // report_progress sets a new `last_report_time` internally.
            self.report_progress(state)?;
        }
        Ok(())
    }

    /// Send off an info/monitor/heartbeat message to the broker.
    /// Will return an [`Error`], if the stats could not be sent.
    fn report_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        let executions = *state.executions();
        let cur = current_time();

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

        // If performance monitor are requested, fire the `UpdatePerfMonitor` event
        #[cfg(feature = "introspection")]
        {
            state
                .introspection_monitor_mut()
                .set_current_time(libafl_bolts::cpu::read_time_counter());

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

        // If we are measuring scalability stuff..
        #[cfg(feature = "scalability_introspection")]
        {
            let imported_with_observer = state.scalability_monitor().testcase_with_observers;
            let imported_without_observer = state.scalability_monitor().testcase_without_observers;

            self.fire(
                state,
                Event::UpdateUserStats {
                    name: Cow::from("total imported"),
                    value: UserStats::new(
                        UserStatsValue::Number(
                            (imported_with_observer + imported_without_observer) as u64,
                        ),
                        AggregatorOps::Avg,
                    ),
                    phantom: PhantomData,
                },
            )?;
        }

        *state.last_report_time_mut() = Some(cur);

        Ok(())
    }
}

/// Restartable trait
pub trait EventRestarter: UsesState {
    /// For restarting event managers, implement a way to forward state to their next peers.
    /// You *must* ensure that [`HasCurrentStageId::on_restart`] will be invoked in this method, by you
    /// or an internal [`EventRestarter`], before the state is saved for recovery.
    #[inline]
    fn on_restart(&mut self, state: &mut Self::State) -> Result<(), Error> {
        state.on_restart()?;
        self.await_restart_safe();
        Ok(())
    }

    /// Send information that this client is exiting.
    /// No need to restart us any longer, and no need to print an error, either.
    fn send_exiting(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Block until we are safe to exit, usually called inside `on_restart`.
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

    /// Shutdown gracefully; typically without saving state.
    fn on_shutdown(&mut self) -> Result<(), Error>;
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
    Self::State: HasMetadata + HasExecutions + HasLastReportTime,
{
}

/// The handler function for custom buffers exchanged via [`EventManager`]
type CustomBufHandlerFn<S> = dyn FnMut(&mut S, &str, &[u8]) -> Result<CustomBufEventResult, Error>;

/// Supports custom buf handlers to handle `CustomBuf` events.
pub trait HasCustomBufHandlers: UsesState {
    /// Adds a custom buffer handler that will run for each incoming `CustomBuf` event.
    fn add_custom_buf_handler(&mut self, handler: Box<CustomBufHandlerFn<Self::State>>);
}

/// An eventmgr for tests, and as placeholder if you really don't need an event manager.
#[derive(Copy, Clone, Debug)]
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

impl<S> Default for NopEventManager<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> UsesState for NopEventManager<S>
where
    S: State,
{
    type State = S;
}

impl<S> EventFirer for NopEventManager<S>
where
    S: State,
{
    fn should_send(&self) -> bool {
        true
    }

    fn fire(
        &mut self,
        _state: &mut Self::State,
        _event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<S> EventRestarter for NopEventManager<S> where S: State {}

impl<E, S, Z> EventProcessor<E, Z> for NopEventManager<S>
where
    S: State + HasExecutions,
{
    fn process(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut Self::State,
        _executor: &mut E,
    ) -> Result<usize, Error> {
        Ok(0)
    }

    fn on_shutdown(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl<E, S, Z> EventManager<E, Z> for NopEventManager<S> where
    S: State + HasExecutions + HasLastReportTime + HasMetadata
{
}

impl<S> HasCustomBufHandlers for NopEventManager<S>
where
    S: State,
{
    fn add_custom_buf_handler(
        &mut self,
        _handler: Box<
            dyn FnMut(&mut Self::State, &str, &[u8]) -> Result<CustomBufEventResult, Error>,
        >,
    ) {
    }
}

impl<S> ProgressReporter for NopEventManager<S> where
    S: State + HasExecutions + HasLastReportTime + HasMetadata
{
}

impl<S> HasEventManagerId for NopEventManager<S> {
    fn mgr_id(&self) -> EventManagerId {
        EventManagerId(0)
    }
}

/// An [`EventManager`] type that wraps another manager, but captures a `monitor` type as well.
/// This is useful to keep the same API between managers with and without an internal `monitor`.
#[derive(Copy, Clone, Debug)]
pub struct MonitorTypedEventManager<EM, M> {
    inner: EM,
    phantom: PhantomData<M>,
}

impl<EM, M> MonitorTypedEventManager<EM, M> {
    /// Creates a new [`EventManager`] that wraps another manager, but captures a `monitor` type as well.
    #[must_use]
    pub fn new(inner: EM) -> Self {
        MonitorTypedEventManager {
            inner,
            phantom: PhantomData,
        }
    }
}

impl<EM, M> UsesState for MonitorTypedEventManager<EM, M>
where
    EM: UsesState,
{
    type State = EM::State;
}

impl<EM, M> EventFirer for MonitorTypedEventManager<EM, M>
where
    EM: EventFirer,
{
    fn should_send(&self) -> bool {
        true
    }

    #[inline]
    fn fire(
        &mut self,
        state: &mut Self::State,
        event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        self.inner.fire(state, event)
    }

    #[inline]
    fn log(
        &mut self,
        state: &mut Self::State,
        severity_level: LogSeverity,
        message: String,
    ) -> Result<(), Error> {
        self.inner.log(state, severity_level, message)
    }

    #[inline]
    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error>
    where
        OT: ObserversTuple<<Self as UsesInput>::Input, Self::State> + Serialize,
    {
        self.inner.serialize_observers(observers)
    }

    #[inline]
    fn configuration(&self) -> EventConfig {
        self.inner.configuration()
    }
}

impl<EM, M> EventRestarter for MonitorTypedEventManager<EM, M>
where
    EM: EventRestarter,
{
    #[inline]
    fn on_restart(&mut self, state: &mut Self::State) -> Result<(), Error> {
        self.inner.on_restart(state)
    }

    #[inline]
    fn send_exiting(&mut self) -> Result<(), Error> {
        self.inner.send_exiting()
    }

    #[inline]
    fn await_restart_safe(&mut self) {
        self.inner.await_restart_safe();
    }
}

impl<E, EM, M, Z> EventProcessor<E, Z> for MonitorTypedEventManager<EM, M>
where
    EM: EventProcessor<E, Z>,
{
    #[inline]
    fn process(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        executor: &mut E,
    ) -> Result<usize, Error> {
        self.inner.process(fuzzer, state, executor)
    }

    fn on_shutdown(&mut self) -> Result<(), Error> {
        self.inner.on_shutdown()
    }
}

impl<E, EM, M, Z> EventManager<E, Z> for MonitorTypedEventManager<EM, M>
where
    EM: EventManager<E, Z>,
    Self::State: HasLastReportTime + HasExecutions + HasMetadata,
{
}

impl<EM, M> HasCustomBufHandlers for MonitorTypedEventManager<EM, M>
where
    Self: UsesState,
    EM: HasCustomBufHandlers<State = Self::State>,
{
    #[inline]
    fn add_custom_buf_handler(
        &mut self,
        handler: Box<
            dyn FnMut(&mut Self::State, &str, &[u8]) -> Result<CustomBufEventResult, Error>,
        >,
    ) {
        self.inner.add_custom_buf_handler(handler);
    }
}

impl<EM, M> ProgressReporter for MonitorTypedEventManager<EM, M>
where
    Self: UsesState,
    EM: ProgressReporter<State = Self::State>,
    Self::State: HasLastReportTime + HasExecutions + HasMetadata,
{
    #[inline]
    fn maybe_report_progress(
        &mut self,
        state: &mut Self::State,
        monitor_timeout: Duration,
    ) -> Result<(), Error> {
        self.inner.maybe_report_progress(state, monitor_timeout)
    }

    #[inline]
    fn report_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        self.inner.report_progress(state)
    }
}

impl<EM, M> HasEventManagerId for MonitorTypedEventManager<EM, M>
where
    EM: HasEventManagerId,
{
    #[inline]
    fn mgr_id(&self) -> EventManagerId {
        self.inner.mgr_id()
    }
}

/// Collected stats to decide if observers must be serialized or not
pub trait AdaptiveSerializer {
    /// Expose the collected observers serialization time
    fn serialization_time(&self) -> Duration;
    /// Expose the collected observers deserialization time
    fn deserialization_time(&self) -> Duration;
    /// How many times observers were serialized
    fn serializations_cnt(&self) -> usize;
    /// How many times shoukd have been serialized an observer
    fn should_serialize_cnt(&self) -> usize;

    /// Expose the collected observers serialization time (mut)
    fn serialization_time_mut(&mut self) -> &mut Duration;
    /// Expose the collected observers deserialization time (mut)
    fn deserialization_time_mut(&mut self) -> &mut Duration;
    /// How many times observers were serialized (mut)
    fn serializations_cnt_mut(&mut self) -> &mut usize;
    /// How many times shoukd have been serialized an observer (mut)
    fn should_serialize_cnt_mut(&mut self) -> &mut usize;

    /// A [`Handle`] to the time observer to determine the `time_factor`
    fn time_ref(&self) -> &Option<Handle<TimeObserver>>;

    /// Serialize the observer using the `time_factor` and `percentage_threshold`.
    /// These parameters are unique to each of the different types of `EventManager`
    fn serialize_observers_adaptive<S, OT>(
        &mut self,
        observers: &OT,
        time_factor: u32,
        percentage_threshold: usize,
    ) -> Result<Option<Vec<u8>>, Error>
    where
        OT: ObserversTuple<S::Input, S> + Serialize,
        S: UsesInput,
    {
        match self.time_ref() {
            Some(t) => {
                let exec_time = observers
                    .get(t)
                    .map(|o| o.last_runtime().unwrap_or(Duration::ZERO))
                    .unwrap();

                let mut must_ser = (self.serialization_time() + self.deserialization_time())
                    * time_factor
                    < exec_time;
                if must_ser {
                    *self.should_serialize_cnt_mut() += 1;
                }

                if self.serializations_cnt() > 32 {
                    must_ser = (self.should_serialize_cnt() * 100 / self.serializations_cnt())
                        > percentage_threshold;
                }

                if self.serialization_time() == Duration::ZERO
                    || must_ser
                    || self.serializations_cnt().trailing_zeros() >= 8
                {
                    let start = current_time();
                    let ser = postcard::to_allocvec(observers)?;
                    *self.serialization_time_mut() = current_time() - start;

                    *self.serializations_cnt_mut() += 1;
                    Ok(Some(ser))
                } else {
                    *self.serializations_cnt_mut() += 1;
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {

    use libafl_bolts::{current_time, tuples::tuple_list, Named};
    use tuple_list::tuple_list_type;

    use crate::{
        events::{Event, EventConfig},
        executors::ExitKind,
        inputs::bytes::BytesInput,
        observers::StdMapObserver,
    };

    static mut MAP: [u32; 4] = [0; 4];

    #[test]
    fn test_event_serde() {
        let map_ptr = &raw const MAP;
        let obv = unsafe {
            let len = (*map_ptr).len();
            StdMapObserver::from_mut_ptr("test", &raw mut MAP as *mut u32, len)
        };
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
            forward_id: None,
            #[cfg(all(unix, feature = "std", feature = "multi_machine"))]
            node_id: None,
        };

        let serialized = postcard::to_allocvec(&e).unwrap();

        let d = postcard::from_bytes::<Event<BytesInput>>(&serialized).unwrap();
        match d {
            Event::NewTestcase { observers_buf, .. } => {
                let o: tuple_list_type!(StdMapObserver::<u32, false>) =
                    postcard::from_bytes(observers_buf.as_ref().unwrap()).unwrap();
                assert_eq!("test", o.0.name());
            }
            _ => panic!("mistmatch"),
        };
    }
}
