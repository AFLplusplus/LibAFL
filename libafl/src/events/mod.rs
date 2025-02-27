//! An `EventManager` manages all events that go to other instances of the fuzzer.
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
pub mod launcher;

pub mod llmp;
pub use llmp::*;
#[cfg(feature = "tcp_manager")]
pub mod tcp;

pub mod broker_hooks;
#[cfg(feature = "introspection")]
use alloc::boxed::Box;
use alloc::{borrow::Cow, string::String, vec::Vec};
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
use libafl_bolts::os::CTRL_C_EXIT;
#[cfg(all(unix, feature = "std"))]
use libafl_bolts::os::unix_signals::{Signal, SignalHandler, siginfo_t, ucontext_t};
#[cfg(feature = "std")]
use libafl_bolts::tuples::MatchNameRef;
use libafl_bolts::{current_time, tuples::Handle};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use uuid::Uuid;

use crate::{
    Error, HasMetadata,
    executors::ExitKind,
    inputs::Input,
    monitors::stats::UserStats,
    state::{HasExecutions, HasLastReportTime, MaybeHasClientPerfMonitor},
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
/// by `1` in multiprocessed `EventManagers`, such as [`LlmpRestartingEventManager`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct EventManagerId(
    /// The id
    pub usize,
);

#[cfg(all(unix, feature = "std", feature = "multi_machine"))]
use crate::events::multi_machine::NodeId;
#[cfg(feature = "introspection")]
use crate::monitors::stats::ClientPerfStats;
use crate::{observers::TimeObserver, state::HasCurrentStageId};

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
    fn from(name: &str) -> Self {
        Self::from_name(name)
    }
}

impl From<String> for EventConfig {
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
pub enum Event<I> {
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
        introspection_stats: Box<ClientPerfStats>,

        /// phantomm data
        phantom: PhantomData<I>,
    },
    /// A new objective was found
    Objective {
        /// Input of newly found Objective
        #[cfg(feature = "share_objectives")]
        input: I,
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
    /// Exit gracefully
    Stop,
    /*/// A custom type
    Custom {
        // TODO: Allow custom events
        // custom_event: Box<dyn CustomEvent<I, OT>>,
    },*/
}

impl<I> Event<I> {
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
            /*Event::Custom {
                sender_id: _, /*custom_event} => custom_event.name()*/
            } => "todo",*/
            Event::Stop => "Stop",
        }
    }

    /// Event's corresponding name with additional info
    fn name_detailed(&self) -> Cow<'static, str>
    where
        I: Input,
    {
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
pub trait EventFirer<I, S> {
    /// Send off an [`Event`] to the broker
    ///
    /// For multi-processed managers, such as [`LlmpRestartingEventManager`],
    /// this serializes the [`Event`] and commits it to the [`llmp`] page.
    /// In this case, if you `fire` faster than the broker can consume
    /// (for example for each [`Input`], on multiple cores)
    /// the [`llmp`] shared map may fill up and the client will eventually OOM or [`panic`].
    /// This should not happen for a normal use-case.
    fn fire(&mut self, state: &mut S, event: Event<I>) -> Result<(), Error>;

    /// Send off an [`Event::Log`] event to the broker.
    /// This is a shortcut for [`EventFirer::fire`] with [`Event::Log`] as argument.
    fn log(
        &mut self,
        state: &mut S,
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

    /// Get the configuration
    fn configuration(&self) -> EventConfig {
        EventConfig::AlwaysUnique
    }

    /// Return if we really send this event or not
    fn should_send(&self) -> bool;
}

/// Serialize all observers for this type and manager
/// Serialize the observer using the `time_factor` and `percentage_threshold`.
/// These parameters are unique to each of the different types of `EventManager`
#[cfg(feature = "std")]
pub(crate) fn serialize_observers_adaptive<EM, OT>(
    manager: &mut EM,
    observers: &OT,
    time_factor: u32,
    percentage_threshold: usize,
) -> Result<Option<Vec<u8>>, Error>
where
    EM: AdaptiveSerializer,
    OT: MatchNameRef + Serialize,
{
    match manager.time_ref() {
        Some(t) => {
            let exec_time = observers
                .get(t)
                .map(|o| o.last_runtime().unwrap_or(Duration::ZERO))
                .unwrap();

            let mut must_ser = (manager.serialization_time() + manager.deserialization_time())
                * time_factor
                < exec_time;
            if must_ser {
                *manager.should_serialize_cnt_mut() += 1;
            }

            if manager.serializations_cnt() > 32 {
                must_ser = (manager.should_serialize_cnt() * 100 / manager.serializations_cnt())
                    > percentage_threshold;
            }

            if manager.serialization_time() == Duration::ZERO
                || must_ser
                || manager.serializations_cnt().trailing_zeros() >= 8
            {
                let start = current_time();
                let ser = postcard::to_allocvec(observers)?;
                *manager.serialization_time_mut() = current_time() - start;

                *manager.serializations_cnt_mut() += 1;
                Ok(Some(ser))
            } else {
                *manager.serializations_cnt_mut() += 1;
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

/// Default implementation of [`ProgressReporter::maybe_report_progress`] for implementors with the
/// given constraints
pub fn std_maybe_report_progress<PR, S>(
    reporter: &mut PR,
    state: &mut S,
    monitor_timeout: Duration,
) -> Result<(), Error>
where
    PR: ProgressReporter<S>,
    S: HasMetadata + HasExecutions + HasLastReportTime,
{
    let Some(last_report_time) = state.last_report_time() else {
        // this is the first time we execute, no need to report progress just yet.
        *state.last_report_time_mut() = Some(current_time());
        return Ok(());
    };
    let cur = current_time();
    // default to 0 here to avoid crashes on clock skew
    if cur.checked_sub(*last_report_time).unwrap_or_default() > monitor_timeout {
        // report_progress sets a new `last_report_time` internally.
        reporter.report_progress(state)?;
    }
    Ok(())
}

/// Default implementation of [`ProgressReporter::report_progress`] for implementors with the
/// given constraints
pub fn std_report_progress<EM, I, S>(reporter: &mut EM, state: &mut S) -> Result<(), Error>
where
    EM: EventFirer<I, S>,
    S: HasExecutions + HasLastReportTime + MaybeHasClientPerfMonitor,
{
    let executions = *state.executions();
    let cur = current_time();

    // Default no introspection implmentation
    #[cfg(not(feature = "introspection"))]
    reporter.fire(
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
            .introspection_stats_mut()
            .set_current_time(libafl_bolts::cpu::read_time_counter());

        // Send the current monitor over to the manager. This `.clone` shouldn't be
        // costly as `ClientPerfStats` impls `Copy` since it only contains `u64`s
        reporter.fire(
            state,
            Event::UpdatePerfMonitor {
                executions,
                time: cur,
                introspection_stats: Box::new(state.introspection_stats().clone()),
                phantom: PhantomData,
            },
        )?;
    }

    *state.last_report_time_mut() = Some(cur);

    Ok(())
}

/// [`ProgressReporter`] report progress to the broker.
pub trait ProgressReporter<S> {
    /// Given the last time, if `monitor_timeout` seconds passed, send off an info/monitor/heartbeat message to the broker.
    /// Returns the new `last` time (so the old one, unless `monitor_timeout` time has passed and monitor have been sent)
    /// Will return an [`Error`], if the stats could not be sent.
    /// [`std_maybe_report_progress`] is the standard implementation that you can call.
    fn maybe_report_progress(
        &mut self,
        state: &mut S,
        monitor_timeout: Duration,
    ) -> Result<(), Error>;

    /// Send off an info/monitor/heartbeat message to the broker.
    /// Will return an [`Error`], if the stats could not be sent.
    /// [`std_report_progress`] is the standard implementation that you can call.
    fn report_progress(&mut self, state: &mut S) -> Result<(), Error>;
}

/// Restartable trait
pub trait EventRestarter<S> {
    /// For restarting event managers, implement a way to forward state to their next peers.
    /// You *must* ensure that [`HasCurrentStageId::on_restart`] will be invoked in this method, by you
    /// or an internal [`EventRestarter`], before the state is saved for recovery.
    /// [`std_on_restart`] is the standard implementation that you can call.
    fn on_restart(&mut self, state: &mut S) -> Result<(), Error>;
}

/// Default implementation of [`EventRestarter::on_restart`] for implementors with the given
/// constraints
pub fn std_on_restart<EM, S>(restarter: &mut EM, state: &mut S) -> Result<(), Error>
where
    EM: EventRestarter<S> + AwaitRestartSafe,
    S: HasCurrentStageId,
{
    state.on_restart()?;
    restarter.await_restart_safe();
    Ok(())
}

/// The class that implements this must be able to serialize an observer.
pub trait CanSerializeObserver<OT> {
    /// Do serialize the observer
    fn serialize_observers(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error>;
}

/// Send that we're about to exit
pub trait SendExiting {
    /// Send information that this client is exiting.
    /// No need to restart us any longer, and no need to print an error, either.
    fn send_exiting(&mut self) -> Result<(), Error>;

    /// Shutdown gracefully; typically without saving state.
    /// This is usually called from `fuzz_loop`.
    fn on_shutdown(&mut self) -> Result<(), Error>;
}

/// Wait until it's safe to restart
pub trait AwaitRestartSafe {
    /// Block until we are safe to exit, usually called inside `on_restart`.
    fn await_restart_safe(&mut self);
}

/// [`EventReceiver`] process all the incoming messages
pub trait EventReceiver<I, S> {
    /// Lookup for incoming events and process them.
    /// Return the event, if any, that needs to be evaluated
    fn try_receive(&mut self, state: &mut S) -> Result<Option<(Event<I>, bool)>, Error>;

    /// Run the post processing routine after the fuzzer deemed this event as interesting
    /// For example, in centralized manager you wanna send this an event.
    fn on_interesting(&mut self, state: &mut S, event: Event<I>) -> Result<(), Error>;
}
/// The id of this `EventManager`.
/// For multi processed `EventManagers`,
/// each connected client should have a unique ids.
pub trait HasEventManagerId {
    /// The id of this manager. For Multiprocessed `EventManagers`,
    /// each client should have a unique ids.
    fn mgr_id(&self) -> EventManagerId;
}

/// An eventmgr for tests, and as placeholder if you really don't need an event manager.
#[derive(Copy, Clone, Debug, Default)]
pub struct NopEventManager {}

impl NopEventManager {
    /// Creates a new [`NopEventManager`]
    #[must_use]
    pub fn new() -> Self {
        NopEventManager {}
    }
}

impl RecordSerializationTime for NopEventManager {}

impl<I, S> EventFirer<I, S> for NopEventManager {
    fn should_send(&self) -> bool {
        true
    }

    fn fire(&mut self, _state: &mut S, _event: Event<I>) -> Result<(), Error> {
        Ok(())
    }
}

impl<S> EventRestarter<S> for NopEventManager
where
    S: HasCurrentStageId,
{
    fn on_restart(&mut self, state: &mut S) -> Result<(), Error> {
        std_on_restart(self, state)
    }
}

impl SendExiting for NopEventManager {
    /// Send information that this client is exiting.
    /// No need to restart us any longer, and no need to print an error, either.
    fn send_exiting(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn on_shutdown(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl AwaitRestartSafe for NopEventManager {
    /// Block until we are safe to exit, usually called inside `on_restart`.
    fn await_restart_safe(&mut self) {}
}

impl<I, S> EventReceiver<I, S> for NopEventManager {
    fn try_receive(&mut self, _state: &mut S) -> Result<Option<(Event<I>, bool)>, Error> {
        Ok(None)
    }

    fn on_interesting(&mut self, _state: &mut S, _event_vec: Event<I>) -> Result<(), Error> {
        Ok(())
    }
}

impl<OT> CanSerializeObserver<OT> for NopEventManager
where
    OT: Serialize,
{
    fn serialize_observers(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error> {
        Ok(Some(postcard::to_allocvec(observers)?))
    }
}

impl<S> ProgressReporter<S> for NopEventManager {
    fn maybe_report_progress(
        &mut self,
        _state: &mut S,
        _monitor_timeout: Duration,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn report_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl HasEventManagerId for NopEventManager {
    fn mgr_id(&self) -> EventManagerId {
        EventManagerId(0)
    }
}

/// An `EventManager` type that wraps another manager, but captures a `monitor` type as well.
/// This is useful to keep the same API between managers with and without an internal `monitor`.
#[derive(Copy, Clone, Debug)]
pub struct MonitorTypedEventManager<EM, M> {
    inner: EM,
    phantom: PhantomData<M>,
}

impl<EM, M> RecordSerializationTime for MonitorTypedEventManager<EM, M> {}

impl<EM, M> MonitorTypedEventManager<EM, M> {
    /// Creates a new `EventManager` that wraps another manager, but captures a `monitor` type as well.
    #[must_use]
    pub fn new(inner: EM) -> Self {
        MonitorTypedEventManager {
            inner,
            phantom: PhantomData,
        }
    }
}

impl<EM, M, OT> CanSerializeObserver<OT> for MonitorTypedEventManager<EM, M>
where
    OT: Serialize,
{
    fn serialize_observers(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error> {
        Ok(Some(postcard::to_allocvec(observers)?))
    }
}

impl<EM, I, M, S> EventFirer<I, S> for MonitorTypedEventManager<EM, M>
where
    EM: EventFirer<I, S>,
{
    fn should_send(&self) -> bool {
        true
    }

    #[inline]
    fn fire(&mut self, state: &mut S, event: Event<I>) -> Result<(), Error> {
        self.inner.fire(state, event)
    }

    #[inline]
    fn log(
        &mut self,
        state: &mut S,
        severity_level: LogSeverity,
        message: String,
    ) -> Result<(), Error> {
        self.inner.log(state, severity_level, message)
    }

    #[inline]
    fn configuration(&self) -> EventConfig {
        self.inner.configuration()
    }
}

impl<EM, M, S> EventRestarter<S> for MonitorTypedEventManager<EM, M>
where
    EM: EventRestarter<S>,
{
    #[inline]
    fn on_restart(&mut self, state: &mut S) -> Result<(), Error> {
        self.inner.on_restart(state)
    }
}

impl<EM, M> SendExiting for MonitorTypedEventManager<EM, M>
where
    EM: SendExiting,
{
    #[inline]
    fn send_exiting(&mut self) -> Result<(), Error> {
        self.inner.send_exiting()
    }

    fn on_shutdown(&mut self) -> Result<(), Error> {
        self.inner.on_shutdown()
    }
}

impl<EM, M> AwaitRestartSafe for MonitorTypedEventManager<EM, M>
where
    EM: AwaitRestartSafe,
{
    #[inline]
    fn await_restart_safe(&mut self) {
        self.inner.await_restart_safe();
    }
}

impl<EM, I, M, S> EventReceiver<I, S> for MonitorTypedEventManager<EM, M>
where
    EM: EventReceiver<I, S>,
{
    #[inline]
    fn try_receive(&mut self, state: &mut S) -> Result<Option<(Event<I>, bool)>, Error> {
        self.inner.try_receive(state)
    }
    fn on_interesting(&mut self, _state: &mut S, _event_vec: Event<I>) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, M, S> ProgressReporter<S> for MonitorTypedEventManager<EM, M>
where
    EM: ProgressReporter<S>,
{
    #[inline]
    fn maybe_report_progress(
        &mut self,
        state: &mut S,
        monitor_timeout: Duration,
    ) -> Result<(), Error> {
        self.inner.maybe_report_progress(state, monitor_timeout)
    }

    #[inline]
    fn report_progress(&mut self, state: &mut S) -> Result<(), Error> {
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

/// Record the deserialization time for this event manager
pub trait RecordSerializationTime {
    /// Set the deserialization time (mut)
    fn set_deserialization_time(&mut self, _dur: Duration) {}
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
}

#[cfg(test)]
mod tests {

    use libafl_bolts::{Named, current_time, tuples::tuple_list};
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
        }
    }
}
