//! A very simple event manager, that just supports log outputs, but no multiprocessing

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
#[cfg(all(unix, feature = "std"))]
use core::ffi::c_void;
#[cfg(all(unix, feature = "std"))]
use core::ptr::write_volatile;
#[cfg(feature = "std")]
use core::sync::atomic::{compiler_fence, Ordering};
use core::{fmt::Debug, marker::PhantomData};

#[cfg(feature = "std")]
use serde::{de::DeserializeOwned, Serialize};

use super::{CustomBufEventResult, CustomBufHandlerFn, HasCustomBufHandlers, ProgressReporter};
#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use crate::bolts::os::startable_self;
#[cfg(all(unix, feature = "std", not(miri)))]
use crate::bolts::os::unix_signals::setup_signal_handler;
#[cfg(all(feature = "std", feature = "fork", unix))]
use crate::bolts::os::{fork, ForkResult};
#[cfg(all(unix, feature = "std"))]
use crate::events::{shutdown_handler, SHUTDOWN_SIGHANDLER_DATA};
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
#[cfg(feature = "std")]
use crate::{
    bolts::{shmem::ShMemProvider, staterestore::StateRestorer},
    corpus::Corpus,
    monitors::SimplePrintingMonitor,
    state::{HasCorpus, HasSolutions},
};

/// The llmp connection from the actual fuzzer to the process supervising it
const _ENV_FUZZER_SENDER: &str = "_AFL_ENV_FUZZER_SENDER";
const _ENV_FUZZER_RECEIVER: &str = "_AFL_ENV_FUZZER_RECEIVER";
/// The llmp (2 way) connection from a fuzzer to the broker (broadcasting all other fuzzer messages)
const _ENV_FUZZER_BROKER_CLIENT_INITIAL: &str = "_AFL_ENV_FUZZER_BROKER_CLIENT";

/// A simple, single-threaded event manager that just logs
pub struct SimpleEventManager<MT, S>
where
    S: UsesInput,
{
    /// The monitor
    monitor: MT,
    /// The events that happened since the last handle_in_broker
    events: Vec<Event<S::Input>>,
    /// The custom buf handler
    custom_buf_handlers: Vec<Box<CustomBufHandlerFn<S>>>,
    phantom: PhantomData<S>,
}

impl<MT, S> Debug for SimpleEventManager<MT, S>
where
    MT: Debug,
    S: UsesInput,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SimpleEventManager")
            //.field("custom_buf_handlers", self.custom_buf_handlers)
            .field("monitor", &self.monitor)
            .field("events", &self.events)
            .finish_non_exhaustive()
    }
}

impl<MT, S> UsesState for SimpleEventManager<MT, S>
where
    S: UsesInput,
{
    type State = S;
}

impl<MT, S> EventFirer for SimpleEventManager<MT, S>
where
    MT: Monitor,
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
}

impl<MT, S> EventRestarter for SimpleEventManager<MT, S>
where
    MT: Monitor,
    S: UsesInput,
{
}

impl<E, MT, S, Z> EventProcessor<E, Z> for SimpleEventManager<MT, S>
where
    MT: Monitor,
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

impl<E, MT, S, Z> EventManager<E, Z> for SimpleEventManager<MT, S>
where
    MT: Monitor,
    S: UsesInput + HasClientPerfMonitor + HasExecutions + HasMetadata,
{
}

impl<MT, S> HasCustomBufHandlers for SimpleEventManager<MT, S>
where
    MT: Monitor, //CE: CustomEvent<I, OT>,
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

impl<MT, S> ProgressReporter for SimpleEventManager<MT, S>
where
    MT: Monitor,
    S: UsesInput + HasExecutions + HasClientPerfMonitor + HasMetadata,
{
}

impl<MT, S> HasEventManagerId for SimpleEventManager<MT, S>
where
    MT: Monitor,
    S: UsesInput,
{
    fn mgr_id(&self) -> EventManagerId {
        EventManagerId(0)
    }
}

#[cfg(feature = "std")]
impl<S> SimpleEventManager<SimplePrintingMonitor, S>
where
    S: UsesInput,
{
    /// Creates a [`SimpleEventManager`] that just prints to `stdout`.
    #[must_use]
    pub fn printing() -> Self {
        Self::new(SimplePrintingMonitor::new())
    }
}

impl<MT, S> SimpleEventManager<MT, S>
where
    MT: Monitor, //TODO CE: CustomEvent,
    S: UsesInput,
{
    /// Creates a new [`SimpleEventManager`].
    pub fn new(monitor: MT) -> Self {
        Self {
            monitor,
            events: vec![],
            custom_buf_handlers: vec![],
            phantom: PhantomData,
        }
    }

    /// Handle arriving events in the broker
    #[allow(clippy::unnecessary_wraps)]
    fn handle_in_broker(
        monitor: &mut MT,
        event: &Event<S::Input>,
    ) -> Result<BrokerEventResult, Error> {
        match event {
            Event::NewTestcase {
                input: _,
                client_config: _,
                exit_kind: _,
                corpus_size,
                observers_buf: _,
                time,
                executions,
                forward_id: _,
            } => {
                monitor
                    .client_stats_mut_for(ClientId(0))
                    .update_corpus_size(*corpus_size as u64);
                monitor
                    .client_stats_mut_for(ClientId(0))
                    .update_executions(*executions as u64, *time);
                monitor.display(event.name().to_string(), ClientId(0));
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateExecStats {
                time,
                executions,
                phantom: _,
            } => {
                // TODO: The monitor buffer should be added on client add.
                let client = monitor.client_stats_mut_for(ClientId(0));

                client.update_executions(*executions as u64, *time);

                monitor.display(event.name().to_string(), ClientId(0));
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateUserStats {
                name,
                value,
                phantom: _,
            } => {
                monitor
                    .client_stats_mut_for(ClientId(0))
                    .update_user_stats(name.clone(), value.clone());
                monitor.display(event.name().to_string(), ClientId(0));
                Ok(BrokerEventResult::Handled)
            }
            #[cfg(feature = "introspection")]
            Event::UpdatePerfMonitor {
                time,
                executions,
                introspection_monitor,
                phantom: _,
            } => {
                // TODO: The monitor buffer should be added on client add.
                let client = monitor.client_stats_mut_for(ClientId(0));
                client.update_executions(*executions as u64, *time);
                client.update_introspection_monitor((**introspection_monitor).clone());
                monitor.display(event.name().to_string(), ClientId(0));
                Ok(BrokerEventResult::Handled)
            }
            Event::Objective { objective_size } => {
                monitor
                    .client_stats_mut_for(ClientId(0))
                    .update_objective_size(*objective_size as u64);
                monitor.display(event.name().to_string(), ClientId(0));
                Ok(BrokerEventResult::Handled)
            }
            Event::Log {
                severity_level,
                message,
                phantom: _,
            } => {
                let (_, _) = (message, severity_level);
                log::log!((*severity_level).into(), "{message}");
                Ok(BrokerEventResult::Handled)
            }
            Event::CustomBuf { .. } => Ok(BrokerEventResult::Forward),
            //_ => Ok(BrokerEventResult::Forward),
        }
    }

    // Handle arriving events in the client
    #[allow(clippy::needless_pass_by_value, clippy::unused_self)]
    fn handle_in_client(&mut self, state: &mut S, event: Event<S::Input>) -> Result<(), Error> {
        if let Event::CustomBuf { tag, buf } = &event {
            for handler in &mut self.custom_buf_handlers {
                handler(state, tag, buf)?;
            }
            Ok(())
        } else {
            Err(Error::unknown(format!(
                "Received illegal message that message should not have arrived: {event:?}."
            )))
        }
    }
}

/// Provides a `builder` which can be used to build a [`SimpleRestartingEventManager`], which is a combination of a
/// `restarter` and `runner`, that can be used on systems both with and without `fork` support. The
/// `restarter` will start a new process each time the child crashes or times out.
#[cfg(feature = "std")]
#[allow(clippy::default_trait_access)]
#[derive(Debug)]
pub struct SimpleRestartingEventManager<MT, S, SP>
where
    S: UsesInput,
    SP: ShMemProvider, //CE: CustomEvent<I, OT>,
{
    /// The actual simple event mgr
    simple_event_mgr: SimpleEventManager<MT, S>,
    /// [`StateRestorer`] for restarts
    staterestorer: StateRestorer<SP>,
}

#[cfg(feature = "std")]
impl<MT, S, SP> UsesState for SimpleRestartingEventManager<MT, S, SP>
where
    S: UsesInput,
    SP: ShMemProvider,
{
    type State = S;
}

#[cfg(feature = "std")]
impl<MT, S, SP> EventFirer for SimpleRestartingEventManager<MT, S, SP>
where
    MT: Monitor,
    S: UsesInput,
    SP: ShMemProvider,
{
    fn fire(
        &mut self,
        _state: &mut Self::State,
        event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        self.simple_event_mgr.fire(_state, event)
    }
}

#[cfg(feature = "std")]
impl<MT, S, SP> EventRestarter for SimpleRestartingEventManager<MT, S, SP>
where
    S: UsesInput + Serialize,
    SP: ShMemProvider,
{
    /// Reset the single page (we reuse it over and over from pos 0), then send the current state to the next runner.
    fn on_restart(&mut self, state: &mut S) -> Result<(), Error> {
        // First, reset the page to 0 so the next iteration can read read from the beginning of this page
        self.staterestorer.reset();
        self.staterestorer.save(state)
    }

    fn send_exiting(&mut self) -> Result<(), Error> {
        self.staterestorer.send_exiting();
        Ok(())
    }
}

#[cfg(feature = "std")]
impl<E, MT, S, SP, Z> EventProcessor<E, Z> for SimpleRestartingEventManager<MT, S, SP>
where
    MT: Monitor,
    S: UsesInput + HasClientPerfMonitor + HasExecutions + Serialize,
    SP: ShMemProvider,
{
    fn process(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        executor: &mut E,
    ) -> Result<usize, Error> {
        self.simple_event_mgr.process(fuzzer, state, executor)
    }
}

#[cfg(feature = "std")]
impl<E, MT, S, SP, Z> EventManager<E, Z> for SimpleRestartingEventManager<MT, S, SP>
where
    MT: Monitor,
    S: UsesInput + HasExecutions + HasClientPerfMonitor + HasMetadata + Serialize,
    SP: ShMemProvider,
{
}

#[cfg(feature = "std")]
impl<MT, S, SP> HasCustomBufHandlers for SimpleRestartingEventManager<MT, S, SP>
where
    MT: Monitor,
    S: UsesInput,
    SP: ShMemProvider,
{
    fn add_custom_buf_handler(
        &mut self,
        handler: Box<dyn FnMut(&mut S, &String, &[u8]) -> Result<CustomBufEventResult, Error>>,
    ) {
        self.simple_event_mgr.add_custom_buf_handler(handler);
    }
}

#[cfg(feature = "std")]
impl<MT, S, SP> ProgressReporter for SimpleRestartingEventManager<MT, S, SP>
where
    MT: Monitor,
    S: UsesInput + HasExecutions + HasClientPerfMonitor + HasMetadata,
    SP: ShMemProvider,
{
}

#[cfg(feature = "std")]
impl<MT, S, SP> HasEventManagerId for SimpleRestartingEventManager<MT, S, SP>
where
    MT: Monitor,
    S: UsesInput,
    SP: ShMemProvider,
{
    fn mgr_id(&self) -> EventManagerId {
        self.simple_event_mgr.mgr_id()
    }
}

#[cfg(feature = "std")]
#[allow(clippy::type_complexity, clippy::too_many_lines)]
impl<MT, S, SP> SimpleRestartingEventManager<MT, S, SP>
where
    S: UsesInput,
    SP: ShMemProvider,
    MT: Monitor, //TODO CE: CustomEvent,
{
    /// Creates a new [`SimpleEventManager`].
    fn launched(monitor: MT, staterestorer: StateRestorer<SP>) -> Self {
        Self {
            staterestorer,
            simple_event_mgr: SimpleEventManager::new(monitor),
        }
    }

    /// Launch the simple restarting manager.
    /// This [`EventManager`] is simple and single threaded,
    /// but can still used shared maps to recover from crashes and timeouts.
    #[allow(clippy::similar_names)]
    pub fn launch(mut monitor: MT, shmem_provider: &mut SP) -> Result<(Option<S>, Self), Error>
    where
        S: DeserializeOwned + Serialize + HasCorpus + HasSolutions,
        MT: Debug,
    {
        // We start ourself as child process to actually fuzz
        let mut staterestorer = if std::env::var(_ENV_FUZZER_SENDER).is_err() {
            // First, create a place to store state in, for restarts.
            #[cfg(unix)]
            let mut staterestorer: StateRestorer<SP> =
                StateRestorer::new(shmem_provider.new_shmem(256 * 1024 * 1024)?);
            #[cfg(not(unix))]
            let staterestorer: StateRestorer<SP> =
                StateRestorer::new(shmem_provider.new_shmem(256 * 1024 * 1024)?);

            //let staterestorer = { LlmpSender::new(shmem_provider.clone(), 0, false)? };
            staterestorer.write_to_env(_ENV_FUZZER_SENDER)?;

            #[cfg(unix)]
            unsafe {
                let data = &mut SHUTDOWN_SIGHANDLER_DATA;
                // Write the pointer to staterestorer so we can release its shmem later
                write_volatile(
                    &mut data.staterestorer_ptr,
                    &mut staterestorer as *mut _ as *mut c_void,
                );
                data.allocator_pid = std::process::id() as usize;
                data.shutdown_handler = shutdown_handler::<SP> as *const c_void;
            }

            // We setup signal handlers to clean up shmem segments used by state restorer
            #[cfg(all(unix, not(miri)))]
            if let Err(_e) = unsafe { setup_signal_handler(&mut SHUTDOWN_SIGHANDLER_DATA) } {
                // We can live without a proper ctrl+c signal handler. Print and ignore.
                log::error!("Failed to setup signal handlers: {_e}");
            }

            let mut ctr: u64 = 0;
            // Client->parent loop
            loop {
                log::info!("Spawning next client (id {ctr})");

                // On Unix, we fork
                #[cfg(all(unix, feature = "fork"))]
                let child_status = {
                    shmem_provider.pre_fork()?;
                    match unsafe { fork() }? {
                        ForkResult::Parent(handle) => {
                            shmem_provider.post_fork(false)?;
                            handle.status()
                        }
                        ForkResult::Child => {
                            shmem_provider.post_fork(true)?;
                            break staterestorer;
                        }
                    }
                };

                // On Windows (or in any case without forks), we spawn ourself again
                #[cfg(any(windows, not(feature = "fork")))]
                let child_status = startable_self()?.status()?;
                #[cfg(all(unix, not(feature = "fork")))]
                let child_status = child_status.code().unwrap_or_default();

                compiler_fence(Ordering::SeqCst);

                #[allow(clippy::manual_assert)]
                if !staterestorer.has_content() {
                    #[cfg(unix)]
                    if child_status == 137 {
                        // Out of Memory, see https://tldp.org/LDP/abs/html/exitcodes.html
                        // and https://github.com/AFLplusplus/LibAFL/issues/32 for discussion.
                        panic!("Fuzzer-respawner: The fuzzed target crashed with an out of memory error! Fix your harness, or switch to another executor (for example, a forkserver).");
                    }

                    // Storing state in the last round did not work
                    panic!("Fuzzer-respawner: Storing state in crashed fuzzer instance did not work, no point to spawn the next client! This can happen if the child calls `exit()`, in that case make sure it uses `abort()`, if it got killed unrecoverable (OOM), or if there is a bug in the fuzzer itself. (Child exited with: {child_status})");
                }

                ctr = ctr.wrapping_add(1);
            }
        } else {
            // We are the newly started fuzzing instance (i.e. on Windows), first, connect to our own restore map.
            // We get here *only on Windows*, if we were started by a restarting fuzzer.
            // A staterestorer and a receiver for single communication
            StateRestorer::from_env(shmem_provider, _ENV_FUZZER_SENDER)?
        };

        // If we're restarting, deserialize the old state.
        let (state, mgr) = match staterestorer.restore::<S>()? {
            None => {
                log::info!("First run. Let's set it all up");
                // Mgr to send and receive msgs from/to all other fuzzer instances
                (
                    None,
                    SimpleRestartingEventManager::launched(monitor, staterestorer),
                )
            }
            // Restoring from a previous run, deserialize state and corpus.
            Some(state) => {
                log::info!("Subsequent run. Loaded previous state.");
                // We reset the staterestorer, the next staterestorer and receiver (after crash) will reuse the page from the initial message.
                staterestorer.reset();

                // load the corpus size into monitor to still display the correct numbers after restart.
                let client_stats = monitor.client_stats_mut_for(ClientId(0));
                client_stats.update_corpus_size(state.corpus().count().try_into()?);
                client_stats.update_objective_size(state.solutions().count().try_into()?);

                (
                    Some(state),
                    SimpleRestartingEventManager::launched(monitor, staterestorer),
                )
            }
        };

        /* TODO: Not sure if this is needed
        // We commit an empty NO_RESTART message to this buf, against infinite loops,
        // in case something crashes in the fuzzer.
        staterestorer.send_buf(_LLMP_TAG_NO_RESTART, []);
        */

        Ok((state, mgr))
    }
}

/// `SimpleEventManager` Python bindings
#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use pyo3::prelude::*;

    use crate::{
        events::{pybind::PythonEventManager, SimpleEventManager},
        monitors::pybind::PythonMonitor,
        state::pybind::PythonStdState,
    };

    #[pyclass(unsendable, name = "SimpleEventManager")]
    #[derive(Debug)]
    /// Python class for SimpleEventManager
    pub struct PythonSimpleEventManager {
        /// Rust wrapped SimpleEventManager object
        pub inner: SimpleEventManager<PythonMonitor, PythonStdState>,
    }

    #[pymethods]
    impl PythonSimpleEventManager {
        #[new]
        fn new(py_monitor: PythonMonitor) -> Self {
            Self {
                inner: SimpleEventManager::new(py_monitor),
            }
        }

        fn as_manager(slf: Py<Self>) -> PythonEventManager {
            PythonEventManager::new_simple(slf)
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonSimpleEventManager>()?;
        Ok(())
    }
}
