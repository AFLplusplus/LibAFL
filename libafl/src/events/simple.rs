//! A very simple event manager, that just supports log outputs, but no multiprocessing

use crate::{
    events::{
        BrokerEventResult, Event, EventFirer, EventManager, EventManagerId, EventProcessor,
        EventRestarter, HasEventManagerId,
    },
    inputs::Input,
    monitors::Monitor,
    Error,
};
use alloc::{string::ToString, vec::Vec};
#[cfg(feature = "std")]
use core::sync::atomic::{compiler_fence, Ordering};
#[cfg(feature = "std")]
use serde::{de::DeserializeOwned, Serialize};

#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use crate::bolts::os::startable_self;
#[cfg(all(feature = "std", feature = "fork", unix))]
use crate::bolts::os::{fork, ForkResult};
#[cfg(feature = "std")]
use crate::{
    bolts::{shmem::ShMemProvider, staterestore::StateRestorer},
    corpus::Corpus,
    state::{HasCorpus, HasSolutions},
};

use super::ProgressReporter;

/// The llmp connection from the actual fuzzer to the process supervising it
const _ENV_FUZZER_SENDER: &str = "_AFL_ENV_FUZZER_SENDER";
const _ENV_FUZZER_RECEIVER: &str = "_AFL_ENV_FUZZER_RECEIVER";
/// The llmp (2 way) connection from a fuzzer to the broker (broadcasting all other fuzzer messages)
const _ENV_FUZZER_BROKER_CLIENT_INITIAL: &str = "_AFL_ENV_FUZZER_BROKER_CLIENT";

/// A simple, single-threaded event manager that just logs
#[derive(Clone, Debug)]
pub struct SimpleEventManager<I, MT>
where
    I: Input,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
    /// The monitor
    monitor: MT,
    /// The events that happened since the last handle_in_broker
    events: Vec<Event<I>>,
}

impl<I, MT> EventFirer<I> for SimpleEventManager<I, MT>
where
    I: Input,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
    fn fire<S>(&mut self, _state: &mut S, event: Event<I>) -> Result<(), Error> {
        match Self::handle_in_broker(&mut self.monitor, &event)? {
            BrokerEventResult::Forward => self.events.push(event),
            BrokerEventResult::Handled => (),
        };
        Ok(())
    }
}

impl<I, MT, S> EventRestarter<S> for SimpleEventManager<I, MT>
where
    I: Input,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
}

impl<E, I, MT, S, Z> EventProcessor<E, I, S, Z> for SimpleEventManager<I, MT>
where
    I: Input,
    MT: Monitor, //CE: CustomEvent<I, OT>,
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

impl<E, I, MT, S, Z> EventManager<E, I, S, Z> for SimpleEventManager<I, MT>
where
    I: Input,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
}

impl<I, MT> ProgressReporter<I> for SimpleEventManager<I, MT>
where
    I: Input,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
}

impl<I, MT> HasEventManagerId for SimpleEventManager<I, MT>
where
    I: Input,
    MT: Monitor,
{
    fn mgr_id(&self) -> EventManagerId {
        EventManagerId { id: 0 }
    }
}

impl<I, MT> SimpleEventManager<I, MT>
where
    I: Input,
    MT: Monitor, //TODO CE: CustomEvent,
{
    /// Creates a new [`SimpleEventManager`].
    pub fn new(monitor: MT) -> Self {
        Self {
            monitor,
            events: vec![],
        }
    }

    // Handle arriving events in the broker
    #[allow(clippy::unnecessary_wraps)]
    fn handle_in_broker(monitor: &mut MT, event: &Event<I>) -> Result<BrokerEventResult, Error> {
        match event {
            Event::NewTestcase {
                input: _,
                client_config: _,
                exit_kind: _,
                corpus_size,
                observers_buf: _,
                time,
                executions,
            } => {
                monitor
                    .client_stats_mut_for(0)
                    .update_corpus_size(*corpus_size as u64);
                monitor
                    .client_stats_mut_for(0)
                    .update_executions(*executions as u64, *time);
                monitor.display(event.name().to_string(), 0);
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateExecStats {
                time,
                executions,
                phantom: _,
            } => {
                // TODO: The monitor buffer should be added on client add.
                let client = monitor.client_stats_mut_for(0);

                client.update_executions(*executions as u64, *time);

                monitor.display(event.name().to_string(), 0);
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateUserStats {
                name,
                value,
                phantom: _,
            } => {
                monitor
                    .client_stats_mut_for(0)
                    .update_user_stats(name.clone(), value.clone());
                monitor.display(event.name().to_string(), 0);
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
                let client = &mut monitor.client_stats_mut()[0];
                client.update_executions(*executions as u64, *time);
                client.update_introspection_monitor((**introspection_monitor).clone());
                monitor.display(event.name().to_string(), 0);
                Ok(BrokerEventResult::Handled)
            }
            Event::Objective { objective_size } => {
                monitor
                    .client_stats_mut_for(0)
                    .update_objective_size(*objective_size as u64);
                monitor.display(event.name().to_string(), 0);
                Ok(BrokerEventResult::Handled)
            }
            Event::Log {
                severity_level,
                message,
                phantom: _,
            } => {
                let (_, _) = (message, severity_level);
                #[cfg(feature = "std")]
                println!("[LOG {}]: {}", severity_level, message);
                Ok(BrokerEventResult::Handled)
            } //_ => Ok(BrokerEventResult::Forward),
        }
    }

    // Handle arriving events in the client
    #[allow(clippy::needless_pass_by_value, clippy::unused_self)]
    fn handle_in_client<S>(&mut self, _state: &mut S, event: Event<I>) -> Result<(), Error> {
        Err(Error::Unknown(format!(
            "Received illegal message that message should not have arrived: {:?}.",
            event
        )))
    }
}

/// Provides a `builder` which can be used to build a [`SimpleRestartingEventManager`], which is a combination of a
/// `restarter` and `runner`, that can be used on systems both with and without `fork` support. The
/// `restarter` will start a new process each time the child crashes or times out.
#[cfg(feature = "std")]
#[allow(clippy::default_trait_access)]
#[derive(Debug, Clone)]
pub struct SimpleRestartingEventManager<I, MT, SP>
where
    I: Input,
    SP: ShMemProvider,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
    /// The actual simple event mgr
    simple_event_mgr: SimpleEventManager<I, MT>,
    /// [`StateRestorer`] for restarts
    staterestorer: StateRestorer<SP>,
}

#[cfg(feature = "std")]
impl<I, MT, SP> EventFirer<I> for SimpleRestartingEventManager<I, MT, SP>
where
    I: Input,
    SP: ShMemProvider,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
    fn fire<S2>(&mut self, _state: &mut S2, event: Event<I>) -> Result<(), Error> {
        self.simple_event_mgr.fire(_state, event)
    }
}

#[cfg(feature = "std")]
impl<I, MT, S, SP> EventRestarter<S> for SimpleRestartingEventManager<I, MT, SP>
where
    I: Input,
    S: Serialize,
    SP: ShMemProvider,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
    /// Reset the single page (we reuse it over and over from pos 0), then send the current state to the next runner.
    fn on_restart(&mut self, state: &mut S) -> Result<(), Error> {
        // First, reset the page to 0 so the next iteration can read read from the beginning of this page
        self.staterestorer.reset();
        self.staterestorer.save(state)
    }
}

#[cfg(feature = "std")]
impl<E, I, S, SP, MT, Z> EventProcessor<E, I, S, Z> for SimpleRestartingEventManager<I, MT, SP>
where
    I: Input,
    S: Serialize,
    SP: ShMemProvider,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
    fn process(&mut self, fuzzer: &mut Z, state: &mut S, executor: &mut E) -> Result<usize, Error> {
        self.simple_event_mgr.process(fuzzer, state, executor)
    }
}

#[cfg(feature = "std")]
impl<E, I, S, SP, MT, Z> EventManager<E, I, S, Z> for SimpleRestartingEventManager<I, MT, SP>
where
    I: Input,
    S: Serialize,
    SP: ShMemProvider,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
}

#[cfg(feature = "std")]
impl<I, MT, SP> ProgressReporter<I> for SimpleRestartingEventManager<I, MT, SP>
where
    I: Input,
    SP: ShMemProvider,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
}

#[cfg(feature = "std")]
impl<I, MT, SP> HasEventManagerId for SimpleRestartingEventManager<I, MT, SP>
where
    I: Input,
    SP: ShMemProvider,
    MT: Monitor,
{
    fn mgr_id(&self) -> EventManagerId {
        self.simple_event_mgr.mgr_id()
    }
}

#[cfg(feature = "std")]
#[allow(clippy::type_complexity, clippy::too_many_lines)]
impl<'a, I, MT, SP> SimpleRestartingEventManager<I, MT, SP>
where
    I: Input,
    SP: ShMemProvider,
    MT: Monitor, //TODO CE: CustomEvent,
{
    /// Creates a new [`SimpleEventManager`].
    fn new_launched(monitor: MT, staterestorer: StateRestorer<SP>) -> Self {
        Self {
            staterestorer,
            simple_event_mgr: SimpleEventManager::new(monitor),
        }
    }

    /// Launch the simple restarting manager.
    /// This [`EventManager`] is simple and single threaded,
    /// but can still used shared maps to recover from crashes and timeouts.
    #[allow(clippy::similar_names)]
    pub fn launch<S>(mut monitor: MT, shmem_provider: &mut SP) -> Result<(Option<S>, Self), Error>
    where
        S: DeserializeOwned + Serialize + HasCorpus<I> + HasSolutions<I>,
    {
        // We start ourself as child process to actually fuzz
        let mut staterestorer = if std::env::var(_ENV_FUZZER_SENDER).is_err() {
            // First, create a place to store state in, for restarts.
            let staterestorer: StateRestorer<SP> =
                StateRestorer::new(shmem_provider.new_shmem(256 * 1024 * 1024)?);
            //let staterestorer = { LlmpSender::new(shmem_provider.clone(), 0, false)? };
            staterestorer.write_to_env(_ENV_FUZZER_SENDER)?;

            let mut ctr: u64 = 0;
            // Client->parent loop
            loop {
                println!("Spawning next client (id {})", ctr);

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

                // On windows (or in any case without forks), we spawn ourself again
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
                    panic!("Fuzzer-respawner: Storing state in crashed fuzzer instance did not work, no point to spawn the next client! This can happen if the child calls `exit()`, in that case make sure it uses `abort()`, if it got killed unrecoverable (OOM), or if there is a bug in the fuzzer itself. (Child exited with: {})", child_status);
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
                println!("First run. Let's set it all up");
                // Mgr to send and receive msgs from/to all other fuzzer instances
                (
                    None,
                    SimpleRestartingEventManager::new_launched(monitor, staterestorer),
                )
            }
            // Restoring from a previous run, deserialize state and corpus.
            Some(state) => {
                println!("Subsequent run. Loaded previous state.");
                // We reset the staterestorer, the next staterestorer and receiver (after crash) will reuse the page from the initial message.
                staterestorer.reset();

                // load the corpus size into monitor to still display the correct numbers after restart.
                let client_stats = monitor.client_stats_mut_for(0);
                client_stats.update_corpus_size(state.corpus().count().try_into()?);
                client_stats.update_objective_size(state.solutions().count().try_into()?);

                (
                    Some(state),
                    SimpleRestartingEventManager::new_launched(monitor, staterestorer),
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
pub mod pybind {
    use crate::events::SimpleEventManager;
    use crate::inputs::BytesInput;
    use crate::monitors::pybind::PythonMonitor;
    use pyo3::prelude::*;

    #[pyclass(unsendable, name = "SimpleEventManager")]
    #[derive(Debug, Clone)]
    /// Python class for SimpleEventManager
    pub struct PythonSimpleEventManager {
        /// Rust wrapped SimpleEventManager object
        pub simple_event_manager: SimpleEventManager<BytesInput, PythonMonitor>,
    }

    #[pymethods]
    impl PythonSimpleEventManager {
        #[new]
        fn new(py_monitor: PythonMonitor) -> Self {
            Self {
                simple_event_manager: SimpleEventManager::new(py_monitor),
            }
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonSimpleEventManager>()?;
        Ok(())
    }
}
