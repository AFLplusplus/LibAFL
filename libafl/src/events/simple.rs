//! A very simple event manager, that just supports log outputs, but no multiprocessing

use alloc::vec::Vec;
#[cfg(feature = "std")]
use core::sync::atomic::{compiler_fence, Ordering};
use core::{fmt::Debug, marker::PhantomData, time::Duration};

#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use libafl_bolts::os::startable_self;
#[cfg(all(unix, feature = "std", not(miri)))]
use libafl_bolts::os::unix_signals::setup_signal_handler;
#[cfg(all(feature = "std", feature = "fork", unix))]
use libafl_bolts::os::{fork, ForkResult};
use libafl_bolts::ClientId;
#[cfg(feature = "std")]
use libafl_bolts::{os::CTRL_C_EXIT, shmem::ShMemProvider, staterestore::StateRestorer};
#[cfg(feature = "std")]
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::{std_on_restart, ProgressReporter};
#[cfg(all(unix, feature = "std", not(miri)))]
use crate::events::EVENTMGR_SIGHANDLER_STATE;
use crate::{
    corpus::Corpus,
    events::{
        std_maybe_report_progress, std_report_progress, BrokerEventResult, CanSerializeObserver,
        Event, EventFirer, EventManagerId, EventProcessor, EventRestarter, HasEventManagerId,
        ManagerExit,
    },
    monitors::Monitor,
    stages::HasCurrentStageId,
    state::{HasCorpus, HasExecutions, HasLastReportTime, MaybeHasClientPerfMonitor, Stoppable},
    Error, HasMetadata,
};
#[cfg(feature = "std")]
use crate::{
    monitors::{ClientStats, SimplePrintingMonitor},
    state::HasSolutions,
};

/// The llmp connection from the actual fuzzer to the process supervising it
const _ENV_FUZZER_SENDER: &str = "_AFL_ENV_FUZZER_SENDER";
const _ENV_FUZZER_RECEIVER: &str = "_AFL_ENV_FUZZER_RECEIVER";
/// The llmp (2 way) connection from a fuzzer to the broker (broadcasting all other fuzzer messages)
const _ENV_FUZZER_BROKER_CLIENT_INITIAL: &str = "_AFL_ENV_FUZZER_BROKER_CLIENT";

/// A simple, single-threaded event manager that just logs
pub struct SimpleEventManager<I, MT, S> {
    /// The monitor
    monitor: MT,
    /// The events that happened since the last `handle_in_broker`
    events: Vec<Event<I>>,
    phantom: PhantomData<S>,
}

impl<I, MT, S> Debug for SimpleEventManager<I, MT, S>
where
    MT: Debug,
    I: Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SimpleEventManager")
            //.field("custom_buf_handlers", self.custom_buf_handlers)
            .field("monitor", &self.monitor)
            .field("events", &self.events)
            .finish_non_exhaustive()
    }
}

impl<I, MT, S> EventFirer<I, S> for SimpleEventManager<I, MT, S>
where
    I: Debug,
    MT: Monitor,
    S: Stoppable,
{
    fn should_send(&self) -> bool {
        true
    }

    fn fire(&mut self, _state: &mut S, event: Event<I>) -> Result<(), Error> {
        match Self::handle_in_broker(&mut self.monitor, &event)? {
            BrokerEventResult::Forward => self.events.push(event),
            BrokerEventResult::Handled => (),
        };
        Ok(())
    }
}

impl<I, MT, S> ManagerExit for SimpleEventManager<I, MT, S> {
    fn send_exiting(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn await_restart_safe(&mut self) {}
}

impl<I, MT, S> EventRestarter<S> for SimpleEventManager<I, MT, S>
where
    S: HasCurrentStageId,
{
    fn on_restart(&mut self, state: &mut S) -> Result<(), Error> {
        std_on_restart(self, state)
    }
}

impl<E, I, MT, S, Z> EventProcessor<E, S, Z> for SimpleEventManager<I, MT, S>
where
    I: Debug,
    MT: Monitor,
    S: Stoppable,
{
    fn process(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _executor: &mut E,
    ) -> Result<usize, Error> {
        let count = self.events.len();
        while let Some(event) = self.events.pop() {
            self.handle_in_client(state, &event)?;
        }
        Ok(count)
    }

    fn on_shutdown(&mut self) -> Result<(), Error> {
        self.send_exiting()
    }
}

impl<I, MT, OT, S> CanSerializeObserver<OT> for SimpleEventManager<I, MT, S>
where
    OT: Serialize,
{
    fn serialize_observers(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error> {
        Ok(Some(postcard::to_allocvec(observers)?))
    }
}

impl<I, MT, S> ProgressReporter<S> for SimpleEventManager<I, MT, S>
where
    I: Debug,
    MT: Monitor,
    S: HasMetadata
        + HasExecutions
        + HasLastReportTime
        + Stoppable
        + HasCorpus<I>
        + MaybeHasClientPerfMonitor,
{
    fn maybe_report_progress(
        &mut self,
        state: &mut S,
        monitor_timeout: Duration,
    ) -> Result<(), Error> {
        std_maybe_report_progress(self, state, monitor_timeout)
    }

    fn report_progress(&mut self, state: &mut S) -> Result<(), Error> {
        std_report_progress(self, state)
    }
}

impl<I, MT, S> HasEventManagerId for SimpleEventManager<I, MT, S> {
    fn mgr_id(&self) -> EventManagerId {
        EventManagerId(0)
    }
}

#[cfg(feature = "std")]
impl<I, S> SimpleEventManager<I, SimplePrintingMonitor, S>
where
    I: Debug,
    S: Stoppable,
{
    /// Creates a [`SimpleEventManager`] that just prints to `stdout`.
    #[must_use]
    pub fn printing() -> Self {
        Self::new(SimplePrintingMonitor::new())
    }
}

impl<I, MT, S> SimpleEventManager<I, MT, S>
where
    I: Debug,
    MT: Monitor,
    S: Stoppable,
{
    /// Creates a new [`SimpleEventManager`].
    pub fn new(monitor: MT) -> Self {
        Self {
            monitor,
            events: vec![],
            phantom: PhantomData,
        }
    }

    /// Handle arriving events in the broker
    #[expect(clippy::unnecessary_wraps)]
    fn handle_in_broker(monitor: &mut MT, event: &Event<I>) -> Result<BrokerEventResult, Error> {
        match event {
            Event::NewTestcase { corpus_size, .. } => {
                monitor.client_stats_insert(ClientId(0));
                monitor
                    .client_stats_mut_for(ClientId(0))
                    .update_corpus_size(*corpus_size as u64);
                monitor.display(event.name(), ClientId(0));
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateExecStats {
                time, executions, ..
            } => {
                // TODO: The monitor buffer should be added on client add.
                monitor.client_stats_insert(ClientId(0));
                let client = monitor.client_stats_mut_for(ClientId(0));

                client.update_executions(*executions, *time);

                monitor.display(event.name(), ClientId(0));
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateUserStats { name, value, .. } => {
                monitor.client_stats_insert(ClientId(0));
                monitor
                    .client_stats_mut_for(ClientId(0))
                    .update_user_stats(name.clone(), value.clone());
                monitor.aggregate(name);
                monitor.display(event.name(), ClientId(0));
                Ok(BrokerEventResult::Handled)
            }
            #[cfg(feature = "introspection")]
            Event::UpdatePerfMonitor {
                time,
                executions,
                introspection_monitor,
                ..
            } => {
                // TODO: The monitor buffer should be added on client add.
                monitor.client_stats_insert(ClientId(0));
                let client = monitor.client_stats_mut_for(ClientId(0));
                client.update_executions(*executions, *time);
                client.update_introspection_monitor((**introspection_monitor).clone());
                monitor.display(event.name(), ClientId(0));
                Ok(BrokerEventResult::Handled)
            }
            Event::Objective { objective_size, .. } => {
                monitor.client_stats_insert(ClientId(0));
                monitor
                    .client_stats_mut_for(ClientId(0))
                    .update_objective_size(*objective_size as u64);
                monitor.display(event.name(), ClientId(0));
                Ok(BrokerEventResult::Handled)
            }
            Event::Log {
                severity_level,
                message,
                ..
            } => {
                let (_, _) = (message, severity_level);
                log::log!((*severity_level).into(), "{message}");
                Ok(BrokerEventResult::Handled)
            }
            Event::Stop => Ok(BrokerEventResult::Forward),
        }
    }

    // Handle arriving events in the client
    #[allow(clippy::unused_self)]
    fn handle_in_client(&mut self, state: &mut S, event: &Event<I>) -> Result<(), Error> {
        match event {
            Event::Stop => {
                state.request_stop();
                Ok(())
            }
            _ => Err(Error::unknown(format!(
                "Received illegal message that message should not have arrived: {event:?}."
            ))),
        }
    }
}

/// Provides a `builder` which can be used to build a [`SimpleRestartingEventManager`].
///
/// The [`SimpleRestartingEventManager`] is a combination of a
/// `restarter` and `runner`, that can be used on systems both with and without `fork` support. The
/// `restarter` will start a new process each time the child crashes or times out.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct SimpleRestartingEventManager<I, MT, S, SP>
where
    SP: ShMemProvider,
{
    /// The actual simple event mgr
    inner: SimpleEventManager<I, MT, S>,
    /// [`StateRestorer`] for restarts
    staterestorer: StateRestorer<SP>,
}

#[cfg(feature = "std")]
impl<I, MT, S, SP> EventFirer<I, S> for SimpleRestartingEventManager<I, MT, S, SP>
where
    I: Debug,
    MT: Monitor,
    S: Stoppable,
    SP: ShMemProvider,
{
    fn should_send(&self) -> bool {
        true
    }

    fn fire(&mut self, _state: &mut S, event: Event<I>) -> Result<(), Error> {
        self.inner.fire(_state, event)
    }
}

#[cfg(feature = "std")]
impl<I, MT, S, SP> EventRestarter<S> for SimpleRestartingEventManager<I, MT, S, SP>
where
    SP: ShMemProvider,
    S: HasCurrentStageId + Serialize,
    MT: Monitor,
{
    /// Reset the single page (we reuse it over and over from pos 0), then send the current state to the next runner.
    fn on_restart(&mut self, state: &mut S) -> Result<(), Error> {
        state.on_restart()?;

        // First, reset the page to 0 so the next iteration can read read from the beginning of this page
        self.staterestorer.reset();
        self.staterestorer.save(&(
            state,
            self.inner.monitor.start_time(),
            self.inner.monitor.client_stats(),
        ))
    }
}

#[cfg(feature = "std")]
impl<I, MT, OT, S, SP> CanSerializeObserver<OT> for SimpleRestartingEventManager<I, MT, S, SP>
where
    SP: ShMemProvider,
    OT: Serialize,
{
    fn serialize_observers(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error> {
        Ok(Some(postcard::to_allocvec(observers)?))
    }
}

#[cfg(feature = "std")]
impl<I, MT, S, SP> ManagerExit for SimpleRestartingEventManager<I, MT, S, SP>
where
    SP: ShMemProvider,
{
    fn send_exiting(&mut self) -> Result<(), Error> {
        self.staterestorer.send_exiting();
        Ok(())
    }
    /// Block until we are safe to exit, usually called inside `on_restart`.
    #[inline]
    fn await_restart_safe(&mut self) {}
}

#[cfg(feature = "std")]
impl<E, I, MT, S, SP, Z> EventProcessor<E, S, Z> for SimpleRestartingEventManager<I, MT, S, SP>
where
    I: Debug,
    MT: Monitor,
    SP: ShMemProvider,
    S: Stoppable,
{
    fn process(&mut self, fuzzer: &mut Z, state: &mut S, executor: &mut E) -> Result<usize, Error> {
        self.inner.process(fuzzer, state, executor)
    }

    fn on_shutdown(&mut self) -> Result<(), Error> {
        self.send_exiting()
    }
}

#[cfg(feature = "std")]
impl<I, MT, S, SP> ProgressReporter<S> for SimpleRestartingEventManager<I, MT, S, SP>
where
    I: Debug,
    MT: Monitor,
    SP: ShMemProvider,
    S: HasExecutions
        + HasMetadata
        + HasLastReportTime
        + Stoppable
        + HasCorpus<I>
        + MaybeHasClientPerfMonitor,
{
    fn maybe_report_progress(
        &mut self,
        state: &mut S,
        monitor_timeout: Duration,
    ) -> Result<(), Error> {
        std_maybe_report_progress(self, state, monitor_timeout)
    }

    fn report_progress(&mut self, state: &mut S) -> Result<(), Error> {
        std_report_progress(self, state)
    }
}

#[cfg(feature = "std")]
impl<I, MT, S, SP> HasEventManagerId for SimpleRestartingEventManager<I, MT, S, SP>
where
    SP: ShMemProvider,
{
    fn mgr_id(&self) -> EventManagerId {
        self.inner.mgr_id()
    }
}

#[cfg(feature = "std")]
impl<I, MT, S, SP> SimpleRestartingEventManager<I, MT, S, SP>
where
    I: Debug,
    MT: Monitor,
    S: Stoppable,
    SP: ShMemProvider,
{
    /// Creates a new [`SimpleEventManager`].
    fn launched(monitor: MT, staterestorer: StateRestorer<SP>) -> Self {
        Self {
            staterestorer,
            inner: SimpleEventManager::new(monitor),
        }
    }

    /// Launch the simple restarting manager.
    /// This `EventManager` is simple and single threaded,
    /// but can still used shared maps to recover from crashes and timeouts.
    pub fn launch(mut monitor: MT, shmem_provider: &mut SP) -> Result<(Option<S>, Self), Error>
    where
        S: DeserializeOwned + Serialize + HasCorpus<I> + HasSolutions<I>,
        MT: Debug,
    {
        // We start ourself as child process to actually fuzz
        let mut staterestorer = if std::env::var(_ENV_FUZZER_SENDER).is_err() {
            // First, create a place to store state in, for restarts.
            #[cfg(unix)]
            let staterestorer: StateRestorer<SP> =
                StateRestorer::new(shmem_provider.new_shmem(256 * 1024 * 1024)?);
            #[cfg(not(unix))]
            let staterestorer: StateRestorer<SP> =
                StateRestorer::new(shmem_provider.new_shmem(256 * 1024 * 1024)?);

            //let staterestorer = { LlmpSender::new(shmem_provider.clone(), 0, false)? };
            staterestorer.write_to_env(_ENV_FUZZER_SENDER)?;

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
                            unsafe {
                                libc::signal(libc::SIGINT, libc::SIG_IGN);
                            }
                            shmem_provider.post_fork(false)?;
                            handle.status()
                        }
                        ForkResult::Child => {
                            shmem_provider.post_fork(true)?;
                            break staterestorer;
                        }
                    }
                };

                // If this guy wants to fork, then ignore sigit
                #[cfg(any(windows, not(feature = "fork")))]
                unsafe {
                    #[cfg(windows)]
                    libafl_bolts::os::windows_exceptions::signal(
                        libafl_bolts::os::windows_exceptions::SIGINT,
                        libafl_bolts::os::windows_exceptions::sig_ign(),
                    );

                    #[cfg(unix)]
                    libc::signal(libc::SIGINT, libc::SIG_IGN);
                }

                // On Windows (or in any case without forks), we spawn ourself again
                #[cfg(any(windows, not(feature = "fork")))]
                let child_status = startable_self()?.status()?;
                #[cfg(any(windows, not(feature = "fork")))]
                let child_status = child_status.code().unwrap_or_default();

                compiler_fence(Ordering::SeqCst);

                if child_status == CTRL_C_EXIT || staterestorer.wants_to_exit() {
                    return Err(Error::shutting_down());
                }

                #[expect(clippy::manual_assert)]
                if !staterestorer.has_content() {
                    #[cfg(unix)]
                    if child_status == 9 {
                        panic!("Target received SIGKILL!. This could indicate the target crashed due to OOM, user sent SIGKILL, or the target was in an unrecoverable situation and could not save state to restart");
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

        // At this point we are the fuzzer *NOT* the restarter.
        // We setup signal handlers to clean up shmem segments used by state restorer
        #[cfg(all(unix, not(miri)))]
        if let Err(_e) = unsafe { setup_signal_handler(&raw mut EVENTMGR_SIGHANDLER_STATE) } {
            // We can live without a proper ctrl+c signal handler. Print and ignore.
            log::error!("Failed to setup signal handlers: {_e}");
        }

        // If we're restarting, deserialize the old state.
        let (state, mgr) = match staterestorer.restore::<(S, Duration, Vec<ClientStats>)>()? {
            None => {
                log::info!("First run. Let's set it all up");
                // Mgr to send and receive msgs from/to all other fuzzer instances
                (
                    None,
                    SimpleRestartingEventManager::launched(monitor, staterestorer),
                )
            }
            // Restoring from a previous run, deserialize state and corpus.
            Some((state, start_time, clients_stats)) => {
                log::info!("Subsequent run. Loaded previous state.");
                // We reset the staterestorer, the next staterestorer and receiver (after crash) will reuse the page from the initial message.
                staterestorer.reset();

                // reload the state of the monitor to display the correct stats after restarts
                monitor.set_start_time(start_time);
                *monitor.client_stats_mut() = clients_stats;

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
