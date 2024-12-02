//! The `LLMP` restarting manager will
//! forward messages over lockless shared maps.
//! When the target crashes, a watch process (the parent) will
//! restart/refork it.

use alloc::{boxed::Box, vec::Vec};
#[cfg(feature = "std")]
use core::sync::atomic::{compiler_fence, Ordering};
#[cfg(feature = "std")]
use core::time::Duration;
use core::{marker::PhantomData, num::NonZeroUsize};
#[cfg(feature = "std")]
use std::net::SocketAddr;

#[cfg(feature = "std")]
use libafl_bolts::core_affinity::CoreId;
#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use libafl_bolts::os::startable_self;
#[cfg(all(unix, feature = "std", not(miri)))]
use libafl_bolts::os::unix_signals::setup_signal_handler;
#[cfg(all(feature = "std", feature = "fork", unix))]
use libafl_bolts::os::{fork, ForkResult};
#[cfg(feature = "std")]
use libafl_bolts::{
    llmp::LlmpConnection, os::CTRL_C_EXIT, shmem::StdShMemProvider, staterestore::StateRestorer,
};
use libafl_bolts::{
    llmp::{Broker, LlmpBroker},
    shmem::ShMemProvider,
    tuples::{tuple_list, Handle},
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use typed_builder::TypedBuilder;

#[cfg(all(unix, feature = "std", not(miri)))]
use crate::events::EVENTMGR_SIGHANDLER_STATE;
#[cfg(feature = "std")]
use crate::events::{AdaptiveSerializer, CustomBufEventResult, HasCustomBufHandlers};
use crate::{
    events::{
        launcher::ClientDescription, Event, EventConfig, EventFirer, EventManager,
        EventManagerHooksTuple, EventManagerId, EventProcessor, EventRestarter, HasEventManagerId,
        LlmpEventManager, LlmpShouldSaveState, ProgressReporter, StdLlmpEventHook,
    },
    executors::{Executor, HasObservers},
    fuzzer::{Evaluator, EvaluatorObservers, ExecutionProcessor},
    inputs::UsesInput,
    monitors::Monitor,
    observers::{ObserversTuple, TimeObserver},
    state::{HasExecutions, HasImported, HasLastReportTime, State, UsesState},
    Error, HasMetadata,
};

/// A manager that can restart on the fly, storing states in-between (in `on_restart`)
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct LlmpRestartingEventManager<EMH, S, SP>
where
    S: State,
    SP: ShMemProvider,
    //CE: CustomEvent<I>,
{
    /// The embedded LLMP event manager
    llmp_mgr: LlmpEventManager<EMH, S, SP>,
    /// The staterestorer to serialize the state for the next runner
    staterestorer: StateRestorer<SP>,
    /// Decide if the state restorer must save the serialized state
    save_state: LlmpShouldSaveState,
}

#[cfg(feature = "std")]
impl<EMH, S, SP> AdaptiveSerializer for LlmpRestartingEventManager<EMH, S, SP>
where
    SP: ShMemProvider,
    S: State,
{
    fn serialization_time(&self) -> Duration {
        self.llmp_mgr.serialization_time()
    }
    fn deserialization_time(&self) -> Duration {
        self.llmp_mgr.deserialization_time()
    }
    fn serializations_cnt(&self) -> usize {
        self.llmp_mgr.serializations_cnt()
    }
    fn should_serialize_cnt(&self) -> usize {
        self.llmp_mgr.should_serialize_cnt()
    }

    fn serialization_time_mut(&mut self) -> &mut Duration {
        self.llmp_mgr.serialization_time_mut()
    }
    fn deserialization_time_mut(&mut self) -> &mut Duration {
        self.llmp_mgr.deserialization_time_mut()
    }
    fn serializations_cnt_mut(&mut self) -> &mut usize {
        self.llmp_mgr.serializations_cnt_mut()
    }
    fn should_serialize_cnt_mut(&mut self) -> &mut usize {
        self.llmp_mgr.should_serialize_cnt_mut()
    }

    fn time_ref(&self) -> &Option<Handle<TimeObserver>> {
        &self.llmp_mgr.time_ref
    }
}

#[cfg(feature = "std")]
impl<EMH, S, SP> UsesState for LlmpRestartingEventManager<EMH, S, SP>
where
    S: State,
    SP: ShMemProvider,
{
    type State = S;
}

#[cfg(feature = "std")]
impl<EMH, S, SP> ProgressReporter for LlmpRestartingEventManager<EMH, S, SP>
where
    S: State + HasExecutions + HasMetadata + HasLastReportTime,
    SP: ShMemProvider,
{
}

#[cfg(feature = "std")]
impl<EMH, S, SP> EventFirer for LlmpRestartingEventManager<EMH, S, SP>
where
    SP: ShMemProvider,
    S: State,
    //CE: CustomEvent<I>,
{
    fn should_send(&self) -> bool {
        self.llmp_mgr.should_send()
    }

    fn fire(
        &mut self,
        state: &mut Self::State,
        event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        // Check if we are going to crash in the event, in which case we store our current state for the next runner
        self.llmp_mgr.fire(state, event)?;
        self.intermediate_save()?;
        Ok(())
    }

    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Option<Vec<u8>>, Error>
    where
        OT: ObserversTuple<Self::Input, Self::State> + Serialize,
    {
        self.llmp_mgr.serialize_observers(observers)
    }

    fn configuration(&self) -> EventConfig {
        self.llmp_mgr.configuration()
    }
}

#[cfg(feature = "std")]
impl<EMH, S, SP> EventRestarter for LlmpRestartingEventManager<EMH, S, SP>
where
    S: State + HasExecutions,
    SP: ShMemProvider,
    //CE: CustomEvent<I>,
{
    /// The llmp client needs to wait until a broker mapped all pages, before shutting down.
    /// Otherwise, the OS may already have removed the shared maps,
    #[inline]
    fn await_restart_safe(&mut self) {
        self.llmp_mgr.await_restart_safe();
    }

    /// Reset the single page (we reuse it over and over from pos 0), then send the current state to the next runner.
    fn on_restart(&mut self, state: &mut S) -> Result<(), Error> {
        state.on_restart()?;

        // First, reset the page to 0 so the next iteration can read from the beginning of this page
        self.staterestorer.reset();
        self.staterestorer.save(&(
            if self.save_state.on_restart() {
                Some(state)
            } else {
                None
            },
            &self.llmp_mgr.describe()?,
        ))?;

        log::info!("Waiting for broker...");
        self.await_restart_safe();
        Ok(())
    }

    fn send_exiting(&mut self) -> Result<(), Error> {
        self.staterestorer.send_exiting();
        // Also inform the broker that we are about to exit.
        // This way, the broker can clean up the pages, and eventually exit.
        self.llmp_mgr.send_exiting()
    }
}

#[cfg(feature = "std")]
impl<E, EMH, S, SP, Z> EventProcessor<E, Z> for LlmpRestartingEventManager<EMH, S, SP>
where
    E: HasObservers + Executor<LlmpEventManager<EMH, S, SP>, Z, State = S>,
    E::Observers: ObserversTuple<S::Input, S> + Serialize,
    for<'a> E::Observers: Deserialize<'a>,
    EMH: EventManagerHooksTuple<S>,
    S: State + HasExecutions + HasMetadata + HasImported,
    SP: ShMemProvider,
    Z: ExecutionProcessor<LlmpEventManager<EMH, S, SP>, E::Observers, State = S>
        + EvaluatorObservers<LlmpEventManager<EMH, S, SP>, E::Observers>
        + Evaluator<E, LlmpEventManager<EMH, S, SP>>,
{
    fn process(&mut self, fuzzer: &mut Z, state: &mut S, executor: &mut E) -> Result<usize, Error> {
        let res = self.llmp_mgr.process(fuzzer, state, executor)?;
        self.intermediate_save()?;
        Ok(res)
    }

    fn on_shutdown(&mut self) -> Result<(), Error> {
        self.send_exiting()
    }
}

#[cfg(feature = "std")]
impl<E, EMH, S, SP, Z> EventManager<E, Z> for LlmpRestartingEventManager<EMH, S, SP>
where
    E: HasObservers + Executor<LlmpEventManager<EMH, S, SP>, Z, State = S>,
    E::Observers: ObserversTuple<S::Input, S> + Serialize,
    for<'a> E::Observers: Deserialize<'a>,
    EMH: EventManagerHooksTuple<S>,
    S: State + HasExecutions + HasMetadata + HasLastReportTime + HasImported,
    SP: ShMemProvider,
    Z: ExecutionProcessor<LlmpEventManager<EMH, S, SP>, E::Observers, State = S>
        + EvaluatorObservers<LlmpEventManager<EMH, S, SP>, E::Observers>
        + Evaluator<E, LlmpEventManager<EMH, S, SP>>,
{
}

#[cfg(feature = "std")]
impl<EMH, S, SP> HasEventManagerId for LlmpRestartingEventManager<EMH, S, SP>
where
    S: State,
    SP: ShMemProvider,
{
    fn mgr_id(&self) -> EventManagerId {
        self.llmp_mgr.mgr_id()
    }
}

#[cfg(feature = "std")]
impl<EMH, S, SP> HasCustomBufHandlers for LlmpRestartingEventManager<EMH, S, SP>
where
    S: State,
    SP: ShMemProvider,
{
    fn add_custom_buf_handler(
        &mut self,
        handler: Box<dyn FnMut(&mut S, &str, &[u8]) -> Result<CustomBufEventResult, Error>>,
    ) {
        self.llmp_mgr.add_custom_buf_handler(handler);
    }
}

/// The llmp connection from the actual fuzzer to the process supervising it
const _ENV_FUZZER_SENDER: &str = "_AFL_ENV_FUZZER_SENDER";
const _ENV_FUZZER_RECEIVER: &str = "_AFL_ENV_FUZZER_RECEIVER";
/// The llmp (2 way) connection from a fuzzer to the broker (broadcasting all other fuzzer messages)
const _ENV_FUZZER_BROKER_CLIENT_INITIAL: &str = "_AFL_ENV_FUZZER_BROKER_CLIENT";

#[cfg(feature = "std")]
impl<EMH, S, SP> LlmpRestartingEventManager<EMH, S, SP>
where
    S: State,
    SP: ShMemProvider,
    //CE: CustomEvent<I>,
{
    /// Create a new runner, the executed child doing the actual fuzzing.
    pub fn new(llmp_mgr: LlmpEventManager<EMH, S, SP>, staterestorer: StateRestorer<SP>) -> Self {
        Self {
            llmp_mgr,
            staterestorer,
            save_state: LlmpShouldSaveState::OnRestart,
        }
    }

    /// Create a new runner specifying if it must save the serialized state on restart.
    pub fn with_save_state(
        llmp_mgr: LlmpEventManager<EMH, S, SP>,
        staterestorer: StateRestorer<SP>,
        save_state: LlmpShouldSaveState,
    ) -> Self {
        Self {
            llmp_mgr,
            staterestorer,
            save_state,
        }
    }

    /// Get the staterestorer
    pub fn staterestorer(&self) -> &StateRestorer<SP> {
        &self.staterestorer
    }

    /// Get the staterestorer (mutable)
    pub fn staterestorer_mut(&mut self) -> &mut StateRestorer<SP> {
        &mut self.staterestorer
    }

    /// Save LLMP state and empty state in staterestorer
    pub fn intermediate_save(&mut self) -> Result<(), Error> {
        // First, reset the page to 0 so the next iteration can read read from the beginning of this page
        if self.save_state.oom_safe() {
            self.staterestorer.reset();
            self.staterestorer
                .save(&(None::<S>, &self.llmp_mgr.describe()?))?;
        }
        Ok(())
    }
}

/// The kind of manager we're creating right now
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub enum ManagerKind {
    /// Any kind will do
    Any,
    /// A client, getting messages from a local broker.
    Client {
        /// The client description
        client_description: ClientDescription,
    },
    /// An [`LlmpBroker`], forwarding the packets of local clients.
    Broker,
}

/// Sets up a restarting fuzzer, using the [`StdShMemProvider`], and standard features.
///
/// The restarting mgr is a combination of restarter and runner, that can be used on systems with and without `fork` support.
/// The restarter will spawn a new process each time the child crashes or timeouts.
#[cfg(feature = "std")]
#[allow(clippy::type_complexity)]
pub fn setup_restarting_mgr_std<MT, S>(
    monitor: MT,
    broker_port: u16,
    configuration: EventConfig,
) -> Result<
    (
        Option<S>,
        LlmpRestartingEventManager<(), S, StdShMemProvider>,
    ),
    Error,
>
where
    MT: Monitor + Clone,
    S: State,
{
    RestartingMgr::builder()
        .shmem_provider(StdShMemProvider::new()?)
        .monitor(Some(monitor))
        .broker_port(broker_port)
        .configuration(configuration)
        .hooks(tuple_list!())
        .build()
        .launch()
}

/// Sets up a restarting fuzzer, using the [`StdShMemProvider`], and standard features.
///
/// The restarting mgr is a combination of restarter and runner, that can be used on systems with and without `fork` support.
/// The restarter will spawn a new process each time the child crashes or timeouts.
/// This one, additionally uses the timeobserver for the adaptive serialization
#[cfg(feature = "std")]
#[allow(clippy::type_complexity)]
pub fn setup_restarting_mgr_std_adaptive<MT, S>(
    monitor: MT,
    broker_port: u16,
    configuration: EventConfig,
    time_obs: Handle<TimeObserver>,
) -> Result<
    (
        Option<S>,
        LlmpRestartingEventManager<(), S, StdShMemProvider>,
    ),
    Error,
>
where
    MT: Monitor + Clone,
    S: State,
{
    RestartingMgr::builder()
        .shmem_provider(StdShMemProvider::new()?)
        .monitor(Some(monitor))
        .broker_port(broker_port)
        .configuration(configuration)
        .hooks(tuple_list!())
        .time_ref(Some(time_obs))
        .build()
        .launch()
}

/// Provides a `builder` which can be used to build a [`RestartingMgr`].
///
/// The [`RestartingMgr`] is is a combination of a
/// `restarter` and `runner`, that can be used on systems both with and without `fork` support. The
/// `restarter` will start a new process each time the child crashes or times out.
#[cfg(feature = "std")]
#[allow(clippy::default_trait_access, clippy::ignored_unit_patterns)]
#[derive(TypedBuilder, Debug)]
pub struct RestartingMgr<EMH, MT, S, SP> {
    /// The shared memory provider to use for the broker or client spawned by the restarting
    /// manager.
    shmem_provider: SP,
    #[builder(default = false)]
    /// Consider this testcase as interesting always if true
    always_interesting: bool,
    /// The configuration
    configuration: EventConfig,
    /// The monitor to use
    #[builder(default = None)]
    monitor: Option<MT>,
    /// The broker port to use
    #[builder(default = 1337_u16)]
    broker_port: u16,
    /// The address to connect to
    #[builder(default = None)]
    remote_broker_addr: Option<SocketAddr>,
    /// The type of manager to build
    #[builder(default = ManagerKind::Any)]
    kind: ManagerKind,
    /// The amount of external clients that should have connected (not counting our own tcp client)
    /// before this broker quits _after the last client exited_.
    /// If `None`, the broker will never quit when the last client exits, but run forever.
    ///
    /// So, if this value is `Some(2)`, the broker will not exit after client 1 connected and disconnected,
    /// but it will quit after client 2 connected and disconnected.
    #[builder(default = None)]
    exit_cleanly_after: Option<NonZeroUsize>,
    /// Tell the manager to serialize or not the state on restart
    #[builder(default = LlmpShouldSaveState::OnRestart)]
    serialize_state: LlmpShouldSaveState,
    /// The hooks passed to event manager:
    hooks: EMH,
    #[builder(default = None)]
    time_ref: Option<Handle<TimeObserver>>,
    #[builder(setter(skip), default = PhantomData)]
    phantom_data: PhantomData<(EMH, S)>,
}

#[cfg(feature = "std")]
#[allow(clippy::type_complexity, clippy::too_many_lines)]
impl<EMH, MT, S, SP> RestartingMgr<EMH, MT, S, SP>
where
    EMH: EventManagerHooksTuple<S> + Copy + Clone,
    SP: ShMemProvider,
    S: State,
    MT: Monitor + Clone,
{
    /// Launch the broker and the clients and fuzz
    pub fn launch(&mut self) -> Result<(Option<S>, LlmpRestartingEventManager<EMH, S, SP>), Error> {
        // We start ourselves as child process to actually fuzz
        let (staterestorer, new_shmem_provider, core_id) = if std::env::var(_ENV_FUZZER_SENDER)
            .is_err()
        {
            let broker_things = |mut broker: LlmpBroker<_, SP>, remote_broker_addr| {
                if let Some(remote_broker_addr) = remote_broker_addr {
                    log::info!("B2b: Connecting to {:?}", &remote_broker_addr);
                    broker.inner_mut().connect_b2b(remote_broker_addr)?;
                };

                if let Some(exit_cleanly_after) = self.exit_cleanly_after {
                    broker.set_exit_after(exit_cleanly_after);
                }

                broker.loop_with_timeouts(Duration::from_secs(30), Some(Duration::from_millis(5)));

                #[cfg(feature = "llmp_debug")]
                log::info!("The last client quit. Exiting.");

                Err(Error::shutting_down())
            };
            // We get here if we are on Unix, or we are a broker on Windows (or without forks).
            let (mgr, core_id) = match &self.kind {
                ManagerKind::Any => {
                    let connection =
                        LlmpConnection::on_port(self.shmem_provider.clone(), self.broker_port)?;
                    match connection {
                        LlmpConnection::IsBroker { broker } => {
                            let llmp_hook = StdLlmpEventHook::<S::Input, MT>::new(
                                self.monitor.take().unwrap(),
                            )?;

                            // Yep, broker. Just loop here.
                            log::info!(
                                "Doing broker things. Run this tool again to start fuzzing in a client."
                            );

                            broker_things(
                                broker.add_hooks(tuple_list!(llmp_hook)),
                                self.remote_broker_addr,
                            )?;

                            return Err(Error::shutting_down());
                        }
                        LlmpConnection::IsClient { client } => {
                            let mgr: LlmpEventManager<EMH, S, SP> = LlmpEventManager::builder()
                                .always_interesting(self.always_interesting)
                                .hooks(self.hooks)
                                .build_from_client(
                                    client,
                                    self.configuration,
                                    self.time_ref.clone(),
                                )?;
                            (mgr, None)
                        }
                    }
                }
                ManagerKind::Broker => {
                    let llmp_hook = StdLlmpEventHook::new(self.monitor.take().unwrap())?;

                    let broker = LlmpBroker::create_attach_to_tcp(
                        self.shmem_provider.clone(),
                        tuple_list!(llmp_hook),
                        self.broker_port,
                    )?;

                    broker_things(broker, self.remote_broker_addr)?;
                    unreachable!("The broker may never return normally, only on errors or when shutting down.");
                }
                ManagerKind::Client { client_description } => {
                    // We are a client
                    let mgr = LlmpEventManager::builder()
                        .always_interesting(self.always_interesting)
                        .hooks(self.hooks)
                        .build_on_port(
                            self.shmem_provider.clone(),
                            self.broker_port,
                            self.configuration,
                            self.time_ref.clone(),
                        )?;

                    (mgr, Some(client_description.core_id()))
                }
            };

            if let Some(core_id) = core_id {
                let core_id: CoreId = core_id;
                log::info!("Setting core affinity to {core_id:?}");
                core_id.set_affinity()?;
            }

            // We are the fuzzer respawner in a llmp client
            mgr.to_env(_ENV_FUZZER_BROKER_CLIENT_INITIAL);

            // First, create a channel from the current fuzzer to the next to store state between restarts.
            #[cfg(unix)]
            let staterestorer: StateRestorer<SP> =
                StateRestorer::new(self.shmem_provider.new_shmem(256 * 1024 * 1024)?);

            #[cfg(not(unix))]
            let staterestorer: StateRestorer<SP> =
                StateRestorer::new(self.shmem_provider.new_shmem(256 * 1024 * 1024)?);
            // Store the information to a map.
            staterestorer.write_to_env(_ENV_FUZZER_SENDER)?;

            let mut ctr: u64 = 0;
            // Client->parent loop
            loop {
                log::info!("Spawning next client (id {ctr})");

                // On Unix, we fork (when fork feature is enabled)
                #[cfg(all(unix, feature = "fork"))]
                let child_status = {
                    self.shmem_provider.pre_fork()?;
                    match unsafe { fork() }? {
                        ForkResult::Parent(handle) => {
                            unsafe {
                                libc::signal(libc::SIGINT, libc::SIG_IGN);
                            }
                            self.shmem_provider.post_fork(false)?;
                            handle.status()
                        }
                        ForkResult::Child => {
                            log::debug!(
                                "{} has been forked into {}",
                                std::os::unix::process::parent_id(),
                                std::process::id()
                            );
                            self.shmem_provider.post_fork(true)?;
                            break (staterestorer, self.shmem_provider.clone(), core_id);
                        }
                    }
                };

                // If this guy wants to fork, then ignore sigint
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

                // On Windows (or in any case without fork), we spawn ourself again
                #[cfg(any(windows, not(feature = "fork")))]
                let child_status = startable_self()?.status()?;
                #[cfg(any(windows, not(feature = "fork")))]
                let child_status = child_status.code().unwrap_or_default();

                compiler_fence(Ordering::SeqCst); // really useful?

                if child_status == CTRL_C_EXIT || staterestorer.wants_to_exit() {
                    // if ctrl-c is pressed, we end up in this branch
                    if let Err(err) = mgr.detach_from_broker(self.broker_port) {
                        log::error!("Failed to detach from broker: {err}");
                    }
                    return Err(Error::shutting_down());
                }

                #[allow(clippy::manual_assert)]
                if !staterestorer.has_content() && !self.serialize_state.oom_safe() {
                    if let Err(err) = mgr.detach_from_broker(self.broker_port) {
                        log::error!("Failed to detach from broker: {err}");
                    }
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
            (
                StateRestorer::from_env(&mut self.shmem_provider, _ENV_FUZZER_SENDER)?,
                self.shmem_provider.clone(),
                None,
            )
        };

        // At this point we are the fuzzer *NOT* the restarter.
        // We setup signal handlers to clean up shmem segments used by state restorer
        #[cfg(all(unix, not(miri)))]
        if let Err(_e) = unsafe { setup_signal_handler(&raw mut EVENTMGR_SIGHANDLER_STATE) } {
            // We can live without a proper ctrl+c signal handler. Print and ignore.
            log::error!("Failed to setup signal handlers: {_e}");
        }

        if let Some(core_id) = core_id {
            let core_id: CoreId = core_id;
            core_id.set_affinity()?;
        }

        // If we're restarting, deserialize the old state.
        let (state, mut mgr) =
            if let Some((state_opt, mgr_description)) = staterestorer.restore()? {
                let llmp_mgr = LlmpEventManager::builder()
                    .hooks(self.hooks)
                    .build_existing_client_from_description(
                        new_shmem_provider,
                        &mgr_description,
                        self.configuration,
                        self.time_ref.clone(),
                    )?;
                (
                    state_opt,
                    LlmpRestartingEventManager::with_save_state(
                        llmp_mgr,
                        staterestorer,
                        self.serialize_state,
                    ),
                )
            } else {
                log::info!("First run. Let's set it all up");
                // Mgr to send and receive msgs from/to all other fuzzer instances
                let mgr = LlmpEventManager::builder()
                    .hooks(self.hooks)
                    .build_existing_client_from_env(
                        new_shmem_provider,
                        _ENV_FUZZER_BROKER_CLIENT_INITIAL,
                        self.configuration,
                        self.time_ref.clone(),
                    )?;

                (
                    None,
                    LlmpRestartingEventManager::with_save_state(
                        mgr,
                        staterestorer,
                        self.serialize_state,
                    ),
                )
            };
        // We reset the staterestorer, the next staterestorer and receiver (after crash) will reuse the page from the initial message.
        if self.serialize_state.oom_safe() {
            mgr.intermediate_save()?;
        } else {
            mgr.staterestorer.reset();
        }

        /* TODO: Not sure if this is needed
        // We commit an empty NO_RESTART message to this buf, against infinite loops,
        // in case something crashes in the fuzzer.
        staterestorer.send_buf(_LLMP_TAG_NO_RESTART, []);
        */

        Ok((state, mgr))
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use core::sync::atomic::{compiler_fence, Ordering};

    use libafl_bolts::{
        llmp::{LlmpClient, LlmpSharedMap},
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        staterestore::StateRestorer,
        tuples::{tuple_list, Handled},
        ClientId,
    };
    use serial_test::serial;

    use crate::{
        corpus::{Corpus, InMemoryCorpus, Testcase},
        events::llmp::{restarting::_ENV_FUZZER_SENDER, LlmpEventManager},
        executors::{ExitKind, InProcessExecutor},
        feedbacks::ConstFeedback,
        fuzzer::Fuzzer,
        inputs::BytesInput,
        mutators::BitFlipMutator,
        observers::TimeObserver,
        schedulers::RandScheduler,
        stages::StdMutationalStage,
        state::StdState,
        StdFuzzer,
    };

    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_mgr_state_restore() {
        let rand = StdRand::with_seed(0);

        let time = TimeObserver::new("time");
        let time_ref = time.handle();

        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(vec![0; 4].into());
        corpus.add(testcase).unwrap();

        let solutions = InMemoryCorpus::<BytesInput>::new();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        let mut state =
            StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();

        let mut shmem_provider = StdShMemProvider::new().unwrap();

        let mut llmp_client = LlmpClient::new(
            shmem_provider.clone(),
            LlmpSharedMap::new(ClientId(0), shmem_provider.new_shmem(1024).unwrap()),
            ClientId(0),
        )
        .unwrap();

        // A little hack for CI. Don't do that in a real-world scenario.
        unsafe {
            llmp_client.mark_safe_to_unmap();
        }

        let mut llmp_mgr = LlmpEventManager::builder()
            .build_from_client(llmp_client, "fuzzer".into(), Some(time_ref.clone()))
            .unwrap();

        let scheduler = RandScheduler::new();

        let feedback = ConstFeedback::new(true);
        let objective = ConstFeedback::new(false);

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut harness = |_buf: &BytesInput| ExitKind::Ok;
        let mut executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(time),
            &mut fuzzer,
            &mut state,
            &mut llmp_mgr,
        )
        .unwrap();

        let mutator = BitFlipMutator::new();
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        // First, create a channel from the current fuzzer to the next to store state between restarts.
        let mut staterestorer = StateRestorer::<StdShMemProvider>::new(
            shmem_provider.new_shmem(256 * 1024 * 1024).unwrap(),
        );

        staterestorer.reset();
        staterestorer
            .save(&(&mut state, &llmp_mgr.describe().unwrap()))
            .unwrap();
        assert!(staterestorer.has_content());

        // Store the information to a map.
        staterestorer.write_to_env(_ENV_FUZZER_SENDER).unwrap();

        compiler_fence(Ordering::SeqCst);

        let sc_cpy = StateRestorer::from_env(&mut shmem_provider, _ENV_FUZZER_SENDER).unwrap();
        assert!(sc_cpy.has_content());

        let (mut state_clone, mgr_description) = staterestorer.restore().unwrap().unwrap();
        let mut llmp_clone = LlmpEventManager::builder()
            .build_existing_client_from_description(
                shmem_provider,
                &mgr_description,
                "fuzzer".into(),
                Some(time_ref),
            )
            .unwrap();

        fuzzer
            .fuzz_one(
                &mut stages,
                &mut executor,
                &mut state_clone,
                &mut llmp_clone,
            )
            .unwrap();
    }
}
