//! A very simple event manager, that just supports log outputs, but no multiprocessing

use alloc::{string::ToString, vec::Vec};
#[cfg(feature = "std")]
use core::{
    marker::PhantomData,
    ptr::{addr_of, read_volatile},
};
#[cfg(feature = "std")]
use serde::{de::DeserializeOwned, Serialize};

#[cfg(all(feature = "std", windows))]
use crate::bolts::os::startable_self;
#[cfg(all(feature = "std", unix))]
use crate::bolts::os::{fork, ForkResult};
#[cfg(feature = "std")]
use crate::bolts::{
    llmp::{LlmpReceiver, LlmpSender},
    shmem::ShMemProvider,
};
use crate::{
    bolts::llmp,
    events::{BrokerEventResult, Event, EventFirer, EventManager, EventProcessor, EventRestarter},
    inputs::Input,
    stats::Stats,
    Error,
};

/// The llmp connection from the actual fuzzer to the process supervising it
const _ENV_FUZZER_SENDER: &str = "_AFL_ENV_FUZZER_SENDER";
const _ENV_FUZZER_RECEIVER: &str = "_AFL_ENV_FUZZER_RECEIVER";
/// The llmp (2 way) connection from a fuzzer to the broker (broadcasting all other fuzzer messages)
const _ENV_FUZZER_BROKER_CLIENT_INITIAL: &str = "_AFL_ENV_FUZZER_BROKER_CLIENT";

/// We're restarting right now.
const _LLMP_TAG_RESTART: llmp::Tag = 0x8357A87;

/// A simple, single-threaded event manager that just logs
#[derive(Clone, Debug)]
pub struct SimpleEventManager<I, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    /// The stats
    stats: ST,
    /// The events that happened since the last handle_in_broker
    events: Vec<Event<I>>,
}

impl<I, S, ST> EventFirer<I, S> for SimpleEventManager<I, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    fn fire(&mut self, _state: &mut S, event: Event<I>) -> Result<(), Error> {
        match Self::handle_in_broker(&mut self.stats, &event)? {
            BrokerEventResult::Forward => self.events.push(event),
            BrokerEventResult::Handled => (),
        };
        Ok(())
    }
}

impl<I, S, ST> EventRestarter<S> for SimpleEventManager<I, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
}

impl<E, I, S, ST, Z> EventProcessor<E, I, S, Z> for SimpleEventManager<I, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
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

impl<E, I, S, ST, Z> EventManager<E, I, S, Z> for SimpleEventManager<I, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
}

impl<I, ST> SimpleEventManager<I, ST>
where
    I: Input,
    ST: Stats, //TODO CE: CustomEvent,
{
    /// Creates a new [`SimpleEventManager`].
    pub fn new(stats: ST) -> Self {
        Self {
            stats,
            events: vec![],
        }
    }

    // Handle arriving events in the broker
    #[allow(clippy::unnecessary_wraps)]
    fn handle_in_broker(stats: &mut ST, event: &Event<I>) -> Result<BrokerEventResult, Error> {
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
                stats
                    .client_stats_mut_for(0)
                    .update_corpus_size(*corpus_size as u64);
                stats
                    .client_stats_mut_for(0)
                    .update_executions(*executions as u64, *time);
                stats.display(event.name().to_string(), 0);
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateStats {
                time,
                executions,
                phantom: _,
            } => {
                // TODO: The stats buffer should be added on client add.
                stats
                    .client_stats_mut_for(0)
                    .update_executions(*executions as u64, *time);
                stats.display(event.name().to_string(), 0);
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateUserStats {
                name,
                value,
                phantom: _,
            } => {
                stats
                    .client_stats_mut_for(0)
                    .update_user_stats(name.clone(), value.clone());
                stats.display(event.name().to_string(), 0);
                Ok(BrokerEventResult::Handled)
            }
            #[cfg(feature = "introspection")]
            Event::UpdatePerfStats {
                time,
                executions,
                introspection_stats,
                phantom: _,
            } => {
                // TODO: The stats buffer should be added on client add.
                stats.client_stats_mut()[0].update_executions(*executions as u64, *time);
                stats.client_stats_mut()[0]
                    .update_introspection_stats((**introspection_stats).clone());
                stats.display(event.name().to_string(), 0);
                Ok(BrokerEventResult::Handled)
            }
            Event::Objective { objective_size } => {
                stats
                    .client_stats_mut_for(0)
                    .update_objective_size(*objective_size as u64);
                stats.display(event.name().to_string(), 0);
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

/// Provides a `builder` which can be used to build a [`RestartingMgr`], which is a combination of a
/// `restarter` and `runner`, that can be used on systems both with and without `fork` support. The
/// `restarter` will start a new process each time the child crashes or times out.
#[cfg(feature = "std")]
#[allow(clippy::default_trait_access)]
pub struct SimpleRestartingEventManager<I, S, SP, ST>
where
    I: Input,
    S: Serialize,
    SP: ShMemProvider,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    /// The actual simple event mgr
    simple_event_mgr: SimpleEventManager<I, ST>,
    /// [`LlmpSender`] for restarts
    sender: LlmpSender<SP>,
    /// Phantom data
    _phantom: PhantomData<(I, S)>,
}

#[cfg(feature = "std")]
impl<I, S, SP, ST> EventFirer<I, S> for SimpleRestartingEventManager<I, S, SP, ST>
where
    I: Input,
    S: Serialize,
    SP: ShMemProvider,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    fn fire(&mut self, _state: &mut S, event: Event<I>) -> Result<(), Error> {
        self.simple_event_mgr.fire(_state, event)
    }
}

#[cfg(feature = "std")]
impl<I, S, SP, ST> EventRestarter<S> for SimpleRestartingEventManager<I, S, SP, ST>
where
    I: Input,
    S: Serialize,
    SP: ShMemProvider,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    /// Reset the single page (we reuse it over and over from pos 0), then send the current state to the next runner.
    fn on_restart(&mut self, state: &mut S) -> Result<(), Error> {
        // First, reset the page to 0 so the next iteration can read read from the beginning of this page
        unsafe {
            self.sender.reset();
        }
        self.sender
            .send_buf(_LLMP_TAG_RESTART, &postcard::to_allocvec(state)?)
    }
}

#[cfg(feature = "std")]
impl<E, I, S, SP, ST, Z> EventProcessor<E, I, S, Z> for SimpleRestartingEventManager<I, S, SP, ST>
where
    I: Input,
    S: Serialize,
    SP: ShMemProvider,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    fn process(&mut self, fuzzer: &mut Z, state: &mut S, executor: &mut E) -> Result<usize, Error> {
        self.simple_event_mgr.process(fuzzer, state, executor)
    }
}

#[cfg(feature = "std")]
impl<E, I, S, SP, ST, Z> EventManager<E, I, S, Z> for SimpleRestartingEventManager<I, S, SP, ST>
where
    I: Input,
    S: Serialize,
    SP: ShMemProvider,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
}

#[cfg(feature = "std")]
#[allow(clippy::type_complexity, clippy::too_many_lines)]
impl<I, S, SP, ST> SimpleRestartingEventManager<I, S, SP, ST>
where
    I: Input,
    S: DeserializeOwned + Serialize,
    SP: ShMemProvider,
    ST: Stats, //TODO CE: CustomEvent,
{
    /// Creates a new [`SimpleEventManager`].
    fn new_launched(stats: ST, sender: LlmpSender<SP>) -> Self {
        Self {
            sender,
            simple_event_mgr: SimpleEventManager::new(stats),
            _phantom: PhantomData {},
        }
    }

    /// Launch the simple restarting manager.
    /// This [`EventManager`] is simple and single threaded,
    /// but can still used shared maps to recover from crashes and timeouts.
    #[allow(clippy::similar_names)]
    pub fn launch(
        stats: ST,
        shmem_provider: &mut SP,
    ) -> Result<(Option<S>, SimpleRestartingEventManager<I, S, SP, ST>), Error> {
        // We start ourself as child process to actually fuzz
        let (mut sender, mut receiver) = if std::env::var(_ENV_FUZZER_SENDER).is_err() {
            // First, create a channel from the fuzzer (sender) to us (receiver) to report its state for restarts.
            let sender = { LlmpSender::new(shmem_provider.clone(), 0, false)? };

            let map = { shmem_provider.clone_ref(&sender.out_maps.last().unwrap().shmem)? };
            let receiver = LlmpReceiver::on_existing_map(shmem_provider.clone(), map, None)?;
            // Store the information to a map.
            sender.to_env(_ENV_FUZZER_SENDER)?;
            receiver.to_env(_ENV_FUZZER_RECEIVER)?;

            let mut ctr: u64 = 0;
            // Client->parent loop
            loop {
                dbg!("Spawning next client (id {})", ctr);

                // On Unix, we fork
                #[cfg(unix)]
                let child_status = {
                    shmem_provider.pre_fork()?;
                    match unsafe { fork() }? {
                        ForkResult::Parent(handle) => {
                            shmem_provider.post_fork(false)?;
                            handle.status()
                        }
                        ForkResult::Child => {
                            shmem_provider.post_fork(true)?;
                            break (sender, receiver);
                        }
                    }
                };

                // On windows, we spawn ourself again
                #[cfg(windows)]
                let child_status = startable_self()?.status()?;

                if unsafe { read_volatile(addr_of!((*receiver.current_recv_map.page()).size_used)) }
                    == 0
                {
                    #[cfg(unix)]
                    if child_status == 137 {
                        // Out of Memory, see https://tldp.org/LDP/abs/html/exitcodes.html
                        // and https://github.com/AFLplusplus/LibAFL/issues/32 for discussion.
                        panic!("Fuzzer-respawner: The fuzzed target crashed with an out of memory error! Fix your harness, or switch to another executor (for example, a forkserver).");
                    }

                    // Storing state in the last round did not work
                    panic!("Fuzzer-respawner: Storing state in crashed fuzzer instance did not work, no point to spawn the next client! (Child exited with: {})", child_status);
                }

                ctr = ctr.wrapping_add(1);
            }
        } else {
            // We are the newly started fuzzing instance (i.e. on Windows), first, connect to our own restore map.
            // We get here *only on Windows*, if we were started by a restarting fuzzer.
            // A sender and a receiver for single communication
            (
                LlmpSender::on_existing_from_env(shmem_provider.clone(), _ENV_FUZZER_SENDER)?,
                LlmpReceiver::on_existing_from_env(shmem_provider.clone(), _ENV_FUZZER_RECEIVER)?,
            )
        };

        println!("We're a client, let's fuzz :)");

        // If we're restarting, deserialize the old state.
        let (state, mgr) = match receiver.recv_buf()? {
            None => {
                println!("First run. Let's set it all up");
                // Mgr to send and receive msgs from/to all other fuzzer instances
                (
                    None,
                    SimpleRestartingEventManager::new_launched(stats, sender),
                )
            }
            // Restoring from a previous run, deserialize state and corpus.
            Some((_sender, _tag, msg)) => {
                println!("Subsequent run. Let's load all data from shmem (received {} bytes from previous instance)", msg.len());
                let state: S = postcard::from_bytes(msg)?;
                // We reset the sender, the next sender and receiver (after crash) will reuse the page from the initial message.
                unsafe {
                    sender.reset();
                }

                (
                    Some(state),
                    SimpleRestartingEventManager::new_launched(stats, sender),
                )
            }
        };

        /* TODO: Not sure if this is needed
        // We commit an empty NO_RESTART message to this buf, against infinite loops,
        // in case something crashes in the fuzzer.
        sender.send_buf(_LLMP_TAG_NO_RESTART, []);
        */

        Ok((state, mgr))
    }
}
