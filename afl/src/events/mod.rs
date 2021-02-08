//! Eventmanager manages all events that go to other instances of the fuzzer.

pub mod stats;
pub use stats::*;

use crate::llmp::LlmpSender;
use crate::{llmp::LlmpReceiver, utils::deserialize_state_mgr};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, marker::PhantomData, time::Duration};
use serde::{Deserialize, Serialize};
use std::env;

#[cfg(feature = "std")]
use std::process::Command;

#[cfg(feature = "std")]
#[cfg(unix)]
use crate::shmem::AflShmem;
use crate::{
    corpus::Corpus,
    feedbacks::FeedbacksTuple,
    inputs::Input,
    llmp::{self, LlmpClient, LlmpClientDescription, Tag},
    observers::ObserversTuple,
    shmem::ShMem,
    state::State,
    utils::Rand,
    AflError,
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

/*
/// A custom event, for own messages, with own handler.
pub trait CustomEvent<I>: SerdeAny
where
    I: Input,
{
    /// Returns the name of this event
    fn name(&self) -> &str;
    /// This method will be called in the broker
    fn handle_in_broker(&self) -> Result<BrokerEventResult, AflError>;
    /// This method will be called in the clients after handle_in_broker (unless BrokerEventResult::Handled) was returned in handle_in_broker
    fn handle_in_client(&self) -> Result<(), AflError>;
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
    // The sender can then use it to send Testcase metadatas with CustomEvent
    /// A fuzzer found a new testcase. Rejoice!
    NewTestcase {
        /// The input for the new testcase
        input: I,
        /// The state of the observers when this testcase was found
        observers_buf: Vec<u8>,
        /// The new corpus size of this client
        corpus_size: usize,
        /// The client config for this observers/testcase combination
        client_config: String,
    },
    /// New stats.
    UpdateStats {
        /// The executions of this client
        executions: usize,
        /// The execs per sec for this client
        execs_over_sec: u64,
        phantom: PhantomData<I>,
    },
    /// A crash was found
    Crash {
        /// Crashing input
        input: I,
    },
    /// A timeout was found
    Timeout {
        /// Timeouting input
        input: I,
    },
    /// Write a new log
    Log {
        /// the severity level
        severity_level: LogSeverity,
        /// The message
        message: String,
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
                observers_buf: _,
            } => "New Testcase",
            Event::UpdateStats {
                executions: _,
                execs_over_sec: _,
                phantom: _,
            } => "Stats",
            Event::Crash { input: _ } => "Crash",
            Event::Timeout { input: _ } => "Timeout",
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

/// EventManager is the main communications hub.
/// For the "normal" multi-processed mode, you may want to look into `RestartingEventManager`
pub trait EventManager<I>
where
    I: Input,
{
    /// Fire an Event
    //fn fire<'a>(&mut self, event: Event<I>) -> Result<(), AflError>;

    /// Lookup for incoming events and process them.
    /// Return the number of processes events or an error
    fn process<C, FT, R>(&mut self, state: &mut State<C, I, R, FT>) -> Result<usize, AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand;

    /// Serialize all observers for this type and manager
    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Vec<u8>, AflError>
    where
        OT: ObserversTuple,
    {
        Ok(postcard::to_allocvec(observers)?)
    }

    /// Deserialize all observers for this type and manager
    fn deserialize_observers<OT>(&mut self, observers_buf: &[u8]) -> Result<OT, AflError>
    where
        OT: ObserversTuple,
    {
        Ok(postcard::from_bytes(observers_buf)?)
    }

    /// Send off an event to the broker
    fn fire<C, FT, R>(
        &mut self,
        _state: &mut State<C, I, R, FT>,
        event: Event<I>,
    ) -> Result<(), AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand;
}

/// An eventmgr for tests, and as placeholder if you really don't need an event manager.
#[derive(Copy, Clone, Debug)]
pub struct NopEventManager<I> {
    phantom: PhantomData<I>,
}
impl<I> EventManager<I> for NopEventManager<I>
where
    I: Input,
{
    fn process<C, FT, R>(&mut self, _state: &mut State<C, I, R, FT>) -> Result<usize, AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        Ok(0)
    }

    fn fire<C, FT, R>(
        &mut self,
        _state: &mut State<C, I, R, FT>,
        _event: Event<I>,
    ) -> Result<(), AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        Ok(())
    }
}

/// A simple, single-threaded event manager that just logs
#[derive(Clone, Debug)]
pub struct LoggerEventManager<I, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    /// The stats
    stats: ST,
    /// The events that happened since the last handle_in_broker
    events: Vec<Event<I>>,
}

impl<I, ST> EventManager<I> for LoggerEventManager<I, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    fn process<C, FT, R>(&mut self, state: &mut State<C, I, R, FT>) -> Result<usize, AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        let count = self.events.len();
        while self.events.len() > 0 {
            let event = self.events.pop().unwrap();
            self.handle_in_client(state, 0, event)?;
        }
        Ok(count)
    }

    fn fire<C, FT, R>(
        &mut self,
        _state: &mut State<C, I, R, FT>,
        event: Event<I>,
    ) -> Result<(), AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        match Self::handle_in_broker(&mut self.stats, 0, &event)? {
            BrokerEventResult::Forward => self.events.push(event),
            BrokerEventResult::Handled => (),
        };
        Ok(())
    }
}

impl<I, ST> LoggerEventManager<I, ST>
where
    I: Input,
    ST: Stats, //TODO CE: CustomEvent,
{
    pub fn new(stats: ST) -> Self {
        Self {
            stats: stats,
            events: vec![],
        }
    }

    // Handle arriving events in the broker
    fn handle_in_broker(
        stats: &mut ST,
        _sender_id: u32,
        event: &Event<I>,
    ) -> Result<BrokerEventResult, AflError> {
        match event {
            Event::NewTestcase {
                input: _,
                client_config: _,
                corpus_size,
                observers_buf: _,
            } => {
                stats.client_stats_mut()[0].corpus_size = *corpus_size as u64;
                stats.show(event.name().to_string());
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateStats {
                executions,
                execs_over_sec: _,
                phantom: _,
            } => {
                // TODO: The stats buffer should be added on client add.
                stats.client_stats_mut()[0].executions = *executions as u64;
                stats.show(event.name().to_string());
                Ok(BrokerEventResult::Handled)
            }
            Event::Crash { input: _ } => {
                panic!("LoggerEventManager cannot handle Event::Crash");
            }
            Event::Timeout { input: _ } => {
                panic!("LoggerEventManager cannot handle Event::Timeout");
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
    fn handle_in_client<C, FT, R>(
        &mut self,
        _state: &mut State<C, I, R, FT>,
        _sender_id: u32,
        event: Event<I>,
    ) -> Result<(), AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        match event {
            _ => Err(AflError::Unknown(format!(
                "Received illegal message that message should not have arrived: {:?}.",
                event
            ))),
        }
    }
}

/// Forward this to the client
const _LLMP_TAG_EVENT_TO_CLIENT: llmp::Tag = 0x2C11E471;
/// Only handle this in the broker
const _LLMP_TAG_EVENT_TO_BROKER: llmp::Tag = 0x2B80438;
/// Handle in both
///
const LLMP_TAG_EVENT_TO_BOTH: llmp::Tag = 0x2B0741;

const _LLMP_TAG_RESTART: llmp::Tag = 0x8357A87;
const _LLMP_TAG_NO_RESTART: llmp::Tag = 0x57A7EE71;

#[derive(Clone, Debug)]
pub struct LlmpEventManager<I, SH, ST>
where
    I: Input,
    SH: ShMem,
    ST: Stats,
    //CE: CustomEvent<I>,
{
    stats: Option<ST>,
    llmp: llmp::LlmpConnection<SH>,
    phantom: PhantomData<I>,
}

#[cfg(feature = "std")]
#[cfg(unix)]
impl<I, ST> LlmpEventManager<I, AflShmem, ST>
where
    I: Input,
    ST: Stats,
{
    /// Create llmp on a port
    /// If the port is not yet bound, it will act as broker
    /// Else, it will act as client.
    #[cfg(feature = "std")]
    pub fn new_on_port_std(stats: ST, port: u16) -> Result<Self, AflError> {
        Ok(Self {
            stats: Some(stats),
            llmp: llmp::LlmpConnection::on_port(port)?,
            phantom: PhantomData,
        })
    }

    /// If a client respawns, it may reuse the existing connection, previously stored by LlmpClient::to_env
    /// Std uses AflShmem.
    #[cfg(feature = "std")]
    pub fn existing_client_from_env_std(env_name: &str) -> Result<Self, AflError> {
        Self::existing_client_from_env(env_name)
    }
}

impl<I, SH, ST> LlmpEventManager<I, SH, ST>
where
    I: Input,
    SH: ShMem,
    ST: Stats,
{
    /// Create llmp on a port
    /// If the port is not yet bound, it will act as broker
    /// Else, it will act as client.
    #[cfg(feature = "std")]
    pub fn new_on_port(stats: ST, port: u16) -> Result<Self, AflError> {
        Ok(Self {
            stats: Some(stats),
            llmp: llmp::LlmpConnection::on_port(port)?,
            phantom: PhantomData,
        })
    }

    /// If a client respawns, it may reuse the existing connection, previously stored by LlmpClient::to_env
    #[cfg(feature = "std")]
    pub fn existing_client_from_env(env_name: &str) -> Result<Self, AflError> {
        Ok(Self {
            stats: None,
            llmp: llmp::LlmpConnection::IsClient {
                client: LlmpClient::on_existing_from_env(env_name)?,
            },
            // Inserting a nop-stats element here so rust won't complain.
            // In any case, the client won't currently use it.
            phantom: PhantomData,
        })
    }

    /// Describe the client event mgr's llmp parts in a restorable fashion
    pub fn describe(&self) -> Result<LlmpClientDescription, AflError> {
        self.llmp.describe()
    }

    /// Create an existing client from description
    pub fn existing_client_from_description(
        description: &LlmpClientDescription,
    ) -> Result<Self, AflError> {
        Ok(Self {
            stats: None,
            llmp: llmp::LlmpConnection::existing_client_from_description(description)?,
            // Inserting a nop-stats element here so rust won't complain.
            // In any case, the client won't currently use it.
            phantom: PhantomData,
        })
    }

    /// A client on an existing map
    pub fn for_client(client: LlmpClient<SH>) -> Self {
        Self {
            stats: None,
            llmp: llmp::LlmpConnection::IsClient { client },
            phantom: PhantomData,
        }
    }

    /// Write the config for a client eventmgr to env vars, a new client can reattach using existing_client_from_env
    #[cfg(feature = "std")]
    pub fn to_env(&self, env_name: &str) {
        match &self.llmp {
            llmp::LlmpConnection::IsBroker { broker: _ } => {
                todo!("There is probably no use storing the broker to env. Client only for now")
            }
            llmp::LlmpConnection::IsClient { client } => client.to_env(env_name).unwrap(),
        }
    }

    /// Returns if we are the broker
    pub fn is_broker(&self) -> bool {
        match self.llmp {
            llmp::LlmpConnection::IsBroker { broker: _ } => true,
            _ => false,
        }
    }

    /// Run forever in the broker
    pub fn broker_loop(&mut self) -> Result<(), AflError> {
        match &mut self.llmp {
            llmp::LlmpConnection::IsBroker { broker } => {
                let stats = self.stats.as_mut().unwrap();
                broker.loop_forever(
                    &mut |sender_id: u32, tag: Tag, msg: &[u8]| {
                        if tag == LLMP_TAG_EVENT_TO_BOTH {
                            let event: Event<I> = postcard::from_bytes(msg)?;
                            match Self::handle_in_broker(stats, sender_id, &event)? {
                                BrokerEventResult::Forward => {
                                    Ok(llmp::LlmpMsgHookResult::ForwardToClients)
                                }
                                BrokerEventResult::Handled => Ok(llmp::LlmpMsgHookResult::Handled),
                            }
                        } else {
                            Ok(llmp::LlmpMsgHookResult::ForwardToClients)
                        }
                    },
                    Some(Duration::from_millis(5)),
                );
            }
            _ => Err(AflError::IllegalState(
                "Called broker loop in the client".into(),
            )),
        }
    }

    /// Handle arriving events in the broker
    fn handle_in_broker(
        stats: &mut ST,
        sender_id: u32,
        event: &Event<I>,
    ) -> Result<BrokerEventResult, AflError> {
        match &event {
            Event::NewTestcase {
                input: _,
                client_config: _,
                corpus_size,
                observers_buf: _,
            } => {
                let client = stats.client_stats_mut_for(sender_id);
                client.corpus_size = *corpus_size as u64;
                stats.show(event.name().to_string() + " #" + &sender_id.to_string());
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateStats {
                executions,
                execs_over_sec: _,
                phantom: _,
            } => {
                // TODO: The stats buffer should be added on client add.
                let client = stats.client_stats_mut_for(sender_id);
                client.executions = *executions as u64;
                stats.show(event.name().to_string() + " #" + &sender_id.to_string());
                Ok(BrokerEventResult::Handled)
            }
            Event::Crash { input: _ } => {
                #[cfg(feature = "std")]
                println!("Event::Crash");
                Ok(BrokerEventResult::Handled)
            }
            Event::Timeout { input: _ } => {
                #[cfg(feature = "std")]
                println!("Event::Timeout");
                Ok(BrokerEventResult::Handled)
            }
            Event::Log {
                severity_level,
                message,
                phantom: _,
            } => {
                let (_, _) = (severity_level, message);
                #[cfg(feature = "std")]
                println!("[LOG {}]: {}", severity_level, message);
                Ok(BrokerEventResult::Handled)
            } //_ => Ok(BrokerEventResult::Forward),
        }
    }

    // Handle arriving events in the client
    fn handle_in_client<C, FT, R>(
        &mut self,
        state: &mut State<C, I, R, FT>,
        _sender_id: u32,
        event: Event<I>,
    ) -> Result<(), AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        match event {
            Event::NewTestcase {
                input,
                client_config: _,
                corpus_size: _,
                observers_buf,
            } => {
                // TODO: here u should match client_config, if equal to the current one do not re-execute
                // we need to pass engine to process() too, TODO
                #[cfg(feature = "std")]
                println!("Received new Testcase");
                let observers = postcard::from_bytes(&observers_buf)?;
                let interestingness = state.is_interesting(&input, &observers)?;
                state.add_if_interesting(input, interestingness)?;
                Ok(())
            }
            _ => Err(AflError::Unknown(format!(
                "Received illegal message that message should not have arrived: {:?}.",
                event.name()
            ))),
        }
    }
}

impl<I, SH, ST> EventManager<I> for LlmpEventManager<I, SH, ST>
where
    I: Input,
    SH: ShMem,
    ST: Stats, //CE: CustomEvent<I>,
{
    fn process<C, FT, R>(&mut self, state: &mut State<C, I, R, FT>) -> Result<usize, AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        // TODO: Get around local event copy by moving handle_in_client
        let mut events = vec![];
        match &mut self.llmp {
            llmp::LlmpConnection::IsClient { client } => loop {
                match client.recv_buf()? {
                    Some((sender_id, tag, msg)) => {
                        if tag == _LLMP_TAG_EVENT_TO_BROKER {
                            continue;
                        }
                        let event: Event<I> = postcard::from_bytes(msg)?;
                        events.push((sender_id, event));
                    }
                    None => break,
                }
            },
            _ => {
                #[cfg(feature = "std")]
                dbg!("Skipping process in broker");
            }
        };
        let count = events.len();
        events
            .drain(..)
            .try_for_each(|(sender_id, event)| self.handle_in_client(state, sender_id, event))?;
        Ok(count)
    }

    fn fire<C, FT, R>(
        &mut self,
        _state: &mut State<C, I, R, FT>,
        event: Event<I>,
    ) -> Result<(), AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        I: Input,
        R: Rand,
    {
        let serialized = postcard::to_allocvec(&event)?;
        self.llmp.send_buf(LLMP_TAG_EVENT_TO_BOTH, &serialized)?;
        Ok(())
    }
}

/* TODO

    match exit_kind {
        Exit::Timeout => mgr.fire(Event::Timeout(&input)).expect(&format!(
            "Error sending Timeout event for input {:?}",
            input
        )),
        Exit::Crash => mgr
            .crash(input)
            .expect(&format!("Error sending crash event for input {:?}", input)),
        _ => (),
    }
    println!("foo");
    let state_corpus_serialized = serialize_state_corpus_mgr(state, corpus, mgr).unwrap();
    println!("bar: {:?}", &state_corpus_serialized);
    sender.send_buf(0x1, &state_corpus_serialized).unwrap();

*/

/// A manager that can restart on the fly
#[derive(Clone, Debug)]
pub struct LlmpRestartingEventManager<I, SH, ST>
where
    I: Input,
    SH: ShMem,
    ST: Stats,
    //CE: CustomEvent<I>,
{
    /// The embedded llmp event manager
    llmp_mgr: LlmpEventManager<I, SH, ST>,
    /// The sender to serialize the state for the next runner
    sender: LlmpSender<SH>,
}

impl<I, SH, ST> EventManager<I> for LlmpRestartingEventManager<I, SH, ST>
where
    I: Input,
    SH: ShMem,
    ST: Stats, //CE: CustomEvent<I>,
{
    fn process<C, FT, R>(&mut self, state: &mut State<C, I, R, FT>) -> Result<usize, AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        self.llmp_mgr.process(state)
    }

    fn fire<C, FT, R>(
        &mut self,
        state: &mut State<C, I, R, FT>,
        event: Event<I>,
    ) -> Result<(), AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        // Check if we are going to crash in the event, in which case we store our current state for the next runner
        match &event {
            Event::Crash { input: _ } | Event::Timeout { input: _ } => {
                // First, reset the page to 0 so the next iteration can read read from the beginning of this page
                unsafe { self.sender.reset_last_page() };
                let buf = postcard::to_allocvec(&(&state, &self.llmp_mgr.describe()?))?;
                self.sender.send_buf(_LLMP_TAG_RESTART, &buf).unwrap();
            }
            _ => (),
        };
        self.llmp_mgr.fire(state, event)
    }
}

/// The llmp connection from the actual fuzzer to the process supervising it
const ENV_FUZZER_SENDER: &str = &"_AFL_ENV_FUZZER_SENDER";
const ENV_FUZZER_RECEIVER: &str = &"_AFL_ENV_FUZZER_RECEIVER";
/// The llmp (2 way) connection from a fuzzer to the broker (broadcasting all other fuzzer messages)
const ENV_FUZZER_BROKER_CLIENT_INITIAL: &str = &"_AFL_ENV_FUZZER_BROKER_CLIENT";

impl<I, SH, ST> LlmpRestartingEventManager<I, SH, ST>
where
    I: Input,
    SH: ShMem,
    ST: Stats, //CE: CustomEvent<I>,
{
    /// Create a new runner, the executed child doing the actual fuzzing.
    pub fn new(llmp_mgr: LlmpEventManager<I, SH, ST>, sender: LlmpSender<SH>) -> Self {
        Self { llmp_mgr, sender }
    }

    pub fn temp<C, FT, R>(
        stats: ST,
        broker_port: u16,
    ) -> Result<(Self, Option<State<C, I, R, FT>>), AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        let mut mgr;

        // We start ourself as child process to actually fuzz
        if std::env::var(ENV_FUZZER_SENDER).is_err() {
            // We are either the broker, or the parent of the fuzzing instance
            mgr = LlmpEventManager::new_on_port(stats, broker_port)?;
            if mgr.is_broker() {
                // Yep, broker. Just loop here.
                println!("Doing broker things. Run this tool again to start fuzzing in a client.");
                mgr.broker_loop()?;
            } else {
                // we are one of the fuzzing instances. Let's launch the fuzzer.

                // First, store the mgr to an env so the client can use it
                mgr.to_env(ENV_FUZZER_BROKER_CLIENT_INITIAL);

                // First, create a channel from the fuzzer (sender) to us (receiver) to report its state for restarts.
                let sender = LlmpSender::new(0, false)?;
                let receiver = LlmpReceiver::on_existing_map(
                    AflShmem::clone_ref(&sender.out_maps.last().unwrap().shmem)?,
                    None,
                )?;
                // Store the information to a map.
                sender.to_env(ENV_FUZZER_SENDER)?;
                receiver.to_env(ENV_FUZZER_RECEIVER)?;

                let mut ctr = 0;
                // Client->parent loop
                loop {
                    dbg!("Spawning next client");
                    Command::new(env::current_exe()?)
                        .current_dir(env::current_dir()?)
                        .args(env::args())
                        .status()?;
                    ctr += 1;
                    if ctr == 10 {
                        todo!("This function should be removed");
                    }
                }
            }
        }

        println!("We're a client, let's fuzz :)");

        // We are the fuzzing instance, first, connect to our own restore map.
        // A sender and a receiver for single communication
        let mut receiver = LlmpReceiver::<AflShmem>::on_existing_from_env(ENV_FUZZER_RECEIVER)?;
        let mut sender = LlmpSender::<AflShmem>::on_existing_from_env(ENV_FUZZER_SENDER)?;

        // If we're restarting, deserialize the old state.
        let (mut state, mut mgr) = match receiver.recv_buf()? {
            None => {
                println!("First run. Let's set it all up");
                // Mgr to send and receive msgs from/to all other fuzzer instances
                mgr = LlmpEventManager::existing_client_from_env(ENV_FUZZER_BROKER_CLIENT_INITIAL)?;

                (mgr, None)
            }
            // Restoring from a previous run, deserialize state and corpus.
            Some((_sender, _tag, msg)) => {
                println!("Subsequent run. Let's load all data from shmem (received {} bytes from previous instance)", msg.len());
                deserialize_state_mgr(&msg)?;
                todo!("Remove this func");
            }
        };
        // We reset the sender, the next sender and receiver (after crash) will reuse the page from the initial message.
        unsafe { sender.reset_last_page() };

        //Ok(mgr)
        todo!("Remove this fn");
    }
}

/// A restarting state is a combination of restarter and runner, that can be used on systems without `fork`.
/// The restarter will start a new process each time the child crashes or timeouts.
pub fn setup_restarting_state<I, C, FT, R, SH, ST>(
    mgr: &mut LlmpEventManager<I, SH, ST>,
) -> Result<Option<State<C, I, R, FT>>, AflError>
where
    I: Input,
    C: Corpus<I, R>,
    FT: FeedbacksTuple<I>,
    R: Rand,
    SH: ShMem,
    ST: Stats,
{
    // We start ourself as child process to actually fuzz
    if std::env::var(ENV_FUZZER_SENDER).is_err() {
        mgr.to_env(ENV_FUZZER_BROKER_CLIENT_INITIAL);

        // First, create a channel from the fuzzer (sender) to us (receiver) to report its state for restarts.
        let sender = LlmpSender::new(0, false)?;
        let receiver = LlmpReceiver::on_existing_map(
            AflShmem::clone_ref(&sender.out_maps.last().unwrap().shmem)?,
            None,
        )?;
        // Store the information to a map.
        sender.to_env(ENV_FUZZER_SENDER)?;
        receiver.to_env(ENV_FUZZER_RECEIVER)?;

        let mut ctr = 0;
        // Client->parent loop
        loop {
            dbg!("Spawning next client");
            Command::new(env::current_exe()?)
                .current_dir(env::current_dir()?)
                .args(env::args())
                .status()?;
            ctr += 1;
            if ctr == 10 {
                todo!("Fix this");
            }
        }
    }

    println!("We're a client, let's fuzz :)");

    // We are the fuzzing instance, first, connect to our own restore map.
    // A sender and a receiver for single communication
    let mut receiver = LlmpReceiver::<AflShmem>::on_existing_from_env(ENV_FUZZER_RECEIVER)?;
    let mut sender = LlmpSender::<AflShmem>::on_existing_from_env(ENV_FUZZER_SENDER)?;

    // If we're restarting, deserialize the old state.
    let (mut mgr, mut state) = match receiver.recv_buf()? {
        None => {
            println!("First run. Let's set it all up");
            // Mgr to send and receive msgs from/to all other fuzzer instances
            let client_mgr =
                LlmpEventManager::existing_client_from_env(ENV_FUZZER_BROKER_CLIENT_INITIAL)?;

            (LlmpRestartingEventManager::new(client_mgr, sender), None)
        }
        // Restoring from a previous run, deserialize state and corpus.
        Some((_sender, _tag, msg)) => {
            println!("Subsequent run. Let's load all data from shmem (received {} bytes from previous instance)", msg.len());
            let (mgr, state) = deserialize_state_mgr(&msg)?;
            (LlmpRestartingEventManager::new(mgr), Some(state))
        }
    };
    // We reset the sender, the next sender and receiver (after crash) will reuse the page from the initial message.
    unsafe { sender.reset_last_page() };
    /* TODO: Not sure if this is needed
    // We commit an empty NO_RESTART message to this buf, against infinite loops,
    // in case something crashes in the fuzzer.
    sender.send_buf(_LLMP_TAG_NO_RESTART, []);
    */

    (mgr, state)
}

#[cfg(test)]
mod tests {

    use crate::events::Event;
    use crate::inputs::bytes::BytesInput;
    use crate::observers::ObserversTuple;
    use crate::observers::StdMapObserver;
    use crate::tuples::{tuple_list, MatchNameAndType, Named};

    static mut MAP: [u32; 4] = [0; 4];

    #[test]
    fn test_event_serde() {
        let obv = StdMapObserver::new("test", unsafe { &mut MAP });
        let map = tuple_list!(obv);
        let observers_buf = map.serialize().unwrap();

        let i = BytesInput::new(vec![0]);
        let e = Event::NewTestcase {
            input: i,
            observers_buf,
            corpus_size: 123,
            client_config: "conf".into(),
        };

        let serialized = postcard::to_allocvec(&e).unwrap();

        let d = postcard::from_bytes::<Event<BytesInput>>(&serialized).unwrap();
        match d {
            Event::NewTestcase {
                input: _,
                observers_buf,
                corpus_size: _,
                client_config: _,
            } => {
                let o = map.deserialize(&observers_buf).unwrap();
                let test_observer = o.match_name_type::<StdMapObserver<u32>>("test").unwrap();
                assert_eq!("test", test_observer.name());
            }
            _ => panic!("mistmatch"),
        };
    }
}
