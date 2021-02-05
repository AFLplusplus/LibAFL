//! Eventmanager manages all events that go to other instances of the fuzzer.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    time::Duration,
    {marker::PhantomData, time},
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
#[cfg(unix)]
use crate::shmem::AflShmem;
use crate::{
    corpus::Corpus,
    feedbacks::FeedbacksTuple,
    inputs::Input,
    llmp::{self, LlmpClient, LlmpClientDescription, Tag},
    observers::ObserversTuple,
    serde_anymap::Ptr,
    shmem::ShMem,
    state::State,
    utils::{current_time, Rand},
    AflError,
};

#[derive(Debug, Copy, Clone)]
/// Indicate if an event worked or not
pub enum BrokerEventResult {
    /// The broker haneled this. No need to pass it on.
    Handled,
    /// Pass this message along to the clients.
    Forward,
}

const CLIENT_STATS_TIME_WINDOW_SECS: u64 = 5; // 5 seconds

#[derive(Debug, Clone, Default)]
pub struct ClientStats {
    // stats (maybe we need a separated struct?)
    corpus_size: u64,
    executions: u64,
    last_window_executions: u64,
    last_window_time: time::Duration,
    last_execs_per_sec: u64,
}

impl ClientStats {
    pub fn update_executions(&mut self, executions: u64, cur_time: time::Duration) {
        self.executions = executions;
        if (cur_time - self.last_window_time).as_secs() > CLIENT_STATS_TIME_WINDOW_SECS {
            self.last_execs_per_sec = self.execs_per_sec(cur_time);
            self.last_window_time = cur_time;
            self.last_window_executions = executions;
        }
    }

    pub fn execs_per_sec(&self, cur_time: time::Duration) -> u64 {
        if self.executions == 0 {
            return 0;
        }
        let secs = (cur_time - self.last_window_time).as_secs();
        if secs == 0 {
            self.last_execs_per_sec
        } else {
            let diff = self.executions - self.last_window_executions;
            diff / secs
        }
    }
}

pub trait Stats {
    /// the client stats (mut)
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats>;

    /// the client stats
    fn client_stats(&self) -> &[ClientStats];

    /// creation time
    fn start_time(&mut self) -> time::Duration;

    /// show the stats to the user
    fn show(&mut self, event_msg: String);

    /// Amount of elements in the corpus (combined for all children)
    fn corpus_size(&self) -> u64 {
        self.client_stats()
            .iter()
            .fold(0u64, |acc, x| acc + x.corpus_size)
    }

    /// Total executions
    #[inline]
    fn total_execs(&mut self) -> u64 {
        self.client_stats()
            .iter()
            .fold(0u64, |acc, x| acc + x.executions)
    }

    /// Executions per second
    #[inline]
    fn execs_per_sec(&mut self) -> u64 {
        let cur_time = current_time();
        self.client_stats()
            .iter()
            .fold(0u64, |acc, x| acc + x.execs_per_sec(cur_time))
    }

    /// The client stats for a specific id, creating new if it doesn't exist
    fn client_stats_mut_for(&mut self, client_id: u32) -> &mut ClientStats {
        let client_stat_count = self.client_stats().len();
        for _ in client_stat_count..(client_id + 1) as usize {
            self.client_stats_mut().push(ClientStats {
                last_window_time: current_time(),
                ..Default::default()
            })
        }
        &mut self.client_stats_mut()[client_id as usize]
    }
}

#[derive(Clone, Debug)]
pub struct SimpleStats<F>
where
    F: FnMut(String),
{
    print_fn: F,
    start_time: Duration,
    corpus_size: usize,
    client_stats: Vec<ClientStats>,
}

impl<F> Stats for SimpleStats<F>
where
    F: FnMut(String),
{
    /// the client stats, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client stats
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&mut self) -> time::Duration {
        self.start_time
    }

    fn show(&mut self, event_msg: String) {
        let fmt = format!(
            "[{}] clients: {}, corpus: {}, executions: {}, exec/sec: {}",
            event_msg,
            self.client_stats().len(),
            self.corpus_size(),
            self.total_execs(),
            self.execs_per_sec()
        );
        (self.print_fn)(fmt);
    }
}

impl<F> SimpleStats<F>
where
    F: FnMut(String),
{
    pub fn new(print_fn: F) -> Self {
        Self {
            print_fn: print_fn,
            start_time: current_time(),
            corpus_size: 0,
            client_stats: vec![],
        }
    }

    pub fn with_time(print_fn: F, start_time: time::Duration) -> Self {
        Self {
            print_fn: print_fn,
            start_time: start_time,
            corpus_size: 0,
            client_stats: vec![],
        }
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
    fn handle_in_broker(&self) -> Result<BrokerEventResult, AflError>;
    /// This method will be called in the clients after handle_in_broker (unless BrokerEventResult::Handled) was returned in handle_in_broker
    fn handle_in_client(&self) -> Result<(), AflError>;
}
*/

/// Events sent around in the library
pub trait Event<I>
where
    I: Input,
{
    /// Returns the name of this event
    fn name(&self) -> &str;
    /// This method will be called in the broker
    fn handle_in_broker<ST>(&self, stats: &mut ST) -> Result<BrokerEventResult, AflError>
    where
        ST: Stats;
    /// This method will be called in the clients after handle_in_broker (unless BrokerEventResult::Handled) was returned in handle_in_broker
    fn handle_in_client<C, FT, R>(self, state: &mut State<C, I, R, FT>) -> Result<(), AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand;
}

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

    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Vec<u8>, AflError>
    where
        OT: ObserversTuple,
    {
        Ok(postcard::to_allocvec(observers)?)
    }

    fn deserialize_observers<OT>(&mut self, observers_buf: &[u8]) -> Result<OT, AflError>
    where
        OT: ObserversTuple,
    {
        Ok(postcard::from_bytes(observers_buf)?)
    }

    fn new_testcase<OT>(
        &mut self,
        _input: &I,
        _observers: &OT,
        _corpus_size: usize,
        _config: String,
    ) -> Result<(), AflError>
    where
        OT: ObserversTuple,
    {
        Ok(())
    }

    fn update_stats(&mut self, _executions: usize, _execs_over_sec: u64) -> Result<(), AflError> {
        Ok(())
    }

    fn crash(&mut self, _input: &I) -> Result<(), AflError> {
        Ok(())
    }

    fn timeout(&mut self, _input: &I) -> Result<(), AflError> {
        Ok(())
    }

    fn log(&mut self, _severity_level: u8, _message: String) -> Result<(), AflError> {
        Ok(())
    }

    // TODO Custom event fire (dyn CustomEvent or similar)
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
}

/// Events that may happen
#[derive(Clone, Debug)]
pub enum LoggerEvent<I>
where
    I: Input,
{
    NewTestcase {
        corpus_size: usize,
        phantom: PhantomData<I>,
    },
    UpdateStats {
        executions: usize,
        execs_over_sec: u64,
        phantom: PhantomData<I>,
    },
    Crash {
        input: I,
    },
    Timeout {
        input: I,
    },
    Log {
        severity_level: u8,
        message: String,
        phantom: PhantomData<I>,
    },
    /*Custom {
        // TODO: Allow custom events
        // custom_event: Box<dyn CustomEvent<I, OT>>,
    },*/
}

impl<I> Event<I> for LoggerEvent<I>
where
    I: Input,
{
    #[inline]
    fn name(&self) -> &str {
        match self {
            LoggerEvent::NewTestcase {
                corpus_size: _,
                phantom: _,
            } => "New Testcase",
            LoggerEvent::UpdateStats {
                executions: _,
                execs_over_sec: _,
                phantom: _,
            } => "Stats",
            LoggerEvent::Crash { input: _ } => "Crash",
            LoggerEvent::Timeout { input: _ } => "Timeout",
            LoggerEvent::Log {
                severity_level: _,
                message: _,
                phantom: _,
            } => "Log",
            /*Event::Custom => custom_event.name()
            } => "todo",*/
        }
    }

    /// Broker fun
    #[inline]
    fn handle_in_broker<ST>(&self, stats: &mut ST) -> Result<BrokerEventResult, AflError>
    where
        ST: Stats,
    {
        match self {
            LoggerEvent::NewTestcase {
                corpus_size,
                phantom: _,
            } => {
                stats.client_stats_mut()[0].corpus_size = *corpus_size as u64;
                stats.show(self.name().to_string());
                Ok(BrokerEventResult::Handled)
            }
            LoggerEvent::UpdateStats {
                executions,
                execs_over_sec: _,
                phantom: _,
            } => {
                // TODO: The stats buffer should be added on client add.
                stats.client_stats_mut()[0].executions = *executions as u64;
                stats.show(self.name().to_string());
                Ok(BrokerEventResult::Handled)
            }
            LoggerEvent::Crash { input: _ } => {
                panic!("LoggerEventManager cannot handle Event::Crash");
            }
            LoggerEvent::Timeout { input: _ } => {
                panic!("LoggerEventManager cannot handle Event::Timeout");
            }
            LoggerEvent::Log {
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

    #[inline]
    fn handle_in_client<C, FT, R>(self, _state: &mut State<C, I, R, FT>) -> Result<(), AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        match self {
            _ => Err(AflError::Unknown(format!(
                "Received illegal message that message should not have arrived: {:?}.",
                self
            ))),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LoggerEventManager<I, ST>
where
    I: Input,
    //CE: CustomEvent<I, OT>,
{
    stats: ST,
    events: Vec<LoggerEvent<I>>,
}

impl<I, ST> EventManager<I> for LoggerEventManager<I, ST>
where
    I: Input,
    ST: Stats,
    //CE: CustomEvent<I, OT>,
{
    fn process<C, FT, R>(&mut self, state: &mut State<C, I, R, FT>) -> Result<usize, AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        let count = self.events.len();
        self.events
            .drain(..)
            .try_for_each(|event| event.handle_in_client(state))?;
        Ok(count)
    }

    fn new_testcase<OT>(
        &mut self,
        _input: &I,
        _observers: &OT,
        corpus_size: usize,
        _config: String,
    ) -> Result<(), AflError>
    where
        OT: ObserversTuple,
    {
        let event = LoggerEvent::NewTestcase {
            corpus_size: corpus_size,
            phantom: PhantomData,
        };
        match event.handle_in_broker(&mut self.stats)? {
            BrokerEventResult::Forward => self.events.push(event),
            _ => (),
        };
        Ok(())
    }

    fn update_stats(&mut self, executions: usize, execs_over_sec: u64) -> Result<(), AflError> {
        let event = LoggerEvent::UpdateStats {
            executions: executions,
            execs_over_sec: execs_over_sec,
            phantom: PhantomData,
        };
        match event.handle_in_broker(&mut self.stats)? {
            BrokerEventResult::Forward => self.events.push(event),
            _ => (),
        };
        Ok(())
    }

    fn crash(&mut self, input: &I) -> Result<(), AflError> {
        let event = LoggerEvent::Crash {
            input: input.clone(),
        };
        match event.handle_in_broker(&mut self.stats)? {
            BrokerEventResult::Forward => self.events.push(event),
            _ => (),
        };
        Ok(())
    }

    fn timeout(&mut self, input: &I) -> Result<(), AflError> {
        let event = LoggerEvent::Timeout {
            input: input.clone(),
        };
        match event.handle_in_broker(&mut self.stats)? {
            BrokerEventResult::Forward => self.events.push(event),
            _ => (),
        };
        Ok(())
    }

    fn log(&mut self, severity_level: u8, message: String) -> Result<(), AflError> {
        let event = LoggerEvent::Log {
            severity_level: severity_level,
            message: message,
            phantom: PhantomData,
        };
        match event.handle_in_broker(&mut self.stats)? {
            BrokerEventResult::Forward => self.events.push(event),
            _ => (),
        };
        Ok(())
    }
}

impl<I, ST> LoggerEventManager<I, ST>
where
    I: Input,
    ST: Stats,
    //TODO CE: CustomEvent,
{
    pub fn new(stats: ST) -> Self {
        Self {
            stats: stats,
            events: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub enum LLMPEventKind<'a, I>
where
    I: Input,
{
    // TODO use an ID to keep track of the original index in the sender Corpus
    // The sender can then use it to send Testcase metadatas with CustomEvent
    NewTestcase {
        input: Ptr<'a, I>,
        observers_buf: Vec<u8>,
        corpus_size: usize,
        client_config: String,
    },
    UpdateStats {
        executions: usize,
        execs_over_sec: u64,
        phantom: PhantomData<&'a I>,
    },
    Crash {
        input: I,
    },
    Timeout {
        input: I,
    },
    Log {
        severity_level: u8,
        message: String,
        phantom: PhantomData<I>,
    },
    /*Custom {
        // TODO: Allow custom events
        // custom_event: Box<dyn CustomEvent<I, OT>>,
    },*/
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct LLMPEvent<'a, I>
where
    I: Input,
{
    sender_id: u32,
    kind: LLMPEventKind<'a, I>,
}

impl<'a, I> Event<I> for LLMPEvent<'a, I>
where
    I: Input,
{
    fn name(&self) -> &str {
        match self.kind {
            LLMPEventKind::NewTestcase {
                input: _,
                client_config: _,
                corpus_size: _,
                observers_buf: _,
            } => "New Testcase",
            LLMPEventKind::UpdateStats {
                executions: _,
                execs_over_sec: _,
                phantom: _,
            } => "Stats",
            LLMPEventKind::Crash { input: _ } => "Crash",
            LLMPEventKind::Timeout { input: _ } => "Timeout",
            LLMPEventKind::Log {
                severity_level: _,
                message: _,
                phantom: _,
            } => "Log",
            /*Event::Custom {
                sender_id: _, /*custom_event} => custom_event.name()*/
            } => "todo",*/
        }
    }

    /// Broker fun
    #[inline]
    fn handle_in_broker<ST>(&self, stats: &mut ST) -> Result<BrokerEventResult, AflError>
    where
        ST: Stats,
    {
        match &self.kind {
            LLMPEventKind::NewTestcase {
                input: _,
                client_config: _,
                corpus_size,
                observers_buf: _,
            } => {
                let client = stats.client_stats_mut_for(self.sender_id);
                client.corpus_size = *corpus_size as u64;
                stats.show(self.name().to_string() + " #" + &self.sender_id.to_string());
                Ok(BrokerEventResult::Handled)
            }
            LLMPEventKind::UpdateStats {
                executions,
                execs_over_sec: _,
                phantom: _,
            } => {
                // TODO: The stats buffer should be added on client add.
                let client = stats.client_stats_mut_for(self.sender_id);
                client.executions = *executions as u64;
                stats.show(self.name().to_string() + " #" + &self.sender_id.to_string());
                Ok(BrokerEventResult::Handled)
            }
            LLMPEventKind::Crash { input: _ } => {
                #[cfg(feature = "std")]
                println!("LLMPEvent::Crash");
                Ok(BrokerEventResult::Handled)
            }
            LLMPEventKind::Timeout { input: _ } => {
                #[cfg(feature = "std")]
                println!("LLMPEvent::Timeout");
                Ok(BrokerEventResult::Handled)
            }
            LLMPEventKind::Log {
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

    #[inline]
    fn handle_in_client<C, FT, R>(self, state: &mut State<C, I, R, FT>) -> Result<(), AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        match self.kind {
            LLMPEventKind::NewTestcase {
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
                let interestingness = state.is_interesting(input.as_ref(), &observers)?;
                match input {
                    Ptr::Owned(b) => {
                        state.add_if_interesting(*b, interestingness)?;
                    }
                    _ => {}
                };
                Ok(())
            }
            _ => Err(AflError::Unknown(format!(
                "Received illegal message that message should not have arrived: {:?}.",
                self.name()
            ))),
        }
    }
}

/// Forward this to the client
const _LLMP_TAG_EVENT_TO_CLIENT: llmp::Tag = 0x2C11E471;
/// Only handle this in the broker
const _LLMP_TAG_EVENT_TO_BROKER: llmp::Tag = 0x2B80438;
/// Handle in both
const LLMP_TAG_EVENT_TO_BOTH: llmp::Tag = 0x2B0741;

#[derive(Clone, Debug)]
pub struct LlmpEventManager<I, SH, ST>
where
    I: Input,
    SH: ShMem,
    ST: Stats,
    //CE: CustomEvent<I>,
{
    llmp: llmp::LlmpConnection<SH>,
    stats: ST,
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
    pub fn new_on_port_std(port: u16, stats: ST) -> Result<Self, AflError> {
        Ok(Self {
            llmp: llmp::LlmpConnection::on_port(port)?,
            stats: stats,
            phantom: PhantomData,
        })
    }

    /// If a client respawns, it may reuse the existing connection, previously stored by LlmpClient::to_env
    /// Std uses AflShmem.
    #[cfg(feature = "std")]
    pub fn existing_client_from_env_std(env_name: &str, stats: ST) -> Result<Self, AflError> {
        Self::existing_client_from_env(env_name, stats)
    }
}

impl<I, ST, SH> LlmpEventManager<I, SH, ST>
where
    I: Input,
    SH: ShMem,
    ST: Stats,
{
    /// Create llmp on a port
    /// If the port is not yet bound, it will act as broker
    /// Else, it will act as client.
    #[cfg(feature = "std")]
    pub fn new_on_port(port: u16, stats: ST) -> Result<Self, AflError> {
        Ok(Self {
            llmp: llmp::LlmpConnection::on_port(port)?,
            stats: stats,
            phantom: PhantomData,
        })
    }

    /// If a client respawns, it may reuse the existing connection, previously stored by LlmpClient::to_env
    #[cfg(feature = "std")]
    pub fn existing_client_from_env(env_name: &str, stats: ST) -> Result<Self, AflError> {
        Ok(Self {
            llmp: llmp::LlmpConnection::IsClient {
                client: LlmpClient::on_existing_from_env(env_name)?,
            },
            // Inserting a nop-stats element here so rust won't complain.
            // In any case, the client won't currently use it.
            stats: stats,
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
        stats: ST,
    ) -> Result<Self, AflError> {
        Ok(Self {
            llmp: llmp::LlmpConnection::existing_client_from_description(description)?,
            // Inserting a nop-stats element here so rust won't complain.
            // In any case, the client won't currently use it.
            stats: stats,
            phantom: PhantomData,
        })
    }

    /// A client on an existing map
    pub fn for_client(client: LlmpClient<SH>, stats: ST) -> Self {
        Self {
            llmp: llmp::LlmpConnection::IsClient { client },
            stats,
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
                let stats = &mut self.stats;
                broker.loop_forever(
                    &mut |sender_id: u32, tag: Tag, msg: &[u8]| {
                        if tag == LLMP_TAG_EVENT_TO_BOTH {
                            let kind: LLMPEventKind<I> = postcard::from_bytes(msg)?;
                            let event = LLMPEvent {
                                sender_id: sender_id,
                                kind: kind,
                            };
                            match event.handle_in_broker(stats)? {
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

    /// Send an event kind via llmp
    #[inline]
    fn send_event_kind<'a>(&mut self, event: LLMPEventKind<'a, I>) -> Result<(), AflError> {
        let serialized = postcard::to_allocvec(&event)?;
        self.llmp.send_buf(LLMP_TAG_EVENT_TO_BOTH, &serialized)?;
        Ok(())
    }
}

impl<I, ST, SH> EventManager<I> for LlmpEventManager<I, SH, ST>
where
    I: Input,
    SH: ShMem,
    ST: Stats,
    //CE: CustomEvent<I>,
{
    fn process<C, FT, R>(&mut self, state: &mut State<C, I, R, FT>) -> Result<usize, AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        // TODO: Get around local event copy by moving handle_in_client
        Ok(match &mut self.llmp {
            llmp::LlmpConnection::IsClient { client } => {
                let mut count = 0;
                loop {
                    match client.recv_buf()? {
                        Some((sender_id, tag, msg)) => {
                            if tag == _LLMP_TAG_EVENT_TO_BROKER {
                                continue;
                            }
                            let kind: LLMPEventKind<I> = postcard::from_bytes(msg)?;
                            let event = LLMPEvent {
                                sender_id: sender_id,
                                kind: kind,
                            };
                            event.handle_in_client(state)?;
                            count += 1;
                        }
                        None => break count,
                    }
                }
            }
            _ => {
                #[cfg(feature = "std")]
                dbg!("Skipping process in broker");
                0
            }
        })
    }

    fn new_testcase<OT>(
        &mut self,
        input: &I,
        observers: &OT,
        corpus_size: usize,
        config: String,
    ) -> Result<(), AflError>
    where
        OT: ObserversTuple,
    {
        let kind = LLMPEventKind::NewTestcase {
            input: Ptr::Ref(input),
            observers_buf: postcard::to_allocvec(observers)?,
            corpus_size: corpus_size,
            client_config: config,
        };
        self.send_event_kind(kind)
    }

    fn update_stats(&mut self, executions: usize, execs_over_sec: u64) -> Result<(), AflError> {
        let kind = LLMPEventKind::UpdateStats {
            executions: executions,
            execs_over_sec: execs_over_sec,
            phantom: PhantomData,
        };
        self.send_event_kind(kind)
    }

    fn crash(&mut self, input: &I) -> Result<(), AflError> {
        let kind = LLMPEventKind::Crash {
            input: input.clone(),
        };
        self.send_event_kind(kind)
    }

    fn timeout(&mut self, input: &I) -> Result<(), AflError> {
        let kind = LLMPEventKind::Timeout {
            input: input.clone(),
        };
        self.send_event_kind(kind)
    }

    fn log(&mut self, severity_level: u8, message: String) -> Result<(), AflError> {
        let kind = LLMPEventKind::Log {
            severity_level: severity_level,
            message: message,
            phantom: PhantomData,
        };
        self.send_event_kind(kind)
    }
}

#[cfg(test)]
mod tests {

    use crate::events::{LLMPEvent, LLMPEventKind};
    use crate::inputs::bytes::BytesInput;
    use crate::observers::ObserversTuple;
    use crate::observers::StdMapObserver;
    use crate::serde_anymap::Ptr;
    use crate::tuples::{tuple_list, MatchNameAndType, Named};

    static mut MAP: [u32; 4] = [0; 4];

    #[test]
    fn test_event_serde() {
        let obv = StdMapObserver::new("test", unsafe { &mut MAP });
        let map = tuple_list!(obv);
        let observers_buf = map.serialize().unwrap();

        let i = BytesInput::new(vec![0]);
        let e = LLMPEvent {
            sender_id: 0,
            kind: LLMPEventKind::NewTestcase {
                input: Ptr::Ref(&i),
                observers_buf,
                corpus_size: 123,
                client_config: "conf".into(),
            },
        };

        let serialized = postcard::to_allocvec(&e).unwrap();

        let d = postcard::from_bytes::<LLMPEvent<BytesInput>>(&serialized).unwrap();
        match d.kind {
            LLMPEventKind::NewTestcase {
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
