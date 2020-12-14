#[cfg(feature = "std")]
pub mod llmp;
#[cfg(feature = "std")]
pub mod shmem_translated;

use alloc::string::String;
use core::{marker::PhantomData, time};

use serde::{Deserialize, Serialize};

//#[cfg(feature = "std")]
//pub mod shmem_translated;

#[cfg(feature = "std")]
use std::{io::Write, time::Duration};

use crate::corpus::Corpus;
use crate::executors::Executor;
use crate::feedbacks::FeedbacksTuple;
use crate::inputs::Input;
use crate::observers::ObserversTuple;
use crate::serde_anymap::SerdeAny;
use crate::utils::Rand;
use crate::AflError;
use crate::{engines::State, utils};

use self::llmp::LlmpMsg;

/// Indicate if an event worked or not
pub enum BrokerEventResult {
    /// The broker haneled this. No need to pass it on.
    Handled,
    /// Pass this message along to the clients.
    Forward,
}

pub struct ClientStats {
    // stats (maybe we need a separated struct?)
    executions: u64,
}

/// A custom event, for own messages, with own handler.
pub trait CustomEvent<I, OT>: SerdeAny + Serialize
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

/// Events sent around in the library
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub enum Event<I>
where
    I: Input,
{
    LoadInitial {
        sender_id: u64,
        phantom: PhantomData<I>,
    },
    NewTestcase {
        sender_id: u64,
        input: I,
        observers_buf: Vec<u8>,
        client_config: String,
    },
    UpdateStats {
        sender_id: u64,
        executions: usize,
        execs_over_sec: u64,
        phantom: PhantomData<I>,
    },
    Crash {
        sender_id: u64,
        input: I,
        phantom: PhantomData<I>,
    },
    Timeout {
        sender_id: u64,
        input: I,
        phantom: PhantomData<I>,
    },
    Log {
        sender_id: u64,
        severity_level: u8,
        message: String,
        phantom: PhantomData<I>,
    },
    None {
        phantom: PhantomData<I>,
    },
    Custom {
        sender_id: u64,
        // TODO: Allow custom events
        // custom_event: Box<dyn CustomEvent<I, OT>>,
    },
}

impl<I> Event<I>
where
    I: Input,
{
    pub fn name(&self) -> &str {
        match self {
            Event::LoadInitial {
                sender_id: _,
                phantom: _,
            } => "Initial",
            Event::NewTestcase {
                sender_id: _,
                input: _,
                client_config: _,
                observers_buf: _,
            } => "New Testcase",
            Event::UpdateStats {
                sender_id: _,
                executions: _,
                execs_over_sec: _,
                phantom: _,
            } => "Stats",
            Event::Crash {
                sender_id: _,
                input: _,
                phantom: _,
            } => "Crash",
            Event::Timeout {
                sender_id: _,
                input: _,
                phantom: _,
            } => "Timeout",
            Event::Log {
                sender_id: _,
                severity_level: _,
                message: _,
                phantom: _,
            } => "Log",
            Event::None { phantom: _ } => "None",
            Event::Custom {
                sender_id: _, /*custom_event} => custom_event.name()*/
            } => "todo",
        }
    }

    pub fn log(severity_level: u8, message: String) -> Self {
        Event::Log {
            sender_id: 0,
            severity_level: severity_level,
            message: message,
            phantom: PhantomData,
        }
    }

    pub fn new_testcase<OT>(config: String, input: I, observers: &OT) -> Result<Self, AflError>
    where
        OT: ObserversTuple,
    {
        let observers_buf = postcard::to_allocvec(observers)?;
        Ok(Self::NewTestcase {
            sender_id: 0,
            input: input,
            client_config: config,
            observers_buf: observers_buf,
        })
    }

    pub fn update_stats(executions: usize, execs_over_sec: u64) -> Self {
        Event::UpdateStats {
            sender_id: 0,
            executions: executions,
            execs_over_sec: execs_over_sec,
            phantom: PhantomData,
        }
    }
}

/// Client fun
fn handle_in_client<C, OT, FT, I, R>(
    event: Event<I>,
    state: &mut State<I, R, FT, OT>,
    corpus: &mut C,
) -> Result<(), AflError>
where
    C: Corpus<I, R>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    I: Input,
    R: Rand,
{
    match event {
        Event::NewTestcase {
            sender_id: _,
            input,
            observers_buf,
            client_config: _,
        } => {
            // TODO: here u should match client_config, if equal to the current one do not re-execute
            // we need to pass engine to process() too, TODO
            #[cfg(feature = "std")]
            println!("Received new Testcase");
            let observers = postcard::from_bytes(&observers_buf)?;
            let interestingness = state.is_interesting(&input, &observers)?;
            state.add_if_interesting(corpus, input, interestingness)?;
            Ok(())
        }
        _ => Err(AflError::Unknown(format!(
            "Received illegal message that message should not have arrived: {:?}.",
            event
        ))),
    }
}

pub trait EventManager<C, E, OT, FT, I, R>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    I: Input,
    R: Rand,
{
    /// Fire an Event
    fn fire<'a>(&mut self, event: Event<I>) -> Result<(), AflError>;

    /// Lookup for incoming events and process them.
    /// Return the number of processes events or an error
    fn process(
        &mut self,
        state: &mut State<I, R, FT, OT>,
        corpus: &mut C,
    ) -> Result<usize, AflError>;

    /// the client stat, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats>;
    /// the client stat
    fn client_stats(&self) -> &[ClientStats];

    /// Amount of elements in the corpus (combined for all children)
    fn corpus_size(&self) -> usize;

    /// Incremt the cropus size
    fn corpus_size_inc(&mut self) -> usize;

    /// Time this fuzzing run stated
    fn start_time(&mut self) -> time::Duration;

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
        let time_since_start = (utils::current_time() - self.start_time()).as_secs();
        if time_since_start == 0 {
            0
        } else {
            self.total_execs() / time_since_start
        }
    }

    /// Broker fun
    fn handle_in_broker(&mut self, event: &Event<I>) -> Result<BrokerEventResult, AflError> {
        match event {
            Event::LoadInitial {
                sender_id: _,
                phantom: _,
            } => {
                self.corpus_size_inc();
                Ok(BrokerEventResult::Handled)
            }
            Event::NewTestcase {
                sender_id: _,
                input: _,
                observers_buf: _,
                client_config: _,
            } => {
                self.corpus_size_inc();
                println!(
                    "[NEW] corpus: {} execs: {} execs/s: {}",
                    self.corpus_size(),
                    self.total_execs(),
                    self.execs_per_sec()
                );
                Ok(BrokerEventResult::Forward)
            }
            Event::UpdateStats {
                sender_id,
                executions,
                execs_over_sec: _,
                phantom: _,
            } => {
                // TODO: The stats buffer should be added on client add.
                let client_stat_count = self.client_stats().len();
                for _ in client_stat_count..(*sender_id + 1) as usize {
                    self.client_stats_mut().push(ClientStats { executions: 0 })
                }
                let mut stat = &mut self.client_stats_mut()[*sender_id as usize];
                stat.executions = *executions as u64;
                println!(
                    "[UPDATE] corpus: {} execs: {} execs/s: {}",
                    self.corpus_size(),
                    self.total_execs(),
                    self.execs_per_sec()
                );
                Ok(BrokerEventResult::Handled)
            }
            Event::Crash {
                sender_id: _,
                input: _,
                phantom: _,
            } => {
                panic!("LoggerEventManager cannot handle Event::Crash");
            }
            Event::Timeout {
                sender_id: _,
                input: _,
                phantom: _,
            } => {
                panic!("LoggerEventManager cannot handle Event::Timeout");
            }
            Event::Log {
                sender_id: _,
                severity_level,
                message,
                phantom: _,
            } => {
                println!("[LOG {}]: {}", severity_level, message);
                Ok(BrokerEventResult::Handled)
            }
            _ => Ok(BrokerEventResult::Forward),
        }
    }

    fn serialize_observers(&mut self, observers: &OT) -> Result<Vec<u8>, AflError> {
        Ok(postcard::to_allocvec(observers)?)
    }

    fn deserialize_observers(&mut self, observers_buf: &[u8]) -> Result<OT, AflError> {
        Ok(postcard::from_bytes(observers_buf)?)
    }
}

#[cfg(feature = "std")]
pub struct LoggerEventManager<C, E, OT, FT, I, R, W>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    I: Input,
    R: Rand,
    W: Write,
    //CE: CustomEvent<I, OT>,
{
    writer: W,

    events: Vec<Event<I>>,
    // stats (maybe we need a separated struct?)
    corpus_size: usize,
    start_time: time::Duration,
    client_stats: Vec<ClientStats>,
    phantom: PhantomData<(C, E, I, R, OT, FT)>,
}

#[cfg(feature = "std")]
impl<C, E, OT, FT, I, R, W> EventManager<C, E, OT, FT, I, R>
    for LoggerEventManager<C, E, OT, FT, I, R, W>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    I: Input,
    R: Rand,
    W: Write,
    //CE: CustomEvent<I, OT>,
{
    #[inline]
    fn fire<'a>(&mut self, event: Event<I>) -> Result<(), AflError> {
        match self.handle_in_broker(&event)? {
            BrokerEventResult::Forward => self.events.push(event),
            // Ignore broker-only events
            BrokerEventResult::Handled => (),
        }
        Ok(())
    }

    fn process(
        &mut self,
        state: &mut State<I, R, FT, OT>,
        corpus: &mut C,
    ) -> Result<usize, AflError> {
        let count = self.events.len();
        self.events
            .drain(..)
            .try_for_each(|event| handle_in_client(event, state, corpus))?;
        Ok(count)
    }

    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    fn corpus_size(&self) -> usize {
        self.corpus_size
    }

    fn corpus_size_inc(&mut self) -> usize {
        self.corpus_size += 1;
        self.corpus_size
    }

    fn start_time(&mut self) -> time::Duration {
        self.start_time
    }
}

#[cfg(feature = "std")]
impl<C, E, OT, FT, I, R, W> LoggerEventManager<C, E, OT, FT, I, R, W>
where
    C: Corpus<I, R>,
    I: Input,
    E: Executor<I>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    R: Rand,
    W: Write,
    //TODO CE: CustomEvent,
{
    pub fn new(writer: W) -> Self {
        Self {
            start_time: utils::current_time(),
            client_stats: vec![],
            writer: writer,
            corpus_size: 0,
            phantom: PhantomData,
            events: vec![],
        }
    }
}

#[cfg(feature = "std")]
/// Forward this to the client
const LLMP_TAG_EVENT_TO_CLIENT: llmp::Tag = 0x2C11E471;
#[cfg(feature = "std")]
/// Only handle this in the broker
const _LLMP_TAG_EVENT_TO_BROKER: llmp::Tag = 0x2B80438;
#[cfg(feature = "std")]
/// Handle in both
const _LLMP_TAG_EVENT_TO_BOTH: llmp::Tag = 0x2B0741;

#[cfg(feature = "std")]
pub struct LlmpEventManager<C, E, OT, FT, I, R, W>
where
    W: Write,
    //CE: CustomEvent<I>,
{
    writer: W,

    // stats (maybe we need a separated struct?)
    corpus_size: usize,
    start_time: time::Duration,
    client_stats: Vec<ClientStats>,
    llmp: llmp::LlmpConnection,
    phantom: PhantomData<(C, E, OT, FT, I, R)>,
}

impl<C, E, OT, FT, I, R, W> LlmpEventManager<C, E, OT, FT, I, R, W>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    I: Input,
    R: Rand,
    W: Write,
{
    /// Create llmp on a port
    /// If the port is not yet bound, it will act as broker
    /// Else, it will act as client.
    pub fn new_on_port(port: u16, writer: W) -> Result<Self, AflError> {
        let mgr = Self {
            llmp: llmp::LlmpConnection::on_port(port)?,
            start_time: utils::current_time(),
            corpus_size: 0,
            phantom: PhantomData,
            client_stats: vec![],
            writer,
        };
        Ok(mgr)
    }

    /// Returns if we are the broker
    pub fn is_broker(&self) -> bool {
        match self.llmp {
            llmp::LlmpConnection::IsBroker {
                broker: _,
                listener_thread: _,
            } => true,
            _ => false,
        }
    }

    /// Run forever in the broker
    pub fn broker_loop(&mut self) -> Result<(), AflError> {
        match &mut self.llmp {
            llmp::LlmpConnection::IsBroker {
                broker,
                listener_thread: _,
            } => {
                // TODO: Clean up that api by.. a lot!
                /*
                broker.add_message_hook(|client_id: u32, msg: *mut LlmpMsg| {
                    unsafe {
                        if (*msg).tag == _LLMP_TAG_EVENT_TO_BOTH {
                            let event = postcard::from_bytes((*msg).as_slice_unsafe())?;
                            match self.handle_in_broker(event)? {
                                BrokerEventResult::Forward => llmp::LlmpMsgHookResult::ForwardToClients,
                                BrokerEventResult::Handled => llmp::LlmpMsgHookResult::Handled,
                            }
                        } else {
                            llmp::LlmpMsgHookResult::ForwardToClients
                        }
                    }
                });*/
                broker.loop_forever(Some(Duration::from_millis(5)))
            },
            _ => Err(AflError::IllegalState(
                "Called broker loop in the client".into(),
            )),
        }
    }
}

#[cfg(feature = "std")]
impl<C, E, OT, FT, I, R, W> EventManager<C, E, OT, FT, I, R>
    for LlmpEventManager<C, E, OT, FT, I, R, W>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    FT: FeedbacksTuple<I>,
    OT: ObserversTuple,
    I: Input,
    R: Rand,
    W: Write,
    //CE: CustomEvent<I>,
{
    #[inline]
    fn fire<'a>(&mut self, event: Event<I>) -> Result<(), AflError> {
        let serialized = postcard::to_allocvec(&event)?;
        self.llmp.send_buf(LLMP_TAG_EVENT_TO_CLIENT, &serialized)?;
        Ok(())
    }

    fn process(
        &mut self,
        state: &mut State<I, R, FT, OT>,
        corpus: &mut C,
    ) -> Result<usize, AflError> {
        // TODO: Get around local event copy by moving handle_in_client
        Ok(match &mut self.llmp {
            llmp::LlmpConnection::IsClient { client } => {
                let mut count = 0;
                loop {
                    match client.recv_buf()? {
                        Some((tag, event_buf)) => {
                            if tag == _LLMP_TAG_EVENT_TO_BROKER {
                                continue;
                            }
                            let event: Event<I> = postcard::from_bytes(event_buf)?;
                            handle_in_client(event, state, corpus)?;
                            count += 1;
                        }
                        None => break count,
                    }
                }
            }
            _ => {
                dbg!("Skipping process in broker");
                0
            }
        })
    }

    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    fn corpus_size(&self) -> usize {
        self.corpus_size
    }

    fn corpus_size_inc(&mut self) -> usize {
        self.corpus_size += 1;
        self.corpus_size
    }

    fn start_time(&mut self) -> time::Duration {
        self.start_time
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    use crate::inputs::bytes::BytesInput;
    use crate::observers::StdMapObserver;
    use crate::tuples::{tuple_list, MatchNameAndType, Named};
    use crate::{events::Event, observers::ObserversTuple};

    static mut MAP: [u32; 4] = [0; 4];
    #[test]
    fn test_event_serde() {
        let obv = StdMapObserver::new("test", unsafe { &mut MAP });
        let map = tuple_list!(obv);
        let observers_buf = map.serialize().unwrap();
        // test_event_mgr.serialize_observers(&map).unwrap();

        let i = BytesInput::new(vec![0]);
        let e = Event::NewTestcase {
            sender_id: 0,
            input: i,
            observers_buf,
            client_config: "conf".into(),
        };

        let serialized = postcard::to_allocvec(&e).unwrap();

        match postcard::from_bytes::<Event<BytesInput>>(&serialized).unwrap() {
            Event::NewTestcase {
                sender_id: _,
                input: _,
                observers_buf,
                client_config: _,
            } => {
                let o = map.deserialize(&observers_buf).unwrap();
                let test_observer = o.match_name_type::<StdMapObserver<u32>>("test").unwrap();
                assert_eq!("test", test_observer.name());
            }
            _ => panic!("mistmatch".to_string()),
        };
    }
}
