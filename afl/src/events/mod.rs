#[cfg(feature = "std")]
pub mod llmp;
#[cfg(feature = "std")]
pub mod shmem_translated;

use alloc::string::String;
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

//#[cfg(feature = "std")]
//pub mod shmem_translated;

#[cfg(feature = "std")]
use std::io::Write;

use crate::engines::State;
use crate::executors::Executor;
use crate::observers::ObserversTuple;
use crate::feedbacks::FeedbacksTuple;
use crate::inputs::Input;
use crate::serde_anymap::{SerdeAny, Ptr, PtrMut};
use crate::utils::Rand;
use crate::AflError;
use crate::corpus::Corpus;

/// Indicate if an event worked or not
pub enum BrokerEventResult {
    /// The broker haneled this. No need to pass it on.
    Handled,
    /// Pass this message along to the clients.
    Forward,
}

pub trait ShowStats {}

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
#[derive(Serialize, Deserialize)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub enum Event<'a, I, OT>
where
    I: Input,
    OT: ObserversTuple
{
    LoadInitial {
        sender_id: u64,
        phantom: PhantomData<I>,
    },
    NewTestcase {
        sender_id: u64,
        input: Ptr<'a, I>,
        observers: PtrMut<'a, OT>,
        corpus_count: usize,
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

impl<'a, I, OT> Event<'a, I, OT>
where
    I: Input,
    OT: ObserversTuple
    //CE: CustomEvent<I, OT>,
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
                observers: _,
                corpus_count: _,
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

    pub fn update_stats(executions: usize, execs_over_sec: u64) -> Self {
        Event::UpdateStats {
            sender_id: 0,
            executions: executions,
            execs_over_sec: execs_over_sec,
            phantom: PhantomData,
        }
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
    fn fire<'a>(&mut self, event: Event<'a, I, OT>) -> Result<(), AflError>;

    /// Lookup for incoming events and process them.
    /// Return the number of processes events or an error
    fn process(&mut self, state: &mut State<I, R, FT>, corpus: &mut C) -> Result<usize, AflError>;

    #[inline]
    fn on_recv(&self, _state: &mut State<I, R, FT>, _corpus: &mut C) -> Result<(), AflError> {
        // TODO: Better way to move out of testcase, or get ref
        //Ok(corpus.add(self.testcase.take().unwrap()))
        Ok(())
    }

    // TODO the broker has a state? do we need to pass state and corpus?
    fn handle_in_broker(&mut self, event: &Event<I, OT>) -> Result<BrokerEventResult, AflError> {
        match event {
            Event::LoadInitial {
                sender_id: _,
                phantom: _,
            } => Ok(BrokerEventResult::Handled),
            Event::NewTestcase {
                sender_id: _,
                input: _,
                observers: _,
                corpus_count: _,
            } => Ok(BrokerEventResult::Forward),
            Event::UpdateStats {
                sender_id: _,
                executions: _,
                execs_over_sec: _,
                phantom: _,
            } => {
                // TODO
                Ok(BrokerEventResult::Handled)
            }
            Event::Crash {
                sender_id: _,
                input: _,
                phantom: _,
            } => Ok(BrokerEventResult::Handled),
            Event::Timeout {
                sender_id: _,
                input: _,
                phantom: _,
            } => {
                // TODO
                Ok(BrokerEventResult::Handled)
            }
            Event::Log {
                sender_id,
                severity_level,
                message,
                phantom: _,
            } => {
                //TODO: broker.log()
                #[cfg(feature = "std")]
                println!("{}[{}]: {}", sender_id, severity_level, message);
                // Silence warnings for no_std
                let (_, _, _) = (sender_id, severity_level, message);
                Ok(BrokerEventResult::Handled)
            }
            Event::None { phantom: _ } => Ok(BrokerEventResult::Handled),
            Event::Custom {
                sender_id: _, /*custom_event} => custom_event.handle_in_broker(state, corpus)*/
            } => Ok(BrokerEventResult::Forward),
            //_ => Ok(BrokerEventResult::Forward),
        }
    }

    fn handle_in_client(
        &mut self,
        event: Event<I, OT>,
        _state: &mut State<I, R, FT>,
        _corpus: &mut C,
    ) -> Result<(), AflError> {
        match event {
            Event::NewTestcase {
                sender_id: _,
                input: _,
                observers: _,
                corpus_count: _,
            } => {
                // here u should match sender_id, if equal to the current one do not re-execute
                // we need to pass engine to process() too, TODO
                #[cfg(feature = "std")]
                println!("PLACEHOLDER: received NewTestcase");
                Ok(())
            }
            _ => Err(AflError::Unknown(
                "Received illegal message that message should not have arrived.".into(),
            )),
        }
    }
}

/*TODO
    fn on_recv(&self, state: &mut State<I, R, FT>, _corpus: &mut C) -> Result<(), AflError> {
        println!(
            "#{}\t exec/s: {}",
            state.executions(),
            //TODO: Count corpus.entries().len(),
            state.executions_over_seconds()
        );
        Ok(())
    }
*/

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
    count: usize,

    // stats (maybe we need a separated struct?)
    executions: usize,
    execs_over_sec: u64,
    corpus_count: usize,

    phantom: PhantomData<(C, E, OT, FT, I, R)>,
}

#[cfg(feature = "std")]
impl<C, E, OT, FT, I, R, W> EventManager<C, E, OT, FT, I, R> for LoggerEventManager<C, E, OT, FT, I, R, W>
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
    fn fire<'a>(&mut self, event: Event<'a, I, OT>) -> Result<(), AflError> {
        match self.handle_in_broker(&event)? {
            BrokerEventResult::Forward => (), //self.handle_in_client(event, state, corpus)?,
            // Ignore broker-only events
            BrokerEventResult::Handled => (),
        }
        Ok(())
    }

    fn process(&mut self, _state: &mut State<I, R, FT>, _corpus: &mut C) -> Result<usize, AflError> {
        let c = self.count;
        self.count = 0;
        Ok(c)
    }

    fn handle_in_broker(&mut self, event: &Event<I, OT>) -> Result<BrokerEventResult, AflError> {
        match event {
            Event::NewTestcase {
                sender_id: _,
                input: _,
                observers: _,
                corpus_count,
            } => {
                self.corpus_count = *corpus_count;
                writeln!(
                    self.writer,
                    "[NEW] corpus: {} execs: {} execs/s: {}",
                    self.corpus_count, self.executions, self.execs_over_sec
                )?;
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateStats {
                sender_id: _,
                executions,
                execs_over_sec,
                phantom: _,
            } => {
                self.executions = *executions;
                self.execs_over_sec = *execs_over_sec;
                writeln!(
                    self.writer,
                    "[UPDATE] corpus: {} execs: {} execs/s: {}",
                    self.corpus_count, self.executions, self.execs_over_sec
                )?;
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
                writeln!(self.writer, "[LOG {}]: {}", severity_level, message)?;
                Ok(BrokerEventResult::Handled)
            }
            _ => Ok(BrokerEventResult::Handled),
        }
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
            writer: writer,
            count: 0,
            executions: 0,
            execs_over_sec: 0,
            corpus_count: 0,
            phantom: PhantomData,
        }
    }
}

/// Eventmanager for multi-processed application
#[cfg(feature = "std")]
pub struct LlmpBrokerEventManager<C, E, OT, FT, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    E: Executor<I>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    R: Rand,
    //CE: CustomEvent<I, OT>,
{
    llmp_broker: llmp::LlmpBroker,
    phantom: PhantomData<(C, E, OT, FT, I, R)>,
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

/// Eventmanager for multi-processed application
#[cfg(feature = "std")]
pub struct LlmpClientEventManager<C, E, OT, FT, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    E: Executor<I>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    R: Rand,
    //CE: CustomEvent<I, OT>,
{
    _llmp_client: llmp::LlmpClient,
    phantom: PhantomData<(C, E, OT, FT, I, R)>,
}

#[cfg(feature = "std")]
impl<C, E, OT, FT, I, R> EventManager<C, E, OT, FT, I, R> for LlmpBrokerEventManager<C, E, OT, FT, I, R>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    I: Input,
    R: Rand,
{
    /// Fire an Event
    fn fire<'a>(&mut self, event: Event<'a, I, OT>) -> Result<(), AflError> {
        let serialized = postcard::to_allocvec(&event)?;
        self.llmp_broker
            .send_buf(LLMP_TAG_EVENT_TO_CLIENT, &serialized)?;
        Ok(())
    }

    fn process(&mut self, _state: &mut State<I, R, FT>, _corpus: &mut C) -> Result<usize, AflError> {
        // TODO: iterators
        /*
        let mut handled = vec![];
        for x in self.events.iter() {
            handled.push(x.handle_in_broker(state, corpus)?);
        }
        handled
            .iter()
            .zip(self.events.iter())
            .map(|(x, event)| match x {
                BrokerEventResult::Forward => event.handle_in_client(state, corpus),
                // Ignore broker-only events
                BrokerEventResult::Handled => Ok(()),
            })
            .for_each(drop);
        let count = self.events.len();
        dbg!("Handled {} events", count);
        self.events.clear();

        let num = self.events.len();
        for event in &self.events {}

        self.events.clear();
        */

        Ok(0)
    }

    fn on_recv(&self, _state: &mut State<I, R, FT>, _corpus: &mut C) -> Result<(), AflError> {
        // TODO: Better way to move out of testcase, or get ref
        //Ok(corpus.add(self.testcase.take().unwrap()))
        Ok(())
    }

    fn handle_in_broker(&mut self, event: &Event<I, OT>) -> Result<BrokerEventResult, AflError> {
        match event {
            Event::LoadInitial {
                sender_id: _,
                phantom: _,
            } => Ok(BrokerEventResult::Handled),
            Event::NewTestcase {
                sender_id: _,
                input: _,
                observers: _,
                corpus_count: _,
            } => Ok(BrokerEventResult::Forward),
            Event::UpdateStats {
                sender_id: _,
                executions: _,
                execs_over_sec: _,
                phantom: _,
            } => {
                // TODO
                Ok(BrokerEventResult::Handled)
            }
            Event::Crash {
                sender_id: _,
                input: _,
                phantom: _,
            } => Ok(BrokerEventResult::Handled),
            Event::Timeout {
                sender_id: _,
                input: _,
                phantom: _,
            } => {
                // TODO
                Ok(BrokerEventResult::Handled)
            }
            Event::Log {
                sender_id,
                severity_level,
                message,
                phantom: _,
            } => {
                //TODO: broker.log()
                #[cfg(feature = "std")]
                println!("{}[{}]: {}", sender_id, severity_level, message);
                Ok(BrokerEventResult::Handled)
            }
            Event::None { phantom: _ } => Ok(BrokerEventResult::Handled),
            Event::Custom {
                sender_id: _, /*custom_event} => custom_event.handle_in_broker(state, corpus)*/
            } => Ok(BrokerEventResult::Forward),
            //_ => Ok(BrokerEventResult::Forward),
        }
    }

    fn handle_in_client(
        &mut self,
        event: Event<I, OT>,
        _state: &mut State<I, R, FT>,
        _corpus: &mut C,
    ) -> Result<(), AflError> {
        match event {
            Event::NewTestcase {
                sender_id: _,
                input: _,
                observers: _,
                corpus_count: _,
            } => {
                // here u should match sender_id, if equal to the current one do not re-execute
                // we need to pass engine to process() too, TODO
                #[cfg(feature = "std")]
                println!("PLACEHOLDER: received NewTestcase");
                Ok(())
            }
            _ => Err(AflError::Unknown(
                "Received illegal message that message should not have arrived.".into(),
            )),
        }
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    use crate::events::Event;
    use crate::inputs::bytes::BytesInput;
    use crate::observers::{Observer, StdMapObserver, ObserversTuple};
    use crate::tuples::{MatchNameAndType, Named, tuple_list, tuple_list_type};
    use crate::serde_anymap::{Ptr, PtrMut};

    static mut MAP: [u32; 4] = [0; 4];

    #[test]
    fn test_event_serde() {
        
        let obv = StdMapObserver::new("test", unsafe { &mut MAP });
        let mut map = tuple_list!(obv);

        let i = BytesInput::new(vec![0]);
        let e = Event::NewTestcase {
            sender_id: 0,
            input: Ptr::Ref(&i),
            observers: PtrMut::Ref(&mut map),
            corpus_count: 1,
        };

        let j = serde_json::to_string(&e).unwrap();

        let d: Event<BytesInput, tuple_list_type!(StdMapObserver<u32>)> = serde_json::from_str(&j).unwrap();
        match d {
            Event::NewTestcase {
                sender_id: _,
                input: _,
                observers,
                corpus_count: _,
            } => {
                let o = observers.as_ref().match_name_type::<StdMapObserver<u32>>("test").unwrap();
                assert_eq!("test", o.name());
            }
            _ => panic!("mistmatch".to_string()),
        };
    }
}
