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

use crate::{corpus::Corpus, serde_anymap::SerdeAny};
use crate::engines::State;
use crate::executors::Executor;
use crate::inputs::Input;
use crate::serde_anymap::{Ptr, PtrMut};
use crate::utils::Rand;
use crate::AflError;

/// Indicate if an event worked or not
pub enum BrokerEventResult {
    /// The broker haneled this. No need to pass it on.
    Handled,
    /// Pass this message along to the clients.
    Forward,
}

pub trait ShowStats {}

/// A custom event, for own messages, with own handler.
pub trait CustomEvent<I>: SerdeAny + Serialize
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
pub enum Event<'a, I>
where
    I: Input,
{
    LoadInitial {
        sender_id: u64,
        phantom: PhantomData<I>,
    },
    NewTestcase {
        sender_id: u64,
        input: Ptr<'a, I>,
        observers: PtrMut<'a, crate::observers::observer_serde::NamedSerdeAnyMap>,
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
        // custom_event: Box<dyn CustomEvent<I>>,
    },
}

impl<'a, I> Event<'a, I>
where
    I: Input,
    //CE: CustomEvent<I>,
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
            Event::Custom {sender_id, /*custom_event} => custom_event.name()*/} => "todo",
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

pub trait EventManager<C, E, I, R>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
{
    /// Fire an Event
    fn fire<'a>(
        &mut self,
        event: Event<'a, I>,
        state: &mut State<I, R>,
        corpus: &mut C,
    ) -> Result<(), AflError>;

    /// Lookup for incoming events and process them.
    /// Return the number of processes events or an error
    fn process(&mut self, state: &mut State<I, R>, corpus: &mut C) -> Result<usize, AflError>;

    fn on_recv(&self, _state: &mut State<I, R>, _corpus: &mut C) -> Result<(), AflError> {
        // TODO: Better way to move out of testcase, or get ref
        //Ok(corpus.add(self.testcase.take().unwrap()))
        Ok(())
    }

    // TODO the broker has a state? do we need to pass state and corpus?
    fn handle_in_broker(
        &self,
        event: &Event<I>,
        /*broker: &dyn EventManager<C, E, I, R>,*/ _state: &mut State<I, R>,
        _corpus: &mut C,
    ) -> Result<BrokerEventResult, AflError> {
        match event {
            Event::LoadInitial {
                sender_id: _,
                phantom: _,
            } => Ok(BrokerEventResult::Handled),
            Event::NewTestcase {
                sender_id: _,
                input: _,
                observers: _,
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
            },
            Event::None {
                phantom: _,
            } => Ok(BrokerEventResult::Handled),
            Event::Custom {sender_id, /*custom_event} => custom_event.handle_in_broker(state, corpus)*/} => Ok(BrokerEventResult::Forward),
            //_ => Ok(BrokerEventResult::Forward),
        }
    }

    fn handle_in_client(
        &self,
        event: Event<I>,
        /*client: &dyn EventManager<C, E, I, R>,*/ _state: &mut State<I, R>,
        corpus: &mut C,
    ) -> Result<(), AflError> {
        match event {
            Event::NewTestcase {
                sender_id: _,
                input: _,
                observers: _,
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
    fn on_recv(&self, state: &mut State<I, R>, _corpus: &mut C) -> Result<(), AflError> {
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
pub struct LoggerEventManager<C, E, I, R, W>
where
    W: Write,
    //CE: CustomEvent<I>,
{
    writer: W,
    count: usize,
    phantom: PhantomData<(C, E, I, R)>,
}

#[cfg(feature = "std")]
impl<C, E, I, R, W> EventManager<C, E, I, R> for LoggerEventManager<C, E, I, R, W>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
    W: Write,
    //CE: CustomEvent<I>,
{
    fn fire<'a>(
        &mut self,
        event: Event<'a, I>,
        state: &mut State<I, R>,
        corpus: &mut C,
    ) -> Result<(), AflError> {
        match self.handle_in_broker(&event, state, corpus)? {
            BrokerEventResult::Forward => (), //self.handle_in_client(event, state, corpus)?,
            // Ignore broker-only events
            BrokerEventResult::Handled => (),
        }
        Ok(())
    }

    fn process(&mut self, _state: &mut State<I, R>, _corpus: &mut C) -> Result<usize, AflError> {
        let c = self.count;
        self.count = 0;
        Ok(c)
    }
}

#[cfg(feature = "std")]
impl<C, E, I, R, W> LoggerEventManager<C, E, I, R, W>
where
    C: Corpus<I, R>,
    I: Input,
    E: Executor<I>,
    R: Rand,
    W: Write,
    //TODO CE: CustomEvent,
{
    pub fn new(writer: W) -> Self {
        Self {
            writer: writer,
            count: 0,
            phantom: PhantomData,
        }
    }
}

/// Eventmanager for multi-processed application
#[cfg(feature = "std")]
pub struct LlmpBrokerEventManager<C, E, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    E: Executor<I>,
    R: Rand,
    //CE: CustomEvent<I>,
{
    llmp_broker: llmp::LlmpBroker,
    phantom: PhantomData<(C, E, I, R)>,
}

/// Forward this to the client
const LLMP_TAG_EVENT_TO_CLIENT: llmp::Tag = 0x2C11E471;
/// Only handle this in the broker
const LLMP_TAG_EVENT_TO_BROKER: llmp::Tag = 0x2B80438;
const LLMP_TAG_EVENT_TO_BOTH: llmp::Tag = 0x2B0741;

/// Eventmanager for multi-processed application
#[cfg(feature = "std")]
pub struct LlmpClientEventManager<C, E, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    E: Executor<I>,
    R: Rand,
    //CE: CustomEvent<I>,
{
    llmp_client: llmp::LlmpClient,
    phantom: PhantomData<(C, E, I, R)>,
}

#[cfg(feature = "std")]
impl<C, E, I, R> EventManager<C, E, I, R> for LlmpBrokerEventManager<C, E, I, R>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
{
    /// Fire an Event
    fn fire<'a>(
        &mut self,
        event: Event<'a, I>,
        state: &mut State<I, R>,
        corpus: &mut C,
    ) -> Result<(), AflError> {
        let serialized = postcard::to_allocvec(&event)?;
        self.llmp_broker
            .send_buf(LLMP_TAG_EVENT_TO_CLIENT, &serialized)?;
        Ok(())
    }

    fn process(&mut self, _state: &mut State<I, R>, _corpus: &mut C) -> Result<usize, AflError> {
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

    fn on_recv(&self, _state: &mut State<I, R>, _corpus: &mut C) -> Result<(), AflError> {
        // TODO: Better way to move out of testcase, or get ref
        //Ok(corpus.add(self.testcase.take().unwrap()))
        Ok(())
    }

    fn handle_in_broker(
        &self,
        event: &Event<I>,
        /*broker: &dyn EventManager<C, E, I, R>,*/ _state: &mut State<I, R>,
        _corpus: &mut C,
    ) -> Result<BrokerEventResult, AflError> {
        match event {
            Event::LoadInitial {
                sender_id: _,
                phantom: _,
            } => Ok(BrokerEventResult::Handled),
            Event::NewTestcase {
                sender_id: _,
                input: _,
                observers: _,
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
            },
            Event::None {
                phantom: _,
            } => Ok(BrokerEventResult::Handled),
            Event::Custom {sender_id, /*custom_event} => custom_event.handle_in_broker(state, corpus)*/} => Ok(BrokerEventResult::Forward),
            //_ => Ok(BrokerEventResult::Forward),
        }
    }

    fn handle_in_client(
        &self,
        event: Event<I>,
        /*client: &dyn EventManager<C, E, I, R>,*/ _state: &mut State<I, R>,
        corpus: &mut C,
    ) -> Result<(), AflError> {
        match event {
            Event::NewTestcase {
                sender_id: _,
                input: _,
                observers: _,
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

    use std::{thread, time::Duration};

    use crate::events::Event;
    use crate::inputs::bytes::BytesInput;
    use crate::observers::observer_serde::NamedSerdeAnyMap;
    use crate::observers::{Observer, StdMapObserver};
    use crate::serde_anymap::{Ptr, PtrMut};

    use super::llmp::{LlmpConnection, Tag};

    static mut MAP: [u32; 4] = [0; 4];

    #[test]
    fn test_event_serde() {
        let mut map = NamedSerdeAnyMap::new();
        let obv = StdMapObserver::new("test", unsafe { &mut MAP });
        map.insert(Box::new(obv), &"key".to_string());

        let i = BytesInput::new(vec![0]);
        let e = Event::NewTestcase {
            sender_id: 0,
            input: Ptr::Ref(&i),
            observers: PtrMut::Ref(&mut map),
        };

        let j = serde_json::to_string(&e).unwrap();

        let d: Event<BytesInput> = serde_json::from_str(&j).unwrap();
        match d {
            Event::NewTestcase {
                sender_id: _,
                input: _,
                observers: obs,
            } => {
                let o = obs
                    .as_ref()
                    .get::<StdMapObserver<u32>>(&"key".to_string())
                    .unwrap();
                assert_eq!("test".to_string(), *o.name());
            }
            _ => panic!("mistmatch".to_string()),
        };
    }

    use crate::events::tests::LlmpConnection::{IsBroker, IsClient};

    #[test]
    pub fn llmp_connection() {
        let mut broker = match LlmpConnection::on_port(1337).unwrap() {
            IsClient { client } => panic!("Could not bind to port as broker"),
            IsBroker {
                broker,
                listener_thread,
            } => broker,
        };
        let mut client = match LlmpConnection::on_port(1337).unwrap() {
            IsBroker {
                broker,
                listener_thread,
            } => panic!("Second connect should be a client!"),
            IsClient { client } => client,
        };
        // Add the first client (2nd, actually, because of the tcp listener client)
        broker.once().unwrap();
        assert_eq!(broker.llmp_clients.len(), 2);

        let tag: Tag = 0x1337;
        let arr: [u8; 1] = [1u8];
        // Send stuff
        client.send_buf(tag, &arr).unwrap();
        // Forward stuff to clients
        broker.once().unwrap();
        broker.once().unwrap();
        let (tag2, arr2) = client.recv_buf_blocking().unwrap();
        assert_eq!(tag, tag2);
        assert_eq!(arr[0], arr2[0]);
    }
}
