//! Eventmanager manages all events that go to other instances of the fuzzer.

pub mod logger;
pub use logger::*;
pub mod llmp;
pub use llmp::*;

use core::{fmt, marker::PhantomData, time::Duration};
use serde::{Deserialize, Serialize};

use crate::{
    executors::{Executor},
    inputs::Input,
    observers::ObserversTuple,
    Error,
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
    fn handle_in_broker(&self) -> Result<BrokerEventResult, Error>;
    /// This method will be called in the clients after handle_in_broker (unless BrokerEventResult::Handled) was returned in handle_in_broker
    fn handle_in_client(&self) -> Result<(), Error>;
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
        /// The time of generation of the event
        time: Duration,
        /// The executions of this client
        executions: usize,
    },
    /// New stats.
    UpdateStats {
        /// The time of generation of the event
        time: Duration,
        /// The executions of this client
        executions: usize,
        phantom: PhantomData<I>,
    },
    /// A new objective was found
    Objective {
        /// Objective corpus size
        objective_size: usize,
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
                time: _,
                executions: _,
            } => "New Testcase",
            Event::UpdateStats {
                time: _,
                executions: _,
                phantom: _,
            } => "Stats",
            Event::Objective { objective_size: _ } => "Objective",
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
    //fn fire<'a>(&mut self, event: Event<I>) -> Result<(), Error>;

    /// Lookup for incoming events and process them.
    /// Return the number of processes events or an error
    fn process<E, S>(
        &mut self,
        state: &mut S,
        executor: &mut E,
    ) -> Result<usize, Error>
    where
        E: Executor<I>;

    /// Serialize all observers for this type and manager
    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Vec<u8>, Error>
    where
        OT: ObserversTuple,
    {
        Ok(postcard::to_allocvec(observers)?)
    }

    /// Deserialize all observers for this type and manager
    fn deserialize_observers<OT>(&mut self, observers_buf: &[u8]) -> Result<OT, Error>
    where
        OT: ObserversTuple,
    {
        Ok(postcard::from_bytes(observers_buf)?)
    }

    /// For restarting event managers, implement a way to forward state to their next peers.
    #[inline]
    fn on_restart<S>(
        &mut self,
        _state: &mut S,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Block until we are safe to exit.
    #[inline]
    fn await_restart_safe(&mut self) {}

    /// Send off an event to the broker
    fn fire<S>(
        &mut self,
        state: &mut S,
        event: Event<I>,
    ) -> Result<(), Error>;
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
    fn process<E, S>(
        &mut self,
        _state: &mut S,
        _executor: &mut E,
    ) -> Result<usize, Error>
    where
        E: Executor<I>,
    {
        Ok(0)
    }

    fn fire<S>(
        &mut self,
        _state: &mut S,
        _event: Event<I>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::bolts::tuples::tuple_list;
    use crate::events::Event;
    use crate::inputs::bytes::BytesInput;
    use crate::observers::StdMapObserver;
    use crate::utils::current_time;

    static mut MAP: [u32; 4] = [0; 4];

    #[test]
    fn test_event_serde() {
        let obv = StdMapObserver::new("test", unsafe { &mut MAP });
        let map = tuple_list!(obv);
        let observers_buf = postcard::to_allocvec(&map).unwrap();

        let i = BytesInput::new(vec![0]);
        let e = Event::NewTestcase {
            input: i,
            observers_buf,
            corpus_size: 123,
            client_config: "conf".into(),
            time: current_time(),
            executions: 0,
        };

        let serialized = postcard::to_allocvec(&e).unwrap();

        let d = postcard::from_bytes::<Event<BytesInput>>(&serialized).unwrap();
        match d {
            Event::NewTestcase {
                input: _,
                observers_buf,
                corpus_size: _,
                client_config: _,
                time: _,
                executions: _,
            } => {
                let o: tuple_list!(StdMapObserver::<u32>) =
                    postcard::from_bytes(&observers_buf).unwrap();
                let test_observer = o.match_name_type::<StdMapObserver<u32>>("test").unwrap();
                assert_eq!("test", test_observer.name());
            }
            _ => panic!("mistmatch"),
        };
    }
}
