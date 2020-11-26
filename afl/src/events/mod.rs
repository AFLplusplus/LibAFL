#[cfg(feature = "std")]
pub mod llmp;
#[cfg(feature = "std")]
pub mod llmp_translated; // TODO: Abstract away.
#[cfg(feature = "std")]
pub mod shmem_translated;

#[cfg(feature = "std")]
pub use crate::events::llmp::LLMP;

#[cfg(feature = "std")]
use std::{io::Write, marker::PhantomData};

use crate::corpus::{Corpus, Testcase};
use crate::engines::State;
use crate::executors::Executor;
use crate::inputs::Input;
use crate::utils::Rand;
use crate::AflError;
/// Indicate if an event worked or not
enum BrokerEventResult {
    /// The broker haneled this. No need to pass it on.
    Handled,
    /// Pass this message along to the clients.
    Forward,
}

/*

/// A custom event, in case a user wants to extend the features (at compile time)
pub trait CustomEvent<S, C, E, I, R>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
{
    /// Returns the name of this event
    fn name(&self) -> &str;
    /// This method will be called in the broker
    fn handle_in_broker(&self, broker: &dyn EventManager<S, C, E, I, R, Self>, state: &mut S, corpus: &mut C) -> Result<BrokerEventResult, AflError>;
    /// This method will be called in the clients after handle_in_broker (unless BrokerEventResult::Handled) was returned in handle_in_broker
    fn handle_in_client(&self, client: &dyn EventManager<S, C, E, I, R, Self>, state: &mut S, corpus: &mut C) -> Result<(), AflError>;
}

struct UnusedCustomEvent {}
impl<S, C, E, I, R> CustomEvent<S, C, E, I, R> for UnusedCustomEvent<S, C, E, I, R>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
{
    fn name(&self) -> &str {"No custom events"}
    fn handle_in_broker(&self, broker: &dyn EventManager<S, C, E, I, R, Self>, state: &mut S, corpus: &mut C) {Ok(BrokerEventResult::Handled)}
    fn handle_in_client(&self, client: &dyn EventManager<S, C, E, I, R, Self>, state: &mut S, corpus: &mut C) {Ok(())}
}
*/

/// Events sent around in the library
pub enum Event<S, C, E, I, R>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
    // CE: CustomEvent<S, C, E, I, R>,
{
    LoadInitial {
        sender_id: u64,
        _marker: PhantomData<(S, C, E, I, R)>,
    },
    NewTestcase {
        sender_id: u64,
        input: I,
        fitness: u32,
        _marker: PhantomData<(S, C, E, I, R)>,
    },
    UpdateStats {
        sender_id: u64,
        new_execs: usize,
        _marker: PhantomData<(S, C, E, I, R)>,
    },
    Crash {
        sender_id: u64,
        input: I,
        _marker: PhantomData<(S, C, E, I, R)>,
    },
    Timeout {
        sender_id: u64,
        input: I,
        _marker: PhantomData<(S, C, E, I, R)>,
    },
    Log {
        sender_id: u64,
        severity_level: u8,
        message: String,
        _marker: PhantomData<(S, C, E, I, R)>,
    },
    //Custom {sender_id: u64, custom_event: CE},
}

impl<S, C, E, I, R> Event<S, C, E, I, R>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
    //CE: CustomEvent<S, C, E, I, R>,
{
    fn name(&self) -> &str {
        match self {
            Event::LoadInitial { sender_id, _marker } => "Initial",
            Event::NewTestcase {
                sender_id,
                input,
                fitness,
                _marker,
            } => "New Testcase",
            Event::UpdateStats {
                sender_id,
                new_execs,
                _marker,
            } => "Stats",
            Event::Crash {
                sender_id,
                input,
                _marker,
            } => "Crash",
            Event::Timeout {
                sender_id,
                input,
                _marker,
            } => "Timeout",
            Event::Log {
                sender_id,
                severity_level,
                message,
                _marker,
            } => "Log",
            //Event::Custom {sender_id, custom_event} => custom_event.name(),
        }
    }

    fn handle_in_broker(
        &self,
        /*broker: &dyn EventManager<S, C, E, I, R>,*/ state: &mut S,
        corpus: &mut C,
    ) -> Result<BrokerEventResult, AflError> {
        match self {
            Event::LoadInitial { sender_id, _marker } => Ok(BrokerEventResult::Handled),
            Event::NewTestcase {
                sender_id,
                input,
                fitness,
                _marker,
            } => Ok(BrokerEventResult::Forward),
            Event::UpdateStats {
                sender_id,
                new_execs,
                _marker,
            } => {
                // TODO
                Ok(BrokerEventResult::Handled)
            }
            Event::Crash {
                sender_id,
                input,
                _marker,
            } => Ok(BrokerEventResult::Handled),
            Event::Timeout {
                sender_id,
                input,
                _marker,
            } => {
                // TODO
                Ok(BrokerEventResult::Handled)
            }
            Event::Log {
                sender_id,
                severity_level,
                message,
                _marker,
            } => {
                //TODO: broker.log()
                println!("{}[{}]: {}", sender_id, severity_level, message);
                Ok(BrokerEventResult::Handled)
            }
            //Event::Custom {sender_id, custom_event} => custom_event.handle_in_broker(state, corpus),
            _ => Ok(BrokerEventResult::Forward),
        }
    }

    fn handle_in_client(
        &self,
        /*client: &dyn EventManager<S, C, E, I, R>,*/ state: &mut S,
        corpus: &mut C,
    ) -> Result<(), AflError> {
        match self {
            Event::NewTestcase {
                sender_id,
                input,
                fitness,
                _marker,
            } => {
                let mut testcase = Testcase::new(input.to_owned());
                testcase.set_fitness(*fitness);
                corpus.add(testcase);
                Ok(())
            }
            _ => Err(AflError::Unknown(
                "Received illegal message that message should not have arrived.".into(),
            )),
        }
    }

    // TODO serialize and deserialize, defaults to serde
}

pub trait EventManager<S, C, E, I, R>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
{
    /// Check if this EventaManager support a given Event type
    /// To compare events, use Event::name().as_ptr()
    fn enabled(&self) -> bool;

    /// Fire an Event
    fn fire(&mut self, event: Event<S, C, E, I, R>) -> Result<(), AflError>;

    /// Lookup for incoming events and process them.
    /// Return the number of processes events or an error
    fn process(&mut self, state: &mut S, corpus: &mut C) -> Result<usize, AflError>;

    fn on_recv(&self, _state: &mut S, corpus: &mut C) -> Result<(), AflError> {
        // TODO: Better way to move out of testcase, or get ref
        //Ok(corpus.add(self.testcase.take().unwrap()))
        Ok(())
    }
}

/*TODO
    fn on_recv(&self, state: &mut S, _corpus: &mut C) -> Result<(), AflError> {
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
pub struct LoggerEventManager<S, C, E, I, R, W>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    I: Input,
    E: Executor<I>,
    R: Rand,
    W: Write,
    //CE: CustomEvent<S, C, E, I, R>,
{
    events: Vec<Event<S, C, E, I, R>>,
    writer: W,
}

#[cfg(feature = "std")]
impl<S, C, E, I, R, W> EventManager<S, C, E, I, R> for LoggerEventManager<S, C, E, I, R, W>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
    W: Write,
    //CE: CustomEvent<S, C, E, I, R>,
{
    fn enabled(&self) -> bool {
        true
    }

    fn fire(&mut self, event: Event<S, C, E, I, R>) -> Result<(), AflError> {
        self.events.push(event);
        Ok(())
    }

    fn process(&mut self, state: &mut S, corpus: &mut C) -> Result<usize, AflError> {
        // TODO: iterators
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
            .collect::<Result<(), AflError>>();
        let count = self.events.len();
        dbg!("Handled {} events", count);
        self.events.clear();

        /*
        let num = self.events.len();
        for event in &self.events {}

        self.events.clear();
        */

        Ok(count)
    }
}

#[cfg(feature = "std")]
impl<S, C, E, I, R, W> LoggerEventManager<S, C, E, I, R, W>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    I: Input,
    E: Executor<I>,
    R: Rand,
    W: Write,
    //TODO CE: CustomEvent,
{
    pub fn new(writer: W) -> Self {
        LoggerEventManager {
            events: vec![],
            writer: writer,
        }
    }
}
