#[cfg(feature = "std")]
pub mod llmp;
#[cfg(feature = "std")]
pub mod llmp_translated; // TODO: Abstract away.
#[cfg(feature = "std")]
pub mod shmem_translated;

#[cfg(feature = "std")]
pub use crate::events::llmp::LLMP;

use core::fmt::Formatter;
#[cfg(feature = "std")]
use std::io::Write;

use crate::corpus::{Corpus, Testcase};
use crate::engines::State;
use crate::executors::Executor;
use crate::inputs::Input;
use crate::utils::Rand;
use crate::AflError;

pub enum EventDestination {
    Main,
    Broker,
    Clients,
}

pub trait Event {
    fn name() -> &'static str;

    fn destination() -> EventDestination;

    fn log<S, C, E, I, R>(&self, formatter: &mut Formatter, _state: &S) -> Result<(), AflError>
    where
        S: State<C, E, I, R>,
        C: Corpus<I, R>,
        E: Executor<I>,
        I: Input,
        R: Rand,
    {
        match write!(formatter, "[{}]", Self::name()) {
            Ok(_) => Ok(()),
            Err(_) => Err(AflError::Unknown("write error".to_string())),
        }
    }

    fn on_recv<S, C, E, I, R>(&self, _state: &mut S) -> Result<(), AflError>
    where
        S: State<C, E, I, R>,
        C: Corpus<I, R>,
        E: Executor<I>,
        I: Input,
        R: Rand,
    {
        Ok(())
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
    fn enabled<T>(&self) -> bool
    where
        T: Event;

    /// Fire an Event
    fn fire<T>(&mut self, event: T) -> Result<(), AflError>
    where
        T: Event;

    /// Lookup for incoming events and process them.
    /// Return the number of processes events or an error
    fn process(&mut self, state: &mut S) -> Result<usize, AflError>;
}

// e.g. fire_event!(manager, MyEvent, myparam1, ...)
#[macro_export]
macro_rules! fire_event {
    ($manager:expr, $event:ty, $( $x:expr ),+ ) => {
        {
            if $manager.enabled::<$event>() {
                $manager.fire(<$event>::new($( $x ),*))
            } else {
                Ok(())
            }
        }
    };
    ($manager:expr, $event:ty) => {
        {
            if $manager.enabled::<$event>() {
                $manager.fire(<$event>::new())
            } else {
                Ok(())
            }
        }
    };
}

pub struct LoadInitialEvent {}
impl Event for LoadInitialEvent {
    fn name() -> &'static str {
        "LOAD"
    }

    fn destination() -> EventDestination {
        EventDestination::Broker
    }
}
impl LoadInitialEvent {
    pub fn new() -> Self {
        LoadInitialEvent {}
    }
}

pub struct NewTestcaseEvent<I>
where
    I: Input,
{
    testcase: Testcase<I>,
}

impl<I> Event for NewTestcaseEvent<I>
where
    I: Input,
{
    fn name() -> &'static str {
        "NEW"
    }

    fn destination() -> EventDestination {
        EventDestination::Clients
    }
}

impl<I> NewTestcaseEvent<I>
where
    I: Input,
{
    pub fn new(testcase: Testcase<I>) -> Self {
        NewTestcaseEvent { testcase: testcase }
    }

    pub fn testcase(&self) -> &Testcase<I> {
        &self.testcase
    }
}

pub struct UpdateStatsEvent {}
impl Event for UpdateStatsEvent {
    fn name() -> &'static str {
        "STATS"
    }

    fn destination() -> EventDestination {
        EventDestination::Broker
    }
}
impl UpdateStatsEvent {
    pub fn new() -> Self {
        UpdateStatsEvent {}
    }
}

pub struct CrashEvent {}
impl Event for CrashEvent {
    fn name() -> &'static str {
        "CRASH"
    }

    fn destination() -> EventDestination {
        EventDestination::Broker
    }
}
impl CrashEvent {
    pub fn new() -> Self {
        CrashEvent {}
    }
}

#[cfg(feature = "std")]
pub struct LoggerEventManager<W>
where
    W: Write,
{
    events: Vec<String>,
    writer: W,
}

#[cfg(feature = "std")]
impl<S, C, E, I, R, W> EventManager<S, C, E, I, R> for LoggerEventManager<W>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
    W: Write,
{
    fn enabled<T>(&self) -> bool
    where
        T: Event,
    {
        true
    }

    fn fire<T>(&mut self, _event: T) -> Result<(), AflError>
    where
        T: Event,
    {
        self.events.push(T::name().to_string());
        Ok(())
    }

    fn process(&mut self, state: &mut S) -> Result<usize, AflError> {
        let num = self.events.len();
        for event in &self.events {
            writeln!(
                &mut self.writer,
                "#{}\t[{}] exec/s: {}",
                state.executions(),
                event,
                //TODO: Count corpus.entries().len(),
                state.executions_over_seconds()
            )?;
        }
        self.events.clear();
        Ok(num)
    }
}

#[cfg(feature = "std")]
impl<W> LoggerEventManager<W>
where
    W: Write,
{
    pub fn new(writer: W) -> Self {
        LoggerEventManager {
            events: vec![],
            writer: writer,
        }
    }
}
