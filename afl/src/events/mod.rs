#[cfg(feature = "std")]
pub mod llmp;
#[cfg(feature = "std")]
pub mod llmp_translated; // TODO: Abstract away.
#[cfg(feature = "std")]
pub mod shmem_translated;

#[cfg(feature = "std")]
pub use crate::events::llmp::LLMP;

//use core::any::TypeId;
#[cfg(feature = "std")]
use std::io::Write;

use crate::corpus::{Corpus, Testcase};
use crate::engines::State;
use crate::executors::Executor;
use crate::inputs::Input;
use crate::utils::Rand;
use crate::AflError;

pub trait Event {
    fn name(&self) -> &'static str;
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
    fn name(&self) -> &'static str {
        "LOAD"
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
    fn name(&self) -> &'static str {
        "NEW"
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
    fn name(&self) -> &'static str {
        "STATS"
    }
}
impl UpdateStatsEvent {
    pub fn new() -> Self {
        UpdateStatsEvent {}
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
        /*let _load = TypeId::of::<LoadInitialEvent>();
        let _new = TypeId::of::<NewTestcaseEvent>();
        match TypeId::of::<T>() {
            _load => true,
            _new => true,
            _ => false,
        }*/
    }

    fn fire<T>(&mut self, event: T) -> Result<(), AflError>
    where
        T: Event,
    {
        self.events.push(event.name().to_string());
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
