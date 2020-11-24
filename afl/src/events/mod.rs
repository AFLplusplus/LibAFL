#[cfg(feature = "std")]
pub mod llmp;
#[cfg(feature = "std")]
pub mod llmp_translated; // TODO: Abstract away.
#[cfg(feature = "std")]
pub mod shmem_translated;

#[cfg(feature = "std")]
pub use crate::events::llmp::LLMP;

use core::any::Any;
//use core::any::TypeId;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::io::Write;

use crate::AflError;
use crate::corpus::Corpus;
use crate::engines::State;
use crate::executors::Executor;
use crate::inputs::Input;
use crate::utils::Rand;

pub trait Event: Display + Any {}

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
impl Event for LoadInitialEvent {}
impl Display for LoadInitialEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Load")
    }
}
impl LoadInitialEvent {
    pub fn new() -> Self {
        LoadInitialEvent {}
    }
}

pub struct NewTestcaseEvent {}
impl Event for NewTestcaseEvent {}
impl Display for NewTestcaseEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "New")
    }
}
impl NewTestcaseEvent {
    pub fn new() -> Self {
        NewTestcaseEvent {}
    }
}

#[cfg(feature = "std")]
pub struct LoggerEventManager<W>
where
    W: Write,
{
    events: Vec<Box<dyn Event>>,
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
        self.events.push(Box::new(event));
        Ok(())
    }

    fn process(&mut self, state: &mut S) -> Result<usize, AflError> {
        let num = self.events.len();
        for event in &self.events {
            writeln!(
                &mut self.writer,
                "#{}\t[{}] corp: {} exec/s: {}",
                state.executions(),
                event,
                state.corpus().entries().len(),
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
