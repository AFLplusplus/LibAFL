pub mod llmp;
pub mod llmp_translated; // TODO: Abstract away.
pub mod shmem_translated;
pub use crate::events::llmp::LLMP;

use core::any::{Any, TypeId};
use core::fmt::Display;

use crate::AflError;

pub trait Event: Display + Any {}

pub trait EventManager {
    /// Check if this EventaManager support a given Event type
    fn enabled<E: Event>(&self) -> bool;
    /* fn enabled<E: Event>(&self) -> bool {
        match TypeId::of::<E>() {
            TypeId::of::<MyEvent>() => true,
            _ => false,
        }
    } */

    /// Fire an Event
    fn fire<E: Event>(&mut self, event: E) -> Result<(), AflError>;

    /// Lookup for incoming events and process them.
    /// Return the number of processes events or an error
    fn lookup(&mut self) -> Result<usize, AflError>;
}

// e.g. fire_event!(manager, MyEvent, myparam1, ...)
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

/*
#[derive(Debug)]
pub struct MyEvent {}
impl Event for MyEvent {}
impl MyEvent {
    pub fn new() -> Self {
        MyEvent {}
    }
}

pub fn my_event_test<M: EventManager>(manager: &mut M) {
    fire_event!(manager, MyEvent).unwrap();
}
*/

pub struct NewTestcaseEvent {}
impl Event for NewTestcaseEvent {}
impl Display for NewTestcaseEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[NewTestcase] idx: ")
    }
}

pub struct LoggerEventManager {}

impl EventManager for LoggerEventManager {
    fn enabled<E: Event>(&self) -> bool {
        let _new_testcase = TypeId::of::<NewTestcaseEvent>();
        match TypeId::of::<E>() {
            _new_testcase => true,
            //_ => false,
        }
    }

    fn fire<E: Event>(&mut self, _event: E) -> Result<(), AflError> {
        #[cfg(feature = "std")]
        println!("{}", _event);
        Ok(())
    }

    fn lookup(&mut self) -> Result<usize, AflError> {
        Ok(0)
    }
}

impl LoggerEventManager {
    pub fn new() -> Self {
        LoggerEventManager {}
    }
}
