use core::any::TypeId;
use core::fmt::Debug;

use crate::AflError;

pub trait Event: Debug {}

pub trait EventManager {
    /// Check if this EventaManager support a given Event type
    fn enabled<E: Event>(&self) -> bool;
    /* fn enabled<E: Event>() -> bool {
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
