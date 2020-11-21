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
    fn fire<E: Event>(&mut self) -> Result<(), AflError>;

    /// Lookup for incoming events and process them.
    /// Return the number of processes events or an error
    fn lookup(&mut self) -> Result<usize, AflError>;
}
