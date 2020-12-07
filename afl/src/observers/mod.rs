extern crate num;

use core::any::Any;
use core::slice::from_raw_parts_mut;
use num::Integer;

use crate::metamap::AsAny;
use crate::AflError;

/// Observers observe different information about the target.
/// They can then be used by various sorts of feedback.
pub trait Observer: Any + AsAny {
    fn flush(&mut self) -> Result<(), AflError> {
        Ok(())
    }

    fn reset(&mut self) -> Result<(), AflError>;

    fn post_exec(&mut self) -> Result<(), AflError> {
        Ok(())
    }

    fn name(&self) -> &'static str;
}

/// A MapObserver observes the static map, as oftentimes used for afl-like coverage information
pub trait MapObserver<T>
where
    T: Integer + Copy,
{
    /// Get the map
    fn map(&self) -> &[T];

    /// Get the map (mutable)
    fn map_mut(&mut self) -> &mut [T];

    /// Get the initial value for reset()
    fn initial(&self) -> &T;

    /// Get the initial value for reset()
    fn initial_mut(&mut self) -> &mut T;

    /// Set the initial value for reset()
    fn set_initial(&mut self, initial: T);

    /// Reset the map
    fn reset_map(&mut self) -> Result<(), AflError> {
        // Normal memset, see https://rust.godbolt.org/z/Trs5hv
        for i in self.map_mut().iter_mut() {
            *i = T::zero();
        }
        Ok(())
    }
}

pub struct StdMapObserver<T>
where
    T: Integer + Copy + 'static,
{
    map: &'static mut [T],
    initial: T,
    name: &'static str,
}

impl<T> Observer for StdMapObserver<T>
where
    T: Integer + Copy,
{
    fn reset(&mut self) -> Result<(), AflError> {
        self.reset_map()
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

impl<T> AsAny for StdMapObserver<T>
where
    T: Integer + Copy,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl<T> MapObserver<T> for StdMapObserver<T>
where
    T: Integer + Copy,
{
    fn map(&self) -> &[T] {
        &self.map
    }

    fn map_mut(&mut self) -> &mut [T] {
        &mut self.map
    }

    fn initial(&self) -> &T {
        &self.initial
    }

    fn initial_mut(&mut self) -> &mut T {
        &mut self.initial
    }

    fn set_initial(&mut self, initial: T) {
        self.initial = initial
    }
}

impl<T> StdMapObserver<T>
where
    T: Integer + Copy,
{
    /// Creates a new MapObserver
    pub fn new(name: &'static str, map: &'static mut [T]) -> Self {
        let initial = if map.len() > 0 { map[0] } else { T::zero() };
        Self {
            map: map,
            initial: initial,
            name: name,
        }
    }

    /// Creates a new MapObserver from a raw pointer
    pub fn new_from_ptr(name: &'static str, map_ptr: *mut T, len: usize) -> Self {
        unsafe {
            let initial = if len > 0 { *map_ptr } else { T::zero() };
            StdMapObserver {
                map: from_raw_parts_mut(map_ptr, len),
                initial: initial,
                name: name,
            }
        }
    }
}
