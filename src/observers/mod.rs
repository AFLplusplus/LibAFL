extern crate num;

use core::slice::from_raw_parts_mut;
use num::Integer;

use crate::AflError;

/// Observers observe different information about the target.
/// They can then be used by various sorts of feedback.
pub trait Observer {
    fn flush(&mut self) -> Result<(), AflError> {
        Ok(())
    }

    fn reset(&mut self) -> Result<(), AflError>;

    fn post_exec(&mut self) -> Result<(), AflError> {
        Ok(())
    }
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

pub struct DefaultMapObserver<'a, T>
where
    T: Integer + Copy,
{
    map: &'a mut [T],
    initial: T,
}

impl<'a, T: Integer + Copy> Observer for DefaultMapObserver<'a, T> {
    fn reset(&mut self) -> Result<(), AflError> {
        self.reset_map()
    }
}

impl<'a, T: Integer + Copy> MapObserver<T> for DefaultMapObserver<'a, T> {
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

impl<'a, T: Integer + Copy> DefaultMapObserver<'a, T> {
    /// Creates a new MapObserver
    pub fn new(map: &'a mut [T]) -> Self {
        let initial = if map.len() > 0 { map[0] } else { T::zero() };
        DefaultMapObserver {
            map: map,
            initial: initial,
        }
    }

    /// Creates a new MapObserver from a raw pointer
    pub fn new_from_ptr(map_ptr: *mut T, len: usize) -> Self {
        unsafe {
            let initial = if len > 0 { *map_ptr } else { T::zero() };
            DefaultMapObserver {
                map: from_raw_parts_mut(map_ptr, len),
                initial: initial,
            }
        }
    }
}
