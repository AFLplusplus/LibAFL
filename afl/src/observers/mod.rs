extern crate num;

use core::any::Any;
use core::slice::from_raw_parts_mut;
use num::Integer;
use serde::{Deserialize, Serialize};

use crate::serde_anymap::{SerdeAny, SliceMut};
use crate::AflError;

/// Observers observe different information about the target.
/// They can then be used by various sorts of feedback.
pub trait Observer: SerdeAny + 'static {
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
    fn initial(&self) -> T;

    /// Get the initial value for reset()
    fn initial_mut(&mut self) -> &mut T;

    /// Set the initial value for reset()
    fn set_initial(&mut self, initial: T);

    /// Reset the map
    fn reset_map(&mut self) -> Result<(), AflError> {
        // Normal memset, see https://rust.godbolt.org/z/Trs5hv
        let initial = self.initial();
        for i in self.map_mut().iter_mut() {
            *i = initial;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct StdMapObserver<T>
where
    T: Integer + Copy + 'static,
{
    map: SliceMut<'static, T>,
    initial: T,
    name: &'static str,
}

impl<T> Observer for StdMapObserver<T>
where
    T: Integer + Copy + 'static + serde::Serialize,
{
    fn reset(&mut self) -> Result<(), AflError> {
        self.reset_map()
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

impl<T> SerdeAny for StdMapObserver<T>
where
    T: Integer + Copy + 'static + serde::Serialize,
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
        match &self.map {
            SliceMut::Ref(r) => r,
            SliceMut::Owned(v) => v.as_slice(),
        }
    }

    fn map_mut(&mut self) -> &mut [T] {
        match &mut self.map {
            SliceMut::Ref(r) => r,
            SliceMut::Owned(v) => v.as_mut_slice(),
        }
    }

    fn initial(&self) -> T {
        self.initial
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
            map: SliceMut::Ref(map),
            initial: initial,
            name: name,
        }
    }

    /// Creates a new MapObserver from a raw pointer
    pub fn new_from_ptr(name: &'static str, map_ptr: *mut T, len: usize) -> Self {
        unsafe {
            let initial = if len > 0 { *map_ptr } else { T::zero() };
            StdMapObserver {
                map: SliceMut::Ref(from_raw_parts_mut(map_ptr, len)),
                initial: initial,
                name: name,
            }
        }
    }
}
