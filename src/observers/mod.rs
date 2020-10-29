extern crate num;

use crate::AflError;
use std::slice::from_raw_parts_mut;

use num::Integer;

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

/// A staticMapObserver observes the static map, as oftentimes used for afl-like coverage information
pub struct MapObserver<'a, MapT: Integer + Copy> {
    map: &'a mut [MapT],
}

impl<'a, MapT: Integer + Copy> Observer for MapObserver<'a, MapT> {
    fn reset(&mut self) -> Result<(), AflError> {
        // Normal memset, see https://rust.godbolt.org/z/Trs5hv
        for i in self.map.iter_mut() {
            *i = MapT::zero();
        }
        Ok(())
    }
}

impl<'a, MapT: Integer + Copy> MapObserver<'a, MapT> {
    pub fn get_map(&self) -> &[MapT] {
        self.map
    }

    pub fn get_map_mut(&mut self) -> &mut [MapT] {
        self.map
    }
}

impl<'a, MapT: Integer + Copy> MapObserver<'a, MapT> {
    /// Creates a new MapObserver from a raw pointer.
    pub fn new(map_ptr: *mut MapT, len: usize) -> Self {
        unsafe {
            MapObserver {
                map: from_raw_parts_mut(map_ptr, len),
            }
        }
    }
}
