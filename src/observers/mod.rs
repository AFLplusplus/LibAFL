extern crate num;

use std::slice::from_raw_parts_mut;
use std::any::Any;
use num::Integer;

use crate::AflError;

/// Observers observe different information about the target.
/// They can then be used by various sorts of feedback.
pub trait Observer : Any {
    fn flush(&mut self) -> Result<(), AflError> {
        Ok(())
    }

    fn reset(&mut self) -> Result<(), AflError>;

    fn post_exec(&mut self) -> Result<(), AflError> {
        Ok(())
    }

    fn as_any(&self) -> &dyn Any;
}

/// A staticMapObserver observes the static map, as oftentimes used for afl-like coverage information
pub struct MapObserver<MapT: Integer + Copy + 'static + 'static> {
    map: &'static mut [MapT],
}

impl<MapT: Integer + Copy + 'static> Observer for MapObserver<MapT> {
    fn reset(&mut self) -> Result<(), AflError> {
        // Normal memset, see https://rust.godbolt.org/z/Trs5hv
        for i in self.map.iter_mut() {
            *i = MapT::zero();
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<MapT: Integer + Copy + 'static> MapObserver<MapT> {
    pub fn get_map(&self) -> &[MapT] {
        self.map
    }

    pub fn get_map_mut(&mut self) -> &mut [MapT] {
        self.map
    }
}

impl<MapT: Integer + Copy + 'static> MapObserver<MapT> {
    /// Creates a new MapObserver from a raw pointer.
    pub fn new(map_ptr: *mut MapT, len: usize) -> Self {
        unsafe {
            MapObserver {
                map: from_raw_parts_mut(map_ptr, len),
            }
        }
    }
}
