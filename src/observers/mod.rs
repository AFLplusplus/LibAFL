use crate::AflError;
use std::slice::from_raw_parts_mut;

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

/// A MapObserver contains a map with values, collected from the child.
pub trait MapObserver<MapT>: Observer {
    fn get_map(&self) -> &[MapT];
    fn get_map_mut(&mut self) -> &mut [MapT];
}

/// A staticMapObserver observes the static map, as oftentimes used for afl-like coverage information
pub struct StaticMapObserver {
    map: &'static mut [u8],
}

impl Observer for StaticMapObserver {
    fn reset(&mut self) -> Result<(), AflError> {
        // Normal memset, see https://rust.godbolt.org/z/Trs5hv
        for i in self.map.iter_mut() {
            *i = 0;
        }
        Ok(())
    }
}

impl MapObserver<u8> for StaticMapObserver {
    fn get_map(&self) -> &[u8] {
        self.map
    }

    fn get_map_mut(&mut self) -> &mut [u8] {
        self.map
    }
}

impl StaticMapObserver {
    /// Creates a new StaticMapObserver from a raw pointer.
    pub fn new(map_ptr: *mut u8, len: usize) -> Self {
        unsafe {
            StaticMapObserver {
                map: from_raw_parts_mut(map_ptr, len),
            }
        }
    }
}
