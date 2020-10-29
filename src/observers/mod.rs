use crate::AflError;
use std::slice::from_raw_parts_mut;

pub trait Observer {
    fn flush(&mut self) -> Result<(), AflError> {
        Ok(())
    }

    fn reset(&mut self) -> Result<(), AflError>;

    fn post_exec(&mut self) -> Result<(), AflError> {
        Ok(())
    }
}

pub trait MapObserver<MapT>: Observer {

    // TODO: Rust
    fn get_map(&self) -> &[MapT];
    //fn get_map_mut(&mut self) -> &mut Vec<MapT>;

    fn get_map_mut(&mut self) -> &mut [u8];

}

pub struct U8MapObserver {
    
    map: &'static mut [u8],

}

impl Observer for U8MapObserver {
    fn reset(&mut self) -> Result<(), AflError> {

        // TODO: Clear
        Err(AflError::Unknown)

    }
}

impl MapObserver<u8> for U8MapObserver {

    fn get_map(&self) -> &[u8] {
        self.map
    }

    fn get_map_mut(&mut self) -> &mut [u8] {
        self.map
    }

}

impl U8MapObserver {
    pub fn new(map_ptr: *mut u8, len: usize) -> Self {
        unsafe {
            U8MapObserver{map: from_raw_parts_mut(map_ptr, len)}
        }
    }
}