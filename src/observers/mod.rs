use crate::AflError;
use std::slice::from_raw_parts;

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

}

pub struct U8MapObserver {
    
    map: &'static [u8],

}

impl Observer for U8MapObserver {
    fn reset(&mut self) -> Result<(), AflError> {

        // TODO: Clear
        Err(AflError::Unknown)

    }
}

impl MapObserver<u8> for U8MapObserver {

    // TODO: Rust
    fn get_map(&self) -> &[u8] {
        return self.map;
    }
    //fn get_map_mut(&mut self) -> &mut Vec<MapT>;

}

impl U8MapObserver {
    pub fn new(map_ptr: *const u8, len: usize) -> Self {
        unsafe {
            U8MapObserver{map: from_raw_parts(map_ptr, len)}
        }
    }
}