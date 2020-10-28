use crate::AflError;
use std::cell::RefCell;

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
    fn get_map(&self) -> &RefCell<Vec<MapT>>;
    //fn get_map_mut(&mut self) -> &mut Vec<MapT>;

}

pub struct U8MapObserver {
    
    map: RefCell<Vec<u8>>,

}

impl Observer for U8MapObserver {
    fn reset(&mut self) -> Result<(), AflError> {

        // TODO: Clear
        Err(AflError::Unknown)

    }
}

impl MapObserver<u8> for U8MapObserver {

    fn get_map(&self) -> &RefCell<Vec<u8>> {
        // TODO: Rust this better
        return &self.map;
    }

}

impl U8MapObserver {
    pub fn new(map: RefCell<Vec<u8>>) -> Self {
        U8MapObserver{map: map}
    }
}