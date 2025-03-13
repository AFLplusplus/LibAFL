//! # host
//! This implementation of the shadow map makes use of a `Host` implementation
//! in order to relay the requested shadow map queries or updates to the host
//! emulator. In the case of QEMU on Linux, this will typically be by means of a
//! bespoke `syscall`.
use core::marker::PhantomData;

use log::debug;
use thiserror::Error;

use crate::{
    GuestAddr,
    host::Host,
    shadow::{PoisonType, Shadow},
};

#[derive(Debug)]
pub struct HostShadow<H> {
    _phantom: PhantomData<H>,
}

impl<H: Host> Shadow for HostShadow<H> {
    type Error = HostShadowError<H>;

    fn load(&self, start: GuestAddr, len: usize) -> Result<(), Self::Error> {
        debug!("load - start: 0x{:x}, len: 0x{:x}", start, len);
        H::load(start, len).map_err(|e| HostShadowError::HostError(e))
    }

    fn store(&self, start: GuestAddr, len: usize) -> Result<(), Self::Error> {
        debug!("store - start: 0x{:x}, len: 0x{:x}", start, len);
        H::store(start, len).map_err(|e| HostShadowError::HostError(e))
    }

    fn poison(&mut self, start: GuestAddr, len: usize, val: PoisonType) -> Result<(), Self::Error> {
        debug!(
            "poison - start: 0x{:x}, len: 0x{:x}, pioson: {:?}",
            start, len, val
        );
        H::poison(start, len, val).map_err(|e| HostShadowError::HostError(e))
    }

    fn unpoison(&mut self, start: GuestAddr, len: usize) -> Result<(), Self::Error> {
        debug!("unpoison - start: 0x{:x}, len: 0x{:x}", start, len);
        H::unpoison(start, len).map_err(|e| HostShadowError::HostError(e))
    }

    fn is_poison(&self, start: GuestAddr, len: usize) -> Result<bool, Self::Error> {
        debug!("is_poison - start: 0x{:x}, len: 0x{:x}", start, len);
        H::is_poison(start, len).map_err(|e| HostShadowError::HostError(e))
    }
}

impl<H: Host> HostShadow<H> {
    pub fn new() -> Result<HostShadow<H>, HostShadowError<H>> {
        Ok(HostShadow::<H> {
            _phantom: PhantomData,
        })
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum HostShadowError<H: Host> {
    #[error("Host error: {0:?}")]
    HostError(H::Error),
}
