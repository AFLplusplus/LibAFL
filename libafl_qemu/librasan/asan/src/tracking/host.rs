//! # host
//! Like `HostShadow` this implementation makes use of a `Host` implementation
//! in order to relay the requests for memory tracking to the host emulator. In
//! the case of QEMU on Linux, this will typically be by means of a bespoke
//! `syscall`.
use core::marker::PhantomData;

use log::debug;
use syscalls::Errno;
use thiserror::Error;

use crate::{GuestAddr, host::Host, tracking::Tracking};

#[derive(Debug)]
pub struct HostTracking<H> {
    _phantom: PhantomData<H>,
}

impl<H: Host> Tracking for HostTracking<H> {
    type Error = HostTrackingError<H>;

    fn track(&mut self, start: GuestAddr, len: usize) -> Result<(), Self::Error> {
        debug!("alloc - start: 0x{:x}, len: 0x{:x}", start, len);
        /* Here QEMU expects a start and end, rather than start and length */
        H::track(start, start + len).map_err(|e| HostTrackingError::HostError(e))
    }

    fn untrack(&mut self, start: GuestAddr) -> Result<(), Self::Error> {
        debug!("free - start: 0x{:x}", start);
        H::untrack(start).map_err(|e| HostTrackingError::HostError(e))
    }
}

impl<H: Host> HostTracking<H> {
    pub fn new() -> Result<Self, Errno> {
        Ok(HostTracking::<H> {
            _phantom: PhantomData,
        })
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum HostTrackingError<H: Host> {
    #[error("Host error: {0:?}")]
    HostError(H::Error),
}
