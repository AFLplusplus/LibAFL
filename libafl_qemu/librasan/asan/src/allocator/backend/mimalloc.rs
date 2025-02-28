use alloc::fmt::{self, Debug, Formatter};
use core::alloc::{GlobalAlloc, Layout, LayoutError};

use baby_mimalloc::Mimalloc;
use thiserror::Error;

use crate::{GuestAddr, allocator::backend::AllocatorBackend};

pub struct MimallocBackend<G: GlobalAlloc + Debug> {
    mimalloc: Mimalloc<G>,
}

impl<G: GlobalAlloc + Debug> MimallocBackend<G> {
    pub const fn new(global_allocator: G) -> Self {
        MimallocBackend {
            mimalloc: Mimalloc::with_os_allocator(global_allocator),
        }
    }
}

impl<G: GlobalAlloc + Debug> Debug for MimallocBackend<G> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "MimallocBackend")
    }
}

impl<G: GlobalAlloc + Debug> AllocatorBackend for MimallocBackend<G> {
    type Error = MimallocBackendError;

    fn alloc(&mut self, len: usize, align: usize) -> Result<GuestAddr, Self::Error> {
        let layout =
            Layout::from_size_align(len, align).map_err(MimallocBackendError::LayoutError)?;
        let ptr = unsafe { self.mimalloc.alloc(layout) };
        if ptr.is_null() {
            Err(MimallocBackendError::NullAllocationError)?;
        }
        Ok(ptr as GuestAddr)
    }

    fn dealloc(
        &mut self,
        addr: crate::GuestAddr,
        len: usize,
        align: usize,
    ) -> Result<(), Self::Error> {
        let layout =
            Layout::from_size_align(len, align).map_err(MimallocBackendError::LayoutError)?;
        let ptr = addr as *mut u8;
        unsafe {
            self.mimalloc.dealloc(ptr, layout);
        }
        Ok(())
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum MimallocBackendError {
    #[error("Layout error: {0:?}")]
    LayoutError(LayoutError),
    #[error("Null allocation")]
    NullAllocationError,
}
