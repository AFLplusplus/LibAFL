//! # default
//! The default frontend is primarily designed for simplicity. Though called
//! the default, it may be subsequently replaced as the preferred frontend
//! should a more optimal design be implemented at a later date.
//!
//! This frontend stores all of it's metadata out-of-band, that is no meta-data
//! is stored adjacent to the user's buffers. The size of the red-zone applied
//! to each allocation is configurable. The frontend also supports the use of a
//! quarantine (whose size is configurable) to prevent user buffers from being
//! re-used for a period of time.
use alloc::{
    alloc::{GlobalAlloc, Layout, LayoutError},
    collections::{BTreeMap, VecDeque},
    fmt::Debug,
};
use core::slice::from_raw_parts_mut;

use log::debug;
use thiserror::Error;

use crate::{
    GuestAddr,
    allocator::frontend::AllocatorFrontend,
    shadow::{PoisonType, Shadow},
    tracking::Tracking,
};

struct Allocation {
    frontend_len: usize,
    backend_addr: GuestAddr,
    backend_len: usize,
    backend_align: usize,
}

pub struct DefaultFrontend<B: GlobalAlloc + Send, S: Shadow, T: Tracking> {
    backend: B,
    shadow: S,
    tracking: T,
    red_zone_size: usize,
    allocations: BTreeMap<GuestAddr, Allocation>,
    quarantine: VecDeque<Allocation>,
    quarantine_size: usize,
    quaratine_used: usize,
}

impl<B: GlobalAlloc + Send, S: Shadow, T: Tracking> AllocatorFrontend for DefaultFrontend<B, S, T> {
    type Error = DefaultFrontendError<S, T>;

    fn alloc(&mut self, len: usize, align: usize) -> Result<GuestAddr, Self::Error> {
        debug!("alloc - len: 0x{:x}, align: 0x{:x}", len, align);
        if align % size_of::<GuestAddr>() != 0 {
            Err(DefaultFrontendError::InvalidAlignment(align))?;
        }
        let size = len + align;
        let allocated_size = (self.red_zone_size * 2) + Self::align_up(size);
        assert!(allocated_size % Self::ALLOC_ALIGN_SIZE == 0);
        let ptr = unsafe {
            self.backend.alloc(
                Layout::from_size_align(allocated_size, Self::ALLOC_ALIGN_SIZE)
                    .map_err(DefaultFrontendError::LayoutError)?,
            )
        };

        if ptr.is_null() {
            Err(DefaultFrontendError::AllocatorError)?;
        }

        let orig = ptr as GuestAddr;

        debug!(
            "alloc - buffer: 0x{:x}, len: 0x{:x}, align: 0x{:x}",
            orig,
            allocated_size,
            Self::ALLOC_ALIGN_SIZE
        );

        let rz = orig + self.red_zone_size;
        let data = if align == 0 {
            rz
        } else {
            rz + align - (rz % align)
        };
        assert!(align == 0 || data % align == 0);
        assert!(data + len <= orig + allocated_size);

        self.allocations.insert(
            data,
            Allocation {
                frontend_len: len,
                backend_addr: orig,
                backend_len: allocated_size,
                backend_align: Self::ALLOC_ALIGN_SIZE,
            },
        );

        self.tracking
            .track(data, len)
            .map_err(|e| DefaultFrontendError::TrackingError(e))?;
        self.shadow
            .poison(orig, data - orig, PoisonType::AsanHeapLeftRz)
            .map_err(|e| DefaultFrontendError::ShadowError(e))?;
        self.shadow
            .unpoison(data, len)
            .map_err(|e| DefaultFrontendError::ShadowError(e))?;
        let poison_len = Self::align_up(len) - len + self.red_zone_size;
        self.shadow
            .poison(data + len, poison_len, PoisonType::AsanStackRightRz)
            .map_err(|e| DefaultFrontendError::ShadowError(e))?;

        let buffer = unsafe { from_raw_parts_mut(data as *mut u8, len) };
        buffer.iter_mut().for_each(|b| *b = 0xff);
        Ok(data)
    }

    fn dealloc(&mut self, addr: GuestAddr) -> Result<(), Self::Error> {
        debug!("dealloc - addr: 0x{:x}", addr);
        if addr == 0 {
            return Ok(());
        }

        let alloc = self
            .allocations
            .remove(&addr)
            .ok_or_else(|| DefaultFrontendError::InvalidAddress(addr))?;
        self.shadow
            .poison(
                alloc.backend_addr,
                alloc.backend_len,
                PoisonType::AsanHeapFreed,
            )
            .map_err(|e| DefaultFrontendError::ShadowError(e))?;
        self.tracking
            .untrack(addr)
            .map_err(|e| DefaultFrontendError::TrackingError(e))?;
        self.quaratine_used += alloc.backend_len;
        self.quarantine.push_back(alloc);
        self.purge_quarantine()?;
        Ok(())
    }

    fn get_size(&self, addr: GuestAddr) -> Result<usize, Self::Error> {
        debug!("get_size - addr: 0x{:x}", addr);
        let alloc = self
            .allocations
            .get(&addr)
            .ok_or_else(|| DefaultFrontendError::InvalidAddress(addr))?;
        Ok(alloc.frontend_len)
    }
}

impl<B: GlobalAlloc + Send, S: Shadow, T: Tracking> DefaultFrontend<B, S, T> {
    #[cfg(target_pointer_width = "32")]
    const ALLOC_ALIGN_SIZE: usize = 8;

    #[cfg(target_pointer_width = "64")]
    const ALLOC_ALIGN_SIZE: usize = 16;

    pub const DEFAULT_REDZONE_SIZE: usize = 128;
    pub const DEFAULT_QUARANTINE_SIZE: usize = 50 << 20;

    pub fn new(
        backend: B,
        shadow: S,
        tracking: T,
        red_zone_size: usize,
        quarantine_size: usize,
    ) -> Result<DefaultFrontend<B, S, T>, DefaultFrontendError<S, T>> {
        if red_zone_size % Self::ALLOC_ALIGN_SIZE != 0 {
            Err(DefaultFrontendError::InvalidRedZoneSize(red_zone_size))?;
        }
        Ok(DefaultFrontend::<B, S, T> {
            backend,
            shadow,
            tracking,
            red_zone_size,
            allocations: BTreeMap::new(),
            quarantine: VecDeque::new(),
            quarantine_size,
            quaratine_used: 0,
        })
    }

    fn purge_quarantine(&mut self) -> Result<(), DefaultFrontendError<S, T>> {
        while self.quaratine_used > self.quarantine_size {
            let alloc = self
                .quarantine
                .pop_front()
                .ok_or(DefaultFrontendError::QuarantineCorruption)?;
            unsafe {
                self.backend.dealloc(
                    alloc.backend_addr as *mut u8,
                    Layout::from_size_align(alloc.backend_len, alloc.backend_align)
                        .map_err(DefaultFrontendError::LayoutError)?,
                )
            };
            self.quaratine_used -= alloc.backend_len;
        }
        Ok(())
    }

    fn align_up(size: usize) -> usize {
        assert!(size <= GuestAddr::MAX - (Self::ALLOC_ALIGN_SIZE - 1));
        let val = size + (Self::ALLOC_ALIGN_SIZE - 1);
        val & !(Self::ALLOC_ALIGN_SIZE - 1)
    }

    pub fn shadow(&self) -> &S {
        &self.shadow
    }

    pub fn shadow_mut(&mut self) -> &mut S {
        &mut self.shadow
    }

    pub fn tracking(&self) -> &T {
        &self.tracking
    }

    pub fn tracking_mut(&mut self) -> &mut T {
        &mut self.tracking
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum DefaultFrontendError<S: Shadow, T: Tracking> {
    #[error("Invalid red_zone_size: {0}")]
    InvalidRedZoneSize(usize),
    #[error("Invalid alignment: {0}")]
    InvalidAlignment(usize),
    #[error("Allocator error")]
    AllocatorError,
    #[error("Layout error: {0:?}")]
    LayoutError(LayoutError),
    #[error("Shadow error: {0:?}")]
    ShadowError(S::Error),
    #[error("Tracking error: {0:?}")]
    TrackingError(T::Error),
    #[error("Invalid address: {0:x}")]
    InvalidAddress(GuestAddr),
    #[error("Quarantine corruption")]
    QuarantineCorruption,
}
