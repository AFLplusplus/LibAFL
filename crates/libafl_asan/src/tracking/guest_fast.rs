//! # guest
//! This implementation performs guest memory tracking by use of a hash table
//! and hence requires no interaction with the guest. Unlike GuestTracking, this
//! faster variant is unable to detect whether a new allocation overlaps an
//! existing one (though this should be taken care of by the allocator).
use core::hash::BuildHasherDefault;

use ahash::AHasher;
use hashbrown::HashSet;
use log::debug;
use thiserror::Error;

use crate::{GuestAddr, tracking::Tracking};

type Hasher = BuildHasherDefault<AHasher>;

#[derive(Debug)]
pub struct GuestFastTracking {
    ranges: HashSet<GuestAddr, Hasher>,
}

impl Tracking for GuestFastTracking {
    type Error = GuestFastTrackingError;

    fn track(&mut self, start: GuestAddr, len: usize) -> Result<(), Self::Error> {
        debug!("alloc - start: {start:#x}, len: {len:#x}");
        if Self::is_out_of_bounds(start, len) {
            Err(GuestFastTrackingError::AddressRangeOverflow(start, len))?;
        }

        if len == 0 {
            Err(GuestFastTrackingError::ZeroLength(start))?;
        }

        if !self.ranges.insert(start) {
            Err(GuestFastTrackingError::TrackingConflict(start, len))?;
        }

        Ok(())
    }

    fn untrack(&mut self, start: GuestAddr) -> Result<(), Self::Error> {
        debug!("dealloc - start: {start:#x}");

        if !self.ranges.remove(&start) {
            Err(GuestFastTrackingError::AllocationNotFound(start))?;
        }
        Ok(())
    }
}

impl GuestFastTracking {
    pub fn new() -> Result<Self, GuestFastTrackingError> {
        Ok(GuestFastTracking {
            ranges: HashSet::with_capacity_and_hasher(4096, Hasher::default()),
        })
    }

    pub fn is_out_of_bounds(addr: GuestAddr, len: usize) -> bool {
        if len == 0 {
            false
        } else {
            GuestAddr::MAX - len + 1 < addr
        }
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum GuestFastTrackingError {
    #[error("Address overflow: {0:x}, len: {1:x}")]
    AddressRangeOverflow(GuestAddr, usize),
    #[error("Allocation not found: {0:x}")]
    AllocationNotFound(GuestAddr),
    #[error("Tracking conflict: {0:x}, len: {1:x}")]
    TrackingConflict(GuestAddr, usize),
    #[error("Zero Length")]
    ZeroLength(GuestAddr),
}
