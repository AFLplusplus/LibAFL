//! # guest
//! This implementation performs guest memory tracking by use of a simple sorted
//! list residing in the guest's user space. Hence no interaction with the host
//! is required.
use alloc::vec::Vec;
use core::cmp::Ordering;

use log::debug;
use thiserror::Error;

use crate::{GuestAddr, tracking::Tracking};

#[derive(Eq, Debug)]
struct Range {
    start: GuestAddr,
    len: usize,
}

impl PartialEq for Range {
    fn eq(&self, other: &Self) -> bool {
        if self.start > other.start {
            let delta = self.start - other.start;
            delta < other.len
        } else {
            let delta = other.start - self.start;
            delta < self.len
        }
    }
}

impl PartialOrd for Range {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Range {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.eq(other) {
            Ordering::Equal
        } else {
            self.start.cmp(&other.start)
        }
    }
}

type Ranges = Vec<Range>;

#[derive(Debug)]
pub struct GuestTracking {
    ranges: Ranges,
}

impl Tracking for GuestTracking {
    type Error = GuestTrackingError;

    fn track(&mut self, start: GuestAddr, len: usize) -> Result<(), Self::Error> {
        debug!("alloc - start: 0x{:x}, len: 0x{:x}", start, len);
        if Self::is_out_of_bounds(start, len) {
            Err(GuestTrackingError::AddressRangeOverflow(start, len))?;
        }

        if len == 0 {
            Err(GuestTrackingError::ZeroLength(start))?;
        }

        let item = Range { start, len };

        let pos = self.ranges.binary_search(&item);
        match pos {
            Ok(pos) => {
                let conflict = &self.ranges[pos];
                Err(GuestTrackingError::TrackingConflict(
                    conflict.start,
                    conflict.len,
                    item.start,
                    item.len,
                ))?;
            }
            Err(pos) => {
                self.ranges.insert(pos, item);
            }
        }

        Ok(())
    }

    fn untrack(&mut self, start: GuestAddr) -> Result<(), Self::Error> {
        debug!("dealloc - start: 0x{:x}", start);
        let pos = self.ranges.binary_search_by(|item| item.start.cmp(&start));
        match pos {
            Ok(pos) => {
                self.ranges.remove(pos);
                Ok(())
            }
            Err(_pos) => Err(GuestTrackingError::AllocationNotFound(start)),
        }
    }
}

impl GuestTracking {
    pub fn new() -> Result<Self, GuestTrackingError> {
        Ok(GuestTracking { ranges: Vec::new() })
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
pub enum GuestTrackingError {
    #[error("Address overflow: {0:x}, len: {1:x}")]
    AddressRangeOverflow(GuestAddr, usize),
    #[error("Allocation not found: {0:x}")]
    AllocationNotFound(GuestAddr),
    #[error("Tracking conflict")]
    TrackingConflict(GuestAddr, usize, GuestAddr, usize),
    #[error("Zero Length")]
    ZeroLength(GuestAddr),
}
