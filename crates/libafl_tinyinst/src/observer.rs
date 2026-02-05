//! `TinyInst` map observer for `MaxMapFeedback` compatibility
//!
//! This module provides [`TinyInstMapObserver`], which converts `TinyInst`'s
//! `Vec<u64>` coverage offsets into a u8 hitcount map compatible with `LibAFL`'s
//! `MaxMapFeedback`.

use alloc::borrow::Cow;

extern crate alloc;
use core::hash::{Hash, Hasher};

use libafl::{
    Error,
    executors::ExitKind,
    observers::{MapObserver, Observer},
};
use libafl_bolts::{HasLen, Named};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Default map size (AFL-style 64KB)
pub const DEFAULT_MAP_SIZE: usize = 65536;

/// A map observer that converts `TinyInst`'s `Vec<u64>` coverage offsets
/// into a u8 hitcount map compatible with `MaxMapFeedback`.
///
/// `TinyInst` provides coverage as a list of offsets (`Vec<u64>`), but `LibAFL`'s
/// feedback mechanisms expect a fixed-size map where each bucket contains
/// a hitcount. This observer performs that conversion using XOR-shift hashing.
#[derive(Clone, Debug)]
pub struct TinyInstMapObserver {
    /// The underlying hitcount map
    map: Vec<u8>,
    /// Name of this observer
    name: Cow<'static, str>,
    /// Pointer to the coverage vec from `TinyInst` executor
    coverage_ptr: *const Vec<u64>,
}

// Safety: The coverage_ptr is only used during post_exec which is single-threaded
unsafe impl Send for TinyInstMapObserver {}
unsafe impl Sync for TinyInstMapObserver {}

impl TinyInstMapObserver {
    /// Create a new `TinyInstMapObserver` with default map size (65536)
    ///
    /// # Arguments
    /// * `name` - Name for this observer
    /// * `coverage_ptr` - Pointer to the `Vec<u64>` that receives coverage from `TinyInst`
    ///
    /// # Safety
    /// The `coverage_ptr` must point to a valid `Vec<u64>` that outlives this observer.
    #[must_use]
    pub fn new(name: &'static str, coverage_ptr: *const Vec<u64>) -> Self {
        Self::with_map_size(name, coverage_ptr, DEFAULT_MAP_SIZE)
    }

    /// Create a new `TinyInstMapObserver` with custom map size
    ///
    /// # Arguments
    /// * `name` - Name for this observer
    /// * `coverage_ptr` - Pointer to the `Vec<u64>` that receives coverage from `TinyInst`
    /// * `map_size` - Size of the hitcount map (should be power of 2)
    ///
    /// # Safety
    /// The `coverage_ptr` must point to a valid `Vec<u64>` that outlives this observer.
    #[must_use]
    pub fn with_map_size(name: &'static str, coverage_ptr: *const Vec<u64>, map_size: usize) -> Self {
        Self {
            map: vec![0u8; map_size],
            name: Cow::Borrowed(name),
            coverage_ptr,
        }
    }

    /// Hash an offset to a bucket index using XOR-shift
    #[inline]
    fn hash_offset(&self, offset: u64) -> usize {
        // XOR-shift hash for better distribution
        let mut h = offset;
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
        h ^= h >> 33;
        (h as usize) % self.map.len()
    }

    /// Update the map from coverage offsets
    fn update_map_from_coverage(&mut self) {
        // Reset the map first
        self.map.fill(0);

        // Safety: We trust that coverage_ptr is valid as per constructor contract
        if self.coverage_ptr.is_null() {
            return;
        }

        let coverage = unsafe { &*self.coverage_ptr };

        for &offset in coverage {
            let idx = self.hash_offset(offset);
            // Saturating increment to avoid overflow
            self.map[idx] = self.map[idx].saturating_add(1);
        }
    }

    /// Get the underlying map as a slice
    #[must_use]
    pub fn map(&self) -> &[u8] {
        &self.map
    }

    /// Get the underlying map as a mutable slice
    #[must_use]
    pub fn map_mut(&mut self) -> &mut [u8] {
        &mut self.map
    }
}

impl Named for TinyInstMapObserver {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl HasLen for TinyInstMapObserver {
    #[inline]
    fn len(&self) -> usize {
        self.map.len()
    }
}

impl Hash for TinyInstMapObserver {
    #[inline]
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.map.hash(hasher);
    }
}

impl<I, S> Observer<I, S> for TinyInstMapObserver {
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.map.fill(0);
        Ok(())
    }

    #[inline]
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.update_map_from_coverage();
        Ok(())
    }
}

impl AsRef<Self> for TinyInstMapObserver {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsMut<Self> for TinyInstMapObserver {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

// Custom serde implementation to handle the raw pointer
#[derive(Serialize, Deserialize)]
struct TinyInstMapObserverData {
    map: Vec<u8>,
    name: Cow<'static, str>,
}

impl Serialize for TinyInstMapObserver {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = TinyInstMapObserverData {
            map: self.map.clone(),
            name: self.name.clone(),
        };
        data.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TinyInstMapObserver {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = TinyInstMapObserverData::deserialize(deserializer)?;
        Ok(TinyInstMapObserver {
            map: data.map,
            name: data.name,
            coverage_ptr: core::ptr::null(),
        })
    }
}

// Implement MapObserver trait for compatibility with MaxMapFeedback
impl MapObserver for TinyInstMapObserver {
    type Entry = u8;

    #[inline]
    fn get(&self, idx: usize) -> Self::Entry {
        self.map[idx]
    }

    #[inline]
    fn set(&mut self, idx: usize, val: Self::Entry) {
        self.map[idx] = val;
    }

    #[inline]
    fn usable_count(&self) -> usize {
        self.map.len()
    }

    fn count_bytes(&self) -> u64 {
        self.map.iter().filter(|&&x| x != 0).count() as u64
    }

    #[inline]
    fn initial(&self) -> Self::Entry {
        0
    }

    fn reset_map(&mut self) -> Result<(), Error> {
        self.map.fill(0);
        Ok(())
    }

    fn to_vec(&self) -> Vec<Self::Entry> {
        self.map.clone()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        let cnt = self.map.len();
        indexes
            .iter()
            .filter(|&&i| i < cnt && self.map[i] != 0)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_distribution() {
        let coverage: Vec<u64> = vec![];
        let observer = TinyInstMapObserver::new("test", &coverage);

        // Test that different offsets hash to different buckets
        let h1 = observer.hash_offset(0x1000);
        let h2 = observer.hash_offset(0x1001);
        let h3 = observer.hash_offset(0x2000);

        // They should be different (with high probability)
        assert!(h1 != h2 || h2 != h3);
    }

    #[test]
    fn test_map_update() {
        let coverage: Vec<u64> = vec![0x1000, 0x2000, 0x3000, 0x1000]; // 0x1000 appears twice
        let mut observer = TinyInstMapObserver::new("test", &coverage);

        observer.update_map_from_coverage();

        // Check that we have some non-zero entries
        assert!(observer.count_bytes() > 0);

        // The bucket for 0x1000 should have count >= 2 (could collide with others)
        let idx = observer.hash_offset(0x1000);
        assert!(observer.get(idx) >= 2);
    }

    #[test]
    fn test_reset() {
        let coverage: Vec<u64> = vec![0x1000, 0x2000];
        let mut observer = TinyInstMapObserver::new("test", &coverage);

        observer.update_map_from_coverage();
        assert!(observer.count_bytes() > 0);

        observer.reset_map().unwrap();
        assert_eq!(observer.count_bytes(), 0);
    }
}
