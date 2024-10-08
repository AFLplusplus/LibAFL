//! Map observer with a const size

use alloc::{borrow::Cow, vec::Vec};
use core::{
    fmt::Debug,
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
};

use ahash::RandomState;
use libafl_bolts::{ownedref::OwnedMutSlice, AsSlice, AsSliceMut, HasLen, Named};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    observers::{map::MapObserver, Observer, VariableLengthMapObserver},
    Error,
};

// TODO: remove the size field and implement ConstantLengthMapObserver

/// Use a const size to speedup `Feedback::is_interesting` when the user can
/// know the size of the map at compile time.
#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct ConstMapObserver<'a, T, const N: usize> {
    map: OwnedMutSlice<'a, T>,
    initial: T,
    name: Cow<'static, str>,
    size: usize,
}

impl<I, S, T, const N: usize> Observer<I, S> for ConstMapObserver<'_, T, N>
where
    Self: MapObserver,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<T, const N: usize> Named for ConstMapObserver<'_, T, N> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<T, const N: usize> HasLen for ConstMapObserver<'_, T, N> {
    #[inline]
    fn len(&self) -> usize {
        N
    }
}

impl<T, const N: usize> Hash for ConstMapObserver<'_, T, N>
where
    T: Hash,
{
    #[inline]
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.map.as_slice().hash(hasher);
    }
}
impl<T, const N: usize> AsRef<Self> for ConstMapObserver<'_, T, N> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<T, const N: usize> AsMut<Self> for ConstMapObserver<'_, T, N> {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl<T, const N: usize> MapObserver for ConstMapObserver<'_, T, N>
where
    T: PartialEq + Copy + Hash + Serialize + DeserializeOwned + Debug + 'static,
{
    type Entry = T;

    #[inline]
    fn initial(&self) -> T {
        self.initial
    }

    #[inline]
    fn get(&self, idx: usize) -> T {
        self.as_slice()[idx]
    }

    #[inline]
    fn set(&mut self, idx: usize, val: T) {
        self.map.as_slice_mut()[idx] = val;
    }

    /// Count the set bytes in the map
    fn count_bytes(&self) -> u64 {
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = self.as_slice();
        let mut res = 0;
        for x in &map[0..cnt] {
            if *x != initial {
                res += 1;
            }
        }
        res
    }

    fn usable_count(&self) -> usize {
        self.as_slice().len()
    }

    #[inline]
    fn hash_simple(&self) -> u64 {
        RandomState::with_seeds(0, 0, 0, 0).hash_one(self)
    }

    /// Reset the map
    #[inline]
    fn reset_map(&mut self) -> Result<(), Error> {
        // Normal memset, see https://rust.godbolt.org/z/Trs5hv
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = self.as_slice_mut();
        for x in &mut map[0..cnt] {
            *x = initial;
        }
        Ok(())
    }

    fn to_vec(&self) -> Vec<T> {
        self.as_slice().to_vec()
    }

    /// Get the number of set entries with the specified indexes
    fn how_many_set(&self, indexes: &[usize]) -> usize {
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = self.as_slice();
        let mut res = 0;
        for i in indexes {
            if *i < cnt && map[*i] != initial {
                res += 1;
            }
        }
        res
    }
}

impl<T, const N: usize> VariableLengthMapObserver for ConstMapObserver<'_, T, N>
where
    T: PartialEq + Copy + Hash + Serialize + DeserializeOwned + Debug + 'static,
{
    fn map_slice(&mut self) -> &[Self::Entry] {
        self.map.as_slice()
    }

    fn map_slice_mut(&mut self) -> &mut [Self::Entry] {
        self.map.as_slice_mut()
    }

    fn size(&mut self) -> &usize {
        &N
    }

    fn size_mut(&mut self) -> &mut usize {
        &mut self.size
    }
}

impl<T, const N: usize> Deref for ConstMapObserver<'_, T, N> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.map
    }
}

impl<T, const N: usize> DerefMut for ConstMapObserver<'_, T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.map
    }
}

impl<'a, T, const N: usize> ConstMapObserver<'a, T, N>
where
    T: Default,
{
    /// Creates a new [`MapObserver`]
    ///
    /// # Note
    /// Will get a pointer to the map and dereference it at any point in time.
    /// The map must not move in memory!
    #[must_use]
    pub fn new(name: &'static str, map: &'a mut [T]) -> Self {
        assert!(map.len() >= N);
        Self {
            map: OwnedMutSlice::from(map),
            name: Cow::from(name),
            initial: T::default(),
            size: N,
        }
    }

    /// Creates a new [`MapObserver`] from a raw pointer
    ///
    /// # Safety
    /// Will dereference the `map_ptr` with up to len elements.
    pub unsafe fn from_mut_ptr(name: &'static str, map_ptr: *mut T) -> Self {
        ConstMapObserver {
            map: OwnedMutSlice::from_raw_parts_mut(map_ptr, N),
            name: Cow::from(name),
            initial: T::default(),
            size: N,
        }
    }
}

impl<T, const N: usize> ConstMapObserver<'_, T, N>
where
    T: Default + Clone,
{
    /// Creates a new [`MapObserver`] with an owned map
    #[must_use]
    pub fn owned(name: &'static str, map: Vec<T>) -> Self {
        assert!(map.len() >= N);
        let initial = if map.is_empty() {
            T::default()
        } else {
            map[0].clone()
        };
        Self {
            map: OwnedMutSlice::from(map),
            name: Cow::from(name),
            initial,
            size: N,
        }
    }
}
