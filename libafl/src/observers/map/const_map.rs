//! Map observer with a const size

use alloc::{borrow::Cow, vec::Vec};
use core::{
    fmt::Debug,
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
    slice::{Iter, IterMut},
};

use ahash::RandomState;
use libafl_bolts::{ownedref::OwnedMutSlice, AsSlice, AsSliceMut, HasLen, Named};
use num_traits::Bounded;
use serde::{Deserialize, Serialize};

use crate::{
    inputs::UsesInput,
    observers::{map::MapObserver, Observer},
    Error,
};

/// Use a const size to speedup `Feedback::is_interesting` when the user can
/// know the size of the map at compile time.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct ConstMapObserver<'a, T, const N: usize>
where
    T: Default + Copy + 'static + Serialize,
{
    map: OwnedMutSlice<'a, T>,
    initial: T,
    name: Cow<'static, str>,
}

impl<'a, S, T, const N: usize> Observer<S> for ConstMapObserver<'a, T, N>
where
    S: UsesInput,
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
    Self: MapObserver,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, T, const N: usize> Named for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<'a, T, const N: usize> HasLen for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn len(&self) -> usize {
        N
    }
}

impl<'a, 'it, T, const N: usize> IntoIterator for &'it ConstMapObserver<'a, T, N>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + Hash
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Item = <Iter<'it, T> as Iterator>::Item;
    type IntoIter = Iter<'it, T>;

    fn into_iter(self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_slice()[..cnt].iter()
    }
}

impl<'a, 'it, T, const N: usize> IntoIterator for &'it mut ConstMapObserver<'a, T, N>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + Hash
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Item = <IterMut<'it, T> as Iterator>::Item;
    type IntoIter = IterMut<'it, T>;

    fn into_iter(self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_slice_mut()[..cnt].iter_mut()
    }
}

impl<'a, T, const N: usize> ConstMapObserver<'a, T, N>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + Hash
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    /// Returns an iterator over the map.
    pub fn iter(&self) -> Iter<'_, T> {
        <&Self as IntoIterator>::into_iter(self)
    }

    /// Returns a mutable iterator over the map.
    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        <&mut Self as IntoIterator>::into_iter(self)
    }
}

impl<'a, T, const N: usize> Hash for ConstMapObserver<'a, T, N>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + Hash
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    #[inline]
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.as_slice().hash(hasher);
    }
}
impl<'a, T, const N: usize> AsRef<Self> for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + Serialize,
{
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'a, T, const N: usize> AsMut<Self> for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + Serialize,
{
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl<'a, T, const N: usize> MapObserver for ConstMapObserver<'a, T, N>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + Hash
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
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

impl<'a, T, const N: usize> Deref for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.map
    }
}

impl<'a, T, const N: usize> DerefMut for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.map
    }
}

impl<'a, T, const N: usize> ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
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
        }
    }

    /// Creates a new [`MapObserver`] with an owned map
    #[must_use]
    pub fn owned(name: &'static str, map: Vec<T>) -> Self {
        assert!(map.len() >= N);
        let initial = if map.is_empty() { T::default() } else { map[0] };
        Self {
            map: OwnedMutSlice::from(map),
            name: Cow::from(name),
            initial,
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
        }
    }
}
