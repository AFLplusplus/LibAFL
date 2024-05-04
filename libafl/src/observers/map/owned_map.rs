//! An observer that owns its map

use alloc::{borrow::Cow, vec::Vec};
use core::{
    fmt::Debug,
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
    slice::{Iter, IterMut},
};

use ahash::RandomState;
use libafl_bolts::{AsSlice, AsSliceMut, HasLen, Named};
use num_traits::Bounded;
use serde::{Deserialize, Serialize};

use crate::{
    inputs::UsesInput,
    observers::{map::MapObserver, Observer},
    Error,
};

/// Exact copy of `StdMapObserver` that owns its map
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize,
{
    map: Vec<T>,
    initial: T,
    name: Cow<'static, str>,
}

impl<S, T> Observer<S> for OwnedMapObserver<T>
where
    S: UsesInput,
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
    Self: MapObserver,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<T> Named for OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<T> HasLen for OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn len(&self) -> usize {
        self.map.as_slice().len()
    }
}

impl<'it, T> IntoIterator for &'it OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Item = <Iter<'it, T> as Iterator>::Item;
    type IntoIter = Iter<'it, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<'it, T> IntoIterator for &'it mut OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Item = <IterMut<'it, T> as Iterator>::Item;
    type IntoIter = IterMut<'it, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice_mut().iter_mut()
    }
}

impl<T> OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
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

impl<T> Hash for OwnedMapObserver<T>
where
    T: 'static + Hash + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[inline]
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.as_slice().hash(hasher);
    }
}

impl<T> AsRef<Self> for OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize,
{
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<T> AsMut<Self> for OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize,
{
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl<T> MapObserver for OwnedMapObserver<T>
where
    T: 'static
        + Bounded
        + PartialEq
        + Default
        + Copy
        + Hash
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Entry = T;

    #[inline]
    fn get(&self, pos: usize) -> T {
        self.as_slice()[pos]
    }

    #[inline]
    fn set(&mut self, pos: usize, val: Self::Entry) {
        self.as_slice_mut()[pos] = val;
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

    #[inline]
    fn usable_count(&self) -> usize {
        self.as_slice().len()
    }

    #[inline]
    fn hash_simple(&self) -> u64 {
        RandomState::with_seeds(0, 0, 0, 0).hash_one(self)
    }

    #[inline]
    fn initial(&self) -> T {
        self.initial
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

impl<T> Deref for OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.map
    }
}

impl<T> DerefMut for OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.map
    }
}

impl<T> OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`] with an owned map
    #[must_use]
    pub fn new(name: &'static str, map: Vec<T>) -> Self {
        let initial = if map.is_empty() { T::default() } else { map[0] };
        Self {
            map,
            name: Cow::from(name),
            initial,
        }
    }
}
