//! An observer that takes multiple pointers or slices to observe

use alloc::{borrow::Cow, vec::Vec};
use core::{
    fmt::Debug,
    hash::{Hash, Hasher},
    iter::Flatten,
    mem::size_of,
    slice::{self, Iter, IterMut},
};

use ahash::RandomState;
use libafl_bolts::{
    ownedref::OwnedMutSlice, AsIter, AsIterMut, AsSlice, AsSliceMut, HasLen, Named,
};
use meminterval::IntervalTree;
use num_traits::Bounded;
use serde::{Deserialize, Serialize};

use crate::{
    inputs::UsesInput,
    observers::{map::MapObserver, DifferentialObserver, Observer, ObserversTuple},
    Error,
};

/// The Multi Map Observer merge different maps into one observer
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct MultiMapObserver<'a, T, const DIFFERENTIAL: bool>
where
    T: 'static + Default + Copy + Serialize + Debug,
{
    maps: Vec<OwnedMutSlice<'a, T>>,
    intervals: IntervalTree<usize, usize>,
    len: usize,
    initial: T,
    name: Cow<'static, str>,
    iter_idx: usize,
}

impl<'a, S, T> Observer<S> for MultiMapObserver<'a, T, false>
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

impl<'a, S, T> Observer<S> for MultiMapObserver<'a, T, true>
where
    S: UsesInput,
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
    Self: MapObserver,
{
    // in differential mode, we are *not* responsible for resetting the map!
}

impl<'a, T, const DIFFERENTIAL: bool> Named for MultiMapObserver<'a, T, DIFFERENTIAL>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<'a, T, const DIFFERENTIAL: bool> HasLen for MultiMapObserver<'a, T, DIFFERENTIAL>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[inline]
    fn len(&self) -> usize {
        self.len
    }
}

impl<'a, T, const DIFFERENTIAL: bool> Hash for MultiMapObserver<'a, T, DIFFERENTIAL>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        for map in &self.maps {
            let slice = map.as_slice();
            let ptr = slice.as_ptr() as *const u8;
            let map_size = slice.len() / size_of::<T>();
            unsafe {
                hasher.write(slice::from_raw_parts(ptr, map_size));
            }
        }
    }
}

impl<'a, T, const DIFFERENTIAL: bool> AsRef<Self> for MultiMapObserver<'a, T, DIFFERENTIAL>
where
    T: 'static + Default + Copy + Serialize + Debug,
{
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'a, T, const DIFFERENTIAL: bool> AsMut<Self> for MultiMapObserver<'a, T, DIFFERENTIAL>
where
    T: 'static + Default + Copy + Serialize + Debug,
{
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl<'a, T, const DIFFERENTIAL: bool> MapObserver for MultiMapObserver<'a, T, DIFFERENTIAL>
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
    fn get(&self, idx: usize) -> T {
        let elem = self.intervals.query(idx..=idx).next().unwrap();
        let i = *elem.value;
        let j = idx - elem.interval.start;
        self.maps[i].as_slice()[j]
    }

    #[inline]
    fn set(&mut self, idx: usize, val: Self::Entry) {
        let elem = self.intervals.query(idx..=idx).next().unwrap();
        let i = *elem.value;
        let j = idx - elem.interval.start;
        self.maps[i].as_slice_mut()[j] = val;
    }

    #[inline]
    fn initial(&self) -> T {
        self.initial
    }

    fn count_bytes(&self) -> u64 {
        let initial = self.initial();
        let mut res = 0;
        for map in &self.maps {
            for x in map.as_slice() {
                if *x != initial {
                    res += 1;
                }
            }
        }
        res
    }

    #[inline]
    fn hash_simple(&self) -> u64 {
        RandomState::with_seeds(0, 0, 0, 0).hash_one(self)
    }

    fn reset_map(&mut self) -> Result<(), Error> {
        let initial = self.initial();
        for map in &mut self.maps {
            for x in map.as_slice_mut() {
                *x = initial;
            }
        }
        Ok(())
    }

    fn usable_count(&self) -> usize {
        self.len()
    }

    fn to_vec(&self) -> Vec<Self::Entry> {
        let cnt = self.usable_count();
        let mut res = Vec::with_capacity(cnt);
        for i in 0..cnt {
            res.push(self.get(i));
        }
        res
    }

    /// Get the number of set entries with the specified indexes
    fn how_many_set(&self, indexes: &[usize]) -> usize {
        let initial = self.initial();
        let cnt = self.usable_count();
        let mut res = 0;
        for i in indexes {
            if *i < cnt && self.get(*i) != initial {
                res += 1;
            }
        }
        res
    }
}

impl<'a, T, const DIFFERENTIAL: bool> MultiMapObserver<'a, T, DIFFERENTIAL>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    /// Creates a new [`MultiMapObserver`], maybe in differential mode
    #[must_use]
    fn maybe_differential(name: &'static str, maps: Vec<OwnedMutSlice<'a, T>>) -> Self {
        let mut idx = 0;
        let mut intervals = IntervalTree::new();
        for (v, x) in maps.iter().enumerate() {
            let l = x.as_slice().len();
            intervals.insert(idx..(idx + l), v);
            idx += l;
        }
        Self {
            maps,
            intervals,
            len: idx,
            name: Cow::from(name),
            initial: T::default(),
            iter_idx: 0,
        }
    }
}

impl<'a, T> MultiMapObserver<'a, T, true>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    /// Creates a new [`MultiMapObserver`] in differential mode
    #[must_use]
    pub fn differential(name: &'static str, maps: Vec<OwnedMutSlice<'a, T>>) -> Self {
        Self::maybe_differential(name, maps)
    }
}

impl<'a, T> MultiMapObserver<'a, T, false>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    /// Creates a new [`MultiMapObserver`]
    #[must_use]
    pub fn new(name: &'static str, maps: Vec<OwnedMutSlice<'a, T>>) -> Self {
        Self::maybe_differential(name, maps)
    }

    /// Creates a new [`MultiMapObserver`] with an owned map
    #[must_use]
    pub fn owned(name: &'static str, maps: Vec<Vec<T>>) -> Self {
        let mut idx = 0;
        let mut v = 0;
        let mut intervals = IntervalTree::new();
        let maps: Vec<_> = maps
            .into_iter()
            .map(|x| {
                let l = x.len();
                intervals.insert(idx..(idx + l), v);
                idx += l;
                v += 1;
                OwnedMutSlice::from(x)
            })
            .collect();
        Self {
            maps,
            intervals,
            len: idx,
            name: Cow::from(name),
            initial: T::default(),
            iter_idx: 0,
        }
    }
}

impl<'a, 'it, T, const DIFFERENTIAL: bool> AsIter<'it> for MultiMapObserver<'a, T, DIFFERENTIAL>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
    'a: 'it,
{
    type Item = T;
    type Ref = &'it T;
    type IntoIter = Flatten<Iter<'it, OwnedMutSlice<'a, T>>>;

    fn as_iter(&'it self) -> Self::IntoIter {
        self.maps.iter().flatten()
    }
}

impl<'a, 'it, T, const DIFFERENTIAL: bool> AsIterMut<'it> for MultiMapObserver<'a, T, DIFFERENTIAL>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
    'a: 'it,
{
    type RefMut = &'it mut T;
    type IntoIterMut = Flatten<IterMut<'it, OwnedMutSlice<'a, T>>>;

    fn as_iter_mut(&'it mut self) -> Self::IntoIterMut {
        self.maps.iter_mut().flatten()
    }
}

impl<'a, 'it, T, const DIFFERENTIAL: bool> IntoIterator
    for &'it MultiMapObserver<'a, T, DIFFERENTIAL>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Item = <Iter<'it, T> as Iterator>::Item;
    type IntoIter = Flatten<Iter<'it, OwnedMutSlice<'a, T>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.maps.iter().flatten()
    }
}

impl<'a, 'it, T, const DIFFERENTIAL: bool> IntoIterator
    for &'it mut MultiMapObserver<'a, T, DIFFERENTIAL>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Item = <IterMut<'it, T> as Iterator>::Item;
    type IntoIter = Flatten<IterMut<'it, OwnedMutSlice<'a, T>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.maps.iter_mut().flatten()
    }
}

impl<'a, T, const DIFFERENTIAL: bool> MultiMapObserver<'a, T, DIFFERENTIAL>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    /// Returns an iterator over the map.
    pub fn iter(&self) -> <&Self as IntoIterator>::IntoIter {
        <&Self as IntoIterator>::into_iter(self)
    }

    /// Returns a mutable iterator over the map.
    pub fn iter_mut(&mut self) -> <&mut Self as IntoIterator>::IntoIter {
        <&mut Self as IntoIterator>::into_iter(self)
    }
}

impl<'a, T, OTA, OTB, S> DifferentialObserver<OTA, OTB, S> for MultiMapObserver<'a, T, true>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
    Self: MapObserver,
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
}
