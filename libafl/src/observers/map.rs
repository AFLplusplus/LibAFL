//! The `MapObserver` provides access a map, usually injected into the target

use ahash::AHasher;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt::Debug,
    hash::Hasher,
    iter::Flatten,
    marker::PhantomData,
    slice::{from_raw_parts, Iter, IterMut},
};
use intervaltree::IntervalTree;
use num_traits::Bounded;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{
        ownedref::{OwnedRefMut, OwnedSliceMut},
        tuples::Named,
        AsMutIterator, AsMutSlice, AsRefIterator, AsSlice, HasLen,
    },
    executors::ExitKind,
    observers::Observer,
    Error,
};

/// Compute the hash of a slice
fn hash_slice<T>(slice: &[T]) -> u64 {
    let mut hasher = AHasher::new_with_keys(0, 0);
    let ptr = slice.as_ptr() as *const u8;
    let map_size = slice.len() / core::mem::size_of::<T>();
    unsafe {
        hasher.write(from_raw_parts(ptr, map_size));
    }
    hasher.finish()
}

/// A [`MapObserver`] observes the static map, as oftentimes used for AFL-like coverage information
///
/// TODO: enforce `iter() -> AssociatedTypeIter` when generic associated types stabilize
pub trait MapObserver: HasLen + Named + Serialize + serde::de::DeserializeOwned + Debug
// where
//     for<'it> &'it Self: IntoIterator<Item = &'it Self::Entry>
{
    /// Type of each entry in this map
    type Entry: Bounded + PartialEq + Default + Copy + Debug + 'static;

    /// Get the value at `idx`
    fn get(&self, idx: usize) -> &Self::Entry;

    /// Get the value at `idx` (mutable)
    fn get_mut(&mut self, idx: usize) -> &mut Self::Entry;

    /// Get the number of usable entries in the map (all by default)
    fn usable_count(&self) -> usize;

    /// Count the set bytes in the map
    fn count_bytes(&self) -> u64 {
        let initial = self.initial();
        let cnt = self.usable_count();
        let mut res = 0;
        for i in 0..cnt {
            if *self.get(i) != initial {
                res += 1;
            }
        }
        res
    }

    /// Compute the hash of the map
    fn hash(&self) -> u64;

    /// Get the initial value for reset()
    fn initial(&self) -> Self::Entry;

    /// Get the initial value for reset() (mutable)
    fn initial_mut(&mut self) -> &mut Self::Entry;

    /// Set the initial value for reset()
    fn set_initial(&mut self, initial: Self::Entry) {
        *self.initial_mut() = initial;
    }

    /// Reset the map
    #[inline]
    fn reset_map(&mut self) -> Result<(), Error> {
        // Normal memset, see https://rust.godbolt.org/z/Trs5hv
        let initial = self.initial();
        let cnt = self.usable_count();
        for i in 0..cnt {
            *self.get_mut(i) = initial;
        }
        Ok(())
    }

    /// Get these observer's contents as [`Vec`]
    fn to_vec(&self) -> Vec<Self::Entry> {
        let cnt = self.usable_count();
        let mut res = Vec::with_capacity(cnt);
        for i in 0..cnt {
            res.push(*self.get(i));
        }
        res
    }

    /// Get the number of set entries with the specified indexes
    fn how_many_set(&self, indexes: &[usize]) -> usize {
        let initial = self.initial();
        let cnt = self.usable_count();
        let mut res = 0;
        for i in indexes {
            if *i < cnt && *self.get(*i) != initial {
                res += 1;
            }
        }
        res
    }
}

/// A Simple iterator calling `MapObserver::get`
#[derive(Debug)]
pub struct MapObserverSimpleIterator<'a, O>
where
    O: 'a + MapObserver,
{
    index: usize,
    observer: *const O,
    phantom: PhantomData<&'a u8>,
}

impl<'a, O> Iterator for MapObserverSimpleIterator<'a, O>
where
    O: 'a + MapObserver,
{
    type Item = &'a O::Entry;
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if self.index >= self.observer.as_ref().unwrap().usable_count() {
                None
            } else {
                let i = self.index;
                self.index += 1;
                Some(self.observer.as_ref().unwrap().get(i))
            }
        }
    }
}

/// A Simple iterator calling `MapObserver::get_mut`
#[derive(Debug)]
pub struct MapObserverSimpleIteratoMut<'a, O>
where
    O: 'a + MapObserver,
{
    index: usize,
    observer: *mut O,
    phantom: PhantomData<&'a u8>,
}

impl<'a, O> Iterator for MapObserverSimpleIteratoMut<'a, O>
where
    O: 'a + MapObserver,
{
    type Item = &'a O::Entry;
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if self.index >= self.observer.as_ref().unwrap().usable_count() {
                None
            } else {
                let i = self.index;
                self.index += 1;
                Some(self.observer.as_mut().unwrap().get_mut(i))
            }
        }
    }
}

/// The Map Observer retrieves the state of a map,
/// that will get updated by the target.
/// A well-known example is the AFL-Style coverage map.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct StdMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize,
{
    map: OwnedSliceMut<'a, T>,
    initial: T,
    name: String,
}

impl<'a, I, S, T> Observer<I, S> for StdMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, T> Named for StdMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<'a, T> HasLen for StdMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn len(&self) -> usize {
        self.map.as_slice().len()
    }
}

impl<'a, 'it, T> AsRefIterator<'it> for StdMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Item = T;
    type IntoIter = Iter<'it, T>;

    fn as_ref_iter(&'it self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_slice()[..cnt].iter()
    }
}

impl<'a, 'it, T> AsMutIterator<'it> for StdMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Item = T;
    type IntoIter = IterMut<'it, T>;

    fn as_mut_iter(&'it mut self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_mut_slice()[..cnt].iter_mut()
    }
}

impl<'a, 'it, T> IntoIterator for &'it StdMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
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

impl<'a, 'it, T> IntoIterator for &'it mut StdMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Item = <IterMut<'it, T> as Iterator>::Item;
    type IntoIter = IterMut<'it, T>;

    fn into_iter(self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_mut_slice()[..cnt].iter_mut()
    }
}

impl<'a, T> MapObserver for StdMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Entry = T;

    #[inline]
    fn get(&self, pos: usize) -> &T {
        &self.as_slice()[pos]
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> &mut T {
        &mut self.as_mut_slice()[idx]
    }

    #[inline]
    fn usable_count(&self) -> usize {
        self.as_slice().len()
    }

    fn hash(&self) -> u64 {
        hash_slice(self.as_slice())
    }

    #[inline]
    fn initial(&self) -> T {
        self.initial
    }

    #[inline]
    fn initial_mut(&mut self) -> &mut T {
        &mut self.initial
    }

    fn to_vec(&self) -> Vec<T> {
        self.as_slice().to_vec()
    }
}

impl<'a, T> AsSlice<T> for StdMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[must_use]
    #[inline]
    fn as_slice(&self) -> &[T] {
        self.map.as_slice()
    }
}
impl<'a, T> AsMutSlice<T> for StdMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[must_use]
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [T] {
        self.map.as_mut_slice()
    }
}

impl<'a, T> StdMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`]
    #[must_use]
    pub fn new<S>(name: S, map: &'a mut [T]) -> Self
    where
        S: Into<String>,
    {
        Self {
            map: OwnedSliceMut::from(map),
            name: name.into(),
            initial: T::default(),
        }
    }

    /// Creates a new [`MapObserver`] with an owned map
    #[must_use]
    pub fn new_owned<S>(name: S, map: Vec<T>) -> Self
    where
        S: Into<String>,
    {
        Self {
            map: OwnedSliceMut::from(map),
            name: name.into(),
            initial: T::default(),
        }
    }

    /// Creates a new [`MapObserver`] from an [`OwnedSliceMut`] map.
    ///
    /// # Safety
    /// Will dereference the owned slice with up to len elements.
    #[must_use]
    pub fn new_from_ownedref<S>(name: S, map: OwnedSliceMut<'a, T>) -> Self
    where
        S: Into<String>,
    {
        Self {
            map,
            name: name.into(),
            initial: T::default(),
        }
    }

    /// Creates a new [`MapObserver`] from a raw pointer
    ///
    /// # Safety
    /// Will dereference the `map_ptr` with up to len elements.
    pub unsafe fn new_from_ptr<S>(name: S, map_ptr: *mut T, len: usize) -> Self
    where
        S: Into<String>,
    {
        StdMapObserver {
            map: OwnedSliceMut::from_raw_parts_mut(map_ptr, len),
            name: name.into(),
            initial: T::default(),
        }
    }
}

/// Use a const size to speedup `Feedback::is_interesting` when the user can
/// know the size of the map at compile time.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct ConstMapObserver<'a, T, const N: usize>
where
    T: Default + Copy + 'static + Serialize,
{
    map: OwnedSliceMut<'a, T>,
    initial: T,
    name: String,
}

impl<'a, I, S, T, const N: usize> Observer<I, S> for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
    Self: MapObserver,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, T, const N: usize> Named for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
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

impl<'a, 'it, T, const N: usize> AsRefIterator<'it> for ConstMapObserver<'a, T, N>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Item = T;
    type IntoIter = Iter<'it, T>;

    fn as_ref_iter(&'it self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_slice()[..cnt].iter()
    }
}

impl<'a, 'it, T, const N: usize> AsMutIterator<'it> for ConstMapObserver<'a, T, N>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Item = T;
    type IntoIter = IterMut<'it, T>;

    fn as_mut_iter(&'it mut self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_mut_slice()[..cnt].iter_mut()
    }
}

impl<'a, 'it, T, const N: usize> IntoIterator for &'it ConstMapObserver<'a, T, N>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
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
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Item = <IterMut<'it, T> as Iterator>::Item;
    type IntoIter = IterMut<'it, T>;

    fn into_iter(self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_mut_slice()[..cnt].iter_mut()
    }
}

impl<'a, T, const N: usize> MapObserver for ConstMapObserver<'a, T, N>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
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
    fn initial_mut(&mut self) -> &mut T {
        &mut self.initial
    }

    #[inline]
    fn get(&self, idx: usize) -> &T {
        &self.as_slice()[idx]
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> &mut T {
        &mut self.as_mut_slice()[idx]
    }

    fn usable_count(&self) -> usize {
        self.as_slice().len()
    }

    fn hash(&self) -> u64 {
        hash_slice(self.as_slice())
    }

    fn to_vec(&self) -> Vec<T> {
        self.as_slice().to_vec()
    }
}

impl<'a, T, const N: usize> AsSlice<T> for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[inline]
    fn as_slice(&self) -> &[T] {
        self.map.as_slice()
    }
}
impl<'a, T, const N: usize> AsMutSlice<T> for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [T] {
        self.map.as_mut_slice()
    }
}

impl<'a, T, const N: usize> ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`]
    #[must_use]
    pub fn new(name: &'static str, map: &'a mut [T]) -> Self {
        assert!(map.len() >= N);
        Self {
            map: OwnedSliceMut::from(map),
            name: name.to_string(),
            initial: T::default(),
        }
    }

    /// Creates a new [`MapObserver`] with an owned map
    #[must_use]
    pub fn new_owned(name: &'static str, map: Vec<T>) -> Self {
        assert!(map.len() >= N);
        let initial = if map.is_empty() { T::default() } else { map[0] };
        Self {
            map: OwnedSliceMut::from(map),
            name: name.to_string(),
            initial,
        }
    }

    /// Creates a new [`MapObserver`] from a raw pointer
    ///
    /// # Safety
    /// Will dereference the `map_ptr` with up to len elements.
    pub unsafe fn new_from_ptr(name: &'static str, map_ptr: *mut T) -> Self {
        ConstMapObserver {
            map: OwnedSliceMut::from_raw_parts_mut(map_ptr, N),
            name: name.to_string(),
            initial: T::default(),
        }
    }
}

/// Overlooking a variable bitmap
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct VariableMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize,
{
    map: OwnedSliceMut<'a, T>,
    size: OwnedRefMut<'a, usize>,
    initial: T,
    name: String,
}

impl<'a, I, S, T> Observer<I, S> for VariableMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
    Self: MapObserver,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, T> Named for VariableMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<'a, T> HasLen for VariableMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn len(&self) -> usize {
        self.map.as_slice().len()
    }
}

impl<'a, 'it, T> AsRefIterator<'it> for VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Item = T;
    type IntoIter = Iter<'it, T>;

    fn as_ref_iter(&'it self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_slice()[..cnt].iter()
    }
}

impl<'a, 'it, T> AsMutIterator<'it> for VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Item = T;
    type IntoIter = IterMut<'it, T>;

    fn as_mut_iter(&'it mut self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_mut_slice()[..cnt].iter_mut()
    }
}

impl<'a, 'it, T> IntoIterator for &'it VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
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

impl<'a, 'it, T> IntoIterator for &'it mut VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Item = <IterMut<'it, T> as Iterator>::Item;
    type IntoIter = IterMut<'it, T>;

    fn into_iter(self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_mut_slice()[..cnt].iter_mut()
    }
}

impl<'a, T> MapObserver for VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
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
    fn initial_mut(&mut self) -> &mut T {
        &mut self.initial
    }

    #[inline]
    fn usable_count(&self) -> usize {
        *self.size.as_ref()
    }

    fn get(&self, idx: usize) -> &T {
        &self.map.as_slice()[idx]
    }

    fn get_mut(&mut self, idx: usize) -> &mut T {
        &mut self.map.as_mut_slice()[idx]
    }

    fn hash(&self) -> u64 {
        hash_slice(self.as_slice())
    }
    fn to_vec(&self) -> Vec<T> {
        self.as_slice().to_vec()
    }
}

impl<'a, T> AsSlice<T> for VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    #[inline]
    fn as_slice(&self) -> &[T] {
        let cnt = self.usable_count();
        &self.map.as_slice()[..cnt]
    }
}
impl<'a, T> AsMutSlice<T> for VariableMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [T] {
        self.map.as_mut_slice()
    }
}

impl<'a, T> VariableMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`]
    pub fn new(name: &'static str, map: &'a mut [T], size: &'a mut usize) -> Self {
        Self {
            map: OwnedSliceMut::from(map),
            size: OwnedRefMut::Ref(size),
            name: name.into(),
            initial: T::default(),
        }
    }

    /// Creates a new [`MapObserver`] from a raw pointer
    ///
    /// # Safety
    /// Dereferences `map_ptr` with up to `max_len` elements of size.
    pub unsafe fn new_from_ptr(
        name: &'static str,
        map_ptr: *mut T,
        max_len: usize,
        size: &'a mut usize,
    ) -> Self {
        VariableMapObserver {
            map: OwnedSliceMut::from_raw_parts_mut(map_ptr, max_len),
            size: OwnedRefMut::Ref(size),
            name: name.into(),
            initial: T::default(),
        }
    }
}

/// Map observer with hitcounts postprocessing
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "M: serde::de::DeserializeOwned")]
pub struct HitcountsMapObserver<M>
where
    M: Serialize,
{
    base: M,
}

static COUNT_CLASS_LOOKUP: [u8; 256] = [
    0, 1, 2, 4, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
];

impl<I, S, M> Observer<I, S> for HitcountsMapObserver<M>
where
    M: MapObserver<Entry = u8> + Observer<I, S>,
    for<'it> M: AsMutIterator<'it, Item = u8>,
{
    #[inline]
    fn pre_exec(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        self.base.pre_exec(state, input)
    }

    #[inline]
    fn post_exec(&mut self, state: &mut S, input: &I, exit_kind: &ExitKind) -> Result<(), Error> {
        for elem in self.as_mut_iter() {
            *elem = COUNT_CLASS_LOOKUP[*elem as usize];
        }
        self.base.post_exec(state, input, exit_kind)
    }
}

impl<M> Named for HitcountsMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.base.name()
    }
}

impl<M> HasLen for HitcountsMapObserver<M>
where
    M: MapObserver,
{
    #[inline]
    fn len(&self) -> usize {
        self.base.len()
    }
}

impl<M> MapObserver for HitcountsMapObserver<M>
where
    M: MapObserver<Entry = u8>,
    for<'it> M: AsMutIterator<'it, Item = u8>,
{
    type Entry = u8;

    #[inline]
    fn initial(&self) -> u8 {
        self.base.initial()
    }

    #[inline]
    fn initial_mut(&mut self) -> &mut u8 {
        self.base.initial_mut()
    }

    #[inline]
    fn usable_count(&self) -> usize {
        self.base.usable_count()
    }

    #[inline]
    fn get(&self, idx: usize) -> &u8 {
        self.base.get(idx)
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> &mut u8 {
        self.base.get_mut(idx)
    }

    fn hash(&self) -> u64 {
        self.base.hash()
    }
    fn to_vec(&self) -> Vec<u8> {
        self.base.to_vec()
    }
}

impl<M> AsSlice<u8> for HitcountsMapObserver<M>
where
    M: MapObserver + AsSlice<u8>,
{
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.base.as_slice()
    }
}
impl<M> AsMutSlice<u8> for HitcountsMapObserver<M>
where
    M: MapObserver + AsMutSlice<u8>,
{
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.base.as_mut_slice()
    }
}

impl<M> HitcountsMapObserver<M>
where
    M: Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`]
    pub fn new(base: M) -> Self {
        Self { base }
    }
}

impl<'it, M> AsRefIterator<'it> for HitcountsMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + AsRefIterator<'it, Item = u8>,
{
    type Item = u8;
    type IntoIter = <M as AsRefIterator<'it>>::IntoIter;

    fn as_ref_iter(&'it self) -> Self::IntoIter {
        self.base.as_ref_iter()
    }
}

impl<'it, M> AsMutIterator<'it> for HitcountsMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + AsMutIterator<'it, Item = u8>,
{
    type Item = u8;
    type IntoIter = <M as AsMutIterator<'it>>::IntoIter;

    fn as_mut_iter(&'it mut self) -> Self::IntoIter {
        self.base.as_mut_iter()
    }
}

impl<'it, M> IntoIterator for &'it HitcountsMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned,
    &'it M: IntoIterator<Item = &'it u8>,
{
    type Item = &'it u8;
    type IntoIter = <&'it M as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.base.into_iter()
    }
}

impl<'it, M> IntoIterator for &'it mut HitcountsMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned,
    &'it mut M: IntoIterator<Item = &'it mut u8>,
{
    type Item = &'it mut u8;
    type IntoIter = <&'it mut M as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.base.into_iter()
    }
}

/// The Multi Map Observer merge different maps into one observer
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct MultiMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + Debug,
{
    maps: Vec<OwnedSliceMut<'a, T>>,
    intervals: IntervalTree<usize, usize>,
    len: usize,
    initial: T,
    name: String,
    iter_idx: usize,
}

impl<'a, I, S, T> Observer<I, S> for MultiMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
    Self: MapObserver,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, T> Named for MultiMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<'a, T> HasLen for MultiMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[inline]
    fn len(&self) -> usize {
        self.len
    }
}

impl<'a, T> MapObserver for MultiMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Entry = T;

    #[inline]
    fn get(&self, idx: usize) -> &T {
        let elem = self.intervals.query_point(idx).next().unwrap();
        let i = elem.value;
        let j = idx - elem.range.start;
        &self.maps[i].as_slice()[j]
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> &mut T {
        let elem = self.intervals.query_point(idx).next().unwrap();
        let i = elem.value;
        let j = idx - elem.range.start;
        &mut self.maps[i].as_mut_slice()[j]
    }

    #[inline]
    fn initial(&self) -> T {
        self.initial
    }

    #[inline]
    fn initial_mut(&mut self) -> &mut T {
        &mut self.initial
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

    fn hash(&self) -> u64 {
        let mut hasher = AHasher::new_with_keys(0, 0);
        for map in &self.maps {
            let slice = map.as_slice();
            let ptr = slice.as_ptr() as *const u8;
            let map_size = slice.len() / core::mem::size_of::<T>();
            unsafe {
                hasher.write(from_raw_parts(ptr, map_size));
            }
        }
        hasher.finish()
    }

    fn reset_map(&mut self) -> Result<(), Error> {
        let initial = self.initial();
        for map in &mut self.maps {
            for x in map.as_mut_slice() {
                *x = initial;
            }
        }
        Ok(())
    }

    fn usable_count(&self) -> usize {
        self.len()
    }
}

impl<'a, T> MultiMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    /// Creates a new [`MultiMapObserver`]
    #[must_use]
    pub fn new(name: &'static str, maps: &'a mut [&'a mut [T]]) -> Self {
        let mut idx = 0;
        let mut v = 0;
        let mut builder = vec![];
        let maps: Vec<_> = maps
            .iter_mut()
            .map(|x| {
                let l = x.len();
                let r = (idx..(idx + l), v);
                idx += l;
                builder.push(r);
                v += 1;
                OwnedSliceMut::from(x)
            })
            .collect();
        Self {
            maps,
            intervals: builder.into_iter().collect::<IntervalTree<usize, usize>>(),
            len: idx,
            name: name.to_string(),
            initial: T::default(),
            iter_idx: 0,
        }
    }

    /// Creates a new [`MultiMapObserver`] with an owned map
    #[must_use]
    pub fn new_owned(name: &'static str, maps: Vec<Vec<T>>) -> Self {
        let mut idx = 0;
        let mut v = 0;
        let mut builder = vec![];
        let maps: Vec<_> = maps
            .into_iter()
            .map(|x| {
                let l = x.len();
                let r = (idx..(idx + l), v);
                idx += l;
                builder.push(r);
                v += 1;
                OwnedSliceMut::from(x)
            })
            .collect();
        Self {
            maps,
            intervals: builder.into_iter().collect::<IntervalTree<usize, usize>>(),
            len: idx,
            name: name.to_string(),
            initial: T::default(),
            iter_idx: 0,
        }
    }
}

impl<'a, 'it, T> AsRefIterator<'it> for MultiMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
    'a: 'it,
{
    type Item = T;
    type IntoIter = Flatten<Iter<'it, OwnedSliceMut<'a, T>>>;

    fn as_ref_iter(&'it self) -> Self::IntoIter {
        self.maps.iter().flatten()
    }
}

impl<'a, 'it, T> AsMutIterator<'it> for MultiMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
    'a: 'it,
{
    type Item = T;
    type IntoIter = Flatten<IterMut<'it, OwnedSliceMut<'a, T>>>;

    fn as_mut_iter(&'it mut self) -> Self::IntoIter {
        self.maps.iter_mut().flatten()
    }
}

impl<'a, 'it, T> IntoIterator for &'it MultiMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Item = <Iter<'it, T> as Iterator>::Item;
    type IntoIter = Flatten<Iter<'it, OwnedSliceMut<'a, T>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.maps.iter().flatten()
    }
}

impl<'a, 'it, T> IntoIterator for &'it mut MultiMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Item = <IterMut<'it, T> as Iterator>::Item;
    type IntoIter = Flatten<IterMut<'it, OwnedSliceMut<'a, T>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.maps.iter_mut().flatten()
    }
}

/// Exact copy of `StdMapObserver` that owns its map
/// Used for python bindings
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct OwnedMapObserver<T>
where
    T: Default + Copy + 'static + Serialize,
{
    map: Vec<T>,
    initial: T,
    name: String,
}

impl<I, S, T> Observer<I, S> for OwnedMapObserver<T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
    Self: MapObserver,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<T> Named for OwnedMapObserver<T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<T> HasLen for OwnedMapObserver<T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn len(&self) -> usize {
        self.map.as_slice().len()
    }
}

impl<'it, T> AsRefIterator<'it> for OwnedMapObserver<T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Item = T;
    type IntoIter = Iter<'it, T>;

    fn as_ref_iter(&'it self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<'it, T> AsMutIterator<'it> for OwnedMapObserver<T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Item = T;
    type IntoIter = IterMut<'it, T>;

    fn as_mut_iter(&'it mut self) -> Self::IntoIter {
        self.as_mut_slice().iter_mut()
    }
}

impl<'it, T> IntoIterator for &'it OwnedMapObserver<T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Item = <Iter<'it, T> as Iterator>::Item;
    type IntoIter = Iter<'it, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<'it, T> IntoIterator for &'it mut OwnedMapObserver<T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Item = <IterMut<'it, T> as Iterator>::Item;
    type IntoIter = IterMut<'it, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_mut_slice().iter_mut()
    }
}

impl<T> MapObserver for OwnedMapObserver<T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Entry = T;

    #[inline]
    fn get(&self, pos: usize) -> &T {
        &self.as_slice()[pos]
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> &mut T {
        &mut self.as_mut_slice()[idx]
    }

    #[inline]
    fn usable_count(&self) -> usize {
        self.as_slice().len()
    }

    fn hash(&self) -> u64 {
        hash_slice(self.as_slice())
    }

    #[inline]
    fn initial(&self) -> T {
        self.initial
    }

    #[inline]
    fn initial_mut(&mut self) -> &mut T {
        &mut self.initial
    }

    #[inline]
    fn set_initial(&mut self, initial: T) {
        self.initial = initial;
    }

    fn to_vec(&self) -> Vec<T> {
        self.as_slice().to_vec()
    }
}

impl<T> AsSlice<T> for OwnedMapObserver<T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[must_use]
    #[inline]
    fn as_slice(&self) -> &[T] {
        self.map.as_slice()
    }
}
impl<T> AsMutSlice<T> for OwnedMapObserver<T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[must_use]
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [T] {
        self.map.as_mut_slice()
    }
}

impl<T> OwnedMapObserver<T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`] with an owned map
    #[must_use]
    pub fn new(name: &'static str, map: Vec<T>) -> Self {
        let initial = if map.is_empty() { T::default() } else { map[0] };
        Self {
            map,
            name: name.to_string(),
            initial,
        }
    }
}

/// `MapObserver` Python bindings
#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use super::*;
    use crate::observers::pybind::PythonObserver;
    use concat_idents::concat_idents;
    use pyo3::prelude::*;
    use serde::{Deserialize, Serialize};

    #[macro_export]
    macro_rules! mapob_unwrap_me {
        ($wrapper_name:ident, $wrapper:expr, $name:ident, $body:block) => {
            match &$wrapper {
                $wrapper_name::Std(py_wrapper) => Python::with_gil(|py| -> PyResult<_> {
                    let borrowed = py_wrapper.borrow(py);
                    let $name = &borrowed.inner;
                    Ok($body)
                })
                .unwrap(),
                $wrapper_name::Owned(py_wrapper) => Python::with_gil(|py| -> PyResult<_> {
                    let borrowed = py_wrapper.borrow(py);
                    let $name = &borrowed.inner;
                    Ok($body)
                })
                .unwrap(),
                $wrapper_name::None => panic!("Serde is not supported ATM"),
            }
        };
    }

    #[macro_export]
    macro_rules! mapob_unwrap_me_mut {
        ($wrapper_name:ident, $wrapper:expr, $name:ident, $body:block) => {
            match &mut $wrapper {
                $wrapper_name::Std(py_wrapper) => Python::with_gil(|py| -> PyResult<_> {
                    let mut borrowed = py_wrapper.borrow_mut(py);
                    let $name = &mut borrowed.inner;
                    Ok($body)
                })
                .unwrap(),
                $wrapper_name::Owned(py_wrapper) => Python::with_gil(|py| -> PyResult<_> {
                    let mut borrowed = py_wrapper.borrow_mut(py);
                    let $name = &mut borrowed.inner;
                    Ok($body)
                })
                .unwrap(),
                $wrapper_name::None => panic!("Serde is not supported ATM"),
            }
        };
    }

    macro_rules! define_python_map_observer {
        ($struct_name1:ident, $py_name1:tt, $struct_name2:ident, $py_name2:tt, $struct_name_trait:ident, $py_name_trait:tt, $datatype:ty, $wrapper_name: ident) => {
            #[pyclass(unsendable, name = $py_name1)]
            #[derive(Serialize, Deserialize, Debug, Clone)]
            /// Python class for StdMapObserver
            pub struct $struct_name1 {
                /// Rust wrapped StdMapObserver object
                pub inner: StdMapObserver<'static, $datatype>,
            }

            #[pymethods]
            impl $struct_name1 {
                #[new]
                fn new(name: String, ptr: usize, size: usize) -> Self {
                    Self {
                        inner: unsafe { StdMapObserver::new_from_ptr(name, ptr as *mut $datatype, size) }
                    }
                }

                pub fn as_map_observer(slf: Py<Self>) -> $struct_name_trait {
                    $struct_name_trait::new_std(slf)
                }

                pub fn as_observer(slf: Py<Self>) -> PythonObserver {
                    let m = Self::as_map_observer(slf);
                    Python::with_gil(|py| -> PyResult<PythonObserver> {
                        let p: Py<_> = Py::new(py, m)?;
                        Ok($struct_name_trait::as_observer(p))
                    }).unwrap()
                }

                fn __getitem__(&self, idx: usize) -> $datatype {
                    *self.inner.get(idx)
                }

                fn __setitem__(&mut self, idx: usize, val: $datatype) {
                    *self.inner.get_mut(idx) = val;
                }

                #[pyo3(name = "usable_count")]
                fn pyusable_count(&self) -> usize {
                    self.inner.usable_count()
                }

                #[pyo3(name = "len")]
                fn pylen(&self) -> usize {
                    self.inner.len()
                }

                #[pyo3(name = "name")]
                fn pyname(&self) -> &str {
                    self.inner.name()
                }

            }

            #[pyclass(unsendable, name = $py_name2)]
            #[derive(Serialize, Deserialize, Debug, Clone)]
            /// Python class for OwnedMapObserver (i.e. StdMapObserver with owned map)
            pub struct $struct_name2 {
                /// Rust wrapped OwnedMapObserver object
                pub inner: OwnedMapObserver<$datatype>,
            }

            #[pymethods]
            impl $struct_name2 {
                #[new]
                fn new(name: String, map: Vec<$datatype>) -> Self {
                    Self {
                        //TODO: Not leak memory
                        inner: OwnedMapObserver::new(Box::leak(name.into_boxed_str()), map),
                    }
                }

                pub fn as_map_observer(slf: Py<Self>) -> $struct_name_trait {
                    $struct_name_trait::new_owned(slf)
                }

                pub fn as_observer(slf: Py<Self>) -> PythonObserver {
                    let m = Self::as_map_observer(slf);
                    Python::with_gil(|py| -> PyResult<PythonObserver> {
                        let p: Py<_> = Py::new(py, m)?;
                        Ok($struct_name_trait::as_observer(p))
                    }).unwrap()
                }

                fn __getitem__(&self, idx: usize) -> $datatype {
                    *self.inner.get(idx)
                }

                fn __setitem__(&mut self, idx: usize, val: $datatype) {
                    *self.inner.get_mut(idx) = val;
                }

                #[pyo3(name = "usable_count")]
                fn pyusable_count(&self) -> usize {
                    self.inner.usable_count()
                }

                #[pyo3(name = "len")]
                fn pylen(&self) -> usize {
                    self.inner.len()
                }

                #[pyo3(name = "name")]
                fn pyname(&self) -> &str {
                    self.inner.name()
                }
            }

            #[derive(Debug, Clone)]
            pub enum $wrapper_name {
                Std(Py<$struct_name1>),
                Owned(Py<$struct_name2>),
                None
            }

            impl Default for $wrapper_name {
                fn default() -> Self {
                    $wrapper_name::None
                }
            }

            // Should not be exposed to user
            #[pyclass(unsendable, name = $py_name_trait)]
            #[derive(Serialize, Deserialize, Debug, Clone)]
            /// MapObserver + Observer Trait binding
            pub struct $struct_name_trait {
                #[serde(skip)]
                pub wrapper: $wrapper_name,
            }

            #[pymethods]
            impl $struct_name_trait {
                #[staticmethod]
                fn new_std(std_map: Py<$struct_name1>) -> Self {
                    Self {
                        wrapper: $wrapper_name::Std(std_map),
                    }
                }

                #[staticmethod]
                fn new_owned(owned_map: Py<$struct_name2>) -> Self {
                    Self {
                        wrapper: $wrapper_name::Owned(owned_map),
                    }
                }

                pub fn as_observer(slf: Py<Self>) -> PythonObserver {
                    concat_idents!(func = new_map_,$datatype {
                           PythonObserver::func(slf)
                    })
                }

                fn __getitem__(&self, idx: usize) -> $datatype {
                    *self.get(idx)
                }

                fn __setitem__(&mut self, idx: usize, val: $datatype) {
                    *self.get_mut(idx) = val;
                }

                #[pyo3(name = "usable_count")]
                fn pyusable_count(&self) -> usize {
                    self.usable_count()
                }

                #[pyo3(name = "len")]
                fn pylen(&self) -> usize {
                    self.len()
                }

                #[pyo3(name = "name")]
                fn pyname(&self) -> &str {
                    self.name()
                }
            }

            impl<'it> AsRefIterator<'it> for $struct_name_trait {
                type Item = $datatype;
                type IntoIter = Iter<'it, $datatype>;

                fn as_ref_iter(&'it self) -> Self::IntoIter {
                    mapob_unwrap_me!($wrapper_name, self.wrapper, m, { unsafe { std::mem::transmute::<_, Self::IntoIter>(m.as_ref_iter()) } })
                }
            }

            impl<'it> AsMutIterator<'it> for $struct_name_trait {
                type Item = $datatype;
                type IntoIter = IterMut<'it, $datatype>;

                fn as_mut_iter(&'it mut self) -> Self::IntoIter {
                    mapob_unwrap_me_mut!($wrapper_name, self.wrapper, m, { unsafe { std::mem::transmute::<_, Self::IntoIter>(m.as_mut_iter()) } })
                }
            }

            impl MapObserver for $struct_name_trait {
                type Entry = $datatype;

                #[inline]
                fn get(&self, idx: usize) -> &$datatype {
                    let ptr = mapob_unwrap_me!($wrapper_name, self.wrapper, m, { m.get(idx) as *const $datatype });
                    unsafe { ptr.as_ref().unwrap() }
                }

                #[inline]
                fn get_mut(&mut self, idx: usize) -> &mut $datatype {
                    let ptr = mapob_unwrap_me_mut!($wrapper_name, self.wrapper, m, { m.get_mut(idx) as *mut $datatype });
                    unsafe { ptr.as_mut().unwrap() }
                }

                #[inline]
                fn usable_count(&self) -> usize {
                    mapob_unwrap_me!($wrapper_name, self.wrapper, m, { m.usable_count() })
                }

                fn hash(&self) -> u64 {
                    mapob_unwrap_me!($wrapper_name, self.wrapper, m, { m.hash() })
                }

                #[inline]
                fn initial(&self) -> $datatype {
                    mapob_unwrap_me!($wrapper_name, self.wrapper, m, { m.initial() })
                }

                #[inline]
                fn initial_mut(&mut self) -> &mut $datatype {
                    let ptr = mapob_unwrap_me_mut!($wrapper_name, self.wrapper, m, { m.initial_mut() as *mut $datatype });
                    unsafe { ptr.as_mut().unwrap() }
                }

                #[inline]
                fn set_initial(&mut self, initial: $datatype) {
                    mapob_unwrap_me_mut!($wrapper_name, self.wrapper, m, { m.set_initial(initial) });
                }

                fn to_vec(&self) -> Vec<$datatype> {
                    mapob_unwrap_me!($wrapper_name, self.wrapper, m, { m.to_vec() })
                }
            }

            impl Named for $struct_name_trait {
                #[inline]
                fn name(&self) -> &str {
                    let ptr = mapob_unwrap_me!($wrapper_name, self.wrapper, m, { m.name() as *const str });
                    unsafe { ptr.as_ref().unwrap() }
                }
            }

            impl HasLen for $struct_name_trait {
                #[inline]
                fn len(&self) -> usize {
                    mapob_unwrap_me!($wrapper_name, self.wrapper, m, { m.len() })
                }
            }

            impl<I, S> Observer<I, S> for $struct_name_trait
            where
                Self: MapObserver,
            {
                #[inline]
                fn pre_exec(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
                    mapob_unwrap_me_mut!($wrapper_name, self.wrapper, m, { m.pre_exec(state, input) })
                }
            }
        };
    }

    define_python_map_observer!(
        PythonStdMapObserverI8,
        "StdMapObserverI8",
        PythonOwnedMapObserverI8,
        "OwnedMapObserverI8",
        PythonMapObserverI8,
        "MapObserverI8",
        i8,
        PythonMapObserverWrapperI8
    );
    define_python_map_observer!(
        PythonStdMapObserverI16,
        "StdMapObserverI16",
        PythonOwnedMapObserverI16,
        "OwnedMapObserverI16",
        PythonMapObserverI16,
        "MapObserverI16",
        i16,
        PythonMapObserverWrapperI16
    );
    define_python_map_observer!(
        PythonStdMapObserverI32,
        "StdMapObserverI32",
        PythonOwnedMapObserverI32,
        "OwnedMapObserverI32",
        PythonMapObserverI32,
        "MapObserverI32",
        i32,
        PythonMapObserverWrapperI32
    );
    define_python_map_observer!(
        PythonStdMapObserverI64,
        "StdMapObserverI64",
        PythonOwnedMapObserverI64,
        "OwnedMapObserverI64",
        PythonMapObserverI64,
        "MapObserverI64",
        i64,
        PythonMapObserverWrapperI64
    );

    define_python_map_observer!(
        PythonStdMapObserverU8,
        "StdMapObserverU8",
        PythonOwnedMapObserverU8,
        "OwnedMapObserverU8",
        PythonMapObserverU8,
        "MapObserverU8",
        u8,
        PythonMapObserverWrapperU8
    );
    define_python_map_observer!(
        PythonStdMapObserverU16,
        "StdMapObserverU16",
        PythonOwnedMapObserverU16,
        "OwnedMapObserverU16",
        PythonMapObserverU16,
        "MapObserverU16",
        u16,
        PythonMapObserverWrapperU16
    );
    define_python_map_observer!(
        PythonStdMapObserverU32,
        "StdMapObserverU32",
        PythonOwnedMapObserverU32,
        "OwnedMapObserverU32",
        PythonMapObserverU32,
        "MapObserverU32",
        u32,
        PythonMapObserverWrapperU32
    );
    define_python_map_observer!(
        PythonStdMapObserverU64,
        "StdMapObserverU64",
        PythonOwnedMapObserverU64,
        "OwnedMapObserverU64",
        PythonMapObserverU64,
        "MapObserverU64",
        u64,
        PythonMapObserverWrapperU64
    );

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonStdMapObserverI8>()?;
        m.add_class::<PythonOwnedMapObserverI8>()?;
        m.add_class::<PythonMapObserverI8>()?;
        m.add_class::<PythonStdMapObserverI16>()?;
        m.add_class::<PythonOwnedMapObserverI16>()?;
        m.add_class::<PythonMapObserverI16>()?;
        m.add_class::<PythonStdMapObserverI32>()?;
        m.add_class::<PythonOwnedMapObserverI32>()?;
        m.add_class::<PythonMapObserverI32>()?;
        m.add_class::<PythonStdMapObserverI64>()?;
        m.add_class::<PythonOwnedMapObserverI64>()?;
        m.add_class::<PythonMapObserverI64>()?;

        m.add_class::<PythonStdMapObserverU8>()?;
        m.add_class::<PythonOwnedMapObserverU8>()?;
        m.add_class::<PythonMapObserverU8>()?;
        m.add_class::<PythonStdMapObserverU16>()?;
        m.add_class::<PythonOwnedMapObserverU16>()?;
        m.add_class::<PythonMapObserverU16>()?;
        m.add_class::<PythonStdMapObserverU32>()?;
        m.add_class::<PythonOwnedMapObserverU32>()?;
        m.add_class::<PythonMapObserverU32>()?;
        m.add_class::<PythonStdMapObserverU64>()?;
        m.add_class::<PythonOwnedMapObserverU64>()?;
        m.add_class::<PythonMapObserverU64>()?;
        Ok(())
    }
}
