//! The `MapObserver` provides access a map, usually injected into the target

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt::Debug,
    hash::{BuildHasher, Hasher},
    iter::Flatten,
    marker::PhantomData,
    mem::size_of,
    slice::{self, Iter, IterMut},
};

use ahash::RandomState;
use libafl_bolts::{
    ownedref::{OwnedMutPtr, OwnedMutSlice},
    AsIter, AsIterMut, AsMutSlice, AsSlice, HasLen, Named, Truncate,
};
use meminterval::IntervalTree;
use num_traits::Bounded;
use serde::{Deserialize, Serialize};

use crate::{
    executors::ExitKind,
    inputs::UsesInput,
    observers::{DifferentialObserver, Observer, ObserversTuple},
    Error,
};

/// Hitcounts class lookup
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

/// Hitcounts class lookup for 16-byte values
static mut COUNT_CLASS_LOOKUP_16: Vec<u16> = vec![];

/// Initialize the 16-byte hitcounts map
///
/// # Safety
///
/// Calling this from multiple threads may be racey and hence leak 65k mem
fn init_count_class_16() {
    unsafe {
        if !COUNT_CLASS_LOOKUP_16.is_empty() {
            return;
        }

        COUNT_CLASS_LOOKUP_16 = vec![0; 65536];
        for i in 0..256 {
            for j in 0..256 {
                COUNT_CLASS_LOOKUP_16[(i << 8) + j] =
                    (u16::from(COUNT_CLASS_LOOKUP[i]) << 8) | u16::from(COUNT_CLASS_LOOKUP[j]);
            }
        }
    }
}

/// Compute the hash of a slice
fn hash_slice<T>(slice: &[T]) -> u64 {
    let mut hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
    let ptr = slice.as_ptr() as *const u8;
    let map_size = slice.len() / size_of::<T>();
    unsafe {
        hasher.write(slice::from_raw_parts(ptr, map_size));
    }
    hasher.finish()
}

/// A [`MapObserver`] observes the static map, as oftentimes used for AFL-like coverage information
///
/// TODO: enforce `iter() -> AssociatedTypeIter` when generic associated types stabilize
pub trait MapObserver: HasLen + Named + Serialize + serde::de::DeserializeOwned
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
    fn count_bytes(&self) -> u64;

    /// Compute the hash of the map
    fn hash(&self) -> u64;

    /// Get the initial value for `reset()`
    fn initial(&self) -> Self::Entry;

    /// Reset the map
    fn reset_map(&mut self) -> Result<(), Error>;

    /// Get these observer's contents as [`Vec`]
    fn to_vec(&self) -> Vec<Self::Entry>;

    /// Get the number of set entries with the specified indexes
    fn how_many_set(&self, indexes: &[usize]) -> usize;
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
pub struct MapObserverSimpleIteratorMut<'a, O>
where
    O: 'a + MapObserver,
{
    index: usize,
    observer: *mut O,
    phantom: PhantomData<&'a u8>,
}

impl<'a, O> Iterator for MapObserverSimpleIteratorMut<'a, O>
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
pub struct StdMapObserver<'a, T, const DIFFERENTIAL: bool>
where
    T: Default + Copy + 'static + Serialize,
{
    map: OwnedMutSlice<'a, T>,
    initial: T,
    name: String,
}

impl<'a, S, T> Observer<S> for StdMapObserver<'a, T, false>
where
    S: UsesInput,
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
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, S, T> Observer<S> for StdMapObserver<'a, T, true>
where
    S: UsesInput,
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
}

impl<'a, T, const DIFFERENTIAL: bool> Named for StdMapObserver<'a, T, DIFFERENTIAL>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<'a, T, const DIFFERENTIAL: bool> HasLen for StdMapObserver<'a, T, DIFFERENTIAL>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn len(&self) -> usize {
        self.map.as_slice().len()
    }
}

impl<'a, 'it, T, const DIFFERENTIAL: bool> AsIter<'it> for StdMapObserver<'a, T, DIFFERENTIAL>
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

    fn as_iter(&'it self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_slice()[..cnt].iter()
    }
}

impl<'a, 'it, T, const DIFFERENTIAL: bool> AsIterMut<'it> for StdMapObserver<'a, T, DIFFERENTIAL>
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

    fn as_iter_mut(&'it mut self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_mut_slice()[..cnt].iter_mut()
    }
}

impl<'a, 'it, T, const DIFFERENTIAL: bool> IntoIterator for &'it StdMapObserver<'a, T, DIFFERENTIAL>
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

impl<'a, 'it, T, const DIFFERENTIAL: bool> IntoIterator
    for &'it mut StdMapObserver<'a, T, DIFFERENTIAL>
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

impl<'a, T, const DIFFERENTIAL: bool> StdMapObserver<'a, T, DIFFERENTIAL>
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
    /// Returns an iterator over the map.
    pub fn iter(&self) -> Iter<'_, T> {
        <&Self as IntoIterator>::into_iter(self)
    }

    /// Returns a mutable iterator over the map.
    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        <&mut Self as IntoIterator>::into_iter(self)
    }
}

impl<'a, T, const DIFFERENTIAL: bool> MapObserver for StdMapObserver<'a, T, DIFFERENTIAL>
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

    fn hash(&self) -> u64 {
        hash_slice(self.as_slice())
    }

    #[inline]
    fn initial(&self) -> T {
        self.initial
    }

    fn to_vec(&self) -> Vec<T> {
        self.as_slice().to_vec()
    }

    /// Reset the map
    #[inline]
    fn reset_map(&mut self) -> Result<(), Error> {
        // Normal memset, see https://rust.godbolt.org/z/Trs5hv
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = self.as_mut_slice();
        for x in &mut map[0..cnt] {
            *x = initial;
        }
        Ok(())
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

impl<'a, T, const DIFFERENTIAL: bool> Truncate for StdMapObserver<'a, T, DIFFERENTIAL>
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
    fn truncate(&mut self, new_len: usize) {
        self.map.truncate(new_len);
    }
}

impl<'a, T, const DIFFERENTIAL: bool> AsSlice for StdMapObserver<'a, T, DIFFERENTIAL>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Entry = T;
    #[must_use]
    #[inline]
    fn as_slice(&self) -> &[T] {
        self.map.as_slice()
    }
}
impl<'a, T, const DIFFERENTIAL: bool> AsMutSlice for StdMapObserver<'a, T, DIFFERENTIAL>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Entry = T;
    #[must_use]
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [T] {
        self.map.as_mut_slice()
    }
}

impl<'a, T, const DIFFERENTIAL: bool> StdMapObserver<'a, T, DIFFERENTIAL>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`]
    ///
    /// # Safety
    /// Will get a pointer to the map and dereference it at any point in time.
    /// The map must not move in memory!
    #[must_use]
    unsafe fn maybe_differential<S>(name: S, map: &'a mut [T]) -> Self
    where
        S: Into<String>,
    {
        let len = map.len();
        let ptr = map.as_mut_ptr();
        Self::maybe_differential_from_mut_ptr(name, ptr, len)
    }

    /// Creates a new [`MapObserver`] from an [`OwnedMutSlice`]
    #[must_use]
    fn maybe_differential_from_mut_slice<S>(name: S, map: OwnedMutSlice<'a, T>) -> Self
    where
        S: Into<String>,
    {
        StdMapObserver {
            name: name.into(),
            map,
            initial: T::default(),
        }
    }

    /// Creates a new [`MapObserver`] with an owned map
    #[must_use]
    fn maybe_differential_owned<S>(name: S, map: Vec<T>) -> Self
    where
        S: Into<String>,
    {
        Self {
            map: OwnedMutSlice::from(map),
            name: name.into(),
            initial: T::default(),
        }
    }

    /// Creates a new [`MapObserver`] from an [`OwnedMutSlice`] map.
    ///
    /// # Safety
    /// Will dereference the owned slice with up to len elements.
    #[must_use]
    fn maybe_differential_from_ownedref<S>(name: S, map: OwnedMutSlice<'a, T>) -> Self
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
    unsafe fn maybe_differential_from_mut_ptr<S>(name: S, map_ptr: *mut T, len: usize) -> Self
    where
        S: Into<String>,
    {
        Self::maybe_differential_from_mut_slice(
            name,
            OwnedMutSlice::from_raw_parts_mut(map_ptr, len),
        )
    }

    /// Gets the initial value for this map, mutably
    pub fn initial_mut(&mut self) -> &mut T {
        &mut self.initial
    }

    /// Gets the backing for this map
    pub fn map(&self) -> &OwnedMutSlice<'a, T> {
        &self.map
    }

    /// Gets the backing for this map mutably
    pub fn map_mut(&mut self) -> &mut OwnedMutSlice<'a, T> {
        &mut self.map
    }
}

impl<'a, T> StdMapObserver<'a, T, false>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`]
    ///
    /// # Safety
    /// The observer will keep a pointer to the map.
    /// Hence, the map may never move in memory.
    #[must_use]
    pub unsafe fn new<S>(name: S, map: &'a mut [T]) -> Self
    where
        S: Into<String>,
    {
        Self::maybe_differential(name, map)
    }

    /// Creates a new [`MapObserver`] from an [`OwnedMutSlice`]
    pub fn from_mut_slice<S>(name: S, map: OwnedMutSlice<'a, T>) -> Self
    where
        S: Into<String>,
    {
        Self::maybe_differential_from_mut_slice(name, map)
    }

    /// Creates a new [`MapObserver`] with an owned map
    #[must_use]
    pub fn owned<S>(name: S, map: Vec<T>) -> Self
    where
        S: Into<String>,
    {
        Self::maybe_differential_owned(name, map)
    }

    /// Creates a new [`MapObserver`] from an [`OwnedMutSlice`] map.
    ///
    /// # Note
    /// Will dereference the owned slice with up to len elements.
    #[must_use]
    pub fn from_ownedref<S>(name: S, map: OwnedMutSlice<'a, T>) -> Self
    where
        S: Into<String>,
    {
        Self::maybe_differential_from_ownedref(name, map)
    }

    /// Creates a new [`MapObserver`] from a raw pointer
    ///
    /// # Safety
    /// Will dereference the `map_ptr` with up to len elements.
    pub unsafe fn from_mut_ptr<S>(name: S, map_ptr: *mut T, len: usize) -> Self
    where
        S: Into<String>,
    {
        Self::maybe_differential_from_mut_ptr(name, map_ptr, len)
    }
}

impl<'a, T> StdMapObserver<'a, T, true>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`] in differential mode
    ///
    /// # Safety
    /// Will get a pointer to the map and dereference it at any point in time.
    /// The map must not move in memory!
    #[must_use]
    pub unsafe fn differential<S>(name: S, map: &'a mut [T]) -> Self
    where
        S: Into<String>,
    {
        Self::maybe_differential(name, map)
    }

    /// Creates a new [`MapObserver`] with an owned map in differential mode
    #[must_use]
    pub fn differential_owned<S>(name: S, map: Vec<T>) -> Self
    where
        S: Into<String>,
    {
        Self::maybe_differential_owned(name, map)
    }

    /// Creates a new [`MapObserver`] from an [`OwnedMutSlice`] map in differential mode.
    ///
    /// # Note
    /// Will dereference the owned slice with up to len elements.
    #[must_use]
    pub fn differential_from_ownedref<S>(name: S, map: OwnedMutSlice<'a, T>) -> Self
    where
        S: Into<String>,
    {
        Self::maybe_differential_from_ownedref(name, map)
    }

    /// Creates a new [`MapObserver`] from a raw pointer in differential mode
    ///
    /// # Safety
    /// Will dereference the `map_ptr` with up to len elements.
    pub unsafe fn differential_from_mut_ptr<S>(name: S, map_ptr: *mut T, len: usize) -> Self
    where
        S: Into<String>,
    {
        Self::maybe_differential_from_mut_ptr(name, map_ptr, len)
    }
}

impl<'a, OTA, OTB, S, T> DifferentialObserver<OTA, OTB, S> for StdMapObserver<'a, T, true>
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
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
    map: OwnedMutSlice<'a, T>,
    initial: T,
    name: String,
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

impl<'a, 'it, T, const N: usize> AsIter<'it> for ConstMapObserver<'a, T, N>
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

    fn as_iter(&'it self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_slice()[..cnt].iter()
    }
}

impl<'a, 'it, T, const N: usize> AsIterMut<'it> for ConstMapObserver<'a, T, N>
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

    fn as_iter_mut(&'it mut self) -> Self::IntoIter {
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

impl<'a, T, const N: usize> ConstMapObserver<'a, T, N>
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
    /// Returns an iterator over the map.
    pub fn iter(&self) -> Iter<'_, T> {
        <&Self as IntoIterator>::into_iter(self)
    }

    /// Returns a mutable iterator over the map.
    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        <&mut Self as IntoIterator>::into_iter(self)
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
    fn get(&self, idx: usize) -> &T {
        &self.as_slice()[idx]
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> &mut T {
        &mut self.as_mut_slice()[idx]
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

    fn hash(&self) -> u64 {
        hash_slice(self.as_slice())
    }

    /// Reset the map
    #[inline]
    fn reset_map(&mut self) -> Result<(), Error> {
        // Normal memset, see https://rust.godbolt.org/z/Trs5hv
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = self.as_mut_slice();
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

impl<'a, T, const N: usize> AsSlice for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Entry = T;
    #[inline]
    fn as_slice(&self) -> &[T] {
        self.map.as_slice()
    }
}
impl<'a, T, const N: usize> AsMutSlice for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Entry = T;
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
    ///
    /// # Note
    /// Will get a pointer to the map and dereference it at any point in time.
    /// The map must not move in memory!
    #[must_use]
    pub fn new(name: &'static str, map: &'a mut [T]) -> Self {
        assert!(map.len() >= N);
        Self {
            map: OwnedMutSlice::from(map),
            name: name.to_string(),
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
            name: name.to_string(),
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
    T: Default + Copy + 'static + Serialize + PartialEq + Bounded,
{
    map: OwnedMutSlice<'a, T>,
    size: OwnedMutPtr<usize>,
    initial: T,
    name: String,
}

impl<'a, S, T> Observer<S> for VariableMapObserver<'a, T>
where
    S: UsesInput,
    T: Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug
        + Bounded
        + PartialEq,
    Self: MapObserver,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, T> Named for VariableMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Bounded + PartialEq,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<'a, T> HasLen for VariableMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + PartialEq + Bounded,
{
    #[inline]
    fn len(&self) -> usize {
        *self.size.as_ref()
    }
}

impl<'a, 'it, T> AsIter<'it> for VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug
        + PartialEq
        + Bounded,
{
    type Item = T;
    type IntoIter = Iter<'it, T>;

    fn as_iter(&'it self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_slice()[..cnt].iter()
    }
}

impl<'a, 'it, T> AsIterMut<'it> for VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug
        + PartialEq
        + Bounded,
{
    type Item = T;
    type IntoIter = IterMut<'it, T>;

    fn as_iter_mut(&'it mut self) -> Self::IntoIter {
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
        + Debug
        + PartialEq
        + Bounded,
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
        + Debug
        + PartialEq
        + Bounded,
{
    type Item = <IterMut<'it, T> as Iterator>::Item;
    type IntoIter = IterMut<'it, T>;

    fn into_iter(self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_mut_slice()[..cnt].iter_mut()
    }
}

impl<'a, T> VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug
        + PartialEq
        + Bounded,
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

impl<'a, T> MapObserver for VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug
        + PartialEq
        + Bounded,
{
    type Entry = T;

    #[inline]
    fn initial(&self) -> T {
        self.initial
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
    fn hash(&self) -> u64 {
        hash_slice(self.as_slice())
    }

    /// Reset the map
    #[inline]
    fn reset_map(&mut self) -> Result<(), Error> {
        // Normal memset, see https://rust.godbolt.org/z/Trs5hv
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = self.as_mut_slice();
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

impl<'a, T> AsSlice for VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug
        + PartialEq
        + Bounded,
{
    type Entry = T;
    #[inline]
    fn as_slice(&self) -> &[T] {
        let cnt = self.usable_count();
        &self.map.as_slice()[..cnt]
    }
}
impl<'a, T> AsMutSlice for VariableMapObserver<'a, T>
where
    T: 'static
        + Default
        + Copy
        + Serialize
        + serde::de::DeserializeOwned
        + Debug
        + PartialEq
        + Bounded,
{
    type Entry = T;
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [T] {
        let cnt = self.usable_count();
        &mut self.map.as_mut_slice()[..cnt]
    }
}

impl<'a, T> VariableMapObserver<'a, T>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + PartialEq + Bounded,
{
    /// Creates a new [`MapObserver`] from an [`OwnedMutSlice`]
    ///
    /// # Safety
    /// The observer will dereference the owned slice, as well as the `map_ptr`.
    /// Dereferences `map_ptr` with up to `max_len` elements of size.
    pub unsafe fn from_mut_slice(
        name: &'static str,
        map_slice: OwnedMutSlice<'a, T>,
        size: *mut usize,
    ) -> Self {
        VariableMapObserver {
            name: name.into(),
            map: map_slice,
            size: OwnedMutPtr::Ptr(size),
            initial: T::default(),
        }
    }

    /// Creates a new [`MapObserver`] from a raw pointer
    ///
    /// # Safety
    /// The observer will dereference the `size` ptr, as well as the `map_ptr`.
    /// Dereferences `map_ptr` with up to `max_len` elements of size.
    pub unsafe fn from_mut_ptr(
        name: &'static str,
        map_ptr: *mut T,
        max_len: usize,
        size: *mut usize,
    ) -> Self {
        Self::from_mut_slice(
            name,
            OwnedMutSlice::from_raw_parts_mut(map_ptr, max_len),
            size,
        )
    }
}

/// Map observer with AFL-like hitcounts postprocessing
///
/// [`MapObserver`]s that are not slice-backed,
/// such as [`MultiMapObserver`], can use [`HitcountsIterableMapObserver`] instead.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "M: serde::de::DeserializeOwned")]
pub struct HitcountsMapObserver<M>
where
    M: Serialize,
{
    base: M,
}

impl<S, M> Observer<S> for HitcountsMapObserver<M>
where
    M: MapObserver<Entry = u8> + Observer<S> + AsMutSlice<Entry = u8>,
    S: UsesInput,
{
    #[inline]
    fn pre_exec(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.base.pre_exec(state, input)
    }

    #[inline]
    #[allow(clippy::cast_ptr_alignment)]
    fn post_exec(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        let map = self.as_mut_slice();
        let mut len = map.len();
        let align_offset = map.as_ptr().align_offset(size_of::<u16>());

        // if len == 1, the next branch will already do this lookup
        if len > 1 && align_offset != 0 {
            debug_assert_eq!(
                align_offset, 1,
                "Aligning u8 to u16 should always be offset of 1?"
            );
            unsafe {
                *map.get_unchecked_mut(0) =
                    *COUNT_CLASS_LOOKUP.get_unchecked(*map.get_unchecked(0) as usize);
            }
            len -= 1;
        }

        // Fix the last element
        if (len & 1) != 0 {
            unsafe {
                *map.get_unchecked_mut(len - 1) =
                    *COUNT_CLASS_LOOKUP.get_unchecked(*map.get_unchecked(len - 1) as usize);
            }
        }

        let cnt = len / 2;

        let map16 = unsafe {
            slice::from_raw_parts_mut(map.as_mut_ptr().add(align_offset) as *mut u16, cnt)
        };
        // 2022-07: Adding `enumerate` here increases execution speed/register allocation on x86_64.
        #[allow(clippy::unused_enumerate_index)]
        for (_i, item) in map16[0..cnt].iter_mut().enumerate() {
            unsafe {
                *item = *COUNT_CLASS_LOOKUP_16.get_unchecked(*item as usize);
            }
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
{
    type Entry = u8;

    #[inline]
    fn initial(&self) -> u8 {
        self.base.initial()
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

    /// Count the set bytes in the map
    fn count_bytes(&self) -> u64 {
        self.base.count_bytes()
    }

    /// Reset the map
    #[inline]
    fn reset_map(&mut self) -> Result<(), Error> {
        self.base.reset_map()
    }

    fn hash(&self) -> u64 {
        self.base.hash()
    }
    fn to_vec(&self) -> Vec<u8> {
        self.base.to_vec()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        self.base.how_many_set(indexes)
    }
}

impl<M> Truncate for HitcountsMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + Truncate,
{
    fn truncate(&mut self, new_len: usize) {
        self.base.truncate(new_len);
    }
}

impl<M> AsSlice for HitcountsMapObserver<M>
where
    M: MapObserver + AsSlice,
{
    type Entry = <M as AsSlice>::Entry;
    #[inline]
    fn as_slice(&self) -> &[Self::Entry] {
        self.base.as_slice()
    }
}

impl<M> AsMutSlice for HitcountsMapObserver<M>
where
    M: MapObserver + AsMutSlice,
{
    type Entry = <M as AsMutSlice>::Entry;
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [Self::Entry] {
        self.base.as_mut_slice()
    }
}

impl<M> HitcountsMapObserver<M>
where
    M: Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`]
    pub fn new(base: M) -> Self {
        init_count_class_16();
        Self { base }
    }
}

impl<'it, M> AsIter<'it> for HitcountsMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + AsIter<'it, Item = u8>,
{
    type Item = u8;
    type IntoIter = <M as AsIter<'it>>::IntoIter;

    fn as_iter(&'it self) -> Self::IntoIter {
        self.base.as_iter()
    }
}

impl<'it, M> AsIterMut<'it> for HitcountsMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + AsIterMut<'it, Item = u8>,
{
    type Item = u8;
    type IntoIter = <M as AsIterMut<'it>>::IntoIter;

    fn as_iter_mut(&'it mut self) -> Self::IntoIter {
        self.base.as_iter_mut()
    }
}

impl<'it, M> IntoIterator for &'it HitcountsMapObserver<M>
where
    M: Serialize + serde::de::DeserializeOwned,
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
    M: Serialize + serde::de::DeserializeOwned,
    &'it mut M: IntoIterator<Item = &'it mut u8>,
{
    type Item = &'it mut u8;
    type IntoIter = <&'it mut M as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.base.into_iter()
    }
}

impl<M> HitcountsMapObserver<M>
where
    M: Serialize + serde::de::DeserializeOwned,
    for<'it> &'it M: IntoIterator<Item = &'it u8>,
{
    /// Returns an iterator over the map.
    pub fn iter(&self) -> <&M as IntoIterator>::IntoIter {
        <&Self as IntoIterator>::into_iter(self)
    }
}

impl<M> HitcountsMapObserver<M>
where
    M: Serialize + serde::de::DeserializeOwned,
    for<'it> &'it mut M: IntoIterator<Item = &'it mut u8>,
{
    /// Returns a mutable iterator over the map.
    pub fn iter_mut(&mut self) -> <&mut M as IntoIterator>::IntoIter {
        <&mut Self as IntoIterator>::into_iter(self)
    }
}

impl<M, OTA, OTB, S> DifferentialObserver<OTA, OTB, S> for HitcountsMapObserver<M>
where
    M: DifferentialObserver<OTA, OTB, S>
        + MapObserver<Entry = u8>
        + Serialize
        + AsMutSlice<Entry = u8>,
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first(&mut self, observers: &mut OTA) -> Result<(), Error> {
        self.base.pre_observe_first(observers)
    }

    fn post_observe_first(&mut self, observers: &mut OTA) -> Result<(), Error> {
        self.base.post_observe_first(observers)
    }

    fn pre_observe_second(&mut self, observers: &mut OTB) -> Result<(), Error> {
        self.base.pre_observe_second(observers)
    }

    fn post_observe_second(&mut self, observers: &mut OTB) -> Result<(), Error> {
        self.base.post_observe_second(observers)
    }
}

/// Map observer with hitcounts postprocessing
/// Less optimized version for non-slice iterators.
/// Slice-backed observers should use a [`HitcountsMapObserver`].
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "M: serde::de::DeserializeOwned")]
pub struct HitcountsIterableMapObserver<M>
where
    M: Serialize,
{
    base: M,
}

impl<S, M> Observer<S> for HitcountsIterableMapObserver<M>
where
    M: MapObserver<Entry = u8> + Observer<S>,
    for<'it> M: AsIterMut<'it, Item = u8>,
    S: UsesInput,
{
    #[inline]
    fn pre_exec(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.base.pre_exec(state, input)
    }

    #[inline]
    #[allow(clippy::cast_ptr_alignment)]
    fn post_exec(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        for item in self.as_iter_mut() {
            *item = unsafe { *COUNT_CLASS_LOOKUP.get_unchecked((*item) as usize) };
        }

        self.base.post_exec(state, input, exit_kind)
    }
}

impl<M> Named for HitcountsIterableMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.base.name()
    }
}

impl<M> HasLen for HitcountsIterableMapObserver<M>
where
    M: MapObserver,
{
    #[inline]
    fn len(&self) -> usize {
        self.base.len()
    }
}

impl<M> MapObserver for HitcountsIterableMapObserver<M>
where
    M: MapObserver<Entry = u8>,
    for<'it> M: AsIterMut<'it, Item = u8>,
{
    type Entry = u8;

    #[inline]
    fn initial(&self) -> u8 {
        self.base.initial()
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

    /// Count the set bytes in the map
    fn count_bytes(&self) -> u64 {
        self.base.count_bytes()
    }

    /// Reset the map
    #[inline]
    fn reset_map(&mut self) -> Result<(), Error> {
        self.base.reset_map()
    }

    fn hash(&self) -> u64 {
        self.base.hash()
    }
    fn to_vec(&self) -> Vec<u8> {
        self.base.to_vec()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        self.base.how_many_set(indexes)
    }
}

impl<M> Truncate for HitcountsIterableMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + Truncate,
{
    fn truncate(&mut self, new_len: usize) {
        self.base.truncate(new_len);
    }
}

impl<M> AsSlice for HitcountsIterableMapObserver<M>
where
    M: MapObserver + AsSlice,
{
    type Entry = <M as AsSlice>::Entry;
    #[inline]
    fn as_slice(&self) -> &[Self::Entry] {
        self.base.as_slice()
    }
}
impl<M> AsMutSlice for HitcountsIterableMapObserver<M>
where
    M: MapObserver + AsMutSlice,
{
    type Entry = <M as AsMutSlice>::Entry;
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [Self::Entry] {
        self.base.as_mut_slice()
    }
}

impl<M> HitcountsIterableMapObserver<M>
where
    M: Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`]
    pub fn new(base: M) -> Self {
        init_count_class_16();
        Self { base }
    }
}

impl<'it, M> AsIter<'it> for HitcountsIterableMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + AsIter<'it, Item = u8>,
{
    type Item = u8;
    type IntoIter = <M as AsIter<'it>>::IntoIter;

    fn as_iter(&'it self) -> Self::IntoIter {
        self.base.as_iter()
    }
}

impl<'it, M> AsIterMut<'it> for HitcountsIterableMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + AsIterMut<'it, Item = u8>,
{
    type Item = u8;
    type IntoIter = <M as AsIterMut<'it>>::IntoIter;

    fn as_iter_mut(&'it mut self) -> Self::IntoIter {
        self.base.as_iter_mut()
    }
}

impl<'it, M> IntoIterator for &'it HitcountsIterableMapObserver<M>
where
    M: Serialize + serde::de::DeserializeOwned,
    &'it M: IntoIterator<Item = &'it u8>,
{
    type Item = &'it u8;
    type IntoIter = <&'it M as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.base.into_iter()
    }
}

impl<'it, M> IntoIterator for &'it mut HitcountsIterableMapObserver<M>
where
    M: Serialize + serde::de::DeserializeOwned,
    &'it mut M: IntoIterator<Item = &'it mut u8>,
{
    type Item = &'it mut u8;
    type IntoIter = <&'it mut M as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.base.into_iter()
    }
}

impl<M> HitcountsIterableMapObserver<M>
where
    M: Serialize + serde::de::DeserializeOwned,
    for<'it> &'it M: IntoIterator<Item = &'it u8>,
{
    /// Returns an iterator over the map.
    pub fn iter(&self) -> <&M as IntoIterator>::IntoIter {
        <&Self as IntoIterator>::into_iter(self)
    }
}

impl<M> HitcountsIterableMapObserver<M>
where
    M: Serialize + serde::de::DeserializeOwned,
    for<'it> &'it mut M: IntoIterator<Item = &'it mut u8>,
{
    /// Returns a mutable iterator over the map.
    pub fn iter_mut(&mut self) -> <&mut M as IntoIterator>::IntoIter {
        <&mut Self as IntoIterator>::into_iter(self)
    }
}

impl<M, OTA, OTB, S> DifferentialObserver<OTA, OTB, S> for HitcountsIterableMapObserver<M>
where
    M: MapObserver<Entry = u8> + Observer<S> + DifferentialObserver<OTA, OTB, S>,
    for<'it> M: AsIterMut<'it, Item = u8>,
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first(&mut self, observers: &mut OTA) -> Result<(), Error> {
        self.base.pre_observe_first(observers)
    }

    fn post_observe_first(&mut self, observers: &mut OTA) -> Result<(), Error> {
        self.base.post_observe_first(observers)
    }

    fn pre_observe_second(&mut self, observers: &mut OTB) -> Result<(), Error> {
        self.base.pre_observe_second(observers)
    }

    fn post_observe_second(&mut self, observers: &mut OTB) -> Result<(), Error> {
        self.base.post_observe_second(observers)
    }
}

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
    name: String,
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
    fn name(&self) -> &str {
        self.name.as_str()
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

impl<'a, T, const DIFFERENTIAL: bool> MapObserver for MultiMapObserver<'a, T, DIFFERENTIAL>
where
    T: 'static
        + Bounded
        + PartialEq
        + Default
        + Copy
        + Serialize
        + serde::de::DeserializeOwned
        + Debug,
{
    type Entry = T;

    #[inline]
    fn get(&self, idx: usize) -> &T {
        let elem = self.intervals.query(idx..=idx).next().unwrap();
        let i = *elem.value;
        let j = idx - elem.interval.start;
        &self.maps[i].as_slice()[j]
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> &mut T {
        let elem = self.intervals.query(idx..=idx).next().unwrap();
        let i = *elem.value;
        let j = idx - elem.interval.start;
        &mut self.maps[i].as_mut_slice()[j]
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

    fn hash(&self) -> u64 {
        let mut hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
        for map in &self.maps {
            let slice = map.as_slice();
            let ptr = slice.as_ptr() as *const u8;
            let map_size = slice.len() / size_of::<T>();
            unsafe {
                hasher.write(slice::from_raw_parts(ptr, map_size));
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
            name: name.to_string(),
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
            name: name.to_string(),
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
    type Item = T;
    type IntoIter = Flatten<IterMut<'it, OwnedMutSlice<'a, T>>>;

    fn as_iter_mut(&'it mut self) -> Self::IntoIter {
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
    name: String,
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
    fn name(&self) -> &str {
        self.name.as_str()
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

impl<'it, T> AsIter<'it> for OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Item = T;
    type IntoIter = Iter<'it, T>;

    fn as_iter(&'it self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<'it, T> AsIterMut<'it> for OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Item = T;
    type IntoIter = IterMut<'it, T>;

    fn as_iter_mut(&'it mut self) -> Self::IntoIter {
        self.as_mut_slice().iter_mut()
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
        self.as_mut_slice().iter_mut()
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

impl<T> MapObserver for OwnedMapObserver<T>
where
    T: 'static
        + Bounded
        + PartialEq
        + Default
        + Copy
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

    fn hash(&self) -> u64 {
        hash_slice(self.as_slice())
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
        let map = self.as_mut_slice();
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

impl<T> AsSlice for OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Entry = T;
    #[must_use]
    #[inline]
    fn as_slice(&self) -> &[T] {
        self.map.as_slice()
    }
}

impl<T> AsMutSlice for OwnedMapObserver<T>
where
    T: 'static + Default + Copy + Serialize + serde::de::DeserializeOwned + Debug,
{
    type Entry = T;
    #[must_use]
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [T] {
        self.map.as_mut_slice()
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
            name: name.to_string(),
            initial,
        }
    }
}
