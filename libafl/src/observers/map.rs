//! The `MapObserver` provides access a map, usually injected into the target

use ahash::AHasher;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Debug, hash::Hasher, slice::from_raw_parts};
use intervaltree::IntervalTree;
use num_traits::PrimInt;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{
        ownedref::{OwnedRefMut, OwnedSliceMut},
        tuples::Named,
        HasLen,
    },
    observers::Observer,
    Error,
};

/// A [`MapObserver`] observes the static map, as oftentimes used for afl-like coverage information
pub trait MapObserver<T>: HasLen + Named + Serialize + serde::de::DeserializeOwned + Debug
where
    T: PrimInt + Default + Copy + Debug,
{
    /// Get the map if the observer can be represented with a slice
    fn map(&self) -> Option<&[T]>;

    /// Get the map (mutable) if the observer can be represented with a slice
    fn map_mut(&mut self) -> Option<&mut [T]>;

    /// Get the value at `idx`
    fn get(&self, idx: usize) -> &T {
        &self
            .map()
            .expect("Cannot get a map that cannot be represented as slice")[idx]
    }

    /// Get the value at `idx` (mutable)
    fn get_mut(&mut self, idx: usize) -> &mut T {
        &mut self
            .map_mut()
            .expect("Cannot get a map that cannot be represented as slice")[idx]
    }

    /// Get the number of usable entries in the map (all by default)
    fn usable_count(&self) -> usize {
        self.len()
    }

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
    fn hash(&self) -> u64 {
        let mut hasher = AHasher::new_with_keys(0, 0);
        let slice = self
            .map()
            .expect("Cannot hash a map that cannot be represented as slice");
        let ptr = slice.as_ptr() as *const u8;
        let map_size = slice.len() / core::mem::size_of::<T>();
        unsafe {
            hasher.write(from_raw_parts(ptr, map_size));
        }
        hasher.finish()
    }

    /// Get the initial value for reset()
    fn initial(&self) -> T;

    /// Get the initial value for reset()
    fn initial_mut(&mut self) -> &mut T;

    /// Set the initial value for reset()
    fn set_initial(&mut self, initial: T);

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
}

/// The Map Observer retrieves the state of a map,
/// that will get updated by the target.
/// A well-known example is the AFL-Style coverage map.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct StdMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    map: OwnedSliceMut<'a, T>,
    initial: T,
    name: String,
}

impl<'a, I, S, T> Observer<I, S> for StdMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
    Self: MapObserver<T>,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, T> Named for StdMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<'a, T> HasLen for StdMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn len(&self) -> usize {
        self.map.as_slice().len()
    }
}

impl<'a, T> MapObserver<T> for StdMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[inline]
    fn map(&self) -> Option<&[T]> {
        Some(self.map.as_slice())
    }

    #[inline]
    fn map_mut(&mut self) -> Option<&mut [T]> {
        Some(self.map.as_mut_slice())
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
}

impl<'a, T> StdMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`]
    #[must_use]
    pub fn new(name: &'static str, map: &'a mut [T]) -> Self {
        let initial = if map.is_empty() { T::default() } else { map[0] };
        Self {
            map: OwnedSliceMut::Ref(map),
            name: name.to_string(),
            initial,
        }
    }

    /// Creates a new [`MapObserver`] with an owned map
    #[must_use]
    pub fn new_owned(name: &'static str, map: Vec<T>) -> Self {
        let initial = if map.is_empty() { T::default() } else { map[0] };
        Self {
            map: OwnedSliceMut::Owned(map),
            name: name.to_string(),
            initial,
        }
    }

    /// Creates a new [`MapObserver`] from a raw pointer
    ///
    /// # Safety
    /// Will dereference the `map_ptr` with up to len elements.
    pub unsafe fn new_from_ptr(name: &'static str, map_ptr: *mut T, len: usize) -> Self {
        let initial = if len > 0 { *map_ptr } else { T::default() };
        StdMapObserver {
            map: OwnedSliceMut::from_raw_parts_mut(map_ptr, len),
            name: name.to_string(),
            initial,
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
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    map: OwnedSliceMut<'a, T>,
    initial: T,
    name: String,
}

impl<'a, I, S, T, const N: usize> Observer<I, S> for ConstMapObserver<'a, T, N>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
    Self: MapObserver<T>,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, T, const N: usize> Named for ConstMapObserver<'a, T, N>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<'a, T, const N: usize> HasLen for ConstMapObserver<'a, T, N>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn len(&self) -> usize {
        N
    }
}

impl<'a, T, const N: usize> MapObserver<T> for ConstMapObserver<'a, T, N>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[inline]
    fn usable_count(&self) -> usize {
        N
    }

    #[inline]
    fn map(&self) -> Option<&[T]> {
        Some(self.map.as_slice())
    }

    #[inline]
    fn map_mut(&mut self) -> Option<&mut [T]> {
        Some(self.map.as_mut_slice())
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
}

impl<'a, T, const N: usize> ConstMapObserver<'a, T, N>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`]
    #[must_use]
    pub fn new(name: &'static str, map: &'a mut [T]) -> Self {
        assert!(map.len() >= N);
        let initial = if map.is_empty() { T::default() } else { map[0] };
        Self {
            map: OwnedSliceMut::Ref(map),
            name: name.to_string(),
            initial,
        }
    }

    /// Creates a new [`MapObserver`] with an owned map
    #[must_use]
    pub fn new_owned(name: &'static str, map: Vec<T>) -> Self {
        assert!(map.len() >= N);
        let initial = if map.is_empty() { T::default() } else { map[0] };
        Self {
            map: OwnedSliceMut::Owned(map),
            name: name.to_string(),
            initial,
        }
    }

    /// Creates a new [`MapObserver`] from a raw pointer
    ///
    /// # Safety
    /// Will dereference the `map_ptr` with up to len elements.
    pub unsafe fn new_from_ptr(name: &'static str, map_ptr: *mut T) -> Self {
        let initial = if N > 0 { *map_ptr } else { T::default() };
        ConstMapObserver {
            map: OwnedSliceMut::from_raw_parts_mut(map_ptr, N),
            name: name.to_string(),
            initial,
        }
    }
}

/// Overlooking a variable bitmap
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct VariableMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    map: OwnedSliceMut<'a, T>,
    size: OwnedRefMut<'a, usize>,
    initial: T,
    name: String,
}

impl<'a, I, S, T> Observer<I, S> for VariableMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
    Self: MapObserver<T>,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, T> Named for VariableMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<'a, T> HasLen for VariableMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn len(&self) -> usize {
        self.map.as_slice().len()
    }
}

impl<'a, T> MapObserver<T> for VariableMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[inline]
    fn map(&self) -> Option<&[T]> {
        Some(self.map.as_slice())
    }

    #[inline]
    fn map_mut(&mut self) -> Option<&mut [T]> {
        Some(self.map.as_mut_slice())
    }

    #[inline]
    fn usable_count(&self) -> usize {
        *self.size.as_ref()
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
}

impl<'a, T> VariableMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`]
    pub fn new(name: &'static str, map: &'a mut [T], size: &'a mut usize) -> Self {
        let initial = if map.is_empty() { T::default() } else { map[0] };
        Self {
            map: OwnedSliceMut::Ref(map),
            size: OwnedRefMut::Ref(size),
            name: name.into(),
            initial,
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
        let initial = if max_len > 0 { *map_ptr } else { T::default() };
        VariableMapObserver {
            map: OwnedSliceMut::from_raw_parts_mut(map_ptr, max_len),
            size: OwnedRefMut::Ref(size),
            name: name.into(),
            initial,
        }
    }
}

/// Map observer with hitcounts postprocessing
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "M: serde::de::DeserializeOwned")]
pub struct HitcountsMapObserver<M>
where
    M: Serialize + serde::de::DeserializeOwned,
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
    M: MapObserver<u8> + Observer<I, S>,
{
    #[inline]
    fn pre_exec(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        self.base.pre_exec(state, input)
    }

    #[inline]
    fn post_exec(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        let cnt = self.usable_count();
        for i in 0..cnt {
            *self.get_mut(i) = COUNT_CLASS_LOOKUP[*self.get(i) as usize];
        }
        self.base.post_exec(state, input)
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
    M: MapObserver<u8>,
{
    #[inline]
    fn len(&self) -> usize {
        self.base.len()
    }
}

impl<M> MapObserver<u8> for HitcountsMapObserver<M>
where
    M: MapObserver<u8>,
{
    #[inline]
    fn map(&self) -> Option<&[u8]> {
        self.base.map()
    }

    #[inline]
    fn map_mut(&mut self) -> Option<&mut [u8]> {
        self.base.map_mut()
    }

    #[inline]
    fn usable_count(&self) -> usize {
        self.base.usable_count()
    }

    #[inline]
    fn initial(&self) -> u8 {
        self.base.initial()
    }

    #[inline]
    fn initial_mut(&mut self) -> &mut u8 {
        self.base.initial_mut()
    }

    #[inline]
    fn set_initial(&mut self, initial: u8) {
        self.base.set_initial(initial);
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

/// The Multi Map Observer merge different maps into one observer
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct MultiMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    maps: Vec<OwnedSliceMut<'a, T>>,
    intervals: IntervalTree<usize, usize>,
    len: usize,
    initial: T,
    name: String,
}

impl<'a, I, S, T> Observer<I, S> for MultiMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
    Self: MapObserver<T>,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, T> Named for MultiMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<'a, T> HasLen for MultiMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn len(&self) -> usize {
        self.len
    }
}

impl<'a, T> MapObserver<T> for MultiMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
{
    #[inline]
    fn map(&self) -> Option<&[T]> {
        None
    }

    #[inline]
    fn map_mut(&mut self) -> Option<&mut [T]> {
        None
    }

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

    #[inline]
    fn set_initial(&mut self, initial: T) {
        self.initial = initial;
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
}

impl<'a, T> MultiMapObserver<'a, T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MultiMapObserver`]
    #[must_use]
    pub fn new(name: &'static str, maps: &'a mut [&'a mut [T]]) -> Self {
        let mut idx = 0;
        let mut v = 0;
        let mut initial = T::default();
        let mut builder = vec![];
        let maps: Vec<_> = maps
            .iter_mut()
            .map(|x| {
                if !x.is_empty() {
                    initial = x[0];
                }
                let l = x.len();
                let r = (idx..(idx + l), v);
                idx += l;
                builder.push(r);
                v += 1;
                OwnedSliceMut::Ref(x)
            })
            .collect();
        Self {
            maps,
            intervals: builder.into_iter().collect::<IntervalTree<usize, usize>>(),
            len: idx,
            name: name.to_string(),
            initial,
        }
    }

    /// Creates a new [`MultiMapObserver`] with an owned map
    #[must_use]
    pub fn new_owned(name: &'static str, maps: Vec<Vec<T>>) -> Self {
        let mut idx = 0;
        let mut v = 0;
        let mut initial = T::default();
        let mut builder = vec![];
        let maps: Vec<_> = maps
            .into_iter()
            .map(|x| {
                if !x.is_empty() {
                    initial = x[0];
                }
                let l = x.len();
                let r = (idx..(idx + l), v);
                idx += l;
                builder.push(r);
                v += 1;
                OwnedSliceMut::Owned(x)
            })
            .collect();
        Self {
            maps,
            intervals: builder.into_iter().collect::<IntervalTree<usize, usize>>(),
            len: idx,
            name: name.to_string(),
            initial,
        }
    }
}
