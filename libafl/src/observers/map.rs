//! The `MapObserver` provides access a map, usually injected into the target

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::slice::from_raw_parts_mut;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{
        ownedref::{OwnedRefMut, OwnedSliceMut},
        tuples::Named,
    },
    observers::Observer,
    Error,
};

/// A [`MapObserver`] observes the static map, as oftentimes used for afl-like coverage information
pub trait MapObserver<T>: Named + serde::Serialize + serde::de::DeserializeOwned
where
    T: Default + Copy,
{
    /// Get the map
    fn map(&self) -> &[T];

    /// Get the map (mutable)
    fn map_mut(&mut self) -> &mut [T];

    /// Get the number of usable entries in the map (all by default)
    fn usable_count(&self) -> usize {
        self.map().len()
    }

    /// Count the set bytes in the map
    fn count_bytes(&self) -> usize{
        let initial = self.initial();
        let cnt = self.usable_count();
        let res = 0;
        for x in self.map()[0..cnt].iter(){
            /*
            // needs partialeq
            if *x != initial {
                res += 1;
            }
            */
        }
        0
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
        for x in self.map_mut()[0..cnt].iter_mut() {
            *x = initial;
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
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    map: OwnedSliceMut<'a, T>,
    initial: T,
    name: String,
}

impl<'a, I, S, T> Observer<I, S> for StdMapObserver<'a, T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    Self: MapObserver<T>,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, T> Named for StdMapObserver<'a, T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<'a, T> MapObserver<T> for StdMapObserver<'a, T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn map(&self) -> &[T] {
        self.map.as_slice()
    }

    #[inline]
    fn map_mut(&mut self) -> &mut [T] {
        self.map.as_mut_slice()
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
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
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
            map: OwnedSliceMut::Ref(from_raw_parts_mut(map_ptr, len)),
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
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    map: OwnedSliceMut<'a, T>,
    initial: T,
    name: String,
}

impl<'a, I, S, T, const N: usize> Observer<I, S> for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    Self: MapObserver<T>,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, T, const N: usize> Named for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<'a, T, const N: usize> MapObserver<T> for ConstMapObserver<'a, T, N>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn usable_count(&self) -> usize {
        N
    }

    #[inline]
    fn map(&self) -> &[T] {
        self.map.as_slice()
    }

    #[inline]
    fn map_mut(&mut self) -> &mut [T] {
        self.map.as_mut_slice()
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
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
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
            map: OwnedSliceMut::Ref(from_raw_parts_mut(map_ptr, N)),
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
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    map: OwnedSliceMut<'a, T>,
    size: OwnedRefMut<'a, usize>,
    initial: T,
    name: String,
}

impl<'a, I, S, T> Observer<I, S> for VariableMapObserver<'a, T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    Self: MapObserver<T>,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, T> Named for VariableMapObserver<'a, T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<'a, T> MapObserver<T> for VariableMapObserver<'a, T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn map(&self) -> &[T] {
        self.map.as_slice()
    }

    #[inline]
    fn map_mut(&mut self) -> &mut [T] {
        self.map.as_mut_slice()
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
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
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
            map: OwnedSliceMut::Ref(from_raw_parts_mut(map_ptr, max_len)),
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
    M: serde::Serialize + serde::de::DeserializeOwned,
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
        for x in self.map_mut()[0..cnt].iter_mut() {
            *x = COUNT_CLASS_LOOKUP[*x as usize];
        }
        self.base.post_exec(state, input)
    }
}

impl<M> Named for HitcountsMapObserver<M>
where
    M: Named + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.base.name()
    }
}

impl<M> MapObserver<u8> for HitcountsMapObserver<M>
where
    M: MapObserver<u8>,
{
    #[inline]
    fn map(&self) -> &[u8] {
        self.base.map()
    }

    #[inline]
    fn map_mut(&mut self) -> &mut [u8] {
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
    M: serde::Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`]
    pub fn new(base: M) -> Self {
        Self { base }
    }
}
