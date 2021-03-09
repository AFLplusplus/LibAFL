use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{
        ownedref::{ArrayMut, Cptr},
        tuples::Named,
    },
    observers::Observer,
    Error,
};

/// A MapObserver observes the static map, as oftentimes used for afl-like coverage information
pub trait MapObserver<T>: Observer
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
        for i in self.map_mut()[0..cnt].iter_mut() {
            *i = initial;
        }
        Ok(())
    }
}

/// The Map Observer retrieves the state of a map,
/// that will get updated by the target.
/// A well-known example is the AFL-Style coverage map.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct StdMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    map: ArrayMut<T>,
    initial: T,
    name: String,
}

impl<T> Observer for StdMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn pre_exec(&mut self) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<T> Named for StdMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<T> MapObserver<T> for StdMapObserver<T>
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
        self.initial = initial
    }
}

impl<T> StdMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new MapObserver
    pub fn new(name: &'static str, map: &'static mut [T]) -> Self {
        let initial = if map.is_empty() { T::default() } else { map[0] };
        Self {
            map: ArrayMut::Cptr((map.as_mut_ptr(), map.len())),
            name: name.to_string(),
            initial,
        }
    }

    /// Creates a new MapObserver from a raw pointer
    /// # Safety
    /// Will dereference the map_ptr with up to len elements.
    pub unsafe fn new_from_ptr(name: &'static str, map_ptr: *mut T, len: usize) -> Self {
        let initial = if len > 0 { *map_ptr } else { T::default() };
        StdMapObserver {
            map: ArrayMut::Cptr((map_ptr, len)),
            name: name.to_string(),
            initial,
        }
    }
}

/// Overlooking a variable bitmap
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct VariableMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    map: ArrayMut<T>,
    size: Cptr<usize>,
    initial: T,
    name: String,
}

impl<T> Observer for VariableMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn pre_exec(&mut self) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<T> Named for VariableMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<T> MapObserver<T> for VariableMapObserver<T>
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
        self.initial = initial
    }
}

impl<T> VariableMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new MapObserver
    pub fn new(name: &'static str, map: &'static mut [T], size: &usize) -> Self {
        let initial = if map.is_empty() { T::default() } else { map[0] };
        Self {
            map: ArrayMut::Cptr((map.as_mut_ptr(), map.len())),
            size: Cptr::Cptr(size as *const _),
            name: name.into(),
            initial,
        }
    }

    /// Creates a new MapObserver from a raw pointer
    /// # Safety
    /// Dereferences map_ptr with up to max_len elements of size_ptr.
    pub unsafe fn new_from_ptr(
        name: &'static str,
        map_ptr: *mut T,
        max_len: usize,
        size_ptr: *const usize,
    ) -> Self {
        let initial = if max_len > 0 { *map_ptr } else { T::default() };
        VariableMapObserver {
            map: ArrayMut::Cptr((map_ptr, max_len)),
            size: Cptr::Cptr(size_ptr),
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
    M: MapObserver<u8>,
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

impl<M> Observer for HitcountsMapObserver<M>
where
    M: MapObserver<u8>,
{
    #[inline]
    fn pre_exec(&mut self) -> Result<(), Error> {
        self.reset_map()
    }

    #[inline]
    fn post_exec(&mut self) -> Result<(), Error> {
        for x in self.map_mut().iter_mut() {
            *x = COUNT_CLASS_LOOKUP[*x as usize];
        }
        Ok(())
    }
}

impl<M> Named for HitcountsMapObserver<M>
where
    M: MapObserver<u8>,
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
    M: MapObserver<u8>,
{
    /// Creates a new MapObserver
    pub fn new(base: M) -> Self {
        Self { base }
    }
}
