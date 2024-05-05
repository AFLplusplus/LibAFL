//! Map observer with a shrinkable size

use alloc::{borrow::Cow, vec::Vec};
use core::{
    fmt::Debug,
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
    slice::{Iter, IterMut},
};

use ahash::RandomState;
use libafl_bolts::{
    ownedref::{OwnedMutPtr, OwnedMutSlice},
    AsSlice, AsSliceMut, HasLen, Named,
};
use num_traits::Bounded;
use serde::{Deserialize, Serialize};

use crate::{
    inputs::UsesInput,
    observers::{map::MapObserver, Observer},
    Error,
};

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
    name: Cow<'static, str>,
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
    fn name(&self) -> &Cow<'static, str> {
        &self.name
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

impl<'a, 'it, T> IntoIterator for &'it VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + Hash
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
        + Hash
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
        self.as_slice_mut()[..cnt].iter_mut()
    }
}

impl<'a, T> VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + Hash
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

impl<'a, T> Hash for VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + Hash
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug
        + PartialEq
        + Bounded,
{
    #[inline]
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.as_slice().hash(hasher);
    }
}

impl<'a, T> AsRef<Self> for VariableMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + PartialEq + Bounded,
{
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'a, T> AsMut<Self> for VariableMapObserver<'a, T>
where
    T: Default + Copy + 'static + Serialize + PartialEq + Bounded,
{
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl<'a, T> MapObserver for VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + Hash
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

    fn get(&self, idx: usize) -> T {
        self.map.as_slice()[idx]
    }

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

impl<'a, T> Deref for VariableMapObserver<'a, T>
where
    T: Bounded
        + PartialEq
        + Default
        + Copy
        + Hash
        + 'static
        + Serialize
        + serde::de::DeserializeOwned
        + Debug
        + PartialEq
        + Bounded,
{
    type Target = [T];
    fn deref(&self) -> &[T] {
        let cnt = self.usable_count();
        &self.map[..cnt]
    }
}

impl<'a, T> DerefMut for VariableMapObserver<'a, T>
where
    T: 'static
        + Default
        + Copy
        + Hash
        + Serialize
        + serde::de::DeserializeOwned
        + Debug
        + PartialEq
        + Bounded,
{
    fn deref_mut(&mut self) -> &mut [T] {
        let cnt = self.usable_count();
        &mut self.map[..cnt]
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
