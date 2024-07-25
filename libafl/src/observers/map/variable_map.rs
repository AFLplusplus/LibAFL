//! Map observer with a shrinkable size

use alloc::{borrow::Cow, vec::Vec};
use core::{
    fmt::Debug,
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
};

use ahash::RandomState;
use libafl_bolts::{
    ownedref::{OwnedMutPtr, OwnedMutSlice},
    AsSlice, AsSliceMut, HasLen, Named,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    observers::{map::MapObserver, Observer},
    Error,
};

/// Overlooking a variable bitmap
#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct VariableMapObserver<'a, T> {
    map: OwnedMutSlice<'a, T>,
    size: OwnedMutPtr<usize>,
    initial: T,
    name: Cow<'static, str>,
}

impl<'a, I, S, T> Observer<I, S> for VariableMapObserver<'a, T>
where
    Self: MapObserver,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<'a, T> Named for VariableMapObserver<'a, T> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<'a, T> HasLen for VariableMapObserver<'a, T> {
    #[inline]
    fn len(&self) -> usize {
        *self.size.as_ref()
    }
}

impl<'a, T> Hash for VariableMapObserver<'a, T>
where
    T: Hash,
{
    #[inline]
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.as_slice().hash(hasher);
    }
}

impl<'a, T> AsRef<Self> for VariableMapObserver<'a, T> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'a, T> AsMut<Self> for VariableMapObserver<'a, T> {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl<'a, T> MapObserver for VariableMapObserver<'a, T>
where
    T: PartialEq + Copy + Hash + Serialize + DeserializeOwned,
{
    type Entry = T;

    fn get(&self, idx: usize) -> T {
        self.map.as_slice()[idx]
    }

    fn set(&mut self, idx: usize, val: T) {
        self.map.as_slice_mut()[idx] = val;
    }

    #[inline]
    fn usable_count(&self) -> usize {
        *self.size.as_ref()
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

impl<'a, T> Deref for VariableMapObserver<'a, T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        let cnt = *self.size.as_ref();
        &self.map[..cnt]
    }
}

impl<'a, T> DerefMut for VariableMapObserver<'a, T> {
    fn deref_mut(&mut self) -> &mut [T] {
        let cnt = *self.size.as_ref();
        &mut self.map[..cnt]
    }
}

impl<'a, T> VariableMapObserver<'a, T>
where
    T: Default,
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
