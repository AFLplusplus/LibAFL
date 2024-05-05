//! Hitcount map observer is for implementing AFL's hit count bucket
use alloc::{borrow::Cow, vec::Vec};
use core::{fmt::Debug, hash::Hash, mem::size_of, slice};

use libafl_bolts::{AsIter, AsIterMut, AsSlice, AsSliceMut, HasLen, Named, Truncate};
use serde::{Deserialize, Serialize};

use crate::{
    executors::ExitKind,
    inputs::UsesInput,
    observers::{map::MapObserver, DifferentialObserver, Observer, ObserversTuple},
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

/// Map observer with AFL-like hitcounts postprocessing
///
/// [`MapObserver`]s that are not slice-backed, such as `MultiMapObserver`, can use
/// [`HitcountsIterableMapObserver`] instead.
#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
#[serde(bound = "M: serde::de::DeserializeOwned")]
pub struct HitcountsMapObserver<M>
where
    M: Serialize,
{
    base: M,
}

impl<S, M> Observer<S> for HitcountsMapObserver<M>
where
    M: MapObserver<Entry = u8> + Observer<S> + for<'a> AsSliceMut<'a, Entry = u8>,
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
        let mut map = self.as_slice_mut();
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

        drop(map);

        self.base.post_exec(state, input, exit_kind)
    }
}

impl<M> Named for HitcountsMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
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

impl<M> AsRef<Self> for HitcountsMapObserver<M>
where
    M: MapObserver<Entry = u8>,
{
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<M> AsMut<Self> for HitcountsMapObserver<M>
where
    M: MapObserver<Entry = u8>,
{
    fn as_mut(&mut self) -> &mut Self {
        self
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
    fn get(&self, idx: usize) -> u8 {
        self.base.get(idx)
    }

    #[inline]
    fn set(&mut self, idx: usize, val: u8) {
        self.base.set(idx, val);
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

    #[inline]
    fn hash_simple(&self) -> u64 {
        self.base.hash_simple()
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

impl<'a, M> AsSlice<'a> for HitcountsMapObserver<M>
where
    M: MapObserver + AsSlice<'a>,
{
    type Entry = <M as AsSlice<'a>>::Entry;
    type SliceRef = <M as AsSlice<'a>>::SliceRef;

    #[inline]
    fn as_slice(&'a self) -> Self::SliceRef {
        self.base.as_slice()
    }
}

impl<'a, M> AsSliceMut<'a> for HitcountsMapObserver<M>
where
    M: MapObserver + AsSliceMut<'a>,
{
    type SliceRefMut = <M as AsSliceMut<'a>>::SliceRefMut;
    #[inline]
    fn as_slice_mut(&'a mut self) -> Self::SliceRefMut {
        self.base.as_slice_mut()
    }
}

impl<M> HitcountsMapObserver<M>
where
    M: MapObserver,
{
    /// Creates a new [`MapObserver`]
    pub fn new(base: M) -> Self {
        init_count_class_16();
        Self { base }
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
        + for<'a> AsSliceMut<'a, Entry = u8>,
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
#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
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
        for mut item in self.as_iter_mut() {
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
    fn name(&self) -> &Cow<'static, str> {
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

impl<M> AsRef<Self> for HitcountsIterableMapObserver<M>
where
    M: MapObserver<Entry = u8>,
    for<'it> M: AsIterMut<'it, Item = u8>,
{
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<M> AsMut<Self> for HitcountsIterableMapObserver<M>
where
    M: MapObserver<Entry = u8>,
    for<'it> M: AsIterMut<'it, Item = u8>,
{
    fn as_mut(&mut self) -> &mut Self {
        self
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
    fn get(&self, idx: usize) -> u8 {
        self.base.get(idx)
    }

    #[inline]
    fn set(&mut self, idx: usize, val: u8) {
        self.base.set(idx, val);
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

    #[inline]
    fn hash_simple(&self) -> u64 {
        self.base.hash_simple()
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
    type Ref = <M as AsIter<'it>>::Ref;
    type IntoIter = <M as AsIter<'it>>::IntoIter;

    fn as_iter(&'it self) -> Self::IntoIter {
        self.base.as_iter()
    }
}

impl<'it, M> AsIterMut<'it> for HitcountsIterableMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + AsIterMut<'it, Item = u8>,
{
    type RefMut = <M as AsIterMut<'it>>::RefMut;
    type IntoIterMut = <M as AsIterMut<'it>>::IntoIterMut;

    fn as_iter_mut(&'it mut self) -> Self::IntoIterMut {
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
