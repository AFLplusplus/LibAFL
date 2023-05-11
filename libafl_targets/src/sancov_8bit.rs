//! [`LLVM` `8-bi-counters`](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards) runtime for `LibAFL`.
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt::Debug,
    hash::{BuildHasher, Hasher},
    iter::Flatten,
    marker::PhantomData,
    slice::{from_raw_parts, Iter, IterMut},
};

use ahash::RandomState;
use intervaltree::IntervalTree;
use num_traits::Bounded;
use serde::{Deserialize, Serialize};
use libafl::{
    bolts::{
        ownedref::{OwnedMutPtr, OwnedMutSlice},
        tuples::Named,
        AsIter, AsIterMut, AsMutSlice, AsSlice, HasLen, Truncate,
    },
    executors::ExitKind,
    inputs::UsesInput,
    observers::{DifferentialObserver, Observer, ObserversTuple},
    Error,
    prelude::*,
};

/// A [`Vec`] of `8-bit-counters` maps for multiple modules.
/// They are initialized by calling [`__sanitizer_cov_8bit_counters_init`](
pub static mut COUNTERS_MAPS: Vec<OwnedMutSlice<'static, u8>> = Vec::new();

/// Initialize the sancov `8-bit-counters` - usually called by `llvm`.
#[no_mangle]
#[allow(clippy::cast_sign_loss)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn __sanitizer_cov_8bit_counters_init(start: *mut u8, stop: *mut u8) {
    unsafe {
        COUNTERS_MAPS.push(OwnedMutSlice::from_raw_parts_mut(
            start,
            stop.offset_from(start) as usize,
        ));
    }
}

pub unsafe fn counters_maps_observer(name: &'static str) -> CountersMultiMapObserver<false>
{
    CountersMultiMapObserver::new(name)
}

/// The Multi Map Observer merge different maps into one observer
#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct CountersMultiMapObserver<const DIFFERENTIAL: bool>
{
    intervals: IntervalTree<usize, usize>,
    len: usize,
    initial: u8,
    name: String,
    iter_idx: usize,
}

impl<S> Observer<S> for CountersMultiMapObserver<false>
where
    S: UsesInput,
    Self: MapObserver,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<S> Observer<S> for CountersMultiMapObserver<true>
where
    S: UsesInput,
    Self: MapObserver,
{
    // in differential mode, we are *not* responsible for resetting the map!
}

impl<const DIFFERENTIAL: bool> Named for CountersMultiMapObserver<DIFFERENTIAL>
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<const DIFFERENTIAL: bool> HasLen for CountersMultiMapObserver<DIFFERENTIAL>
{
    #[inline]
    fn len(&self) -> usize {
        self.len
    }
}

impl<const DIFFERENTIAL: bool> MapObserver for CountersMultiMapObserver<DIFFERENTIAL>
{
    type Entry = u8;

    #[inline]
    fn get(&self, idx: usize) -> &u8 {
        let elem = self.intervals.query_point(idx).next().unwrap();
        let i = elem.value;
        let j = idx - elem.range.start;
        unsafe { &COUNTERS_MAPS[i].as_slice()[j] }
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> &mut u8 {
        let elem = self.intervals.query_point(idx).next().unwrap();
        let i = elem.value;
        let j = idx - elem.range.start;
        unsafe { &mut COUNTERS_MAPS[i].as_mut_slice()[j] }
    }

    #[inline]
    fn initial(&self) -> u8 {
        self.initial
    }

    fn count_bytes(&self) -> u64 {
        let initial = self.initial();
        let mut res = 0;
        for map in unsafe { &COUNTERS_MAPS } {
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
        for map in unsafe { &COUNTERS_MAPS } {
            let slice = map.as_slice();
            let ptr = slice.as_ptr() as *const u8;
            let map_size = slice.len() / core::mem::size_of::<u8>();
            unsafe {
                hasher.write(from_raw_parts(ptr, map_size));
            }
        }
        hasher.finish()
    }

    fn reset_map(&mut self) -> Result<(), Error> {
        let initial = self.initial();
        for map in unsafe { &mut COUNTERS_MAPS } {
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

impl<const DIFFERENTIAL: bool> CountersMultiMapObserver<DIFFERENTIAL>
{
    /// Creates a new [`CountersMultiMapObserver`], maybe in differential mode
    #[must_use]
    fn maybe_differential(name: &'static str) -> Self {
        let mut idx = 0;
        let mut builder = vec![];
        for (v, x) in unsafe { &COUNTERS_MAPS }.iter().enumerate() {
            let l = x.as_slice().len();
            let r = (idx..(idx + l), v);
            idx += l;
            builder.push(r);
        }
        Self {
            intervals: builder.into_iter().collect::<IntervalTree<usize, usize>>(),
            len: idx,
            name: name.to_string(),
            initial: u8::default(),
            iter_idx: 0,
        }
    }
}

impl CountersMultiMapObserver<true>
{
    /// Creates a new [`CountersMultiMapObserver`] in differential mode
    #[must_use]
    pub fn differential(name: &'static str) -> Self {
        Self::maybe_differential(name)
    }
}

impl CountersMultiMapObserver<false>
{
    /// Creates a new [`CountersMultiMapObserver`]
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self::maybe_differential(name)
    }

    /// Creates a new [`CountersMultiMapObserver`] with an owned map
    #[must_use]
    pub fn owned(name: &'static str) -> Self {
        let mut idx = 0;
        let mut v = 0;
        let mut builder = vec![];
        unsafe { &mut COUNTERS_MAPS }.iter_mut().for_each(|m| {
            let l = m.as_mut_slice().len();
            let r = (idx..(idx + l), v);
            idx += l;
            builder.push(r);
            v += 1;
        });
        Self {
            intervals: builder.into_iter().collect::<IntervalTree<usize, usize>>(),
            len: idx,
            name: name.to_string(),
            initial: u8::default(),
            iter_idx: 0,
        }
    }
}

impl<'it, const DIFFERENTIAL: bool> AsIter<'it>
    for CountersMultiMapObserver<DIFFERENTIAL>
{
    type Item = u8;
    type IntoIter = Flatten<Iter<'it, OwnedMutSlice<'static, u8>>>;

    fn as_iter(&'it self) -> Self::IntoIter {
        unsafe { COUNTERS_MAPS.iter().flatten() }
    }
}

impl<'it, const DIFFERENTIAL: bool> AsIterMut<'it>
    for CountersMultiMapObserver<DIFFERENTIAL>
{
    type Item = u8;
    type IntoIter = Flatten<IterMut<'it, OwnedMutSlice<'static, u8>>>;

    fn as_iter_mut(&'it mut self) -> Self::IntoIter {
        unsafe { COUNTERS_MAPS.iter_mut().flatten() }
    }
}

impl<'it, const DIFFERENTIAL: bool> IntoIterator
    for &'it CountersMultiMapObserver<DIFFERENTIAL>
{
    type Item = <Iter<'it, u8> as Iterator>::Item;
    type IntoIter = Flatten<Iter<'it, OwnedMutSlice<'static, u8>>>;

    fn into_iter(self) -> Self::IntoIter {
        unsafe { &COUNTERS_MAPS }.iter().flatten()
    }
}

impl<'it, const DIFFERENTIAL: bool> IntoIterator
    for &'it mut CountersMultiMapObserver<DIFFERENTIAL>
{
    type Item = <IterMut<'it, u8> as Iterator>::Item;
    type IntoIter = Flatten<IterMut<'it, OwnedMutSlice<'static, u8>>>;

    fn into_iter(self) -> Self::IntoIter {
        unsafe { &mut COUNTERS_MAPS }.iter_mut().flatten()
    }
}

impl<OTA, OTB, S> DifferentialObserver<OTA, OTB, S> for CountersMultiMapObserver<true>
where
    Self: MapObserver,
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
}
