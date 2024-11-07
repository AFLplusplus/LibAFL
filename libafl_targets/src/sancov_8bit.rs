//! [`LLVM` `8-bit-counters`](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards) runtime for `LibAFL`.
use alloc::vec::Vec;

use libafl_bolts::{ownedref::OwnedMutSlice, AsSlice, AsSliceMut};

/// A [`Vec`] of `8-bit-counters` maps for multiple modules.
/// They are initialized by calling [`__sanitizer_cov_8bit_counters_init`](
pub static mut COUNTERS_MAPS: Vec<OwnedMutSlice<'static, u8>> = Vec::new();

/// Gets a pointer to [`COUNTER_MAPS`]
fn counter_maps_ptr() -> *const Vec<OwnedMutSlice<'static, u8>> {
    &raw const COUNTERS_MAPS
}

/// Gets a pointer to [`COUNTER_MAPS`], mut
fn counter_maps_ptr_mut() -> *mut Vec<OwnedMutSlice<'static, u8>> {
    &raw mut COUNTERS_MAPS
}

/// Create more copies of the counters maps
///
/// # Safety
/// You are responsible for ensuring there is no multi-mutability!
#[must_use]
pub unsafe fn extra_counters() -> Vec<OwnedMutSlice<'static, u8>> {
    let counter_maps = &*counter_maps_ptr();
    counter_maps
        .iter()
        .map(|counters| {
            OwnedMutSlice::from_raw_parts_mut(
                counters.as_slice().as_ptr().cast_mut(),
                counters.as_slice().len(),
            )
        })
        .collect()
}

/// Initialize the sancov `8-bit-counters` - usually called by `llvm`.
///
/// # Safety
/// Start and stop are being dereferenced.
#[no_mangle]
#[allow(clippy::cast_sign_loss)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub unsafe extern "C" fn __sanitizer_cov_8bit_counters_init(start: *mut u8, stop: *mut u8) {
    unsafe {
        let counter_maps = &mut *counter_maps_ptr_mut();
        for existing in counter_maps {
            let range = existing.as_slice_mut().as_mut_ptr()
                ..=existing
                    .as_slice_mut()
                    .as_mut_ptr()
                    .add(existing.as_slice().len());
            if range.contains(&start) || range.contains(&stop) {
                // we have overlapping or touching ranges; merge them
                let &start = range.start().min(&start);
                let &stop = range.end().max(&stop);
                *existing =
                    OwnedMutSlice::from_raw_parts_mut(start, stop.offset_from(start) as usize);
                return;
            }
        }

        let counter_maps = &mut *counter_maps_ptr_mut();
        // we didn't overlap; keep going
        counter_maps.push(OwnedMutSlice::from_raw_parts_mut(
            start,
            stop.offset_from(start) as usize,
        ));
    }
}

#[cfg(feature = "observers")]
pub use self::observers::{counters_maps_observer, CountersMultiMapObserver};

#[cfg(feature = "observers")]
mod observers {
    use alloc::{borrow::Cow, vec::Vec};
    use core::{
        fmt::Debug,
        hash::{Hash, Hasher},
        iter::Flatten,
        mem::size_of,
        slice::{from_raw_parts, Iter, IterMut},
    };

    use ahash::RandomState;
    use libafl::{
        observers::{DifferentialObserver, MapObserver, Observer},
        Error,
    };
    use libafl_bolts::{
        ownedref::OwnedMutSlice, AsIter, AsIterMut, AsSlice, AsSliceMut, HasLen, Named,
    };
    use meminterval::IntervalTree;
    use serde::{Deserialize, Serialize};

    use super::{counter_maps_ptr, counter_maps_ptr_mut};

    #[must_use]
    #[export_name = "counters_maps_observer"]
    /// Create a new [`CountersMultiMapObserver`] of the [`super::COUNTERS_MAPS`].
    ///
    /// This is a special [`libafl::observers::MultiMapObserver`] for the [`super::COUNTERS_MAPS`] and may be used when
    /// 8-bit counters are used for `SanitizerCoverage`. You can utilize this observer in a
    /// [`libafl::observers::HitcountsIterableMapObserver`] like so:
    ///
    /// ```rust,ignore
    /// use libafl::{
    ///     observers::HitcountsIterableMapObserver,
    ///     feedbacks::MaxMapFeedback,
    /// };
    /// use libafl_targets::sancov_8bit::counters_maps_observer;
    ///
    /// let counters_maps_observer = unsafe { counters_maps_observer("counters-maps") };
    /// let counters_maps_hitcounts_observer = HitcountsIterableMapObserver::new(counters_maps_observer);
    /// let counters_maps_feedback = MaxMapFeedback::new(&counters_maps_hitcounts_observer);
    /// ```
    ///
    /// # Safety
    ///
    /// This function instantiates an observer of a `static mut` map whose contents are mutated by
    /// `SanitizerCoverage` instrumentation. This is unsafe, and data in the map may be mutated from
    /// under us at any time. It should never be assumed constant.
    pub unsafe fn counters_maps_observer(name: &'static str) -> CountersMultiMapObserver<false> {
        CountersMultiMapObserver::new(name)
    }

    /// The [`CountersMultiMapObserver`] observes all the counters that may be set by
    /// `SanitizerCoverage` in [`super::COUNTERS_MAPS`]
    #[derive(Serialize, Deserialize, Debug)]
    #[allow(clippy::unsafe_derive_deserialize)]
    pub struct CountersMultiMapObserver<const DIFFERENTIAL: bool> {
        intervals: IntervalTree<usize, usize>,
        len: usize,
        initial: u8,
        name: Cow<'static, str>,
        iter_idx: usize,
    }

    impl<I, S> Observer<I, S> for CountersMultiMapObserver<false>
    where
        Self: MapObserver,
    {
        #[inline]
        fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
            self.reset_map()
        }
    }

    impl<I, S> Observer<I, S> for CountersMultiMapObserver<true>
    where
        Self: MapObserver,
    {
        // in differential mode, we are *not* responsible for resetting the map!
    }

    impl<const DIFFERENTIAL: bool> Named for CountersMultiMapObserver<DIFFERENTIAL> {
        #[inline]
        fn name(&self) -> &Cow<'static, str> {
            &self.name
        }
    }

    impl<const DIFFERENTIAL: bool> HasLen for CountersMultiMapObserver<DIFFERENTIAL> {
        #[inline]
        fn len(&self) -> usize {
            self.len
        }
    }

    impl<const DIFFERENTIAL: bool> Hash for CountersMultiMapObserver<DIFFERENTIAL> {
        fn hash<H: Hasher>(&self, hasher: &mut H) {
            for map in unsafe { &*counter_maps_ptr() } {
                let slice = map.as_slice();
                let ptr = slice.as_ptr();
                let map_size = slice.len() / size_of::<u8>();
                unsafe {
                    hasher.write(from_raw_parts(ptr, map_size));
                }
            }
        }
    }

    impl<const DIFFERENTIAL: bool> AsRef<Self> for CountersMultiMapObserver<DIFFERENTIAL> {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    impl<const DIFFERENTIAL: bool> AsMut<Self> for CountersMultiMapObserver<DIFFERENTIAL> {
        fn as_mut(&mut self) -> &mut Self {
            self
        }
    }

    impl<const DIFFERENTIAL: bool> MapObserver for CountersMultiMapObserver<DIFFERENTIAL> {
        type Entry = u8;

        #[inline]
        fn get(&self, idx: usize) -> u8 {
            let elem = self.intervals.query(idx..=idx).next().unwrap();
            let i = elem.value;
            let j = idx - elem.interval.start;
            unsafe { (*counter_maps_ptr())[*i].as_slice()[j] }
        }

        #[inline]
        fn set(&mut self, idx: usize, val: u8) {
            let elem = self.intervals.query_mut(idx..=idx).next().unwrap();
            let i = elem.value;
            let j = idx - elem.interval.start;
            unsafe { (*counter_maps_ptr_mut())[*i].as_slice_mut()[j] = val };
        }

        #[inline]
        fn initial(&self) -> u8 {
            self.initial
        }

        fn count_bytes(&self) -> u64 {
            let initial = self.initial();
            let mut res = 0;
            for map in unsafe { &*counter_maps_ptr() } {
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
            for map in unsafe { &mut *counter_maps_ptr_mut() } {
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

    impl<const DIFFERENTIAL: bool> CountersMultiMapObserver<DIFFERENTIAL> {
        /// Creates a new [`CountersMultiMapObserver`], maybe in differential mode
        #[must_use]
        fn maybe_differential(name: &'static str) -> Self {
            let mut idx = 0;
            let mut intervals = IntervalTree::new();
            for (v, x) in unsafe { &*counter_maps_ptr() }.iter().enumerate() {
                let l = x.as_slice().len();
                intervals.insert(idx..(idx + l), v);
                idx += l;
            }
            Self {
                intervals,
                len: idx,
                name: Cow::from(name),
                initial: u8::default(),
                iter_idx: 0,
            }
        }
    }

    impl CountersMultiMapObserver<true> {
        /// Creates a new [`CountersMultiMapObserver`] in differential mode
        #[must_use]
        pub fn differential(name: &'static str) -> Self {
            Self::maybe_differential(name)
        }
    }

    impl CountersMultiMapObserver<false> {
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
            let mut intervals = IntervalTree::new();
            unsafe { &mut *counter_maps_ptr_mut() }
                .iter_mut()
                .for_each(|m| {
                    let l = m.as_slice_mut().len();
                    intervals.insert(idx..(idx + l), v);
                    idx += l;
                    v += 1;
                });
            Self {
                intervals,
                len: idx,
                name: Cow::from(name),
                initial: u8::default(),
                iter_idx: 0,
            }
        }
    }

    impl<'it, const DIFFERENTIAL: bool> AsIter<'it> for CountersMultiMapObserver<DIFFERENTIAL> {
        type Item = u8;
        type Ref = &'it Self::Item;
        type IntoIter = Flatten<Iter<'it, OwnedMutSlice<'static, u8>>>;

        fn as_iter(&'it self) -> Self::IntoIter {
            unsafe {
                let counters_maps = &*counter_maps_ptr();
                counters_maps.iter().flatten()
            }
        }
    }

    impl<'it, const DIFFERENTIAL: bool> AsIterMut<'it> for CountersMultiMapObserver<DIFFERENTIAL> {
        type RefMut = &'it mut Self::Item;
        type IntoIterMut = Flatten<IterMut<'it, OwnedMutSlice<'static, u8>>>;

        fn as_iter_mut(&'it mut self) -> Self::IntoIterMut {
            unsafe {
                let counters_maps = &mut *counter_maps_ptr_mut();
                counters_maps.iter_mut().flatten()
            }
        }
    }

    impl<'it, const DIFFERENTIAL: bool> IntoIterator for &'it CountersMultiMapObserver<DIFFERENTIAL> {
        type Item = <Iter<'it, u8> as Iterator>::Item;
        type IntoIter = Flatten<Iter<'it, OwnedMutSlice<'static, u8>>>;

        fn into_iter(self) -> Self::IntoIter {
            unsafe { &*counter_maps_ptr() }.iter().flatten()
        }
    }

    impl<'it, const DIFFERENTIAL: bool> IntoIterator
        for &'it mut CountersMultiMapObserver<DIFFERENTIAL>
    {
        type Item = <IterMut<'it, u8> as Iterator>::Item;
        type IntoIter = Flatten<IterMut<'it, OwnedMutSlice<'static, u8>>>;

        fn into_iter(self) -> Self::IntoIter {
            unsafe { &mut *counter_maps_ptr_mut() }.iter_mut().flatten()
        }
    }

    impl<const DIFFERENTIAL: bool> CountersMultiMapObserver<DIFFERENTIAL> {
        /// Returns an iterator over the map.
        #[must_use]
        pub fn iter(&self) -> <&Self as IntoIterator>::IntoIter {
            <&Self as IntoIterator>::into_iter(self)
        }

        /// Returns a mutable iterator over the map.
        #[must_use]
        pub fn iter_mut(&mut self) -> <&mut Self as IntoIterator>::IntoIter {
            <&mut Self as IntoIterator>::into_iter(self)
        }
    }

    impl<OTA, OTB, I, S> DifferentialObserver<OTA, OTB, I, S> for CountersMultiMapObserver<true> {}
}
