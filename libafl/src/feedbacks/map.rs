//! Map feedback, maximizing or minimizing maps, for example the afl-style map observer.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::ops::{BitAnd, BitOr};
use core::{fmt::Debug, marker::PhantomData};
use num_traits::PrimInt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    bolts::{tuples::Named, AsMutSlice, AsRefIterator, AsSlice, HasRefCnt},
    corpus::Testcase,
    events::{Event, EventFirer},
    executors::ExitKind,
    feedbacks::{Feedback, HasObserverName},
    inputs::Input,
    monitors::UserStats,
    observers::{MapObserver, ObserversTuple},
    state::{HasClientPerfMonitor, HasMetadata, HasNamedMetadata},
    Error,
};

/// The prefix of the metadata names
pub const MAPFEEDBACK_PREFIX: &str = "mapfeedback_metadata_";

/// A [`MapFeedback`] that implements the AFL algorithm using an [`OrReducer`] combining the bits for the history map and the bit from ``HitcountsMapObserver``.
pub type AflMapFeedback<I, O, S, T> = MapFeedback<I, DifferentIsNovel, O, OrReducer, S, T>;

/// A [`MapFeedback`] that strives to maximize the map contents.
pub type MaxMapFeedback<I, O, S, T> = MapFeedback<I, DifferentIsNovel, O, MaxReducer, S, T>;
/// A [`MapFeedback`] that strives to minimize the map contents.
pub type MinMapFeedback<I, O, S, T> = MapFeedback<I, DifferentIsNovel, O, MinReducer, S, T>;

/// A [`MapFeedback`] that strives to maximize the map contents,
/// but only, if a value is larger than `pow2` of the previous.
pub type MaxMapPow2Feedback<I, O, S, T> = MapFeedback<I, NextPow2IsNovel, O, MaxReducer, S, T>;
/// A [`MapFeedback`] that strives to maximize the map contents,
/// but only, if a value is larger than `pow2` of the previous.
pub type MaxMapOneOrFilledFeedback<I, O, S, T> =
    MapFeedback<I, OneOrFilledIsNovel, O, MaxReducer, S, T>;

/// A `Reducer` function is used to aggregate values for the novelty search
pub trait Reducer<T>: 'static + Debug
where
    T: Default + Copy + 'static,
{
    /// Reduce two values to one value, with the current [`Reducer`].
    fn reduce(first: T, second: T) -> T;
}

/// A [`OrReducer`] reduces the values returning the bitwise OR with the old value
#[derive(Clone, Debug)]
pub struct OrReducer {}

impl<T> Reducer<T> for OrReducer
where
    T: BitOr<Output = T> + Default + Copy + 'static + PartialOrd,
{
    #[inline]
    fn reduce(history: T, new: T) -> T {
        history | new
    }
}

/// A [`AndReducer`] reduces the values returning the bitwise AND with the old value
#[derive(Clone, Debug)]
pub struct AndReducer {}

impl<T> Reducer<T> for AndReducer
where
    T: BitAnd<Output = T> + Default + Copy + 'static + PartialOrd,
{
    #[inline]
    fn reduce(history: T, new: T) -> T {
        history & new
    }
}

/// A [`MaxReducer`] reduces int values and returns their maximum.
#[derive(Clone, Debug)]
pub struct MaxReducer {}

impl<T> Reducer<T> for MaxReducer
where
    T: Default + Copy + 'static + PartialOrd,
{
    #[inline]
    fn reduce(first: T, second: T) -> T {
        if first > second {
            first
        } else {
            second
        }
    }
}

/// A [`MinReducer`] reduces int values and returns their minimum.
#[derive(Clone, Debug)]
pub struct MinReducer {}

impl<T> Reducer<T> for MinReducer
where
    T: Default + Copy + 'static + PartialOrd,
{
    #[inline]
    fn reduce(first: T, second: T) -> T {
        if first < second {
            first
        } else {
            second
        }
    }
}

/// A `IsNovel` function is used to discriminate if a reduced value is considered novel.
pub trait IsNovel<T>: 'static + Debug
where
    T: Default + Copy + 'static,
{
    /// If a new value in the [`MapFeedback`] was found,
    /// this filter can decide if the result is considered novel or not.
    fn is_novel(old: T, new: T) -> bool;
}

/// [`AllIsNovel`] consider everything a novelty. Here mostly just for debugging.
#[derive(Clone, Debug)]
pub struct AllIsNovel {}

impl<T> IsNovel<T> for AllIsNovel
where
    T: Default + Copy + 'static,
{
    #[inline]
    fn is_novel(_old: T, _new: T) -> bool {
        true
    }
}

/// Calculate the next power of two
/// See <https://stackoverflow.com/a/66253960/1345238>
/// Will saturate at the max value.
/// In case of negative values, returns 1.
#[inline]
fn saturating_next_power_of_two<T: PrimInt>(n: T) -> T {
    if n <= T::one() {
        T::one()
    } else {
        (T::max_value() >> (n - T::one()).leading_zeros().try_into().unwrap())
            .saturating_add(T::one())
    }
}

/// Consider as novelty if the reduced value is different from the old value.
#[derive(Clone, Debug)]
pub struct DifferentIsNovel {}
impl<T> IsNovel<T> for DifferentIsNovel
where
    T: PartialEq + Default + Copy + 'static,
{
    #[inline]
    fn is_novel(old: T, new: T) -> bool {
        old != new
    }
}

/// Only consider as novel the values which are at least the next pow2 class of the old value
#[derive(Clone, Debug)]
pub struct NextPow2IsNovel {}
impl<T> IsNovel<T> for NextPow2IsNovel
where
    T: PrimInt + Default + Copy + 'static,
{
    #[inline]
    fn is_novel(old: T, new: T) -> bool {
        // We use a trait so we build our numbers from scratch here.
        // This way it works with Nums of any size.
        if new <= old {
            false
        } else {
            let pow2 = saturating_next_power_of_two(old.saturating_add(T::one()));
            new >= pow2
        }
    }
}

/// A filter that only saves values which are at least the next pow2 class
#[derive(Clone, Debug)]
pub struct OneOrFilledIsNovel {}
impl<T> IsNovel<T> for OneOrFilledIsNovel
where
    T: PrimInt + Default + Copy + 'static,
{
    #[inline]
    fn is_novel(old: T, new: T) -> bool {
        (new == T::one() || new == T::max_value()) && new > old
    }
}

/// A testcase metadata holding a list of indexes of a map
#[derive(Debug, Serialize, Deserialize)]
pub struct MapIndexesMetadata {
    /// The list of indexes.
    pub list: Vec<usize>,
    /// A refcount used to know when remove this meta
    pub tcref: isize,
}

crate::impl_serdeany!(MapIndexesMetadata);

impl AsSlice<usize> for MapIndexesMetadata {
    /// Convert to a slice
    fn as_slice(&self) -> &[usize] {
        self.list.as_slice()
    }
}
impl AsMutSlice<usize> for MapIndexesMetadata {
    /// Convert to a slice
    fn as_mut_slice(&mut self) -> &mut [usize] {
        self.list.as_mut_slice()
    }
}

impl HasRefCnt for MapIndexesMetadata {
    fn refcnt(&self) -> isize {
        self.tcref
    }

    fn refcnt_mut(&mut self) -> &mut isize {
        &mut self.tcref
    }
}

impl MapIndexesMetadata {
    /// Creates a new [`struct@MapIndexesMetadata`].
    #[must_use]
    pub fn new(list: Vec<usize>) -> Self {
        Self { list, tcref: 0 }
    }
}

/// A testcase metadata holding a list of indexes of a map
#[derive(Debug, Serialize, Deserialize)]
pub struct MapNoveltiesMetadata {
    /// A `list` of novelties.
    pub list: Vec<usize>,
}

crate::impl_serdeany!(MapNoveltiesMetadata);

impl AsSlice<usize> for MapNoveltiesMetadata {
    /// Convert to a slice
    #[must_use]
    fn as_slice(&self) -> &[usize] {
        self.list.as_slice()
    }
}
impl AsMutSlice<usize> for MapNoveltiesMetadata {
    /// Convert to a slice
    #[must_use]
    fn as_mut_slice(&mut self) -> &mut [usize] {
        self.list.as_mut_slice()
    }
}
impl MapNoveltiesMetadata {
    /// Creates a new [`struct@MapNoveltiesMetadata`]
    #[must_use]
    pub fn new(list: Vec<usize>) -> Self {
        Self { list }
    }
}

/// The state of [`MapFeedback`]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: DeserializeOwned")]
pub struct MapFeedbackMetadata<T>
where
    T: Default + Copy + 'static + Serialize,
{
    /// Contains information about untouched entries
    pub history_map: Vec<T>,
}

crate::impl_serdeany!(
    MapFeedbackMetadata<T: Debug + Default + Copy + 'static + Serialize + DeserializeOwned>,
    <u8>,<u16>,<u32>,<u64>,<i8>,<i16>,<i32>,<i64>,<f32>,<f64>,<bool>,<char>
);

impl<T> MapFeedbackMetadata<T>
where
    T: Default + Copy + 'static + Serialize + DeserializeOwned,
{
    /// Create new `MapFeedbackMetadata`
    #[must_use]
    pub fn new(map_size: usize) -> Self {
        Self {
            history_map: vec![T::default(); map_size],
        }
    }

    /// Create new `MapFeedbackMetadata` using a name and a map.
    /// The map can be shared.
    #[must_use]
    pub fn with_history_map(history_map: Vec<T>) -> Self {
        Self { history_map }
    }

    /// Reset the map
    pub fn reset(&mut self) -> Result<(), Error> {
        self.history_map.iter_mut().for_each(|x| *x = T::default());
        Ok(())
    }
}

/// The most common AFL-like feedback type
#[derive(Clone, Debug)]
pub struct MapFeedback<I, N, O, R, S, T>
where
    T: PartialEq + Default + Copy + 'static + Serialize + DeserializeOwned + Debug,
    R: Reducer<T>,
    O: MapObserver<Entry = T>,
    for<'it> O: AsRefIterator<'it, Item = T>,
    N: IsNovel<T>,
    S: HasNamedMetadata,
{
    /// Indexes used in the last observation
    indexes: Option<Vec<usize>>,
    /// New indexes observed in the last observation
    novelties: Option<Vec<usize>>,
    /// Name identifier of this instance
    name: String,
    /// Name identifier of the observer
    observer_name: String,
    /// Phantom Data of Reducer
    phantom: PhantomData<(I, N, S, R, O, T)>,
}

impl<I, N, O, R, S, T> Feedback<I, S> for MapFeedback<I, N, O, R, S, T>
where
    T: PartialEq + Default + Copy + 'static + Serialize + DeserializeOwned + Debug,
    R: Reducer<T>,
    O: MapObserver<Entry = T>,
    for<'it> O: AsRefIterator<'it, Item = T>,
    N: IsNovel<T>,
    I: Input,
    S: HasNamedMetadata + HasClientPerfMonitor + Debug,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        state.add_named_metadata(MapFeedbackMetadata::<T>::default(), &self.name);
        Ok(())
    }

    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        let mut interesting = false;
        // TODO Replace with match_name_type when stable
        let observer = observers.match_name::<O>(&self.observer_name).unwrap();
        let size = observer.usable_count();
        let initial = observer.initial();

        let map_state = state
            .named_metadata_mut()
            .get_mut::<MapFeedbackMetadata<T>>(&self.name)
            .unwrap();
        if map_state.history_map.len() < observer.len() {
            map_state.history_map.resize(observer.len(), T::default());
        }

        // assert!(size <= map_state.history_map.len(), "The size of the associated map observer cannot exceed the size of the history map of the feedback. If you are running multiple instances of slightly different fuzzers (e.g. one with ASan and another without) synchronized using LLMP please check the `configuration` field of the LLMP manager.");

        assert!(size <= observer.len());

        if self.novelties.is_some() {
            for (i, &item) in observer.as_ref_iter().enumerate() {
                let history = map_state.history_map[i];
                let reduced = R::reduce(history, item);
                if N::is_novel(history, reduced) {
                    map_state.history_map[i] = reduced;
                    interesting = true;
                    self.novelties.as_mut().unwrap().push(i);
                }
            }
        } else {
            for (i, &item) in observer.as_ref_iter().enumerate() {
                let history = map_state.history_map[i];
                let reduced = R::reduce(history, item);
                if N::is_novel(history, reduced) {
                    map_state.history_map[i] = reduced;
                    interesting = true;
                }
            }
        }

        if interesting {
            let mut filled = 0;
            for i in 0..size {
                if map_state.history_map[i] != initial {
                    filled += 1;
                    if self.indexes.is_some() {
                        self.indexes.as_mut().unwrap().push(i);
                    }
                }
            }
            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: self.name.to_string(),
                    value: UserStats::Ratio(filled, size as u64),
                    phantom: PhantomData,
                },
            )?;
        }

        Ok(interesting)
    }

    fn append_metadata(&mut self, _state: &mut S, testcase: &mut Testcase<I>) -> Result<(), Error> {
        if let Some(v) = self.indexes.as_mut() {
            let meta = MapIndexesMetadata::new(core::mem::take(v));
            testcase.add_metadata(meta);
        };
        if let Some(v) = self.novelties.as_mut() {
            let meta = MapNoveltiesMetadata::new(core::mem::take(v));
            testcase.add_metadata(meta);
        };
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        if let Some(v) = self.indexes.as_mut() {
            v.clear();
        }
        if let Some(v) = self.novelties.as_mut() {
            v.clear();
        }
        Ok(())
    }
}

impl<I, N, O, R, S, T> Named for MapFeedback<I, N, O, R, S, T>
where
    T: PartialEq + Default + Copy + 'static + Serialize + DeserializeOwned + Debug,
    R: Reducer<T>,
    N: IsNovel<T>,
    O: MapObserver<Entry = T>,
    for<'it> O: AsRefIterator<'it, Item = T>,
    S: HasNamedMetadata,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<I, N, O, R, S, T> HasObserverName for MapFeedback<I, N, O, R, S, T>
where
    T: PartialEq + Default + Copy + 'static + Serialize + DeserializeOwned + Debug,
    R: Reducer<T>,
    N: IsNovel<T>,
    O: MapObserver<Entry = T>,
    for<'it> O: AsRefIterator<'it, Item = T>,
    S: HasNamedMetadata,
{
    #[inline]
    fn observer_name(&self) -> &str {
        self.observer_name.as_str()
    }
}

impl<I, N, O, R, S, T> MapFeedback<I, N, O, R, S, T>
where
    T: PartialEq + Default + Copy + 'static + Serialize + DeserializeOwned + Debug,
    R: Reducer<T>,
    N: IsNovel<T>,
    O: MapObserver<Entry = T>,
    for<'it> O: AsRefIterator<'it, Item = T>,
    S: HasNamedMetadata,
{
    /// Create new `MapFeedback`
    #[must_use]
    pub fn new(map_observer: &O) -> Self {
        Self {
            indexes: None,
            novelties: None,
            name: MAPFEEDBACK_PREFIX.to_string() + map_observer.name(),
            observer_name: map_observer.name().to_string(),
            phantom: PhantomData,
        }
    }

    /// Create new `MapFeedback` specifying if it must track indexes of used entries and/or novelties
    #[must_use]
    pub fn new_tracking(map_observer: &O, track_indexes: bool, track_novelties: bool) -> Self {
        Self {
            indexes: if track_indexes { Some(vec![]) } else { None },
            novelties: if track_novelties { Some(vec![]) } else { None },
            name: MAPFEEDBACK_PREFIX.to_string() + map_observer.name(),
            observer_name: map_observer.name().to_string(),
            phantom: PhantomData,
        }
    }

    /// Create new `MapFeedback`
    #[must_use]
    pub fn with_names(name: &'static str, observer_name: &'static str) -> Self {
        Self {
            indexes: None,
            novelties: None,
            name: name.to_string(),
            observer_name: observer_name.to_string(),
            phantom: PhantomData,
        }
    }

    /// Create new `MapFeedback` specifying if it must track indexes of used entries and/or novelties
    #[must_use]
    pub fn with_names_tracking(
        name: &'static str,
        observer_name: &'static str,
        track_indexes: bool,
        track_novelties: bool,
    ) -> Self {
        Self {
            indexes: if track_indexes { Some(vec![]) } else { None },
            novelties: if track_novelties { Some(vec![]) } else { None },
            observer_name: observer_name.to_string(),
            name: name.to_string(),
            phantom: PhantomData,
        }
    }
}

/// A [`ReachabilityFeedback`] reports if a target has been reached.
#[derive(Clone, Debug)]
pub struct ReachabilityFeedback<O> {
    name: String,
    target_idx: Vec<usize>,
    phantom: PhantomData<O>,
}

impl<O> ReachabilityFeedback<O>
where
    O: MapObserver<Entry = usize>,
    for<'it> O: AsRefIterator<'it, Item = usize>,
{
    /// Creates a new [`ReachabilityFeedback`] for a [`MapObserver`].
    #[must_use]
    pub fn new(map_observer: &O) -> Self {
        Self {
            name: map_observer.name().to_string(),
            target_idx: vec![],
            phantom: PhantomData,
        }
    }

    /// Creates a new [`ReachabilityFeedback`] for a [`MapObserver`] with the given `name`.
    #[must_use]
    pub fn with_name(name: &'static str) -> Self {
        Self {
            name: name.to_string(),
            target_idx: vec![],
            phantom: PhantomData,
        }
    }
}

impl<I, O, S> Feedback<I, S> for ReachabilityFeedback<O>
where
    I: Input,
    O: MapObserver<Entry = usize>,
    for<'it> O: AsRefIterator<'it, Item = usize>,
    S: HasClientPerfMonitor,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        // TODO Replace with match_name_type when stable
        let observer = observers.match_name::<O>(&self.name).unwrap();
        let mut hit_target: bool = false;
        //check if we've hit any targets.
        for (i, &elem) in observer.as_ref_iter().enumerate() {
            if elem > 0 {
                self.target_idx.push(i);
                hit_target = true;
            }
        }
        if hit_target {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn append_metadata(&mut self, _state: &mut S, testcase: &mut Testcase<I>) -> Result<(), Error> {
        if !self.target_idx.is_empty() {
            let meta = MapIndexesMetadata::new(core::mem::take(self.target_idx.as_mut()));
            testcase.add_metadata(meta);
        };
        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.target_idx.clear();
        Ok(())
    }
}

impl<O> Named for ReachabilityFeedback<O>
where
    O: MapObserver<Entry = usize>,
    for<'it> O: AsRefIterator<'it, Item = usize>,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

#[cfg(test)]
mod tests {
    use crate::feedbacks::{AllIsNovel, IsNovel, NextPow2IsNovel};

    #[test]
    fn test_map_is_novel() {
        // sanity check
        assert!(AllIsNovel::is_novel(0_u8, 0));

        assert!(!NextPow2IsNovel::is_novel(0_u8, 0));
        assert!(NextPow2IsNovel::is_novel(0_u8, 1));
        assert!(!NextPow2IsNovel::is_novel(1_u8, 1));
        assert!(NextPow2IsNovel::is_novel(1_u8, 2));
        assert!(!NextPow2IsNovel::is_novel(2_u8, 2));
        assert!(!NextPow2IsNovel::is_novel(2_u8, 3));
        assert!(NextPow2IsNovel::is_novel(2_u8, 4));
        assert!(!NextPow2IsNovel::is_novel(128_u8, 128));
        assert!(!NextPow2IsNovel::is_novel(129_u8, 128));
        assert!(NextPow2IsNovel::is_novel(128_u8, 255));
        assert!(!NextPow2IsNovel::is_novel(255_u8, 128));
        assert!(NextPow2IsNovel::is_novel(254_u8, 255));
        assert!(!NextPow2IsNovel::is_novel(255_u8, 255));
    }
}

/// `MapFeedback` Python bindings
#[cfg(feature = "python")]
pub mod pybind {
    use crate::bolts::{tuples::Named, AsMutIterator, AsRefIterator, HasLen};
    use crate::observers::{map::OwnedMapObserver, MapObserver, Observer};
    use crate::Error;
    use pyo3::prelude::*;
    use serde::{Deserialize, Serialize};
    use std::slice::{Iter, IterMut};

    macro_rules! define_python_map_observer {
        ($struct_name:ident, $py_name:tt, $struct_name_trait:ident, $py_name_trait:tt, $datatype:ty, $wrapper_name: ident) => {
            #[pyclass(unsendable, name = $py_name)]
            #[derive(Serialize, Deserialize, Debug, Clone)]
            /// Python class for OwnedMapObserver (i.e. StdMapObserver with owned map)
            pub struct $struct_name {
                /// Rust wrapped OwnedMapObserver object
                pub inner: OwnedMapObserver<$datatype>,
            }

            #[pymethods]
            impl $struct_name {
                #[new]
                fn new(name: String, map: Vec<$datatype>) -> Self {
                    Self {
                        //TODO: Not leak memory
                        inner: OwnedMapObserver::new(Box::leak(name.into_boxed_str()), map),
                    }
                }
            }

            #[derive(Serialize, Deserialize, Debug, Clone)]
            enum $wrapper_name {
                Owned($struct_name),
            }

            // Should not be exposed to user
            #[pyclass(unsendable, name = $py_name_trait)]
            #[derive(Serialize, Deserialize, Debug, Clone)]
            /// MapObserver + Observer Trait binding
            pub struct $struct_name_trait {
                pub wrapper: $wrapper_name,
            }

            impl $struct_name_trait {
                fn unwrap(&self) -> &impl MapObserver<Entry = $datatype> {
                    unsafe {
                        match &self.wrapper {
                            $wrapper_name::Owned(py_wrapper) => &py_wrapper.inner,
                        }
                    }
                }

                fn unwrap_mut(&mut self) -> &mut impl MapObserver<Entry = $datatype> {
                    unsafe {
                        match &mut self.wrapper {
                            $wrapper_name::Owned(py_wrapper) => &mut py_wrapper.inner,
                        }
                    }
                }

                fn upcast<S>(&self) -> &impl Observer<BytesInput, S> {
                    unsafe {
                        match &self.wrapper {
                            $wrapper_name::Owned(py_wrapper) => &py_wrapper.inner,
                        }
                    }
                }

                fn upcast_mut<S>(&mut self) -> &mut impl Observer<BytesInput, S> {
                    unsafe {
                        match &mut self.wrapper {
                            $wrapper_name::Owned(py_wrapper) => &mut py_wrapper.inner,
                        }
                    }
                }
            }

            #[pymethods]
            impl $struct_name_trait {
                #[staticmethod]
                fn new_from_owned(owned_map: $struct_name) -> Self {
                    Self {
                        wrapper: $wrapper_name::Owned(owned_map),
                    }
                }
            }

            impl<'it> AsRefIterator<'it> for $struct_name_trait {
                type Item = $datatype;
                type IntoIter = Iter<'it, $datatype>;

                fn as_ref_iter(&'it self) -> Self::IntoIter {
                    match &self.wrapper {
                        $wrapper_name::Owned(py_wrapper) => py_wrapper.inner.as_ref_iter(),
                    }
                }
            }

            impl<'it> AsMutIterator<'it> for $struct_name_trait {
                type Item = $datatype;
                type IntoIter = IterMut<'it, $datatype>;

                fn as_mut_iter(&'it mut self) -> Self::IntoIter {
                    match &mut self.wrapper {
                        $wrapper_name::Owned(py_wrapper) => py_wrapper.inner.as_mut_iter(),
                    }
                }
            }

            impl MapObserver for $struct_name_trait {
                type Entry = $datatype;

                #[inline]
                fn get(&self, idx: usize) -> &$datatype {
                    match &self.wrapper {
                        $wrapper_name::Owned(py_wrapper) => &py_wrapper.inner.get(idx),
                    }
                }

                #[inline]
                fn get_mut(&mut self, idx: usize) -> &mut $datatype {
                    match &mut self.wrapper {
                        $wrapper_name::Owned(py_wrapper) => py_wrapper.inner.get_mut(idx),
                    }
                }

                #[inline]
                fn usable_count(&self) -> usize {
                    match &self.wrapper {
                        $wrapper_name::Owned(py_wrapper) => py_wrapper.wrapper.usable_count(),
                    }
                }

                fn hash(&self) -> u64 {
                    match &self.wrapper {
                        $wrapper_name::Owned(py_wrapper) => py_wrapper.inner.hash(),
                    }
                }

                #[inline]
                fn initial(&self) -> $datatype {
                    match &self.wrapper {
                        $wrapper_name::Owned(py_wrapper) => py_wrapper.inner.initial(),
                    }
                }

                #[inline]
                fn initial_mut(&mut self) -> &mut $datatype {
                    match &mut self.wrapper {
                        $wrapper_name::Owned(py_wrapper) => py_wrapper.inner.initial_mut(),
                    }
                }

                #[inline]
                fn set_initial(&mut self, initial: $datatype) {
                    match &mut self.wrapper {
                        $wrapper_name::Owned(py_wrapper) => {
                            py_wrapper.inner.set_initial(initial);
                        }
                    }
                }

                fn to_vec(&self) -> Vec<$datatype> {
                    match &self.wrapper {
                        $wrapper_name::Owned(py_wrapper) => py_wrapper.inner.to_vec(),
                    }
                }
            }

            impl Named for $struct_name_trait {
                #[inline]
                fn name(&self) -> &str {
                    match &self.wrapper {
                        $wrapper_name::Owned(py_wrapper) => py_wrapper.inner.name(),
                    }
                }
            }

            impl HasLen for $struct_name_trait {
                #[inline]
                fn len(&self) -> usize {
                    match &self.wrapper {
                        $wrapper_name::Owned(py_wrapper) => py_wrapper.inner.len(),
                    }
                }
            }

            impl<I, S> Observer<I, S> for $struct_name_trait
            where
                Self: MapObserver,
            {
                #[inline]
                fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
                    match &mut self.wrapper {
                        $wrapper_name::Owned(py_wrapper) => {
                            py_wrapper.inner.pre_exec(_state, _input)
                        }
                    }
                }
            }
        };
    }

    define_python_map_observer!(
        PythonOwnedMapObserverI8,
        "OwnedMapObserverI8",
        PythonMapObserverI8,
        "MapObserverI8",
        i8,
        PythonMapObserverWrapperI8
    );
    define_python_map_observer!(
        PythonOwnedMapObserverI16,
        "OwnedMapObserverI16",
        PythonMapObserverI16,
        "MapObserverI16",
        i16,
        PythonMapObserverWrapperI16
    );
    define_python_map_observer!(
        PythonOwnedMapObserverI32,
        "OwnedMapObserverI32",
        PythonMapObserverI32,
        "MapObserverI32",
        i32,
        PythonMapObserverWrapperI32
    );
    define_python_map_observer!(
        PythonOwnedMapObserverI64,
        "OwnedMapObserverI64",
        PythonMapObserverI64,
        "MapObserverI64",
        i64,
        PythonMapObserverWrapperI64
    );

    define_python_map_observer!(
        PythonOwnedMapObserverU8,
        "OwnedMapObserverU8",
        PythonMapObserverU8,
        "MapObserverU8",
        u8,
        PythonMapObserverWrapperU8
    );
    define_python_map_observer!(
        PythonOwnedMapObserverU16,
        "OwnedMapObserverU16",
        PythonMapObserverU16,
        "MapObserverU16",
        u16,
        PythonMapObserverWrapperU16
    );
    define_python_map_observer!(
        PythonOwnedMapObserverU32,
        "OwnedMapObserverU32",
        PythonMapObserverU32,
        "MapObserverU32",
        u32,
        PythonMapObserverWrapperU32
    );
    define_python_map_observer!(
        PythonOwnedMapObserverU64,
        "OwnedMapObserverU64",
        PythonMapObserverU64,
        "MapObserverU64",
        u64,
        PythonMapObserverWrapperU64
    );

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonOwnedMapObserverI8>()?;
        m.add_class::<PythonMapObserverI8>()?;
        m.add_class::<PythonOwnedMapObserverI16>()?;
        m.add_class::<PythonMapObserverI16>()?;
        m.add_class::<PythonOwnedMapObserverI32>()?;
        m.add_class::<PythonMapObserverI32>()?;
        m.add_class::<PythonOwnedMapObserverI64>()?;
        m.add_class::<PythonMapObserverI64>()?;

        m.add_class::<PythonOwnedMapObserverU8>()?;
        m.add_class::<PythonMapObserverU8>()?;
        m.add_class::<PythonOwnedMapObserverU16>()?;
        m.add_class::<PythonMapObserverU16>()?;
        m.add_class::<PythonOwnedMapObserverU32>()?;
        m.add_class::<PythonMapObserverU32>()?;
        m.add_class::<PythonOwnedMapObserverU64>()?;
        m.add_class::<PythonMapObserverU64>()?;
        Ok(())
    }
}

#[cfg(feature = "python")]
/// Map Feedback Python bindings
pub mod pybind {
    use crate::feedbacks::map::{MapFeedbackMetadata, MaxMapFeedback};
    use crate::inputs::BytesInput;
    use pyo3::prelude::*;

    macro_rules! define_python_map_feedback {
        ($map_feedback_state_struct_name:ident, $map_feedback_state_py_name:tt, $max_map_feedback_struct_name:ident,
            $max_map_feedback_py_name:tt, $datatype:ty, $map_observer_name: ident, $std_state_name: ident) => {
            use crate::observers::map::pybind::$map_observer_name;
            use crate::state::pybind::$std_state_name;

            #[pyclass(unsendable, name = $map_feedback_state_py_name)]
            #[derive(Clone, Debug)]
            /// Python class for MapFeedbackMetadata
            pub struct $map_feedback_state_struct_name {
                /// Rust wrapped MapFeedbackMetadata object
                pub map_feedback_state: MapFeedbackMetadata<$datatype>,
            }

            #[pymethods]
            impl $map_feedback_state_struct_name {
                #[staticmethod]
                fn with_observer(py_observer: &$map_observer_name) -> Self {
                    Self {
                        map_feedback_state: MapFeedbackMetadata::with_observer(py_observer),
                    }
                }
            }

            #[pyclass(unsendable, name = $max_map_feedback_py_name)]
            #[derive(Debug)]
            /// Python class for MaxMapFeedback
            pub struct $max_map_feedback_struct_name {
                /// Rust wrapped MaxMapFeedback object
                pub max_map_feedback:
                    MaxMapFeedback<BytesInput, $map_observer_name, $std_state_name, $datatype>,
            }

            impl Clone for $max_map_feedback_struct_name {
                fn clone(&self) -> Self {
                    Self {
                        max_map_feedback: self.max_map_feedback.clone(),
                    }
                }
            }

            #[pymethods]
            impl $max_map_feedback_struct_name {
                #[new]
                fn new(
                    py_feedback_state: &$map_feedback_state_struct_name,
                    py_observer: &$map_observer_name,
                ) -> Self {
                    Self {
                        max_map_feedback: MaxMapFeedback::new(
                            &py_feedback_state.map_feedback_state,
                            py_observer,
                        ),
                    }
                }
            }
        };
    }

    define_python_map_feedback!(
        PythonMapFeedbackMetadataI8,
        "MapFeedbackMetadataI8",
        PythonMaxMapFeedbackI8,
        "MaxMapFeedbackI8",
        i8,
        PythonMapObserverI8,
        MyStdStateI8
    );

    define_python_map_feedback!(
        PythonMapFeedbackMetadataI16,
        "MapFeedbackMetadataI16",
        PythonMaxMapFeedbackI16,
        "MaxMapFeedbackI16",
        i16,
        PythonMapObserverI16,
        MyStdStateI16
    );
    define_python_map_feedback!(
        PythonMapFeedbackMetadataI32,
        "MapFeedbackMetadataI32",
        PythonMaxMapFeedbackI32,
        "MaxMapFeedbackI32",
        i32,
        PythonMapObserverI32,
        MyStdStateI32
    );
    define_python_map_feedback!(
        PythonMapFeedbackMetadataI64,
        "MapFeedbackMetadataI64",
        PythonMaxMapFeedbackI64,
        "MaxMapFeedbackI64",
        i64,
        PythonMapObserverI64,
        MyStdStateI64
    );

    define_python_map_feedback!(
        PythonMapFeedbackMetadataU8,
        "MapFeedbackMetadataU8",
        PythonMaxMapFeedbackU8,
        "MaxMapFeedbackU8",
        u8,
        PythonMapObserverU8,
        MyStdStateU8
    );

    define_python_map_feedback!(
        PythonMapFeedbackMetadataU16,
        "MapFeedbackMetadataU16",
        PythonMaxMapFeedbackU16,
        "MaxMapFeedbackU16",
        u16,
        PythonMapObserverU16,
        MyStdStateU16
    );
    define_python_map_feedback!(
        PythonMapFeedbackMetadataU32,
        "MapFeedbackMetadataU32",
        PythonMaxMapFeedbackU32,
        "MaxMapFeedbackU32",
        u32,
        PythonMapObserverU32,
        MyStdStateU32
    );
    define_python_map_feedback!(
        PythonMapFeedbackMetadataU64,
        "MapFeedbackMetadataU64",
        PythonMaxMapFeedbackU64,
        "MaxMapFeedbackU64",
        u64,
        PythonMapObserverU64,
        MyStdStateU64
    );

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonMapFeedbackMetadataI8>()?;
        m.add_class::<PythonMapFeedbackMetadataI16>()?;
        m.add_class::<PythonMapFeedbackMetadataI32>()?;
        m.add_class::<PythonMapFeedbackMetadataI64>()?;

        m.add_class::<PythonMapFeedbackMetadataU8>()?;
        m.add_class::<PythonMapFeedbackMetadataU16>()?;
        m.add_class::<PythonMapFeedbackMetadataU32>()?;
        m.add_class::<PythonMapFeedbackMetadataU64>()?;

        m.add_class::<PythonMaxMapFeedbackI8>()?;
        m.add_class::<PythonMaxMapFeedbackI16>()?;
        m.add_class::<PythonMaxMapFeedbackI32>()?;
        m.add_class::<PythonMaxMapFeedbackI64>()?;

        m.add_class::<PythonMaxMapFeedbackU8>()?;
        m.add_class::<PythonMaxMapFeedbackU16>()?;
        m.add_class::<PythonMaxMapFeedbackU32>()?;
        m.add_class::<PythonMaxMapFeedbackU64>()?;
        Ok(())
    }
}
