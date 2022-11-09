//! Map feedback, maximizing or minimizing maps, for example the afl-style map observer.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
#[rustversion::nightly]
use core::simd::SimdOrd;
use core::{
    fmt::Debug,
    marker::PhantomData,
    ops::{BitAnd, BitOr},
};

use num_traits::PrimInt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    bolts::{tuples::Named, AsIter, AsMutSlice, AsSlice, HasRefCnt},
    corpus::Testcase,
    events::{Event, EventFirer},
    executors::ExitKind,
    feedbacks::{Feedback, HasObserverName},
    inputs::UsesInput,
    monitors::UserStats,
    observers::{MapObserver, ObserversTuple},
    state::{HasClientPerfMonitor, HasMetadata, HasNamedMetadata},
    Error,
};

/// The prefix of the metadata names
pub const MAPFEEDBACK_PREFIX: &str = "mapfeedback_metadata_";

/// A [`MapFeedback`] that implements the AFL algorithm using an [`OrReducer`] combining the bits for the history map and the bit from ``HitcountsMapObserver``.
pub type AflMapFeedback<O, S, T> = MapFeedback<DifferentIsNovel, O, OrReducer, S, T>;

/// A [`MapFeedback`] that strives to maximize the map contents.
pub type MaxMapFeedback<O, S, T> = MapFeedback<DifferentIsNovel, O, MaxReducer, S, T>;
/// A [`MapFeedback`] that strives to minimize the map contents.
pub type MinMapFeedback<O, S, T> = MapFeedback<DifferentIsNovel, O, MinReducer, S, T>;

/// A [`MapFeedback`] that strives to maximize the map contents,
/// but only, if a value is larger than `pow2` of the previous.
pub type MaxMapPow2Feedback<O, S, T> = MapFeedback<NextPow2IsNovel, O, MaxReducer, S, T>;
/// A [`MapFeedback`] that strives to maximize the map contents,
/// but only, if a value is larger than `pow2` of the previous.
pub type MaxMapOneOrFilledFeedback<O, S, T> = MapFeedback<OneOrFilledIsNovel, O, MaxReducer, S, T>;

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

impl AsSlice for MapIndexesMetadata {
    type Entry = usize;
    /// Convert to a slice
    fn as_slice(&self) -> &[usize] {
        self.list.as_slice()
    }
}
impl AsMutSlice for MapIndexesMetadata {
    type Entry = usize;
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

impl AsSlice for MapNoveltiesMetadata {
    type Entry = usize;
    /// Convert to a slice
    #[must_use]
    fn as_slice(&self) -> &[usize] {
        self.list.as_slice()
    }
}
impl AsMutSlice for MapNoveltiesMetadata {
    type Entry = usize;
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
        let cnt = self.history_map.len();
        for i in 0..cnt {
            self.history_map[i] = T::default();
        }
        Ok(())
    }

    /// Reset the map with any value
    pub fn reset_with_value(&mut self, value: T) -> Result<(), Error> {
        let cnt = self.history_map.len();
        for i in 0..cnt {
            self.history_map[i] = value;
        }
        Ok(())
    }
}

/// The most common AFL-like feedback type
#[derive(Clone, Debug)]
pub struct MapFeedback<N, O, R, S, T> {
    /// Indexes used in the last observation
    indexes: Option<Vec<usize>>,
    /// New indexes observed in the last observation
    novelties: Option<Vec<usize>>,
    /// Name identifier of this instance
    name: String,
    /// Name identifier of the observer
    observer_name: String,
    /// Name of the feedback as shown in the `UserStats`
    stats_name: String,
    /// Phantom Data of Reducer
    phantom: PhantomData<(N, O, R, S, T)>,
}

impl<N, O, R, S, T> Feedback<S> for MapFeedback<N, O, R, S, T>
where
    N: IsNovel<T> + Debug,
    O: MapObserver<Entry = T> + for<'it> AsIter<'it, Item = T> + Debug,
    R: Reducer<T> + Debug,
    S: UsesInput + HasClientPerfMonitor + HasNamedMetadata + Debug,
    T: Default + Copy + Serialize + for<'de> Deserialize<'de> + PartialEq + Debug + 'static,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        // Initialize `MapFeedbackMetadata` with an empty vector and add it to the state.
        // The `MapFeedbackMetadata` would be resized on-demand in `is_interesting`
        state.add_named_metadata(MapFeedbackMetadata::<T>::default(), &self.name);
        Ok(())
    }

    #[rustversion::nightly]
    default fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &<S as UsesInput>::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        self.is_interesting_default(state, manager, input, observers, exit_kind)
    }

    #[rustversion::not(nightly)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &<S as UsesInput>::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        self.is_interesting_default(state, manager, input, observers, exit_kind)
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        testcase: &mut Testcase<<S as UsesInput>::Input>,
    ) -> Result<(), Error> {
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
    fn discard_metadata(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
    ) -> Result<(), Error> {
        if let Some(v) = self.indexes.as_mut() {
            v.clear();
        }
        if let Some(v) = self.novelties.as_mut() {
            v.clear();
        }
        Ok(())
    }
}

/// Specialize for the common coverage map size, maximization of u8s
#[rustversion::nightly]
impl<O, S> Feedback<S> for MapFeedback<DifferentIsNovel, O, MaxReducer, S, u8>
where
    O: MapObserver<Entry = u8> + AsSlice<Entry = u8>,
    for<'it> O: AsIter<'it, Item = u8>,
    S: UsesInput + HasNamedMetadata + HasClientPerfMonitor + Debug,
{
    #[allow(clippy::wrong_self_convention)]
    #[allow(clippy::needless_range_loop)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        _input: &<S as UsesInput>::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        // 128 bits vectors
        type VectorType = core::simd::u8x16;

        let mut interesting = false;
        // TODO Replace with match_name_type when stable
        let observer = observers.match_name::<O>(&self.observer_name).unwrap();

        let map_state = state
            .named_metadata_mut()
            .get_mut::<MapFeedbackMetadata<u8>>(&self.name)
            .unwrap();
        let size = observer.usable_count();
        let len = observer.len();
        if map_state.history_map.len() < len {
            map_state.history_map.resize(len, u8::default());
        }

        let map = observer.as_slice();
        debug_assert!(map.len() >= size);

        let history_map = map_state.history_map.as_mut_slice();

        // Non vector implementation for reference
        /*for (i, history) in history_map.iter_mut().enumerate() {
            let item = map[i];
            let reduced = MaxReducer::reduce(*history, item);
            if DifferentIsNovel::is_novel(*history, reduced) {
                *history = reduced;
                interesting = true;
                if self.novelties.is_some() {
                    self.novelties.as_mut().unwrap().push(i);
                }
            }
        }*/

        let steps = size / VectorType::LANES;
        let left = size % VectorType::LANES;

        for step in 0..steps {
            let i = step * VectorType::LANES;
            let history = VectorType::from_slice(&history_map[i..]);
            let items = VectorType::from_slice(&map[i..]);

            if items.simd_max(history) != history {
                interesting = true;
                unsafe {
                    for j in i..(i + VectorType::LANES) {
                        let item = *map.get_unchecked(j);
                        if item > *history_map.get_unchecked(j) {
                            *history_map.get_unchecked_mut(j) = item;
                            if self.novelties.is_some() {
                                self.novelties.as_mut().unwrap().push(j);
                            }
                        }
                    }
                }
            }
        }

        for j in (size - left)..size {
            unsafe {
                let item = *map.get_unchecked(j);
                if item > *history_map.get_unchecked(j) {
                    interesting = true;
                    *history_map.get_unchecked_mut(j) = item;
                    if self.novelties.is_some() {
                        self.novelties.as_mut().unwrap().push(j);
                    }
                }
            }
        }

        let initial = observer.initial();
        if interesting {
            let len = history_map.len();
            let mut filled = 0;
            for i in 0..len {
                if history_map[i] != initial {
                    filled += 1;
                    if self.indexes.is_some() {
                        self.indexes.as_mut().unwrap().push(i);
                    }
                }
            }
            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: self.stats_name.to_string(),
                    value: UserStats::Ratio(filled, len as u64),
                    phantom: PhantomData,
                },
            )?;
        }

        Ok(interesting)
    }
}

impl<N, O, R, S, T> Named for MapFeedback<N, O, R, S, T> {
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<N, O, R, S, T> HasObserverName for MapFeedback<N, O, R, S, T>
where
    T: PartialEq + Default + Copy + 'static + Serialize + DeserializeOwned + Debug,
    R: Reducer<T>,
    N: IsNovel<T>,
    O: MapObserver<Entry = T>,
    for<'it> O: AsIter<'it, Item = T>,
    S: HasNamedMetadata,
{
    #[inline]
    fn observer_name(&self) -> &str {
        self.observer_name.as_str()
    }
}

fn create_stats_name(name: &str) -> String {
    name.to_lowercase()
}

impl<N, O, R, S, T> MapFeedback<N, O, R, S, T>
where
    T: PartialEq + Default + Copy + 'static + Serialize + DeserializeOwned + Debug,
    R: Reducer<T>,
    O: MapObserver<Entry = T>,
    for<'it> O: AsIter<'it, Item = T>,
    N: IsNovel<T>,
    S: UsesInput + HasNamedMetadata + HasClientPerfMonitor + Debug,
{
    /// Create new `MapFeedback`
    #[must_use]
    pub fn new(map_observer: &O) -> Self {
        Self {
            indexes: None,
            novelties: None,
            name: MAPFEEDBACK_PREFIX.to_string() + map_observer.name(),
            observer_name: map_observer.name().to_string(),
            stats_name: create_stats_name(map_observer.name()),
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
            stats_name: create_stats_name(map_observer.name()),
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
            stats_name: create_stats_name(name),
            phantom: PhantomData,
        }
    }

    /// Creating a new `MapFeedback` with a specific name. This is usefully whenever the same
    /// feedback is needed twice, but with a different history. Using `new()` always results in the
    /// same name and therefore also the same history.
    #[must_use]
    pub fn with_name(name: &'static str, map_observer: &O) -> Self {
        Self {
            indexes: None,
            novelties: None,
            name: name.to_string(),
            observer_name: map_observer.name().to_string(),
            stats_name: create_stats_name(name),
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
            stats_name: create_stats_name(name),
            name: name.to_string(),
            phantom: PhantomData,
        }
    }

    #[allow(clippy::wrong_self_convention)]
    #[allow(clippy::needless_range_loop)]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn is_interesting_default<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let mut interesting = false;
        // TODO Replace with match_name_type when stable
        let observer = observers.match_name::<O>(&self.observer_name).unwrap();

        let map_state = state
            .named_metadata_mut()
            .get_mut::<MapFeedbackMetadata<T>>(&self.name)
            .unwrap();
        let len = observer.len();
        if map_state.history_map.len() < len {
            map_state.history_map.resize(len, observer.initial());
        }

        let history_map = map_state.history_map.as_mut_slice();

        for (i, (item, history)) in observer.as_iter().zip(history_map.iter_mut()).enumerate() {
            let reduced = R::reduce(*history, *item);
            if N::is_novel(*history, reduced) {
                *history = reduced;
                interesting = true;
                if self.novelties.is_some() {
                    self.novelties.as_mut().unwrap().push(i);
                }
            }
        }

        let initial = observer.initial();
        if interesting {
            let len = history_map.len();
            let mut filled = 0;
            for i in 0..len {
                if history_map[i] != initial {
                    filled += 1;
                    if self.indexes.is_some() {
                        self.indexes.as_mut().unwrap().push(i);
                    }
                }
            }
            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: self.stats_name.to_string(),
                    value: UserStats::Ratio(filled, len as u64),
                    phantom: PhantomData,
                },
            )?;
        }

        Ok(interesting)
    }
}

/// A [`ReachabilityFeedback`] reports if a target has been reached.
#[derive(Clone, Debug)]
pub struct ReachabilityFeedback<O, S> {
    name: String,
    target_idx: Vec<usize>,
    phantom: PhantomData<(O, S)>,
}

impl<O, S> ReachabilityFeedback<O, S>
where
    O: MapObserver<Entry = usize>,
    for<'it> O: AsIter<'it, Item = usize>,
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

impl<O, S> Feedback<S> for ReachabilityFeedback<O, S>
where
    S: UsesInput + Debug + HasClientPerfMonitor,
    O: MapObserver<Entry = usize>,
    for<'it> O: AsIter<'it, Item = usize>,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &<S as UsesInput>::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        // TODO Replace with match_name_type when stable
        let observer = observers.match_name::<O>(&self.name).unwrap();
        let mut hit_target: bool = false;
        //check if we've hit any targets.
        for (i, &elem) in observer.as_iter().enumerate() {
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

    fn append_metadata(
        &mut self,
        _state: &mut S,
        testcase: &mut Testcase<<S as UsesInput>::Input>,
    ) -> Result<(), Error> {
        if !self.target_idx.is_empty() {
            let meta = MapIndexesMetadata::new(core::mem::take(self.target_idx.as_mut()));
            testcase.add_metadata(meta);
        };
        Ok(())
    }

    fn discard_metadata(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
    ) -> Result<(), Error> {
        self.target_idx.clear();
        Ok(())
    }
}

impl<O, S> Named for ReachabilityFeedback<O, S>
where
    O: MapObserver<Entry = usize>,
    for<'it> O: AsIter<'it, Item = usize>,
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
#[allow(missing_docs)]
pub mod pybind {
    use concat_idents::concat_idents;
    use pyo3::prelude::*;

    use super::{Debug, HasObserverName, MaxMapFeedback};
    use crate::{feedbacks::pybind::PythonFeedback, state::pybind::PythonStdState};

    macro_rules! define_python_map_feedback {
        ($struct_name:ident, $py_name:tt, $datatype:ty, $map_observer_type_name: ident, $my_std_state_type_name: ident) => {
            use crate::observers::map::pybind::$map_observer_type_name;

            #[pyclass(unsendable, name = $py_name)]
            #[derive(Debug, Clone)]
            /// Python class for MaxMapFeedback
            pub struct $struct_name {
                /// Rust wrapped MaxMapFeedback object
                pub inner: MaxMapFeedback<
                    $map_observer_type_name, /* PythonMapObserverI8 */
                    $my_std_state_type_name,
                    $datatype,
                >,
            }

            #[pymethods]
            impl $struct_name {
                #[new]
                fn new(observer: &$map_observer_type_name) -> Self {
                    Self {
                        inner: MaxMapFeedback::new(observer),
                    }
                }

                #[must_use]
                pub fn as_feedback(slf: Py<Self>) -> PythonFeedback {
                    concat_idents!(func = new_max_map_,$datatype {
                           PythonFeedback::func(slf)
                    })
                }
            }

            impl HasObserverName for $struct_name {
                fn observer_name(&self) -> &str {
                    self.inner.observer_name()
                }
            }
        };
    }

    define_python_map_feedback!(
        PythonMaxMapFeedbackI8,
        "MaxMapFeedbackI8",
        i8,
        PythonMapObserverI8,
        PythonStdState
    );
    define_python_map_feedback!(
        PythonMaxMapFeedbackI16,
        "MaxMapFeedbackI16",
        i16,
        PythonMapObserverI16,
        PythonStdState
    );
    define_python_map_feedback!(
        PythonMaxMapFeedbackI32,
        "MaxMapFeedbackI32",
        i32,
        PythonMapObserverI32,
        PythonStdState
    );
    define_python_map_feedback!(
        PythonMaxMapFeedbackI64,
        "MaxMapFeedbackI64",
        i64,
        PythonMapObserverI64,
        PythonStdState
    );

    define_python_map_feedback!(
        PythonMaxMapFeedbackU8,
        "MaxMapFeedbackU8",
        u8,
        PythonMapObserverU8,
        PythonStdState
    );
    define_python_map_feedback!(
        PythonMaxMapFeedbackU16,
        "MaxMapFeedbackU16",
        u16,
        PythonMapObserverU16,
        PythonStdState
    );
    define_python_map_feedback!(
        PythonMaxMapFeedbackU32,
        "MaxMapFeedbackU32",
        u32,
        PythonMapObserverU32,
        PythonStdState
    );
    define_python_map_feedback!(
        PythonMaxMapFeedbackU64,
        "MaxMapFeedbackU64",
        u64,
        PythonMapObserverU64,
        PythonStdState
    );

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
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
