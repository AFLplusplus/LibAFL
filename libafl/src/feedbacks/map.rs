//! Map feedback, maximizing or minimizing maps, for example the afl-style map observer.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::marker::PhantomData;
use num_traits::PrimInt;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{tuples::Named, AsSlice, HasRefCnt},
    corpus::Testcase,
    events::{Event, EventFirer},
    executors::ExitKind,
    feedbacks::{Feedback, FeedbackState, FeedbackStatesTuple},
    inputs::Input,
    monitors::UserStats,
    observers::{MapObserver, ObserversTuple},
    state::{HasClientPerfMonitor, HasFeedbackStates, HasMetadata},
    Error,
};

/// A [`MapFeedback`] that strives to maximize the map contents.
pub type MaxMapFeedback<FT, I, O, S, T> = MapFeedback<FT, I, MapNopFilter, O, MaxReducer, S, T>;
/// A [`MapFeedback`] that strives to minimize the map contents.
pub type MinMapFeedback<FT, I, O, S, T> = MapFeedback<FT, I, MapNopFilter, O, MinReducer, S, T>;

/// A [`MapFeedback`] that strives to maximize the map contents,
/// but only, if a value is larger than `pow2` of the previous.
pub type MaxMapPow2Feedback<FT, I, O, S, T> =
    MapFeedback<FT, I, MaxMapPow2Filter, O, MaxReducer, S, T>;
/// A [`MapFeedback`] that strives to maximize the map contents,
/// but only, if a value is larger than `pow2` of the previous.
pub type MaxMapOneOrFilledFeedback<FT, I, O, S, T> =
    MapFeedback<FT, I, MaxMapOneOrFilledFilter, O, MaxReducer, S, T>;

/// A `Reducer` function is used to aggregate values for the novelty search
pub trait Reducer<T>: Serialize + serde::de::DeserializeOwned + 'static
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    /// Reduce two values to one value, with the current [`Reducer`].
    fn reduce(first: T, second: T) -> T;
}

/// A [`MaxReducer`] reduces int values and returns their maximum.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MaxReducer {}

impl<T> Reducer<T> for MaxReducer
where
    T: PrimInt
        + Default
        + Copy
        + 'static
        + serde::Serialize
        + serde::de::DeserializeOwned
        + PartialOrd,
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
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MinReducer {}

impl<T> Reducer<T> for MinReducer
where
    T: PrimInt
        + Default
        + Copy
        + 'static
        + serde::Serialize
        + serde::de::DeserializeOwned
        + PartialOrd,
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

/// A `MapFindFilter` function gets called after the `MapFeedback` found a new entry.
pub trait MapFindFilter<T>: Serialize + serde::de::DeserializeOwned + 'static
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    /// If a new value in the [`MapFeedback`] was found,
    /// this filter can decide if the result is intersting or not.
    /// This way, you can restrict the finds further.
    fn is_interesting(old: T, new: T) -> bool;
}

/// A filter that never filters out any finds.
/// The default
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MapNopFilter {}

impl<T> MapFindFilter<T> for MapNopFilter
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn is_interesting(_old: T, _new: T) -> bool {
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

/// A filter that only saves values which are at least the next pow2 class
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MaxMapPow2Filter {}
impl<T> MapFindFilter<T> for MaxMapPow2Filter
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn is_interesting(old: T, new: T) -> bool {
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
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MaxMapOneOrFilledFilter {}
impl<T> MapFindFilter<T> for MaxMapOneOrFilledFilter
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn is_interesting(old: T, new: T) -> bool {
        (new == T::one() || new == T::one() || new == T::max_value()) && new > old
    }
}

/// A testcase metadata holding a list of indexes of a map
#[derive(Serialize, Deserialize)]
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
#[derive(Serialize, Deserialize)]
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
impl MapNoveltiesMetadata {
    /// Creates a new [`struct@MapNoveltiesMetadata`]
    #[must_use]
    pub fn new(list: Vec<usize>) -> Self {
        Self { list }
    }
}

/// The state of [`MapFeedback`]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct MapFeedbackState<T>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    /// Contains information about untouched entries
    pub history_map: Vec<T>,
    /// Name identifier of this instance
    pub name: String,
}

impl<T> FeedbackState for MapFeedbackState<T>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    fn reset(&mut self) -> Result<(), Error> {
        self.history_map.iter_mut().for_each(|x| *x = T::default());
        Ok(())
    }
}

impl<T> Named for MapFeedbackState<T>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<T> MapFeedbackState<T>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    /// Create new `MapFeedbackState`
    #[must_use]
    pub fn new(name: &'static str, map_size: usize) -> Self {
        Self {
            history_map: vec![T::default(); map_size],
            name: name.to_string(),
        }
    }

    /// Create new `MapFeedbackState` for the observer type.
    pub fn with_observer<O>(map_observer: &O) -> Self
    where
        O: MapObserver<T>,
    {
        Self {
            history_map: vec![T::default(); map_observer.len()],
            name: map_observer.name().to_string(),
        }
    }

    /// Create new `MapFeedbackState` using a name and a map.
    /// The map can be shared.
    #[must_use]
    pub fn with_history_map(name: &'static str, history_map: Vec<T>) -> Self {
        Self {
            history_map,
            name: name.to_string(),
        }
    }
}

/// The most common AFL-like feedback type
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct MapFeedback<FT, I, MF, O, R, S, T>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    R: Reducer<T>,
    O: MapObserver<T>,
    MF: MapFindFilter<T>,
    S: HasFeedbackStates<FT>,
    FT: FeedbackStatesTuple,
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
    phantom: PhantomData<(FT, I, MF, S, R, O, T)>,
}

impl<FT, I, MF, O, R, S, T> Feedback<I, S> for MapFeedback<FT, I, MF, O, R, S, T>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    R: Reducer<T>,
    O: MapObserver<T>,
    MF: MapFindFilter<T>,
    I: Input,
    S: HasFeedbackStates<FT> + HasClientPerfMonitor,
    FT: FeedbackStatesTuple,
{
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I, S>,
        OT: ObserversTuple<I, S>,
    {
        let mut interesting = false;
        // TODO Replace with match_name_type when stable
        let observer = observers.match_name::<O>(&self.observer_name).unwrap();
        let size = observer.usable_count();
        let initial = observer.initial();

        let map_state = state
            .feedback_states_mut()
            .match_name_mut::<MapFeedbackState<T>>(&self.name)
            .unwrap();

        assert!(size <= map_state.history_map.len(), "The size of the associated map observer cannot exceed the size of the history map of the feedback. If you are running multiple instances of slightly different fuzzers (e.g. one with ASan and another without) synchronized using LLMP please check the `configuration` field of the LLMP manager.");

        assert!(size <= observer.len());

        if self.novelties.is_some() {
            for i in 0..size {
                let history = map_state.history_map[i];
                let item = *observer.get(i);

                let reduced = R::reduce(history, item);
                if history != reduced && MF::is_interesting(history, reduced) {
                    map_state.history_map[i] = reduced;
                    interesting = true;
                    self.novelties.as_mut().unwrap().push(i);
                }
            }
        } else {
            for i in 0..size {
                let history = map_state.history_map[i];
                let item = *observer.get(i);

                let reduced = R::reduce(history, item);
                if history != reduced && MF::is_interesting(history, reduced) {
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

impl<FT, I, MF, O, R, S, T> Named for MapFeedback<FT, I, MF, O, R, S, T>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    R: Reducer<T>,
    MF: MapFindFilter<T>,
    O: MapObserver<T>,
    S: HasFeedbackStates<FT>,
    FT: FeedbackStatesTuple,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<FT, I, MF, O, R, S, T> MapFeedback<FT, I, MF, O, R, S, T>
where
    T: PrimInt
        + Default
        + Copy
        + 'static
        + serde::Serialize
        + serde::de::DeserializeOwned
        + PartialOrd,
    R: Reducer<T>,
    MF: MapFindFilter<T>,
    O: MapObserver<T>,
    S: HasFeedbackStates<FT>,
    FT: FeedbackStatesTuple,
{
    /// Create new `MapFeedback`
    #[must_use]
    pub fn new(feedback_state: &MapFeedbackState<T>, map_observer: &O) -> Self {
        Self {
            indexes: None,
            novelties: None,
            name: feedback_state.name().to_string(),
            observer_name: map_observer.name().to_string(),
            phantom: PhantomData,
        }
    }

    /// Create new `MapFeedback` specifying if it must track indexes of used entries and/or novelties
    #[must_use]
    pub fn new_tracking(
        feedback_state: &MapFeedbackState<T>,
        map_observer: &O,
        track_indexes: bool,
        track_novelties: bool,
    ) -> Self {
        Self {
            indexes: if track_indexes { Some(vec![]) } else { None },
            novelties: if track_novelties { Some(vec![]) } else { None },
            name: feedback_state.name().to_string(),
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
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReachabilityFeedback<O> {
    name: String,
    target_idx: Vec<usize>,
    phantom: PhantomData<O>,
}

impl<O> ReachabilityFeedback<O>
where
    O: MapObserver<usize>,
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
    O: MapObserver<usize>,
    S: HasClientPerfMonitor,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I, S>,
        OT: ObserversTuple<I, S>,
    {
        // TODO Replace with match_name_type when stable
        let observer = observers.match_name::<O>(&self.name).unwrap();
        let size = observer.usable_count();
        let mut hit_target: bool = false;
        //check if we've hit any targets.
        for i in 0..size {
            if *observer.get(i) > 0 {
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
    O: MapObserver<usize>,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

#[cfg(test)]
mod tests {
    use crate::feedbacks::{MapFindFilter, MapNopFilter, MaxMapPow2Filter};

    #[test]
    fn test_map_max_pow2_filter() {
        // sanity check
        assert!(MapNopFilter::is_interesting(0_u8, 0));

        assert!(!MaxMapPow2Filter::is_interesting(0_u8, 0));
        assert!(MaxMapPow2Filter::is_interesting(0_u8, 1));
        assert!(!MaxMapPow2Filter::is_interesting(1_u8, 1));
        assert!(MaxMapPow2Filter::is_interesting(1_u8, 2));
        assert!(!MaxMapPow2Filter::is_interesting(2_u8, 2));
        assert!(!MaxMapPow2Filter::is_interesting(2_u8, 3));
        assert!(MaxMapPow2Filter::is_interesting(2_u8, 4));
        assert!(!MaxMapPow2Filter::is_interesting(128_u8, 128));
        assert!(!MaxMapPow2Filter::is_interesting(129_u8, 128));
        assert!(MaxMapPow2Filter::is_interesting(128_u8, 255));
        assert!(!MaxMapPow2Filter::is_interesting(255_u8, 128));
        assert!(MaxMapPow2Filter::is_interesting(254_u8, 255));
        assert!(!MaxMapPow2Filter::is_interesting(255_u8, 255));
    }
}
