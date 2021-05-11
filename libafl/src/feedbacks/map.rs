//! Map feedback, maximizing or minimizing maps, for example the afl-style map observer.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::marker::PhantomData;
use num::Integer;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::tuples::Named,
    corpus::Testcase,
    executors::ExitKind,
    feedbacks::{Feedback, FeedbackStatesTuple},
    inputs::Input,
    observers::{MapObserver, ObserversTuple},
    state::{HasFeedbackStates, HasMetadata},
    utils::AsSlice,
    Error,
};

/// A [`MapFeedback`] that strives to maximize the map contents.
pub type MaxMapFeedback<O, T> = MapFeedback<O, MaxReducer, T>;
/// A [`MapFeedback`] that strives to minimize the map contents.
pub type MinMapFeedback<O, T> = MapFeedback<O, MinReducer, T>;

/// A Reducer function is used to aggregate values for the novelty search
pub trait Reducer<T>: Serialize + serde::de::DeserializeOwned + 'static
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    /// Reduce two values to one value, with the current [`Reducer`].
    fn reduce(first: T, second: T) -> T;
}

/// A [`MinReducer`] reduces [`Integer`] values and returns their maximum.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MaxReducer {}

impl<T> Reducer<T> for MaxReducer
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
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

/// A [`MinReducer`] reduces [`Integer`] values and returns their minimum.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MinReducer {}

impl<T> Reducer<T> for MinReducer
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
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

/// A testcase metadata holding a list of indexes of a map
#[derive(Serialize, Deserialize)]
pub struct MapIndexesMetadata {
    /// The list of indexes.
    pub list: Vec<usize>,
}

crate::impl_serdeany!(MapIndexesMetadata);

impl AsSlice<usize> for MapIndexesMetadata {
    /// Convert to a slice
    fn as_slice(&self) -> &[usize] {
        self.list.as_slice()
    }
}

impl MapIndexesMetadata {
    /// Creates a new [`struct@MapIndexesMetadata`].
    #[must_use]
    pub fn new(list: Vec<usize>) -> Self {
        Self { list }
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

/// The state of MapFeedback
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct MapFeedbackState<T>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    /// Contains information about untouched entries
    pub history_map: Vec<T>,
    /// Indexes used in the last observation
    pub indexes: Option<Vec<usize>>,
    /// New indexes observed in the last observation
    pub novelties: Option<Vec<usize>>,
    /// Name identifier of this instance
    pub name: String,
}

impl<T> Named for MapFeedbackState<T>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<T> MapFeedbackState<T>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    /// Create new `MapFeedbackState`
    #[must_use]
    pub fn new(name: &'static str, map_size: usize) -> Self {
        Self {
            history_map: vec![T::default(); map_size],
            indexes: None,
            novelties: None,
            name: name.to_string(),
        }
    }

    /// Create new `MapFeedbackState` for the observer type.
    pub fn new_with_observer<O>(map_observer: &O) -> Self
    where
        O: MapObserver<T>,
    {
        Self {
            history_map: vec![T::default(); map_observer.map().len()],
            indexes: None,
            novelties: None,
            name: map_observer.name().to_string(),
        }
    }

    /// Create new `MapFeedbackState` specifying if it must track indexes of novelties
    #[must_use]
    pub fn new_tracking(
        name: &'static str,
        map_size: usize,
        track_indexes: bool,
        track_novelties: bool,
    ) -> Self {
        Self {
            history_map: vec![T::default(); map_size],
            indexes: if track_indexes { Some(vec![]) } else { None },
            novelties: if track_novelties { Some(vec![]) } else { None },
            name: name.to_string(),
        }
    }

    /// Create new `MapFeedbackState` for the observer type if it must track indexes of novelties
    pub fn new_tracking_with_observer<O>(
        map_observer: &O,
        track_indexes: bool,
        track_novelties: bool,
    ) -> Self
    where
        O: MapObserver<T>,
    {
        Self {
            history_map: vec![T::default(); map_observer.map().len()],
            indexes: if track_indexes { Some(vec![]) } else { None },
            novelties: if track_novelties { Some(vec![]) } else { None },
            name: map_observer.name().to_string(),
        }
    }

    /// Create new `MapFeedbackState` using a map observer, and a map.
    /// The map can be shared.
    #[must_use]
    pub fn with_history_map(name: &'static str, history_map: Vec<T>) -> Self {
        Self {
            history_map,
            name: name.to_string(),
            indexes: None,
            novelties: None,
        }
    }
}

/// The most common AFL-like feedback type
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct MapFeedback<O, R, T>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    R: Reducer<T>,
    O: MapObserver<T>,
{
    /// Name identifier of this instance
    name: String,
    /// Phantom Data of Reducer
    phantom: PhantomData<(R, O, T)>,
}

impl<I, FT, O, R, S, T> Feedback<FT, I, S> for MapFeedback<O, R, T>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    R: Reducer<T>,
    O: MapObserver<T>,
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    fn is_interesting<OT>(
        &mut self,
        state: &mut S,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
    {
        let mut interesting = false;
        // TODO Replace with match_name_type when stable
        let observer = observers.match_name::<O>(&self.name).unwrap();
        let size = observer.usable_count();
        let initial = observer.initial();

        let map_state = state
            .feedback_states_mut()
            .match_name_mut::<MapFeedbackState<T>>(&self.name)
            .unwrap();

        if map_state.indexes.is_none() && map_state.novelties.is_none() {
            for i in 0..size {
                let history = map_state.history_map[i];
                let item = observer.map()[i];

                let reduced = R::reduce(history, item);
                if history != reduced {
                    map_state.history_map[i] = reduced;
                    interesting = true;
                }
            }
        } else if map_state.indexes.is_some() && map_state.novelties.is_none() {
            for i in 0..size {
                let history = map_state.history_map[i];
                let item = observer.map()[i];
                if item != initial {
                    map_state.indexes.as_mut().unwrap().push(i);
                }

                let reduced = R::reduce(history, item);
                if history != reduced {
                    map_state.history_map[i] = reduced;
                    interesting = true;
                }
            }
        } else if map_state.indexes.is_none() && map_state.novelties.is_some() {
            for i in 0..size {
                let history = map_state.history_map[i];
                let item = observer.map()[i];

                let reduced = R::reduce(history, item);
                if history != reduced {
                    map_state.history_map[i] = reduced;
                    interesting = true;
                    map_state.novelties.as_mut().unwrap().push(i);
                }
            }
        } else {
            for i in 0..size {
                let history = map_state.history_map[i];
                let item = observer.map()[i];
                if item != initial {
                    map_state.indexes.as_mut().unwrap().push(i);
                }

                let reduced = R::reduce(history, item);
                if history != reduced {
                    map_state.history_map[i] = reduced;
                    interesting = true;
                    map_state.novelties.as_mut().unwrap().push(i);
                }
            }
        }

        Ok(interesting)
    }

    fn append_metadata(&mut self, state: &mut S, testcase: &mut Testcase<I>) -> Result<(), Error> {
        let map_state = state
            .feedback_states_mut()
            .match_name_mut::<MapFeedbackState<T>>(&self.name)
            .unwrap();

        if let Some(v) = map_state.indexes.as_mut() {
            let meta = MapIndexesMetadata::new(core::mem::take(v));
            testcase.add_metadata(meta);
        };
        if let Some(v) = map_state.novelties.as_mut() {
            let meta = MapNoveltiesMetadata::new(core::mem::take(v));
            testcase.add_metadata(meta);
        };
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    fn discard_metadata(&mut self, state: &mut S, _input: &I) -> Result<(), Error> {
        let map_state = state
            .feedback_states_mut()
            .match_name_mut::<MapFeedbackState<T>>(&self.name)
            .unwrap();

        if let Some(v) = map_state.indexes.as_mut() {
            v.clear();
        }
        if let Some(v) = map_state.novelties.as_mut() {
            v.clear();
        }
        Ok(())
    }
}

impl<O, R, T> Named for MapFeedback<O, R, T>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    R: Reducer<T>,
    O: MapObserver<T>,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<O, R, T> MapFeedback<O, R, T>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    R: Reducer<T>,
    O: MapObserver<T>,
{
    /// Create new `MapFeedback`
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            phantom: PhantomData,
            name: name.to_string(),
        }
    }
}
/*
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
    pub fn new_with_observer(map_observer: &O) -> Self {
        Self {
            name: map_observer.name().to_string(),
            target_idx: vec![],
            phantom: PhantomData,
        }
    }

    /// Creates a new [`ReachabilityFeedback`] for a [`MapObserver`] with the given `name`.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: name.to_string(),
            target_idx: vec![],
            phantom: PhantomData,
        }
    }
}

impl<I, O> Feedback<I> for ReachabilityFeedback<O>
where
    I: Input,
    O: MapObserver<usize>,
{
    fn is_interesting<OT: ObserversTuple>(
        &mut self,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        // TODO Replace with match_name_type when stable
        let observer = observers.match_name::<O>(&self.name).unwrap();
        let size = observer.usable_count();
        let mut hit_target: bool = false;
        //check if we've hit any targets.
        for i in 0..size {
            if observer.map()[i] > 0 {
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

    fn append_metadata(&mut self, testcase: &mut Testcase<I>) -> Result<(), Error> {
        if !self.target_idx.is_empty() {
            let meta = MapIndexesMetadata::new(core::mem::take(self.target_idx.as_mut()));
            testcase.add_metadata(meta);
        };
        Ok(())
    }

    fn discard_metadata(&mut self, _input: &I) -> Result<(), Error> {
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
*/
