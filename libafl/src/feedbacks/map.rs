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
    feedbacks::Feedback,
    inputs::Input,
    observers::{MapObserver, Observer, ObserversTuple},
    Error,
};

pub type MaxMapFeedback<T, O> = MapFeedback<T, MaxReducer<T>, O>;
pub type MinMapFeedback<T, O> = MapFeedback<T, MinReducer<T>, O>;

//pub type MaxMapTrackerFeedback<T, O> = MapFeedback<T, MaxReducer<T>, O>;
//pub type MinMapTrackerFeedback<T, O> = MapFeedback<T, MinReducer<T>, O>;

/// A Reducer function is used to aggregate values for the novelty search
pub trait Reducer<T>: Serialize + serde::de::DeserializeOwned + 'static
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    fn reduce(first: T, second: T) -> T;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MaxReducer<T>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    phantom: PhantomData<T>,
}

impl<T> Reducer<T> for MaxReducer<T>
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MinReducer<T>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    phantom: PhantomData<T>,
}

impl<T> Reducer<T> for MinReducer<T>
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

/*
/// The most common AFL-like feedback type
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct MapFeedback<T, R, O>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    R: Reducer<T>,
    O: MapObserver<T>,
{
    /// Contains information about untouched entries
    history_map: Vec<T>,
    /// Name identifier of this instance
    name: String,
    /// Phantom Data of Reducer
    phantom: PhantomData<(R, O)>,
}

impl<T, R, O, I> Feedback<I> for MapFeedback<T, R, O>
where
    T: Integer
        + Default
        + Copy
        + 'static
        + serde::Serialize
        + serde::de::DeserializeOwned
        + core::fmt::Debug,
    R: Reducer<T>,
    O: MapObserver<T>,
    I: Input,
{
    fn is_interesting<OT: ObserversTuple>(
        &mut self,
        _input: &I,
        observers: &OT,
        _exit_kind: ExitKind,
    ) -> Result<u32, Error> {
        let mut interesting = 0;
        // TODO optimize
        let observer = observers.match_name_type::<O>(&self.name).unwrap();
        let size = observer.usable_count();
        //println!("count: {:?}, map: {:?}, history: {:?}", size, observer.map(), &self.history_map);
        for i in 0..size {
            let history = self.history_map[i];
            let item = observer.map()[i];
            let reduced = R::reduce(history, item);
            if history != reduced {
                self.history_map[i] = reduced;
                interesting += 1;
            }
        }

        //println!("..interesting: {:?}, new_history: {:?}\n", interesting, &self.history_map);
        //std::thread::sleep(std::time::Duration::from_millis(100));

        Ok(interesting)
    }
}

impl<T, R, O> Named for MapFeedback<T, R, O>
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

impl<T, R, O> MapFeedback<T, R, O>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    R: Reducer<T>,
    O: MapObserver<T> + Observer,
{
    /// Create new MapFeedback
    pub fn new(name: &'static str, map_size: usize) -> Self {
        Self {
            history_map: vec![T::default(); map_size],
            phantom: PhantomData,
            name: name.to_string(),
        }
    }

    /// Create new MapFeedback for the observer type.
    /// Name should match that of the observer.
    pub fn new_with_observer(name: &'static str, map_observer: &O) -> Self {
        debug_assert_eq!(name, map_observer.name());
        Self {
            history_map: vec![T::default(); map_observer.map().len()],
            phantom: PhantomData,
            name: name.to_string(),
        }
    }
}

impl<T, R, O> MapFeedback<T, R, O>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    R: Reducer<T>,
    O: MapObserver<T>,
{
    /// Create new MapFeedback using a map observer, and a map.
    /// The map can be shared.
    pub fn with_history_map(name: &'static str, history_map: Vec<T>) -> Self {
        Self {
            history_map: history_map,
            name: name.to_string(),
            phantom: PhantomData,
        }
    }
}
*/

/// A testcase metadata holding a list of indexes of a map
#[derive(Serialize, Deserialize)]
pub struct MapIndexesMetadata {
    pub list: Vec<usize>,
}

crate::impl_serdeany!(MapIndexesMetadata);

impl IntoIterator for MapIndexesMetadata {
    type Item = usize;
    type IntoIter = alloc::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.list.into_iter()
    }
}

impl MapIndexesMetadata {
    pub fn new(list: Vec<usize>) -> Self {
        Self { list }
    }
}

/// A testcase metadata holding a list of indexes of a map
#[derive(Serialize, Deserialize)]
pub struct MapNoveltiesMetadata {
    pub list: Vec<usize>,
}

crate::impl_serdeany!(MapNoveltiesMetadata);

impl IntoIterator for MapNoveltiesMetadata {
    type Item = usize;
    type IntoIter = alloc::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.list.into_iter()
    }
}

impl MapNoveltiesMetadata {
    pub fn new(list: Vec<usize>) -> Self {
        Self { list }
    }
}

/// The most common AFL-like feedback type
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct MapFeedback<T, R, O>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    R: Reducer<T>,
    O: MapObserver<T>,
{
    /// Contains information about untouched entries
    history_map: Vec<T>,
    /// Indexes used in the last observation
    indexes: Option<Vec<usize>>,
    /// New indexes observed in the last observation
    novelties: Option<Vec<usize>>,
    /// Name identifier of this instance
    name: String,
    /// Phantom Data of Reducer
    phantom: PhantomData<(R, O)>,
}

impl<T, R, O, I> Feedback<I> for MapFeedback<T, R, O>
where
    T: Integer
        + Default
        + Copy
        + 'static
        + serde::Serialize
        + serde::de::DeserializeOwned
        + core::fmt::Debug,
    R: Reducer<T>,
    O: MapObserver<T>,
    I: Input,
{
    fn is_interesting<OT: ObserversTuple>(
        &mut self,
        _input: &I,
        observers: &OT,
        _exit_kind: ExitKind,
    ) -> Result<u32, Error> {
        let mut interesting = 0;
        // TODO optimize
        let observer = observers.match_name_type::<O>(&self.name).unwrap();
        let size = observer.usable_count();
        let initial = observer.initial();

        if self.indexes.is_none() && self.novelties.is_none() {
            for i in 0..size {
                let history = self.history_map[i];
                let item = observer.map()[i];

                let reduced = R::reduce(history, item);
                if history != reduced {
                    self.history_map[i] = reduced;
                    interesting += 1;
                }
            }
        } else if self.indexes.is_some() && self.novelties.is_none() {
            for i in 0..size {
                let history = self.history_map[i];
                let item = observer.map()[i];
                if item != initial {
                    self.indexes.as_mut().unwrap().push(i);
                }

                let reduced = R::reduce(history, item);
                if history != reduced {
                    self.history_map[i] = reduced;
                    interesting += 1;
                }
            }
        } else if self.indexes.is_none() && self.novelties.is_some() {
            for i in 0..size {
                let history = self.history_map[i];
                let item = observer.map()[i];

                let reduced = R::reduce(history, item);
                if history != reduced {
                    self.history_map[i] = reduced;
                    interesting += 1;
                    self.novelties.as_mut().unwrap().push(i);
                }
            }
        } else {
            for i in 0..size {
                let history = self.history_map[i];
                let item = observer.map()[i];
                if item != initial {
                    self.indexes.as_mut().unwrap().push(i);
                }

                let reduced = R::reduce(history, item);
                if history != reduced {
                    self.history_map[i] = reduced;
                    interesting += 1;
                    self.novelties.as_mut().unwrap().push(i);
                }
            }
        }

        Ok(interesting)
    }

    fn append_metadata(&mut self, testcase: &mut Testcase<I>) -> Result<(), Error> {
        match self.indexes.as_mut() {
            Some(v) => {
                let meta = MapIndexesMetadata::new(core::mem::take(v));
                testcase.add_metadata(meta);
            }
            None => {}
        };
        match self.novelties.as_mut() {
            Some(v) => {
                let meta = MapNoveltiesMetadata::new(core::mem::take(v));
                testcase.add_metadata(meta);
            }
            None => {}
        };
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    fn discard_metadata(&mut self, _input: &I) -> Result<(), Error> {
        if let Some(v) = self.indexes.as_mut() {
            v.clear();
        }
        if let Some(v) = self.novelties.as_mut() {
            v.clear();
        }
        Ok(())
    }
}

impl<T, R, O> Named for MapFeedback<T, R, O>
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

impl<T, R, O> MapFeedback<T, R, O>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    R: Reducer<T>,
    O: MapObserver<T> + Observer,
{
    /// Create new MapFeedback
    pub fn new(name: &'static str, map_size: usize) -> Self {
        Self {
            history_map: vec![T::default(); map_size],
            phantom: PhantomData,
            indexes: None,
            novelties: None,
            name: name.to_string(),
        }
    }

    /// Create new MapFeedback for the observer type.
    pub fn new_with_observer(map_observer: &O) -> Self {
        Self {
            history_map: vec![T::default(); map_observer.map().len()],
            phantom: PhantomData,
            indexes: None,
            novelties: None,
            name: map_observer.name().to_string(),
        }
    }

    /// Create new MapFeedback specifying if it must track indexes of novelties
    pub fn new_track(name: &'static str, map_size: usize, track_indexes: bool, track_novelties: bool) -> Self {
        Self {
            history_map: vec![T::default(); map_size],
            phantom: PhantomData,
            indexes: if track_indexes { Some(vec![]) } else { None },
            novelties: if track_novelties { Some(vec![]) } else { None },
            name: name.to_string(),
        }
    }

    /// Create new MapFeedback for the observer type if it must track indexes of novelties
    pub fn new_with_observer_track(map_observer: &O, track_indexes: bool, track_novelties: bool) -> Self {
        Self {
            history_map: vec![T::default(); map_observer.map().len()],
            phantom: PhantomData,
            indexes: if track_indexes { Some(vec![]) } else { None },
            novelties: if track_novelties { Some(vec![]) } else { None },
            name: map_observer.name().to_string(),
        }
    }
}

impl<T, R, O> MapFeedback<T, R, O>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    R: Reducer<T>,
    O: MapObserver<T>,
{
    /// Create new MapFeedback using a map observer, and a map.
    /// The map can be shared.
    pub fn with_history_map(name: &'static str, history_map: Vec<T>) -> Self {
        Self {
            history_map: history_map,
            name: name.to_string(),
            indexes: None,
            novelties: None,
            phantom: PhantomData,
        }
    }
}
