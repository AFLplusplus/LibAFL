use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::marker::PhantomData;
use num::Integer;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::tuples::Named,
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

// TODO: TimeFeedback

/*
#[derive(Serialize, Deserialize)]
pub struct MapNoveltiesMetadata {
    novelties: Vec<usize>,
}

impl SerdeAny for MapNoveltiesMetadata {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl TestcaseMetadata for MapNoveltiesMetadata {
    fn name(&self) -> &'static str {
        "MapNoveltiesMetadata"
    }
}
impl MapNoveltiesMetadata {
    pub fn novelties(&self) -> &[usize] {
        &self.novelties
    }

    pub fn new(novelties: Vec<usize>) -> Self {
        Self {
            novelties: novelties,
        }
    }
}

/// The most common AFL-like feedback type that adds metadata about newly discovered entries
pub struct MapTrackerFeedback<T, R, O>
where
    T: Integer + Copy + 'static,
    R: Reducer<T>,
    O: MapObserver<T>,
{
    /// Contains information about untouched entries
    history_map: Vec<T>,
    /// Name identifier of this instance
    name: &'static str,
    /// Phantom Data of Reducer
    phantom: PhantomData<(R, O)>,
    /// Track novel entries indexes
    novelties: Vec<usize>,
}

impl<T, R, O, I> Feedback<I> for MapTrackerFeedback<T, R, O>
where
    T: Integer + Copy + 'static,
    R: Reducer<T>,
    O: MapObserver<T>,
    I: Input,
{
    fn is_interesting(&mut self, _input: &I) -> Result<u32, Error> {
        let mut interesting = 0;

        // TODO optimize
        let size = self.map_observer.borrow().map().len();
        let mut history_map = self.history_map.borrow_mut();
        let observer = self.map_observer.borrow();
        for i in 0..size {
            let history = history_map[i];
            let item = observer.map()[i];
            let reduced = R::reduce(history, item);
            if history != reduced {
                history_map[i] = reduced;
                interesting += 1;
                self.novelties.push(i);
            }
        }

        Ok(interesting)
    }

    fn append_metadata(&mut self, testcase: &mut Testcase<I>) -> Result<(), Error> {
        let meta = MapNoveltiesMetadata::new(core::mem::take(&mut self.novelties));
        testcase.add_metadata(meta);
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    fn discard_metadata(&mut self, _input: &I) -> Result<(), Error> {
        self.novelties.clear();
        Ok(())
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

impl<T, R, O> MapTrackerFeedback<T, R, O>
where
    T: Integer + Copy + Default + 'static,
    R: Reducer<T>,
    O: MapObserver<T>,
{
    /// Create new MapFeedback using a map observer
    pub fn new(map_observer: Rc<RefCell<O>>, map_size: usize) -> Self {
        Self {
            map_observer: map_observer,
            history_map: create_history_map::<T>(map_size),
            phantom: PhantomData,
            novelties: vec![],
        }
    }
}

impl<T, R, O> MapTrackerFeedback<T, R, O>
where
    T: Integer + Copy + 'static,
    R: Reducer<T>,
    O: MapObserver<T>,
{
    /// Create new MapFeedback using a map observer, and a map.
    /// The map can be shared.
    pub fn with_history_map(
        map_observer: Rc<RefCell<O>>,
        history_map: Rc<RefCell<Vec<T>>>,
    ) -> Self {
        MapTrackerFeedback {
            map_observer: map_observer,
            history_map: history_map,
            phantom: PhantomData,
            novelties: vec![],
        }
    }
}
*/
