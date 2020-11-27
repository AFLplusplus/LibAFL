use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::marker::PhantomData;
use num::Integer;

use crate::corpus::{Testcase, TestcaseMetadata};
use crate::inputs::Input;
use crate::observers::MapObserver;
use crate::AflError;

pub trait Feedback<I>
where
    I: Input,
{
    /// is_interesting should return the "Interestingness" from 0 to 255 (percent times 2.55)
    fn is_interesting(&mut self, input: &I) -> Result<u32, AflError>;

    /// Append to the testcase the generated metadata in case of a new corpus item
    fn append_metadata(&mut self, _testcase: &mut Testcase<I>) -> Result<(), AflError> {
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    fn discard_metadata(&mut self, _input: &I) -> Result<(), AflError> {
        Ok(())
    }
}

/// A Reducer function is used to aggregate values for the novelty search
pub trait Reducer<T>
where
    T: Integer + Copy + 'static,
{
    fn reduce(first: T, second: T) -> T;
}

pub struct MaxReducer<T>
where
    T: Integer + Copy + 'static,
{
    phantom: PhantomData<T>,
}

impl<T> Reducer<T> for MaxReducer<T>
where
    T: Integer + Copy + 'static,
{
    fn reduce(first: T, second: T) -> T {
        if first > second {
            first
        } else {
            second
        }
    }
}

pub struct MinReducer<T>
where
    T: Integer + Copy + 'static,
{
    phantom: PhantomData<T>,
}

impl<T> Reducer<T> for MinReducer<T>
where
    T: Integer + Copy + 'static,
{
    fn reduce(first: T, second: T) -> T {
        if first < second {
            first
        } else {
            second
        }
    }
}

/// Returns a usable history map of the given size
pub fn create_history_map<T>(map_size: usize) -> Rc<RefCell<Vec<T>>>
where
    T: Default + Clone,
{
    {
        Rc::new(RefCell::new(vec![T::default(); map_size]))
    }
}

/// The most common AFL-like feedback type
pub struct MapFeedback<T, R, O>
where
    T: Integer + Copy + 'static,
    R: Reducer<T>,
    O: MapObserver<T>,
{
    /// Contains information about untouched entries
    history_map: Rc<RefCell<Vec<T>>>,
    /// The observer this feedback struct observes
    map_observer: Rc<RefCell<O>>,
    /// Phantom Data of Reducer
    phantom: PhantomData<R>,
}

impl<T, R, O, I> Feedback<I> for MapFeedback<T, R, O>
where
    T: Integer + Copy + 'static,
    R: Reducer<T>,
    O: MapObserver<T>,
    I: Input,
{
    fn is_interesting(&mut self, _input: &I) -> Result<u32, AflError> {
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
            }
        }

        Ok(interesting)
    }
}

impl<T, R, O> MapFeedback<T, R, O>
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
        }
    }
}

impl<T, R, O> MapFeedback<T, R, O>
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
        Self {
            map_observer: map_observer,
            history_map: history_map,
            phantom: PhantomData,
        }
    }
}

pub struct MapNoveltiesMetadata {
    novelties: Vec<usize>,
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
    history_map: Rc<RefCell<Vec<T>>>,
    /// The observer this feedback struct observes
    map_observer: Rc<RefCell<O>>,
    /// Phantom Data of Reducer
    phantom: PhantomData<R>,
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
    fn is_interesting(&mut self, _input: &I) -> Result<u32, AflError> {
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

    fn append_metadata(&mut self, testcase: &mut Testcase<I>) -> Result<(), AflError> {
        let meta = Box::new(MapNoveltiesMetadata::new(core::mem::take(
            &mut self.novelties,
        )));
        testcase.add_metadata(meta);
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    fn discard_metadata(&mut self, _input: &I) -> Result<(), AflError> {
        self.novelties.clear();
        Ok(())
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

pub type MaxMapFeedback<T, O> = MapFeedback<T, MaxReducer<T>, O>;
pub type MinMapFeedback<T, O> = MapFeedback<T, MinReducer<T>, O>;

pub type MaxMapTrackerFeedback<T, O> = MapFeedback<T, MaxReducer<T>, O>;
pub type MinMapTrackerFeedback<T, O> = MapFeedback<T, MinReducer<T>, O>;
