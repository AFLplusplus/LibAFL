extern crate num;

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::marker::PhantomData;
use num::Integer;

use crate::corpus::Testcase;
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
    fn append_metadata(&mut self, _testcase: Rc<RefCell<Testcase<I>>>) -> Result<(), AflError> {
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    fn discard_metadata(&mut self) -> Result<(), AflError> {
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

        // TODO: impl. correctly, optimize
        for (history, map) in self
            .history_map
            .borrow_mut()
            .iter_mut()
            .zip(self.map_observer.borrow().map().iter())
        {
            let reduced = R::reduce(*history, *map);
            if *history != reduced {
                *history = reduced;
                interesting += 25;
                if interesting >= 250 {
                    return Ok(255);
                }
            }
        }
        Ok(interesting)
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
    pub fn new(map_observer: Rc<RefCell<O>>, history_map: Rc<RefCell<Vec<T>>>) -> Self {
        MapFeedback {
            map_observer: map_observer,
            history_map: history_map,
            phantom: PhantomData,
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

pub type MaxMapFeedback<T, O> = MapFeedback<T, MaxReducer<T>, O>;
pub type MinMapFeedback<T, O> = MapFeedback<T, MinReducer<T>, O>;
