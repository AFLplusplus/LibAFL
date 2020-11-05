extern crate num;

use crate::corpus::TestcaseMetadata;
use crate::inputs::Input;
use crate::observers::MapObserver;

use num::Integer;
use std::cell::RefCell;
use std::marker::PhantomData;

pub trait Feedback<I>
where
    I: Input,
{
    /// is_interesting should return the "Interestingness" from 0 to 255 (percent times 2.55)
    fn is_interesting(&mut self, input: &I) -> (u32, Option<Box<dyn TestcaseMetadata>>);
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
pub struct MapFeedback<'a, T, R, O>
where
    T: Integer + Copy + 'static,
    R: Reducer<T>,
    O: MapObserver<T>,
{
    /// Contains information about untouched entries
    history_map: &'a RefCell<Vec<T>>,
    /// The observer this feedback struct observes
    map_observer: &'a RefCell<O>,
    /// Phantom Data of Reducer
    phantom: PhantomData<R>,
}

impl<'a, T, R, O, I> Feedback<I> for MapFeedback<'a, T, R, O>
where
    T: Integer + Copy + 'static,
    R: Reducer<T>,
    O: MapObserver<T>,
    I: Input,
{
    fn is_interesting(&mut self, _input: &I) -> (u32, Option<Box<dyn TestcaseMetadata>>) {
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
                    return (255, None);
                }
            }
        }
        (interesting, None)
    }
}

impl<'a, T, R, O> MapFeedback<'a, T, R, O>
where
    T: Integer + Copy + 'static,
    R: Reducer<T>,
    O: MapObserver<T>,
{
    /// Create new MapFeedback using a map observer, and a map.
    /// The map can be shared.
    pub fn new(map_observer: &'a RefCell<O>, history_map: &'a RefCell<Vec<T>>) -> Self {
        MapFeedback {
            map_observer: map_observer,
            history_map: history_map,
            phantom: PhantomData,
        }
    }
}

/// Returns a usable history map of the given size
pub fn create_history_map<T>(map_size: usize) -> RefCell<Vec<T>>
where
    T: Default + Clone,
{
    {
        RefCell::new(vec![T::default(); map_size])
    }
}

pub type MaxMapFeedback<'a, T, O> = MapFeedback<'a, T, MaxReducer<T>, O>;
pub type MinMapFeedback<'a, T, O> = MapFeedback<'a, T, MinReducer<T>, O>;
