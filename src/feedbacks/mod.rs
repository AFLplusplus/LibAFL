extern crate num;

use crate::corpus::Testcase;
use crate::executors::Executor;
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
    fn is_interesting(&mut self, executor: &dyn Executor<I>, entry: &Testcase<I>) -> u8;
}

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
pub struct MapFeedback<'a, T, R>
where
    T: Integer + Copy + 'static,
    R: Reducer<T>,
{
    /// Contains information about untouched entries
    history_map: &'a RefCell<Vec<T>>,
    /// The observer this feedback struct observes
    map_observer: &'a RefCell<MapObserver</*'a,*/ T>>,
    /// Phantom Data of Reducer
    phantom: PhantomData<R>,
}

impl<'a, T, R, I> Feedback<I> for MapFeedback<'a, T, R>
where
    T: Integer + Copy + 'static,
    R: Reducer<T>,
    I: Input,
{
    fn is_interesting(&mut self, _executor: &dyn Executor<I>, entry: &Testcase<I>) -> u8 {
        let mut interesting = 0;

        // TODO: impl. correctly, optimize
        for (history, map) in self
            .history_map
            .borrow_mut()
            .iter_mut()
            .zip(self.map_observer.borrow().get_map().iter())
        {
            let reduced = R::reduce(*history, *map);
            if *history != reduced {
                *history = reduced;
                interesting += 25;
                if interesting >= 250 {
                    return 255;
                }
            }
        }
        interesting
    }
}

impl<'a, T, R> MapFeedback<'a, T, R>
where
    T: Integer + Copy + 'static,
    R: Reducer<T>,
{
    /// Create new MapFeedback using a map observer, and a map.
    /// The map can be shared.
    pub fn new(
        map_observer: &'a RefCell<MapObserver</*'a, */ T>>,
        history_map: &'a RefCell<Vec<T>>,
    ) -> Self {
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

#[allow(dead_code)]
type MaxMapFeedback<'a, T> = MapFeedback<'a, T, MaxReducer<T>>;
#[allow(dead_code)]
type MinMapFeedback<'a, T> = MapFeedback<'a, T, MinReducer<T>>;
