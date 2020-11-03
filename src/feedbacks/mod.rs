extern crate num;

use crate::corpus::Testcase;
use crate::inputs::Input;
use crate::executors::Executor;
use crate::observers::MapObserver;

use num::Integer;
use std::marker::PhantomData;

pub trait Feedback<I> where I: Input {
    /// is_interesting should return the "Interestingness" from 0 to 255 (percent times 2.55)
    fn is_interesting(&mut self, executor: &dyn Executor<I>, entry: &Testcase<I>) -> u8;
}

/*
pub trait Feedback {
    /// is_interesting should return the "Interestingness" from 0 to 255 (percent times 2.55)
    fn is_interesting(&mut self, executor: &dyn Executor, entry: &Testcase) -> u8;
}

pub trait Reducer<T: Integer + Copy + 'static> {
    fn reduce(first: T, second: T) -> T;
}

pub trait MaxReducer<T: Integer + Copy + 'static> {
    fn reduce(first: T, second: T) -> T {
      if first > second { first } else { second }
    }
}

pub trait MinReducer<T: Integer + Copy + 'static> {
    fn reduce(first: T, second: T) -> T {
      if first < second { first } else { second }
    }
}

pub struct MapFeedback<MapT: Integer + Copy + 'static, ReducerT: Reducer<MapT>> {
    virgin_map: Vec<MapT>,
    _phantom: PhantomData<ReducerT>,
}

impl<'a, MapT: Integer + Copy + 'static, ReducerT: Reducer<MapT>> Feedback for MapFeedback<MapT, ReducerT> {
    fn is_interesting(&mut self, executor: &dyn Executor, _entry: &dyn Testcase) -> u8 {
        let mut interesting = 0;
        for observer in executor.get_observers() {
            if let Some(o) = observer.as_any().downcast_ref::<MapObserver<MapT>>() {
                // TODO: impl. correctly, optimize
                for (virgin, map) in self.virgin_map.iter_mut().zip(o.get_map().iter()) {
                    let reduced = ReducerT::reduce(*virgin, *map);
                    if *virgin != reduced {
                        *virgin = reduced;
                        if interesting < 250 {
                            interesting += 25
                        }
                    }
                }
                break
            }
        }
        interesting
    }
}

impl<'a, MapT: Integer + Copy + 'static, ReducerT: Reducer<MapT>> MapFeedback<MapT, ReducerT> {
    /// Create new MapFeedback using a static map observer
    pub fn new(map_size: usize) -> Self {
        MapFeedback {
            virgin_map: vec![MapT::zero(); map_size],
            _phantom: PhantomData,
        }
    }
}

#[allow(dead_code)]
type MaxMapFeedback<MapT> = MapFeedback<MapT, dyn MaxReducer<MapT>>;
#[allow(dead_code)]
type MinMapFeedback<MapT> = MapFeedback<MapT, dyn MinReducer<MapT>>;

*/