extern crate num;

use crate::corpus::Testcase;
use crate::executors::Executor;
use crate::observers::MapObserver;

use num::Integer;

pub trait Feedback {
    /// is_interesting should return the "Interestingness" from 0 to 255 (percent times 2.55)
    fn is_interesting(&mut self, executor: &dyn Executor, entry: &dyn Testcase) -> u8;
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

pub struct MapFeedback<MapT: Integer + Copy + 'static> {
    virgin_map: Vec<MapT>,
}

impl<'a, MapT: Integer + Copy + 'static, ReducerT: Reducer<MapT>> Feedback for MapFeedback<MapT> {
    fn is_interesting(&mut self, executor: &dyn Executor, entry: &dyn Testcase) -> u8 {
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

impl<'a, MapT: Integer + Copy + 'static> MapFeedback<MapT> {
    /// Create new MapFeedback using a static map observer
    pub fn new(map_size: usize) -> Self {
        MapFeedback {
            virgin_map: vec![MapT::zero(); map_size],
        }
    }
}
