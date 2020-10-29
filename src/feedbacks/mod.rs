extern crate num;

use crate::corpus::Testcase;
use crate::executors::Executor;
use crate::observers::MapObserver;

use num::Integer;

pub trait Feedback {
    /// is_interesting should return the "Interestingness" from 0 to 255 (percent times 2.55)
    fn is_interesting(&mut self, executor: &dyn Executor, entry: &dyn Testcase) -> u8;
}

pub struct CovFeedback<'a, MapT: Integer + Copy> {
    virgin_bits: Vec<MapT>,
    smo: &'a MapObserver<'a, MapT>,
}

impl<'a, MapT: Integer + Copy> Feedback for CovFeedback<'a, MapT> {
    fn is_interesting(&mut self, _executor: &dyn Executor, _entry: &dyn Testcase) -> u8 {
        let mut interesting = 0;
        // TODO: impl. correctly, optimize
        for (virgin, map) in self.virgin_bits.iter_mut().zip(self.smo.get_map().iter()) {
            if virgin != map {
                *virgin = *map;
                if interesting < 250 {
                    interesting += 25
                }
            }
        }

        interesting
    }
}

impl<'a, MapT: Integer + Copy> CovFeedback<'a, MapT> {
    /// Create new CovFeedback using a static map observer
    pub fn new(smo: &'a MapObserver<MapT>) -> Self {
        CovFeedback {
            smo: smo,
            virgin_bits: vec![MapT::zero(); smo.get_map().len()],
        }
    }
}
